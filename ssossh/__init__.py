
import json
import webbrowser
import os
import queue
import subprocess
import requests
import pathlib
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources

q = queue.Queue()


class MyRequestHandler(BaseHTTPRequestHandler):
    """
    The request handler runs twice. Once serves a snippet of
    javascript which takes the token in the URL framgment and puts in into
    a request parameter.
    The second run receives the token as a request parameter and puts it in the queue
    """
    def __init__(self, port, logout, *args, **kwargs):
        self.port = port
        self.logout = logout
        super(MyRequestHandler, self).__init__(*args, **kwargs)

    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self, *args, **kwargs):
        from . import templates
        with pkg_resources.open_text(templates,
                'call_back.html') as f:
            tsrc = f.read()
            rsrc = tsrc.replace('{{ port }}',str(self.port)).replace('{{ logout }}',self.logout).encode()
        if "callback" in self.path:
            self._set_headers()
            self.wfile.write(rsrc)
            self.send_response(200)
            return
        if "favicon.ico" in self.path:
            print('favicon requested, send 404')
            self.send_error(404,message="No favicon here")
        if "extract" in self.path:
            self._set_headers()
            self.wfile.write(rsrc)
            self.send_response(200)
            #self.send_response(204)
            self.wfile.write(b"")
            q.put(self.path)
    def log_message(self, format, *args):
        return

def rm_ssh_files(keypath):
    try:
        mode = os.stat(keypath).st_mode
        import stat
        if stat.S_ISREG(mode):

            try:
                os.unlink(keypath)
            except FileNotFoundError:
                pass
            try:
                os.unlink(keypath+'.pub')
            except FileNotFoundError:
                pass
            try:
                os.unlink(keypath+'-cert.pub')
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass

def make_key(keypath):
    """
    Generate a keyfile (using ssh-keygen)
    """
    rm_ssh_files(keypath)
    subprocess.call(['ssh-keygen', '-t', 'ed25519', '-N', '', '-f', keypath],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)


def sign_cert(keypath, token, url):
    """
    give a public key and a OAuth2 token,
    use the token to access the signing endpoint and save
    the resulting certificate
    """
    with open(keypath + '.pub', 'r') as f:
        pub_key = f.read()
    sess = requests.Session()
    headers = {"Authorization": "Bearer {}".format(token)}
    data = {"public_key": pub_key}
    resp = sess.post(url, json=data, headers=headers, verify=True)
    try:
        data = resp.json()
    except:
        print(resp.status_code)
        print(resp.text)
    cert = data['certificate']
    with open(keypath + "-cert.pub", 'w') as f:
        f.write(cert)


def rm_key_agent(keypath):
    """
    Remove the key/cert from the agent
    """
    subprocess.call(['ssh-add', '-d', keypath],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)


def add_key_agent(keypath, expiry, agentsock=None):
    """
    Add the key and cert to the agent
    """
    env = os.environ.copy()
    if agentsock is not None:
        env['SSH_AUTH_SOCK']=agentsock
    p = subprocess.Popen(['ssh-add', '-t',str(int(expiry)), keypath],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env)
    (stdout, stderr) = p.communicate()


def do_request(authservice, httpd):
    """
    Open a web browser window
    and request an OAuth2 token to sign certificates
    We must service two http requests
    The first is the OAuth2 callback with the token in the URL fragment
    (as specified by OAuth2 Impliciy flow standards)
    The second has the token in the query parameters
    so that the backend can read it
    """
    nonce = os.urandom(8).hex()
    redirect_uri = "http://localhost:4200/sshauthz_callback"
    requrl = (authservice['authorise'] + "?response_type=token&redirect_uri=" +
              redirect_uri + "&state=" + nonce + "&client_id=" +
              authservice['client_id'] + "&scope=" + authservice['scope'])
    webbrowser.open(requrl)
    #print('open a web browser to {}'.format(requrl))

    httpd.handle_request()
    httpd.handle_request()
    path = q.get()
    if 'favicon.ico' in path:
        httpd.handle_request()
    params = path.split('?')[1].split('&')
    token = params[0].split('=')[1]
    state = params[1].split('=')[1]
    if not state == nonce:
        raise Exception('OAuth2 error: A security check failed. Nonce is {} state is {}'.format(nonce,state))
    return token


def parse_cert_contents(lines):
    key = None
    values = []
    res = {}
    for l in lines:
        l = l.rstrip().lstrip()
        if ':' in l:
            if key is not None:
                res[key] = values
            values = []
            (key,v) = l.split(':',1)
            v = v.lstrip().rstrip()
            if v != '':
                values = [v]
        else:
            if l != '':
                values.append(l)
    return res


def get_cert_expiry(path):
    import datetime
    p = subprocess.Popen(['ssh-keygen','-L','-f',path],stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    keygenout,keygenerr = p.communicate()
    # Examine the cert to determine its expiry. Use the -t flag to automatically remove from the ssh-agent when the cert expires
    certcontents = parse_cert_contents(keygenout.decode().splitlines())
    endtime = datetime.datetime.strptime(certcontents['Valid'][0].split()[3],"%Y-%m-%dT%H:%M:%S")
    delta = endtime - datetime.datetime.now() # I *think* the output of ssh-keygen -L is in the current timezone even though I assume the certs validity is in UTC
    return delta


def select_service(config):
    prompt="Enter the number of the site you would like to login to:\n"
    n=0
    for s in config:
        n=n+1
        prompt=prompt+"{}: {}\n".format(n,s['name'])

    v = input(prompt)
    return int(v)-1

def main():
    """
    Read the authservers.json config file
    Get an OAuth2 Implicit token
    Generate an SSH key pair
    Use the OAuth2 token to create a certificate from the pub key
    Add the certificate to the users agent
    """
    from . import config
    import os
    import sys
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--config', default="~/.authservers.json",help="JSON format config file containing the list of places we can log into")
    parser.add_argument('-k','--keypath',default=None,help="Path to store the ssh key (and certificate)")
    parser.add_argument('-a','--agentsock',default=None,help='SSH Agent socket (eg the value os SSH_AUTH_SOCK variable). Default is to use whatever this terminal is using')
    args = parser.parse_args()


    configpath = os.path.expanduser(args.config)

    if os.path.exists(configpath):
        with open(configpath,'r') as f:
            config = json.loads(f.read())
    else:
        print('No config file available')
        print('either specify a json config file or store one at ~/.authservers.json')
        sys.exit(1)

    if len(config) > 1:
        service = select_service(config)
    else:
        service = 0
    authservice = config[service]

    try:
        port = 4200
        server_address = ('', port)
        handler = partial(MyRequestHandler, port, authservice['logout'])
        httpd = HTTPServer(server_address, handler)
    except OSError as e:
        print("Port 4200 is in use")
        print("This script needs to listen for a connection on port 4200")
        print("This allows the web browser to send data back to this script (a process which is intentionally difficult to prevent web browsers leaking information)")
        sys.exit(1)

    token = do_request(authservice, httpd)
    import tempfile

    if args.keypath is not None:
        path = args.keypath
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        path = f.name
    print('generateing a new key at {}'.format(path))
    make_key(path)
    sign_cert(path, token, authservice['sign'])
    expiry = get_cert_expiry("{}-cert.pub".format(path))
    print("cert will expire {}".format(expiry))
    try:
        add_key_agent(path, expiry.total_seconds(), args.agentsock)
    except subprocess.CalledProcessError:
        print('unable to add the certificate to the agent. Is SSH_AUTH_SOCK set correctly?')
        pass
    if args.keypath is None:
        rm_ssh_files(path)
