import json
import webbrowser
import os
import queue
import subprocess
import requests
import pathlib
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from jinja2 import Template
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
        if "callback" in self.path:
            self._set_headers()
            from . import templates
            with pkg_resources.open_text(templates,
                    'call_back.html') as f:
                tsrc = f.read()
                t = Template(tsrc)
                self.wfile.write(t.render(port=self.port,
                                          logout=self.logout).encode())
            return
        else:
            q.put(self.path)


def make_key():
    """
    Generate a keyfile (using ssh-keygen)
    """
    keypath = os.path.expanduser('~/.ssh/ssossh-key')
    try:
        mode = os.stat(keypath).st_mode
        import stat
        if stat.S_ISREG(mode):
            try:
                rm_key_agent(keypath)
            except subprocess.CalledProcessError:
                pass
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
    subprocess.call(['ssh-keygen', '-t', 'ecdsa', '-N', '', '-f', keypath],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
    return keypath


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
    resp = sess.post(url, json=data, headers=headers, verify=False)
    data = resp.json()
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


def add_key_agent(keypath):
    """
    Add the key and cert to the agent
    """
    subprocess.call(['ssh-add', keypath],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)


def do_request(authservice):
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
    port = 4200
    server_address = ('', port)
    handler = partial(MyRequestHandler, port, authservice['logout'])
    httpd = HTTPServer(server_address, handler)
    httpd.handle_request()
    httpd.handle_request()
    path = q.get()
    params = path.split('?')[1].split('&')
    token = params[0].split('=')[1]
    state = params[1].split('=')[1]
    if not state == nonce:
        raise Exception('OAuth2 error: A securit check failed')
    return token


def main():
    """
    Read the authservers.json config file
    Get an OAuth2 Implicit token
    Generate an SSH key pair
    Use the OAuth2 token to create a certificate from the pub key
    Add the certificate to the users agent
    """
    from . import config
    with pkg_resources.open_text(config,'authservers.json') as f:
        config = json.loads(f.read())
        authservice = config[0]

    token = do_request(authservice)
    path = make_key()
    sign_cert(path, token, authservice['sign'])
    add_key_agent(path)


if __name__ == '__main__':
    main()
