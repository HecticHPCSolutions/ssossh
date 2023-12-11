import argparse
import datetime
import json
import tempfile
import os
import queue
import requests
import stat
import subprocess
import sys
import urllib.request
import webbrowser

from http.server import HTTPServer, BaseHTTPRequestHandler
from functools import partial
from pathlib import Path

AUTHSERVERCONFIG="https://raw.githubusercontent.com/HecticHPCSolutions/ssossh/main/ssossh/config/authservers.json"

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources


from . import templates

q = queue.Queue()


class MyRequestHandler(BaseHTTPRequestHandler):
    """
    The request handler runs twice. Once serves a snippet of
    javascript which takes the token in the URL fragment and puts in into
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
        with pkg_resources.open_text(templates,
                                     'call_back.html') as f:
            tsrc = f.read()
            rsrc = tsrc.replace('{{ port }}', str(self.port)).replace(
                '{{ logout }}', self.logout).encode()
        if "callback" in self.path:
            self._set_headers()
            self.wfile.write(rsrc)
            self.send_response(200)
            return
        if "favicon.ico" in self.path:
            print('favicon requested, send 404')
            self.send_error(404, message="No favicon here")
        if "extract" in self.path:
            self._set_headers()
            self.wfile.write(rsrc)
            self.send_response(200)
            # self.send_response(204)
            self.wfile.write(b"")
            q.put(self.path)

    def log_message(self, format, *args):
        return


def rm_ssh_files(keypath):
    """
    Clean up previous entries
    """
    try:
        mode = os.stat(keypath).st_mode

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
                    stdout=subprocess.DEVNULL)


def sign_cert(keypath, token, url):
    """
    give a public key and a OAuth2 token,
    use the token to access the signing endpoint and save
    the resulting certificate
    """
    with open(keypath + '.pub', 'r') as f:
        pub_key = f.read()
    sess = requests.Session()
    headers = {"Authorization": f"Bearer {token}"}
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
                    stdout=subprocess.DEVNULL)


def add_key_agent(keypath, expiry, agentsock=None):
    """
    Add the key and cert to the agent
    """
    env = os.environ.copy()
    if agentsock is not None:
        env['SSH_AUTH_SOCK'] = agentsock
    p = subprocess.Popen(['ssh-add', '-t', str(int(expiry)), keypath],
                         stdout=subprocess.DEVNULL,
                         env=env)
    (stdout, stderr) = p.communicate()


def do_request(auth_service, httpd):
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
    requrl = (auth_service['authorise'] + "?response_type=token&redirect_uri=" +
              redirect_uri + "&state=" + nonce + "&client_id=" +
              auth_service['client_id'] + "&scope=" + auth_service['scope'])
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
        raise Exception(
            'OAuth2 error: A security check failed. Nonce is {} state is {}'.format(nonce, state))
    return token


def parse_cert_contents(path):
    """
    Parse certificate, returning a dictionary of its contents
    """
    # Read certificate
    p = subprocess.Popen(['ssh-keygen', '-L', '-f', path],
                         stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    keygenout, keygenerr = p.communicate()
    lines = keygenout.decode().splitlines()
    
    # Convert certificate to dictionary
    key = None
    values = []
    cert_contents = {}

    # Iterate through lines
    for l in lines:
        l = l.rstrip().lstrip()
        
        if ':' in l:
            if key is not None:
                cert_contents[key] = values

            values = []
            (key, v) = l.split(':', 1)
            v = v.lstrip().rstrip()
            if v != '':
                values = [v]

        else:
            if l != '':
                values.append(l)
    return cert_contents


def get_cert_expiry(path):
    """
    Use parse_cert_contents to get Parse certificate, returning a dictionary of its contents
    """
    cert_contents = parse_cert_contents(path)
    endtime = datetime.datetime.strptime(
        cert_contents['Valid'][0].split()[3], "%Y-%m-%dT%H:%M:%S")
    
    # I *think* the output of ssh-keygen -L is in the current timezone even though I assume the certs validity is in UTC
    delta = endtime - datetime.datetime.now()
    return delta

def get_cert_user(path):
    """
    Use parse_cert_contents to get Parse certificate, returning a dictionary of its contents
    Returns first Principal - users with more than one will need to add support for their other users manually
    These users are assumed to be admins with the abilities to do so themselves
    """
    cert_contents = parse_cert_contents(path)
    return cert_contents['Principals'][0]


def select_service(config):
    """
    Prompt user for which site to login to
    """
    prompt = "Enter the number of the site you would like to login to:\n"
    for i, site in enumerate(config):
        prompt = f"{prompt} {i + 1}: {site['name']}\n"

    return int(input(prompt)) - 1


def parse_consent(yes):
    """
    Confirm if user input should be interpreted as a yes or a no
    Uses global --yes argument as input
    """
    # Skip if --yes
    if yes:
        return True

    # Prompt user
    user_input = input().lower()

    # Parse True/False
    if user_input in ["y", "yes", "1", ""]:
        return True
    elif user_input in ["n", "no", "0"]:
        return False
    
    # Unexpected value
    else:
        print("Invalid input")
        sys.exit(1)


def main():
    """
    Read the authservers.json config file
    Get an OAuth2 Implicit token
    Generate an SSH key pair
    Use the OAuth2 token to create a certificate from the pub key
    Add the certificate to the users agent
    """
    default_authconfig = os.path.expanduser(os.path.join('~','.authservers.json'))
    default_sshconfig = os.path.expanduser(os.path.join('~','.ssh','config'))
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default=default_authconfig,
                        help="JSON format config file containing the list of places we can log into")
    parser.add_argument("-k", "--keypath", default=None,
                        help="Path to store the ssh key (and certificate)")
    parser.add_argument("--agent", action="store_true",
                        help="Use the ssh agent rather than saving the key")
    parser.add_argument("-a", "--agentsock", default=None,
                        help="SSH Agent socket (eg the value os SSH_AUTH_SOCK variable). Default is to use whatever this terminal is using")
    parser.add_argument("--setssh", action="store_true",
                        help="Add an entry to your ssh config")
    parser.add_argument("--sshconfig", default=default_sshconfig,
                        help="The ssh config to modify")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Yes to all")
    parser.add_argument( "--defaultpath", action="store_true",
                        help="When adding the key to the agent, use the usual file path rather than a temp file")
    args = parser.parse_args()

    # Check if config exists
    config_path = os.path.expanduser(args.config)
    if not os.path.exists(config_path):
        # If config can't be found, ask user if they'd like one to be generated
        print("No config file available")
        print("SSOSSH will look for a config at ~/.authservers.json unless specified with '-c'")

        if args.yes:
            print("Creating a key created at ~/.authservers.json")
        else:
            print("Would you have your key created at ~/.authservers.json? ([Y]es/[n]o):")
        
        # If yes create and continue
        if parse_consent(args.yes):
            # wget.download(url, "~/.authservers.json")
            urllib.request.urlretrieve(AUTHSERVERCONFIG, filename=os.path.expanduser("~/.authservers.json"))
            with open(config_path, 'r') as f:
                config = json.loads(f.read())
        # If no exit
        else:
            sys.exit(1)

    # Load config
    with open(config_path, 'r') as f:
        config = json.loads(f.read())

    # Prompt for which service if service doesn't exist
    auth_service = config[select_service(config) if len(config) > 1 else 0]

    # Connect to web browser for auth
    try:
        port = 4200
        server_address = ('', port)
        handler = partial(MyRequestHandler, port, auth_service['logout'])
        httpd = HTTPServer(server_address, handler)
    except OSError as e:
        print("Port 4200 is in use")
        print("This script needs to listen for a connection on port 4200")
        print("This allows the web browser to send data back to this script (a process which is intentionally difficult to prevent web browsers leaking information)")
        sys.exit(1)

    # Get token from request
    token = do_request(auth_service, httpd)

    # Where do we store the key and should we remove it
    # i) user gave us a keypath => save the key at the keypath
    # ii) user wants to use the agent and DIDN'T specify => use a temp key and don't save
    # iii) user wants to use the agent and asked for the default => Save at the default location.
    # iv) user didn't specify anything => Prompt for consent to save at the default location.

    rmkey = True # By default we will remove the key file form disk after loading it into the agent
    # Parse keypath
    if args.keypath is not None:
        path = args.keypath
        rmkey = False
    
    # Create temp if using agent
    elif args.agent and args.keypath is None:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        path = f.name
        rmkey = True

    # Else use name of service to construct path
    else:
        path = os.path.expanduser(os.path.join('~','.ssh',f"{auth_service['name']}"))
        rmkey = True

    # Should we save the key after loading to the agent (not rmkey)
    # if the keypath was already specified, save the key
    # if -y was specified, save the key
    # otherwise prompt to save the key
    if rmkey:
        if args.yes:
            print(f"Creating a key at {path}")
            rmkey = False
        else:
<<<<<<< HEAD
            print(f"Would you like to create a key at {path}? ([Y]es/[n]o):")
        
        # If no, do not continue
        if not parse_consent(args.yes):
            sys.exit(1)
=======
            print(f"Would you like to create a key at {path}? ([Y]es/[N]o):")
        if parse_consent(args.yes):
            rmkey = False
>>>>>>> main

    # Generate new key at the path
    print(f"Generating a new key at {path}")
    make_key(path)
    sign_cert(path, token, auth_service['sign'])
    expiry = get_cert_expiry(f"{path}-cert.pub")
    print(f"Cert will expire {expiry}")

    # Add key to agent and clean up
    if args.agent:
        try:
            add_key_agent(path, expiry.total_seconds(), args.agentsock)
        except subprocess.CalledProcessError:
            print('Unable to add the certificate to the agent. Is SSH_AUTH_SOCK set correctly?')
        
    if rmkey:
        rm_ssh_files(path)
    
    # Optionally add to ssh config
    if args.setssh:
        print("You've selected to set up your ssh config for ssossh.")
        print("This will add two entries to your ssh config. One for the login node, and one for a compute job.")

        if not args.yes:
            print("Would you like to continue? ([Y]es/[n]o):")

        # Confirm with user
        if parse_consent(args.yes):
            with open(args.sshconfig, "a") as ssh_config:
                ssh_command = "ssh.exe" if sys.platform == "win32" else "ssh"
                user = get_cert_user(f"{path}-cert.pub")
                
                # Login node
                ssh_config.write("\n\n")
                ssh_config.write(f"Host {user}_{auth_service['name']}\n")
                ssh_config.write(f"\tHostName {auth_service['login']}\n")
                ssh_config.write(f"\tUser {user}\n")
                ssh_config.write(f"\tIdentityFile {path}\n\n")

                # Compute job
                ssh_config.write(f"Host {user}_{auth_service['name']}_job\n")
                ssh_config.write(f"\tHostName {user}_{auth_service['name']}_job\n")
                ssh_config.write(f"\tUser {user}\n")
                ssh_config.write(f"\tIdentityFile {path}\n")
                ssh_config.write(f"\tProxyCommand {ssh_command} -i {path} {user}@{auth_service['login']} {auth_service['proxy']}\n")
        else:
            sys.exit(1)

