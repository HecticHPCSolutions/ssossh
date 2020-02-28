import json
import webbrowser
import os
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from jinja2 import Template
import queue
import subprocess
import requests
import pathlib

q=queue.Queue()

class MyRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, port, logout, *args,**kwargs):
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
            currpath = pathlib.Path(__file__).parent.absolute()
            with open(os.path.join(currpath,'templates','call_back.html'),'rb') as f:
                tsrc = f.read()
                t = Template(tsrc.decode())
                self.wfile.write(t.render(port=self.port,logout=self.logout).encode())
            return
        else:
            q.put(self.path)

def make_key():
    keypath = os.path.expanduser('~/.ssh/ssossh-key')
    try:
        mode = os.stat(keypath).st_mode
        import stat
        if stat.S_ISREG(mode):
            try:
                rm_cert(keypath)
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
        
    subprocess.call(['ssh-keygen','-N','','-f',keypath],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return keypath

def sign_cert(keypath,token,url):
    with open(keypath+'.pub','r') as f:
        pub_key = f.read()
    sess = requests.Session()
    headers = {"Authorization":"Bearer %s"%token}
    data = {"public_key":pub_key}
    resp = sess.post(url, json=data, headers=headers, verify=False)
    data = resp.json()
    cert = data['certificate']
    with open(keypath+"-cert.pub",'w') as f:
        f.write(cert)

def start_agent():
    pass

def rm_cert(keypath):
    subprocess.call(['ssh-add','-d',keypath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def add_cert(keypath):
    subprocess.call(['ssh-add',keypath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def do_request(authservice):
    nonce = os.urandom(8).hex()
    redirect_uri = "http://localhost:4200/sshauthz_callback"
    requrl = (authservice['authorise'] + "?response_type=token&redirect_uri=" +
            redirect_uri + "&state="+nonce +"&client_id=" +
            authservice['client_id'] + "&scope=" + authservice['scope'])
    webbrowser.open(requrl)
    port=4200
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
        raise Exception('It looks like someone is playing silly buggers and intercepting messages between you and the authentication server')
    return token


def main():
    currpath = pathlib.Path(__file__).parent.absolute()
    with open(os.path.join(currpath,'authservers.json'),'r') as f:
        config = json.loads(f.read())
        authservice = config[0]

    token = do_request(authservice)
    path = make_key()
    sign_cert(path,token,authservice['sign'])
    add_cert(path)

if __name__ == '__main__':
    main()
