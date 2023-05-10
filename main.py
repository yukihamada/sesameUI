import os
import datetime
import base64
import requests
import json
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

uuid = os.environ['uuid']
secret_key = os.environ['secret_key']
api_key = os.environ['api_key']
ifttt_url = os.environ['ifttt']
password = os.environ['password']

def get_cmac(message):
    cmac = CMAC.new(bytes.fromhex(secret_key), ciphermod=AES)
    cmac.update(bytes.fromhex(message))
    return cmac.hexdigest()

def send_cmd(cmd, history):
    base64_history = base64.b64encode(bytes(history, 'utf-8')).decode()
    headers = {'x-api-key': api_key}
    ts = int(datetime.datetime.now().timestamp())
    message = ts.to_bytes(4, byteorder='little').hex()[2:8]
    sign = get_cmac(message)

    url = f'https://app.candyhouse.co/api/sesame2/{uuid}/cmd'
    body = {'cmd': cmd, 'history': base64_history, 'sign': sign}
    return requests.post(url, json.dumps(body), headers=headers)

def process_request(action, key):
    if not action:
        return "Action no request", 200

    if key != password:
        return "Invalid password", 200

    if action == "autounlock":
        response = requests.get(ifttt_url)
        if response.ok:
            if "Congratulations" in response.text:
                return "Unlocked", 200
            else:
                return "Unlock failed", 200
        else:
            return "Autounlock Invalid request", 200  
    else:
        cmd_dict = {"open": 82, "close": 83, "toggle": 88}
        if action not in cmd_dict:
            return "Invalid Action", 200

        history = f'Replit_{action}'
        res = send_cmd(cmd_dict[action], history)

        if res.status_code == 200:
            return f"The lock has been {action}ed.", 200
        else:
            return f"Failed to {action} the lock.", 400

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            try:
                with open('templates/index.html', 'r') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(bytes(content, 'utf8'))
            except:
                self.send_response(404)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'404: File not found')

    def do_POST(self):
        if self.path == '/control':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            post_data_dict = parse_qs(post_data.decode())

            action = post_data_dict.get('action', [None])[0]
            key = post_data_dict.get('key', [None])[0]

            result, status_code = process_request(action, key)

            self.send_response(status_code)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(bytes(result, 'utf8'))
          
httpd = HTTPServer(('', 8000), MyHandler)
httpd.serve_forever()