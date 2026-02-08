import http.server
import socketserver
import os
import json
import base64
from urllib.parse import urlparse, parse_qs

class AudioRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/audio':
            self.stream_audio(parsed_path)
        elif parsed_path.path == '/admin/dashboard':
            self.handle_admin_dashboard()
        else:
            self.send_error(404, "File not found")

    def stream_audio(self, parsed_path):
        range_header = self.headers.get('Range', None)
        file_path = "./audio/sample.mp3"  # Example audio file

        if range_header:
            self.send_range_response(file_path, range_header)
        else:
            self.send_standard_response(file_path)

    def send_range_response(self, file_path, range_header):
        file_size = os.path.getsize(file_path)
        range_match = range_header.match(r'bytes=(\d+)-(\d+)')
        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2)) if range_match.group(2) else file_size - 1
            self.send_response(206)
            self.send_header("Content-Type", "audio/mpeg")
            self.send_header("Content-Range", f'bytes {start}-{end}/{file_size}')
            self.send_header("Content-Length", str(end - start + 1))
            self.end_headers()
            with open(file_path, 'rb') as file:
                file.seek(start)
                self.wfile.write(file.read(end - start + 1))
        else:
            self.send_error(416, "Requested range not satisfiable")

    def send_standard_response(self, file_path):
        self.send_response(200)
        self.send_header("Content-Type", "audio/mpeg")
        self.send_header("Content-Length", str(os.path.getsize(file_path)))
        self.end_headers()
        with open(file_path, 'rb') as file:
            self.wfile.write(file.read())

    def handle_admin_dashboard(self):
        # Authentication and rendering dashboard
dashboard_content = "<html><body><h1>Admin Dashboard</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(dashboard_content.encode('utf-8'))

def run(server_class=http.server.HTTPServer, handler_class=AudioRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()