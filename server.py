from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        data = self.get_audiobook_data()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def get_audiobook_data(self):
        # Placeholder for audiobook data handling
        return {
            'title': 'Sample Audiobook',
            'author': 'Author Name',
            'chapters': ['Chapter 1', 'Chapter 2']
        }

def run(server_class=HTTPServer, handler_class=RequestHandler, host='::', port=8080):
    server_address = (host, port)
    httpd = server_class(server_address, handler_class)
    print(f'Serving on {host}:{port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run()