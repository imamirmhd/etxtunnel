#!/usr/bin/env python3
"""
Simple HTTP web server for testing ETXTunnel
Responds to HTTP requests with a simple message
"""
import http.server
import socketserver
import sys

PORT = 8080

if len(sys.argv) > 1:
    PORT = int(sys.argv[1])

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        message = f"<html><body><h1>ETXTunnel Test Server</h1><p>Request path: {self.path}</p><p>Server is working correctly!</p></body></html>"
        self.wfile.write(message.encode('utf-8'))
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        response = f"Received POST data: {post_data.decode('utf-8', errors='ignore')}"
        self.wfile.write(response.encode('utf-8'))

    def log_message(self, format, *args):
        # Custom logging to show requests
        print(f"[{self.address_string()}] {format % args}")

with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    print(f"Web server started on port {PORT}")
    print(f"Access it at http://localhost:{PORT}")
    print("Press Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down web server...")
        httpd.shutdown()
