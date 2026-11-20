#!/usr/bin/env python3
import http.server
import socketserver
import urllib.request
import urllib.error
import os
import sys

PORT = int(os.environ.get('VITE_PORT', 5175))
DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(DIR, 'dist')
BACKEND_URL = os.environ.get('BACKEND_URL', 'http://127.0.0.1:8002')

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class SPAAndProxyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIST_DIR, **kwargs)

    def do_proxy(self):
        target_url = f"{BACKEND_URL}{self.path}"
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        req_headers = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'content-length')}
        req_headers['Connection'] = 'close'
        req = urllib.request.Request(target_url, data=body, headers=req_headers, method=self.command)

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                self.send_response(resp.status)
                for header, val in resp.getheaders():
                    if header.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                        self.send_header(header, val)
                resp_body = resp.read()
                self.send_header('Content-Length', str(len(resp_body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for header, val in e.headers.items():
                if header.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                    self.send_header(header, val)
            err_body = e.read()
            self.send_header('Content-Length', str(len(err_body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(err_body)
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b'{"error": "Backend reverse proxy unavailable"}')

    def do_GET(self):
        if self.path.startswith('/api'):
            self.do_proxy()
            return
        path = self.translate_path(self.path)
        if not os.path.exists(path) and not any(self.path.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.ico', '.svg', '.woff', '.woff2', '.json']):
            self.path = '/index.html'
        super().do_GET()

    def do_POST(self):
        if self.path.startswith('/api'):
            self.do_proxy()
            return
        self.send_error(405)

    def do_PUT(self):
        if self.path.startswith('/api'):
            self.do_proxy()
            return
        self.send_error(405)

    def do_PATCH(self):
        if self.path.startswith('/api'):
            self.do_proxy()
            return
        self.send_error(405)

    def do_DELETE(self):
        if self.path.startswith('/api'):
            self.do_proxy()
            return
        self.send_error(405)

    def do_OPTIONS(self):
        if self.path.startswith('/api'):
            self.do_proxy()
            return
        super().do_OPTIONS()

if __name__ == '__main__':
    with ThreadingHTTPServer(('0.0.0.0', PORT), SPAAndProxyHandler) as httpd:
        print(f"Serving SPA and multi-threaded /api proxy on http://0.0.0.0:{PORT} -> {BACKEND_URL}")
        httpd.serve_forever()
