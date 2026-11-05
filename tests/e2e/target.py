"""E2E 'internet-facing' target: HTTP on 8080 always; control port 7000 opens/closes extra listeners."""
import json
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTENERS = {}


class Page(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><title>E2E target</title><body>hello</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def open_port(port):
    if port in LISTENERS:
        return
    srv = ThreadingHTTPServer(("0.0.0.0", port), Page)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    LISTENERS[port] = srv


class Control(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        cmd = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        port = int(cmd["port"])
        if self.path == "/open":
            open_port(port)
        elif self.path == "/close" and port in LISTENERS:
            LISTENERS.pop(port).shutdown()
        self.send_response(200)
        self.end_headers()


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    open_port(8080)
    print("target up", flush=True)
    ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 7000), Control).serve_forever()
