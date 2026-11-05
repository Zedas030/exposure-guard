"""Fake Home Assistant: records notify calls and state updates. GET /_records returns them."""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(records, cfg):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            data = json.dumps(records).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/_reset":
                records["notify"].clear()
                records["states"].clear()
            elif cfg.get("down"):
                self.send_response(503)
                self.end_headers()
                return
            elif self.headers.get("Authorization") != "Bearer test-token":
                self.send_response(401)
                self.end_headers()
                return
            elif self.path.startswith("/api/services/notify/"):
                records["notify"].append(body)
            elif self.path.startswith("/api/states/"):
                records["states"][self.path.rsplit("/", 1)[1]] = body
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
    return H


def start(port=0):
    records, cfg = {"notify": [], "states": {}}, {}
    srv = ThreadingHTTPServer(("127.0.0.1" if port == 0 else "0.0.0.0", port), make_handler(records, cfg))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, records, cfg


if __name__ == "__main__":
    srv, _, _ = start(int(sys.argv[1]) if len(sys.argv) > 1 else 8123)
    print("fake HA on", srv.server_address, flush=True)
    threading.Event().wait()
