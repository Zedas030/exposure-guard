"""Read-only web UI + JSON API + /metrics. There are deliberately no write endpoints (acks: YAML or CLI)."""
from __future__ import annotations

import json
import mimetypes
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import metrics
from .util import now, parse_iso

STATIC = os.path.join(os.path.dirname(__file__), "static")


def make_handler(g):
    class H(BaseHTTPRequestHandler):
        server_version = "exposure-guard"

        def log_message(self, fmt, *args):  # quiet access log
            pass

        def _send(self, code: int, body: bytes, ctype: str, cache: str = "no-store"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, default=str, indent=1).encode(), "application/json")

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):  # noqa: C901
            path = self.path.split("?", 1)[0]
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            try:
                if path in ("/", "/index.html"):
                    return self._file(os.path.join(STATIC, "index.html"))
                if path.startswith("/static/"):
                    name = os.path.basename(path)
                    return self._file(os.path.join(STATIC, name), cache="max-age=300")
                if path == "/metrics":
                    return self._send(200, metrics.render(g).encode(), "text/plain; version=0.0.4")
                if path == "/api/health":
                    pub = parse_iso((g.store.get("published") or {}).get("at"))
                    alive = bool(pub) and (now() - pub).total_seconds() < 900
                    return self._json({"alive": alive, "published": pub}, 200 if alive else 503)
                if path == "/api/status":
                    st = g.status()
                    st["ui"] = g.cfg["ui"]
                    st["fritz"] = {k: v for k, v in (g.store.get("fritz:last") or {}).items() if k != "errors"}
                    st["external"] = {"last": g.store.get("external:last"), "last_full": g.store.get("external:last_full"),
                                      "probe": g.store.get("external:health"), "seen_v4": g.store.get("external:seen_v4"),
                                      "seen_v6": g.store.get("external:seen_v6")}
                    st["reports"] = _reports(g)
                    st["devices"] = len(g.devices())
                    return self._json(st)
                if path == "/api/findings":
                    state = None if "all" in query else "open"
                    return self._json(g.engine.annotate(g.store.findings(state)))
                if path == "/api/devices":
                    return self._json(sorted(g.devices().values(), key=lambda d: d.get("first_seen") or ""))
                if path == "/api/events":
                    return self._json(g.store.events(limit=300))
                m = re.fullmatch(r"/reports/([\w\-]+\.(?:html|md))", path)
                if m:
                    f = os.path.join(g.cfg.data_dir, "reports", m.group(1))
                    if os.path.exists(f):
                        return self._file(f)
                return self._send(404, b"not found", "text/plain")
            except Exception as exc:  # noqa: BLE001
                return self._send(500, f"error: {exc}".encode(), "text/plain")

        def _file(self, path: str, cache: str = "no-store"):
            if not os.path.isfile(path):
                return self._send(404, b"not found", "text/plain")
            ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
            if path.endswith(".md"):
                ctype = "text/markdown"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            with open(path, "rb") as fh:
                return self._send(200, fh.read(), ctype, cache)
    return H


def _reports(g) -> list[str]:
    rdir = os.path.join(g.cfg.data_dir, "reports")
    if not os.path.isdir(rdir):
        return []
    return sorted((f[:-5] for f in os.listdir(rdir) if f.endswith(".html")), reverse=True)


def serve(g, stop: threading.Event) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((g.cfg["general"]["listen_host"], int(g.cfg["general"]["listen_port"])), make_handler(g))
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, name="web", daemon=True)
    t.start()
    return srv
