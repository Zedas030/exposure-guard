"""Weekly, gentle look at web interfaces in the LAN: plain HTTP logins, known default-login products, TLS.

Gentle = TCP connect scan of a short port list at nmap -T2 and a packet-rate cap, then at most one GET of the start
page per open port with pauses in between. Never sends credentials, never submits forms."""
from __future__ import annotations

import hashlib
import html
import ipaddress
import os
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.request

import yaml

from . import nmapxml
from .findings import Finding
from .inventory import label
from .tlscheck import lan_tls_info, tls_finding
from .util import log

UA = "Mozilla/5.0 (compatible; exposure-guard; read-only LAN check)"
_FP = None


def fingerprints() -> list[dict]:
    global _FP
    if _FP is None:
        path = os.path.join(os.path.dirname(__file__), "data", "webui_fingerprints.yaml")
        with open(path, encoding="utf-8") as fh:
            _FP = yaml.safe_load(fh) or []
    return _FP


def scan_ports(hosts: list[str], ports: list[int], rate: int) -> dict[str, list[int]]:
    if not hosts:
        return {}
    cmd = ["nmap", "-sT", "-T2", "-n", "-Pn", "--open", "--max-rate", str(rate), "--max-retries", "1",
           "--host-timeout", "10m", "-p", ",".join(str(p) for p in sorted(set(ports))), "-oX", "-"] + hosts
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=4 * 3600)
    if res.returncode != 0:
        raise RuntimeError(f"nmap failed rc={res.returncode}: {res.stderr[-300:]}")
    parsed = nmapxml.parse(res.stdout)
    return {h["addr"]: [p["port"] for p in h["ports"] if p["state"] == "open"] for h in parsed["hosts"]}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str, limit: int = 262_144, timeout: float = 6) -> tuple[int, dict, bytes]:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(limit)
    except urllib.error.HTTPError as exc:
        body = exc.read(limit) if exc.fp else b""
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, body


def page_facts(status: int, headers: dict, body: bytes) -> dict:
    text = body.decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:120] if m else ""
    return {
        "status": status, "title": title, "server": headers.get("server", "")[:80],
        "www_authenticate": headers.get("www-authenticate", "")[:80],
        "password_field": bool(re.search(r"type\s*=\s*['\"]?password", text, re.I)) or status == 401,
        "redirect": headers.get("location", "")[:200] if 300 <= status < 400 else "",
        "body": text[:200_000],
    }


def match_product(facts: dict) -> dict | None:
    for fp in fingerprints():
        ok = True
        for field, src in (("title", facts["title"]), ("body", facts["body"]), ("server", facts["server"])):
            pat = fp.get(field)
            if pat and not re.search(pat, src or "", re.I):
                ok = False
                break
        if ok and any(fp.get(k) for k in ("title", "body", "server")):
            return fp
    return None


def check_endpoint(ip: str, port: int, pause: float) -> dict:
    """TLS first (one handshake), then one GET of '/'; follows nothing."""
    tls = lan_tls_info(ip, port)
    scheme = "https" if tls else "http"
    host = f"[{ip}]" if ":" in ip else ip
    try:
        status, headers, body = fetch(f"{scheme}://{host}:{port}/")
    except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as exc:
        return {"ip": ip, "port": port, "scheme": scheme, "tls": tls, "error": str(exc)[:200]}
    facts = page_facts(status, headers, body)
    time.sleep(pause)
    redirect_https = facts["redirect"].lower().startswith("https://")
    product = match_product(facts)
    facts.pop("body")
    return {"ip": ip, "port": port, "scheme": scheme, "tls": tls, "facts": facts,
            "redirects_to_https": redirect_https, "product": product}


def endpoint_findings(ep: dict, devices: dict, warn_days: int) -> list[Finding]:
    out = []
    ip, port = ep["ip"], ep["port"]
    who = label(devices, ip=ip)
    base = f"lan:{ip}:{port}"
    if ep.get("error"):
        return out
    f, product = ep["facts"], ep.get("product")
    pname = product["name"] if product else ""
    detail = {"ip": ip, "port": port, "scheme": ep["scheme"], "title": f["title"], "server": f["server"],
              "product": pname, "device": who}
    if ep["scheme"] == "http" and not ep["redirects_to_https"]:
        login = f["password_field"]
        out.append(Finding(
            id=f"{base}:http", source="lan_web", kind="web", severity="medium" if login else "low",
            title=f"{'Login page' if login else 'Web interface'} over plain HTTP: {ip}:{port}"
                  + (f" ({f['title'] or pname})" if (f["title"] or pname) else ""),
            message=f"{who} serves '{f['title'] or '-'}' (server '{f['server'] or '-'}') on port {port} without TLS"
                    + (" and asks for a password - credentials travel in clear text in the LAN/Wi-Fi." if login else "."),
            action="Enable HTTPS on the device/service (or put it behind a TLS reverse proxy) and disable plain HTTP; "
                   "for IoT devices without HTTPS keep them in a separate (guest/IoT) network." if login else
                   "Low risk inside the LAN; prefer HTTPS if the interface offers settings.",
            detail=detail, state_key=[login, f["title"], pname]))
    if product and (product.get("default_login") or product.get("unauthenticated")):
        unauth = bool(product.get("unauthenticated")) and not f["password_field"]
        if product.get("default_login") or unauth:
            out.append(Finding(
                id=f"{base}:product", source="lan_web", kind="web", severity="medium",
                title=(f"Unauthenticated admin UI: {pname} at {ip}:{port}" if unauth else
                       f"{pname} at {ip}:{port} ships with a known default login"),
                message=(f"{who} runs {pname}; the start page is reachable without a login prompt." if unauth else
                         f"{who} runs {pname}. Vendor default: {product.get('default_login')}. "
                         "Exposure Guard did not try to log in - please verify yourself."),
                action=product.get("advice", "Verify the credentials were changed."),
                detail=dict(detail, default_login=product.get("default_login", ""), unauthenticated=unauth),
                state_key=[pname, unauth]))
    if ep.get("tls") and ep["tls"].get("not_after"):
        tf = tls_finding(f"tls-lan:{ip}:{port}", "lan_web", f"{who} port {port}", ep["tls"], warn_days, False)
        tf.detail.update(ip=ip, port=port)
        out.append(tf)
    return out


def run(cfg, devices: dict) -> tuple[list[Finding], dict]:
    lw = cfg["lan_web"]
    net = ipaddress.ip_network(cfg["network"]["lan_cidr"], strict=False)
    excl = {str(x) for x in lw["exclude"]}
    hosts = sorted({ip for d in devices.values() if d.get("active") for ip in d["ips"]
                    if ip and ip not in excl and d["mac"] not in excl and ipaddress.ip_address(ip) in net},
                   key=lambda s: tuple(int(x) for x in s.split(".")))
    t0 = time.time()
    open_ports = scan_ports(hosts, lw["ports"], lw["max_rate"])
    findings, endpoints = [], []
    for ip, ports in open_ports.items():
        for port in ports:
            ep = check_endpoint(ip, port, lw["request_pause"])
            endpoints.append({k: v for k, v in ep.items() if k != "product"} | {"product": (ep.get("product") or {}).get("name", "")})
            findings += endpoint_findings(ep, devices, cfg["tls"]["warn_days"])
    log.info("LAN web check: %d hosts, %d open web ports, %.0f s", len(hosts), sum(map(len, open_ports.values())),
             time.time() - t0)
    return findings, {"hosts": len(hosts), "endpoints": endpoints, "seconds": round(time.time() - t0)}
