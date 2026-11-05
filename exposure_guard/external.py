"""External view: talk to the probe over SSH (outbound only), push signed targets, pull sealed results,
turn them into findings with attribution to router mappings and LAN devices."""
from __future__ import annotations

import base64
import ipaddress
import os
import shlex
import subprocess
import time
import zlib

from . import nmapxml
from .crypto import EnvelopeError, GuardKeys, open_envelope, sign_json
from .findings import Finding
from .inventory import ipv6_targets, label
from .tlscheck import tls_finding
from .util import iso, ip_family, log, now, parse_iso, short_hash


class ProbeError(Exception):
    pass


class ProbeClient:
    def __init__(self, cfg, keys: GuardKeys, host: str | None = None):
        ext = cfg["external"]
        self.cfg, self.keys = cfg, keys
        self.host = host or ext["probe_host"]
        self.port, self.user = int(ext["probe_port"]), ext["probe_user"]
        ssh_dir = os.path.join(cfg.data_dir, "ssh")
        self.identity = os.path.join(ssh_dir, "id_ed25519")
        self.known_hosts = os.path.join(ssh_dir, "known_hosts")
        self.timeout = int(ext["connect_timeout"])
        self.verify_key = ext.get("probe_verify_key", "")

    def _ssh(self, verb: str, stdin: str | None = None, timeout: int = 120) -> str:
        if not self.host:
            raise ProbeError("external.probe_host not configured")
        host = f"[{self.host}]" if ":" in self.host else self.host
        cmd = ["ssh", "-i", self.identity, "-p", str(self.port), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
               "-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "StrictHostKeyChecking=yes",
               "-o", f"ConnectTimeout={self.timeout}", "-o", "ServerAliveInterval=15", "-o", "LogLevel=ERROR",
               "-T", f"{self.user}@{host}", verb]
        try:
            res = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise ProbeError(f"probe {self.host}: timeout") from exc
        except OSError as exc:
            raise ProbeError(f"ssh not runnable: {exc}") from exc
        if res.returncode == 255:
            raise ProbeError(f"probe {self.host} unreachable: {res.stderr.strip()[-300:]}")
        if res.returncode not in (0, 2):
            raise ProbeError(f"probe {self.host} '{verb}' failed rc={res.returncode}: {res.stderr.strip()[-300:]}")
        return res.stdout

    def _open(self, text: str) -> dict:
        return open_envelope(text.strip(), self.verify_key, self.keys.box())

    def health(self) -> dict:
        return self._open(self._ssh("health"))

    def put_targets(self, doc: dict) -> dict:
        return self._open(self._ssh("put-targets", stdin=sign_json(doc, self.keys.signing())))

    def scan_now(self) -> dict:
        return self._open(self._ssh("scan-now"))

    def results_after(self, after: str) -> list[tuple[str, dict]]:
        out = []
        for line in self._ssh(f"get-results {shlex.quote(after or '0')}", timeout=300).splitlines():
            if not line.strip():
                continue
            run_id, _, env = line.partition(" ")
            out.append((run_id, self._open(env)))
        return out


# ----------------------------------------------------------------------------------- targets
def build_targets(cfg, store, fritz_snap: dict | None) -> dict:
    ext = cfg["external"]
    targets = []
    snap = fritz_snap or store.get("fritz:last") or {}
    if snap.get("ipv4"):
        targets.append({"addr": snap["ipv4"], "role": "router", "full": True, "label": "router IPv4"})
    if snap.get("ipv6"):
        targets.append({"addr": snap["ipv6"], "role": "router", "full": True, "label": "router IPv6 (WAN)"})
    if ext["ipv6_devices"]:
        rmac = snap.get("router_mac", "")
        for t in ipv6_targets(cfg, store, time.time()):
            if t["addr"] == snap.get("ipv6"):
                continue
            if rmac and t["mac"] == rmac:
                targets.append({"addr": t["addr"], "role": "router", "full": True, "label": "router IPv6 (LAN)"})
            else:
                targets.append({"addr": t["addr"], "role": "device", "full": t["stable"], "label": t["mac"] or "?"})
    extra = set(int(p) for p in ext["extra_tcp_ports"])
    ra = snap.get("remote_access", {})
    if ra.get("port"):
        try:
            extra.add(int(ra["port"]))
        except ValueError:
            pass
    for m in snap.get("port_mappings", []):
        if m["protocol"] == "TCP":
            extra.add(int(m["external_port"]))
    return {"targets": targets, "extra_tcp_ports": sorted(extra), "udp_ports": list(ext["udp_ports"]),
            "max_rate": int(ext["max_rate"]), "tcp_top": 1000,
            "full_weekday": "sat"}


def push_targets_if_needed(client: ProbeClient, store, doc: dict, force: bool = False) -> bool:
    digest = short_hash(doc)
    last = store.get("external:targets") or {}
    age = time.time() - float(last.get("t", 0))
    if not force and last.get("digest") == digest and age < 12 * 3600:
        return False
    if not doc["targets"]:
        raise ProbeError("no external targets known yet (router public IP not read)")
    seq = max(int(time.time() * 1000), int(last.get("seq", 0)) + 1)
    signed_doc = dict(doc, seq=seq, issued=iso())
    res = client.put_targets(signed_doc)
    if not res.get("ok"):
        raise ProbeError(f"probe rejected targets: {res.get('error')}")
    store.set("external:targets", {"digest": digest, "seq": seq, "t": time.time(), "doc": signed_doc})
    log.info("pushed %d targets to probe (seq %s)", len(doc["targets"]), seq)
    return True


# ------------------------------------------------------------------------------------ results
def _port_in_spec(spec: str, proto: str, port: int) -> bool:
    cur = "tcp"
    for part in spec.split(","):
        if part.startswith("T:"):
            cur, part = "tcp", part[2:]
        elif part.startswith("U:"):
            cur, part = "udp", part[2:]
        if cur != proto or not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if int(a) <= port <= int(b):
                return True
        elif int(part) == port:
            return True
    return False


def coverage(result: dict) -> list[dict]:
    """[{addr, spec}] for every address that a run in this result actually scanned."""
    out = []
    for run in result.get("runs", []):
        if run.get("rc") != 0 or not run.get("xml_z"):
            continue  # a failed run proves nothing about absence
        toks = run.get("cmd", "").split()
        spec = toks[toks.index("-p") + 1] if "-p" in toks else ""
        for t in toks:
            try:
                ipaddress.ip_address(t)
            except ValueError:
                continue
            out.append({"addr": t, "spec": spec, "label": run.get("label")})
    return out


def parse_result(result: dict) -> dict:
    """-> {'hosts': {addr: [port dicts open]}, 'missing': [addr], 'errors': [...]}"""
    hosts: dict[str, list] = {}
    seen_hosts: set[str] = set()
    errors = list(result.get("errors", []))
    for run in result.get("runs", []):
        if not run.get("xml_z"):
            continue
        try:
            parsed = nmapxml.parse(zlib.decompress(base64.b64decode(run["xml_z"])).decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{run.get('label')}: unparsable nmap XML ({exc})")
            continue
        for h in parsed["hosts"]:
            addr = str(ipaddress.ip_address(h["addr"])) if h["addr"] else ""
            if h["status"] == "up" and h["ports"] is not None:
                seen_hosts.add(addr)
            for p in h["ports"]:
                if p["state"] == "open":
                    hosts.setdefault(addr, []).append(p)
    expected = {str(ipaddress.ip_address(t["addr"])) for t in result.get("targets", [])}
    missing = sorted(expected - seen_hosts)
    return {"hosts": hosts, "missing": missing, "errors": errors}


def router_addresses(snap: dict, devices: dict) -> set[str]:
    """Public addresses of the router itself: WAN IPv4/IPv6 plus its global LAN IPv6 (same MAC)."""
    out = {a for a in (snap.get("ipv4"), snap.get("ipv6")) if a}
    d = devices.get(snap.get("router_mac", "")) if snap.get("router_mac") else None
    if d:
        out |= set(d.get("ipv6", []))
    return {str(ipaddress.ip_address(a)) for a in out}


def attribute(snap: dict, devices: dict, addr: str, proto: str, port: int) -> tuple[str, dict]:
    """Explain why addr:port is reachable. Returns (text, facts)."""
    fam = ip_family(addr)
    if fam == "v4" or addr in router_addresses(snap, devices):
        for m in snap.get("port_mappings", []):
            if m["protocol"].lower() == proto and int(m["external_port"]) == port:
                who = label(devices, ip=m["internal_client"])
                how = "UPnP mapping created by" if m["origin"] == "upnp" else "manual forwarding to"
                return f"{how} {who}:{m['internal_port']}", {"via": m["origin"], "device": who,
                                                              "internal": f"{m['internal_client']}:{m['internal_port']}"}
        ra = snap.get("remote_access", {})
        if ra.get("enabled") and str(ra.get("port")) == str(port):
            return "FRITZ!Box remote access (HTTPS)", {"via": "router-remote-access"}
        for s in snap.get("myfritz_services", []):
            if str(s.get("port")) == str(port):
                return f"MyFRITZ! sharing '{s['name']}'", {"via": "myfritz", "device": s.get("host", "")}
        return "no forwarding listed by the router - a router service or an unlisted IPv6/manual sharing", {"via": "unknown"}
    who = label(devices, ip=addr)
    return f"IPv6 device {who} directly reachable (IPv6 firewall sharing on the router)", {"via": "ipv6-pinhole",
                                                                                           "device": who}


def result_findings(result: dict, parsed: dict, snap: dict, devices: dict, cfg) -> list[Finding]:
    out: list[Finding] = []
    router = router_addresses(snap, devices) | {str(ipaddress.ip_address(t["addr"])) for t in result.get("targets", [])
                                                if t.get("role") == "router"}
    for addr, ports in parsed["hosts"].items():
        fam = ip_family(addr)
        is_router = addr in router
        for p in ports:
            proto, port = p["proto"], p["port"]
            why, facts = attribute(snap, devices, addr, proto, port)
            svc = " ".join(x for x in (p["service"], p["product"], p["version"]) if x) or "unknown service"
            fid = f"ext:{fam}:{proto}/{port}" if is_router else f"ext6:{addr}:{proto}/{port}"
            where = f"{'public IPv4' if fam == 'v4' else 'IPv6'} {addr} port {port}/{proto}"
            out.append(Finding(
                id=fid, source="external", kind="open_port", severity="critical",
                title=f"Reachable from the internet: {port}/{proto} on {'router ' + fam if is_router else addr} ({p['service'] or '?'})",
                message=f"The external probe reached {where}: {svc}. Cause: {why}.",
                action="If this is not intended: remove the forwarding / IPv6 sharing for the device in FRITZ!Box > "
                       "Internet > Permit Access (and untick 'Permit independent port sharing'). If intended: make sure "
                       "the service is patched and requires authentication, then acknowledge.",
                detail={"addr": addr, "family": fam, "proto": proto, "port": port, "service": p["service"],
                        "product": p["product"], "version": p["version"], "extrainfo": p["extrainfo"],
                        "tunnel": p["tunnel"], "cause": why, **facts, "run_id": result.get("run_id"),
                        "router": is_router,
                        "title_script": p["scripts"].get("http-title", {}).get("output", "")},
                state_key=[addr if not is_router else fam, proto, port, p["service"], p["product"]]))
            info = nmapxml.tls_info(p)
            if info:
                tf = tls_finding(f"tls-ext:{addr if not is_router else fam}:{port}", "external", where, info,
                                 cfg["tls"]["warn_days"], True)
                tf.detail.update(addr=addr, family=fam, proto=proto, port=port, router=is_router)
                out.append(tf)
    return out


def resolvable_for(result: dict, missing: list[str] | None = None):
    """Only findings whose address+port was actually covered by this result may be resolved by absence."""
    cov = [c for c in coverage(result) if c["addr"] not in set(missing or [])]
    current_addrs = {str(ipaddress.ip_address(t["addr"])) for t in result.get("targets", [])}
    router_fams: dict[str, set] = {}
    for t in result.get("targets", []):
        if t.get("role") == "router":
            router_fams.setdefault(t["family"], set()).add(str(ipaddress.ip_address(t["addr"])))

    def ok(f: dict) -> bool:
        d = f.get("detail", {})
        addr, proto, port = d.get("addr") or "", d.get("proto", "tcp"), int(d.get("port") or 0)
        if d.get("router"):
            addrs = router_fams.get(d.get("family"), {addr})  # router findings follow the current public addresses
        elif addr not in current_addrs:
            return True  # device address gone (rotated temporary IPv6) -> finding no longer applies
        else:
            addrs = {addr}
        return any(c["addr"] in addrs and _port_in_spec(c["spec"], proto, port) for c in cov)
    return ok


def summarize(result: dict, parsed: dict) -> dict:
    return {"run_id": result.get("run_id"), "profile": result.get("profile"), "started": result.get("started"),
            "finished": result.get("finished"), "ok": result.get("ok") and not parsed["missing"] and not parsed["errors"],
            "errors": parsed["errors"][:10], "missing": parsed["missing"],
            "open": {a: [f"{p['port']}/{p['proto']} {p['service']}" for p in ps] for a, ps in parsed["hosts"].items()},
            "targets": len(result.get("targets", [])), "probe_addresses": result.get("probe_addresses", [])}


def stale(store, cfg) -> tuple[bool, str]:
    last = store.get("external:last_good")
    if not last:
        return True, "no complete external scan received yet"
    age = (now() - parse_iso(last["finished"])).total_seconds() / 3600
    if age > cfg["external"]["stale_hours"]:
        return True, f"last complete external scan is {age:.0f} h old (limit {cfg['external']['stale_hours']} h)"
    return False, ""


__all__ = ["ProbeClient", "ProbeError", "EnvelopeError", "build_targets", "push_targets_if_needed",
           "parse_result", "result_findings", "resolvable_for", "summarize", "stale"]
