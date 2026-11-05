#!/usr/bin/env python3
"""Exposure Guard - external probe (runs on a small VPS outside the home network).

It scans ONLY the addresses in the target list signed by the guard, seals each result to the guard's public
key and signs it. The guard pulls results over SSH; this host never connects into the home network.

Commands
  exposure-probe init              create the probe signing key, print its public key (run once as root)
  exposure-probe run [auto|daily|full]   run a scan (systemd timer / path unit)
  exposure-probe gate              SSH forced command; reads SSH_ORIGINAL_COMMAND:
                                     health | put-targets | get-results <after-run-id> | scan-now
  exposure-probe status            human readable state
Dependencies: python3, python3-nacl, nmap."""
from __future__ import annotations

import base64
import fcntl
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import time
import zlib
from datetime import datetime, timezone

from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

VERSION = "1.0.0"
CONF = os.environ.get("EXPOSURE_PROBE_CONF", "/etc/exposure-probe/probe.json")
KEY = os.environ.get("EXPOSURE_PROBE_KEY", "/etc/exposure-probe/probe_sign.key")
STATE = os.environ.get("EXPOSURE_PROBE_STATE", "/var/lib/exposure-probe")
NMAP_SERVICES = "/usr/share/nmap/nmap-services"
SCRIPTS = "ssl-cert,ssl-enum-ciphers,http-title,http-server-header"
KEEP_RESULTS = 30
MAX_TARGETS = 160
SCAN_NOW_GAP = 3600


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt=None) -> str:
    return (dt or utcnow()).isoformat(timespec="seconds")


def load_conf() -> dict:
    with open(CONF) as fh:
        return json.load(fh)


def signing_key() -> SigningKey:
    with open(KEY, "rb") as fh:
        return SigningKey(fh.read())


def seal(obj: dict, conf: dict) -> str:
    raw = zlib.compress(json.dumps(obj, separators=(",", ":")).encode(), 9)
    sealed = SealedBox(PublicKey(base64.b64decode(conf["guard_box_public_key"]))).encrypt(raw)
    return base64.b64encode(signing_key().sign(sealed)).decode()


def write_atomic(path: str, data: str, mode: int = 0o640) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_json(path: str, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


# ------------------------------------------------------------------------------------- targets
def validate_targets(doc: dict, conf: dict) -> dict:
    allow_private = bool(conf.get("allow_private_targets"))
    targets = doc.get("targets")
    if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS:
        raise ValueError("target list empty or too long")
    clean = []
    for t in targets:
        ip = ipaddress.ip_address(str(t["addr"]))
        if not (ip.is_global or allow_private):
            raise ValueError(f"refusing non-global target {ip}")
        if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
            raise ValueError(f"refusing target {ip}")
        clean.append({"addr": str(ip), "family": "v6" if ip.version == 6 else "v4",
                      "role": "router" if t.get("role") == "router" else "device",
                      "full": bool(t.get("full")), "label": str(t.get("label", ""))[:80]})
    ports = [int(p) for p in doc.get("extra_tcp_ports", []) if 0 < int(p) < 65536][:200]
    udp = [int(p) for p in doc.get("udp_ports", []) if 0 < int(p) < 65536][:50]
    rate = max(10, min(int(doc.get("max_rate", 300)), 1000))
    top = max(100, min(int(doc.get("tcp_top", 1000)), 5000))
    day = str(doc.get("full_weekday", "sat"))[:3].lower()
    return {"seq": int(doc["seq"]), "issued": str(doc.get("issued", "")), "targets": clean,
            "extra_tcp_ports": ports, "udp_ports": udp, "max_rate": rate, "tcp_top": top, "full_weekday": day}


def load_targets(conf: dict) -> dict | None:
    signed = read_json(os.path.join(STATE, "targets.json"), None)
    if not signed:
        return None
    raw = VerifyKey(base64.b64decode(conf["guard_verify_key"])).verify(base64.b64decode(signed["signed"]))
    return validate_targets(json.loads(raw), conf)


# ---------------------------------------------------------------------------------------- scan
def top_tcp_ports(n: int) -> list[int]:
    ports = []
    with open(NMAP_SERVICES) as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1].endswith("/tcp"):
                try:
                    ports.append((float(parts[2]), int(parts[1].split("/")[0])))
                except ValueError:
                    continue
    ports.sort(reverse=True)
    return sorted({p for _, p in ports[:n]})


def compress_ranges(ports) -> str:
    ports = sorted(set(ports))
    out, start, prev = [], None, None
    for p in ports:
        if start is None:
            start = prev = p
        elif p == prev + 1:
            prev = p
        else:
            out.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = p
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(out)


def nmap(args: list[str], label: str, timeout: int) -> dict:
    out = os.path.join(STATE, "work", f"{label}.xml")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    cmd = ["nmap", "--privileged", "-n", "-Pn", "-oX", out] + args
    t0 = time.time()
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        rc, err = res.returncode, res.stderr[-2000:]
    except subprocess.TimeoutExpired:
        rc, err = -1, f"timeout after {timeout}s"
    xml = ""
    try:
        with open(out, encoding="utf-8", errors="replace") as fh:
            xml = fh.read()
        os.unlink(out)
    except OSError:
        pass
    return {"label": label, "cmd": " ".join(cmd[1:]), "rc": rc, "stderr": err, "seconds": round(time.time() - t0, 1),
            "xml_z": base64.b64encode(zlib.compress(xml.encode(), 9)).decode() if xml else ""}


def own_addresses() -> list[str]:
    try:
        res = subprocess.run(["ip", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    out = []
    for line in res.stdout.splitlines():
        p = line.split()
        if len(p) > 3 and p[2] in ("inet", "inet6"):
            out.append(p[3].split("/")[0])
    return out


def run_scan(profile: str) -> int:
    conf = load_conf()
    os.makedirs(os.path.join(STATE, "results"), exist_ok=True)
    lock = open(os.path.join(STATE, "run.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another scan is running", file=sys.stderr)
        return 0
    started = utcnow()
    result = {"probe_version": VERSION, "started": iso(started), "profile": profile, "runs": [], "errors": [],
              "probe_addresses": own_addresses()}
    try:
        tg = load_targets(conf)
    except (BadSignatureError, ValueError, KeyError) as exc:
        tg = None
        result["errors"].append(f"target list rejected: {exc}")
    if tg is None and not result["errors"]:
        result["errors"].append("no target list received from the guard yet")
    if tg:
        if profile == "auto":
            profile = "full" if started.astimezone().strftime("%a").lower()[:3] == tg["full_weekday"] else "daily"
        result["profile"] = profile
        result["targets_seq"], result["targets"] = tg["seq"], tg["targets"]
        rate = str(tg["max_rate"])
        common = ["-sS", "-sV", "--version-light", "--max-retries", "1", "--max-rate", rate,
                  "--host-timeout", "150m", "--script", SCRIPTS, "--script-timeout", "90s"]
        daily_ports = "T:" + compress_ranges(top_tcp_ports(tg["tcp_top"]) + tg["extra_tcp_ports"])
        for fam in ("v4", "v6"):
            six = ["-6"] if fam == "v6" else []
            fam_t = [t for t in tg["targets"] if t["family"] == fam]
            if not fam_t:
                continue
            if profile == "full":
                full = [t["addr"] for t in fam_t if t["full"] or t["role"] == "router"]
                rest = [t["addr"] for t in fam_t if t["addr"] not in full]
                if full:
                    result["runs"].append(nmap(six + common + ["-p", "T:1-65535"] + full, f"{fam}-tcp-full", 5 * 3600))
                if rest:
                    result["runs"].append(nmap(six + common + ["-p", daily_ports] + rest, f"{fam}-tcp-top", 3 * 3600))
            else:
                result["runs"].append(nmap(six + common + ["-p", daily_ports] + [t["addr"] for t in fam_t],
                                           f"{fam}-tcp-top", 3 * 3600))
            routers = [t["addr"] for t in fam_t if t["role"] == "router"]
            if routers and tg["udp_ports"]:
                result["runs"].append(nmap(six + ["-sU", "-sV", "--version-intensity", "0", "--max-retries", "2",
                                                  "--max-rate", rate, "--host-timeout", "30m",
                                                  "-p", "U:" + compress_ranges(tg["udp_ports"])] + routers,
                                           f"{fam}-udp", 3600))
        for r in result["runs"]:
            if r["rc"] != 0 or not r["xml_z"]:
                result["errors"].append(f"{r['label']}: nmap rc={r['rc']} {r['stderr'][-300:]}")
    finished = utcnow()
    result["finished"] = iso(finished)
    result["ok"] = not result["errors"]
    run_id = started.strftime("%Y%m%dT%H%M%SZ") + "-" + result["profile"]
    result["run_id"] = run_id
    write_atomic(os.path.join(STATE, "results", run_id + ".env"), seal(result, conf))
    files = sorted(f for f in os.listdir(os.path.join(STATE, "results")) if f.endswith(".env"))
    for old in files[:-KEEP_RESULTS]:
        os.unlink(os.path.join(STATE, "results", old))
    health = read_json(os.path.join(STATE, "health.json"), {})
    health["last_run"] = {"run_id": run_id, "profile": result["profile"], "ok": result["ok"],
                          "started": result["started"], "finished": result["finished"],
                          "errors": result["errors"][:5]}
    write_atomic(os.path.join(STATE, "health.json"), json.dumps(health))
    print(f"{run_id}: ok={result['ok']} errors={len(result['errors'])}")
    return 0 if result["ok"] else 1


# ---------------------------------------------------------------------------------------- gate
def gate() -> int:
    conf = load_conf()
    cmd = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    client_ip = (os.environ.get("SSH_CONNECTION", "").split() or [""])[0]
    verb = cmd[0] if cmd else ""
    if verb == "health":
        health = read_json(os.path.join(STATE, "health.json"), {})
        signed = read_json(os.path.join(STATE, "targets.json"), {})
        res_dir = os.path.join(STATE, "results")
        results = sorted(f[:-4] for f in os.listdir(res_dir) if f.endswith(".env")) if os.path.isdir(res_dir) else []
        print(seal({"type": "health", "probe_version": VERSION, "time": iso(), "client_ip": client_ip,
                    "last_run": health.get("last_run"), "targets_seq": signed.get("seq"),
                    "targets_received": signed.get("received"), "latest_result": results[-1] if results else "",
                    "scan_requested": os.path.exists(os.path.join(STATE, "scan-request")),
                    "probe_addresses": own_addresses()}, conf))
        return 0
    if verb == "put-targets":
        text = sys.stdin.read(512_000).strip()
        try:
            raw = VerifyKey(base64.b64decode(conf["guard_verify_key"])).verify(base64.b64decode(text))
            doc = validate_targets(json.loads(raw), conf)
        except (BadSignatureError, ValueError, KeyError) as exc:
            print(seal({"type": "put-targets", "ok": False, "error": str(exc)[:300]}, conf))
            return 2
        current = read_json(os.path.join(STATE, "targets.json"), {})
        if current.get("seq") and doc["seq"] <= int(current["seq"]):
            print(seal({"type": "put-targets", "ok": False, "error": f"stale sequence {doc['seq']}"}, conf))
            return 2
        write_atomic(os.path.join(STATE, "targets.json"),
                     json.dumps({"seq": doc["seq"], "received": iso(), "signed": text}))
        print(seal({"type": "put-targets", "ok": True, "seq": doc["seq"], "count": len(doc["targets"])}, conf))
        return 0
    if verb == "get-results":
        after = cmd[1] if len(cmd) > 1 else ""
        res_dir = os.path.join(STATE, "results")
        files = sorted(f for f in os.listdir(res_dir) if f.endswith(".env")) if os.path.isdir(res_dir) else []
        for f in [f for f in files if f[:-4] > after][:5]:
            with open(os.path.join(res_dir, f)) as fh:
                print(f[:-4] + " " + fh.read().strip())
        return 0
    if verb == "scan-now":
        req = os.path.join(STATE, "scan-request")
        last = read_json(os.path.join(STATE, "scan-now.json"), {}).get("t", 0)
        ok = time.time() - float(last) > SCAN_NOW_GAP
        if ok:
            write_atomic(os.path.join(STATE, "scan-now.json"), json.dumps({"t": time.time()}))
            write_atomic(req, iso())
        print(seal({"type": "scan-now", "accepted": ok}, conf))
        return 0
    print("denied", file=sys.stderr)
    return 3


def init() -> int:
    if os.path.exists(KEY):
        key = signing_key()
    else:
        os.makedirs(os.path.dirname(KEY), exist_ok=True)
        key = SigningKey.generate()
        fd = os.open(KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(bytes(key))
    print(base64.b64encode(bytes(key.verify_key)).decode())
    return 0


def status() -> int:
    health = read_json(os.path.join(STATE, "health.json"), {})
    signed = read_json(os.path.join(STATE, "targets.json"), {})
    print(json.dumps({"version": VERSION, "last_run": health.get("last_run"), "targets_seq": signed.get("seq"),
                      "targets_received": signed.get("received")}, indent=2))
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "gate":
        return gate()
    if argv[0] == "run":
        req = os.path.join(STATE, "scan-request")
        if os.path.exists(req):
            os.unlink(req)
        prof = argv[1] if len(argv) > 1 else "auto"
        if prof not in ("auto", "daily", "full"):
            return 2
        return run_scan(prof)
    if argv[0] == "init":
        return init()
    if argv[0] == "status":
        return status()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
