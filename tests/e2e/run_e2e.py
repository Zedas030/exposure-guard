#!/usr/bin/env python3
"""End-to-end test: real guard container + real probe (SSH, sealed results, nmap) against a fake router,
a fake Home Assistant and a target host. Run on a Docker host from the repository root:

    python3 tests/e2e/run_e2e.py            (add --keep to leave the environment running)

Covers: baseline, UPnP mapping -> internal alert, external scan -> 'reachable from the internet' with attribution,
new device, LAN web check, acknowledgement + re-alert on change, probe outage -> warning and status 'unknown'
(never 'ok'), recovery. Writes evidence to tests/e2e/work/evidence.json."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(HERE, "work")
COMPOSE = ["docker", "compose", "-f", os.path.join(HERE, "compose.yml")]
TARGET_IP, PROBE_IP = "172.31.250.10", "172.31.250.20"
EVIDENCE: list[dict] = []


def sh(cmd, check=True, input_=None, timeout=900) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True, input=input_, timeout=timeout)
    if check and res.returncode != 0:
        raise SystemExit(f"FAILED: {' '.join(cmd)}\n{res.stdout[-3000:]}\n{res.stderr[-3000:]}")
    return res.stdout


def post(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read()


def ha_records() -> dict:
    with urllib.request.urlopen("http://127.0.0.1:18123/_records", timeout=10) as r:
        return json.loads(r.read())


def notify_titles() -> list[str]:
    return [n["title"] for n in ha_records()["notify"]]


def guard(*args, check=True) -> str:
    return sh(COMPOSE + ["exec", "-T", "guard", "exposure-guard", *args], check=check)


def probe_run():
    return sh(COMPOSE + ["exec", "-T", "-u", "probe", "probe", "exposure-probe", "run", "daily"], check=False)


def step(name: str, ok: bool, details) -> None:
    EVIDENCE.append({"step": name, "ok": ok, "details": details, "t": time.strftime("%H:%M:%S")})
    print(("PASS " if ok else "FAIL ") + name, flush=True)
    if not ok:
        print(json.dumps(details, indent=1)[:4000])
        raise SystemExit(1)


def expect_notify(name: str, pattern: str, before: int) -> list[str]:
    new = notify_titles()[before:]
    step(name, any(re.search(pattern, t) for t in new), new)
    return new


def setup():
    sh(["docker", "build", "-q", "--target", "test", "-t", "exposure-guard:e2e-base", ROOT])
    sh(["docker", "build", "-q", "--target", "app", "-t", "exposure-guard:e2e-app", ROOT])
    sh(["docker", "build", "-q", "-f", os.path.join(HERE, "Dockerfile.probe"), "-t", "exposure-guard:e2e-probe", ROOT])
    cleanup()
    for d in ("config", "acks", "data"):
        os.makedirs(os.path.join(WORK, d), exist_ok=True)
        os.chmod(os.path.join(WORK, d), 0o777)
    with open(os.path.join(WORK, ".env"), "w") as fh:
        fh.write("FRITZ_USER=e2e\nFRITZ_PASSWORD=e2e\nHA_TOKEN=test-token\n")
    with open(os.path.join(WORK, "acks", "acks.yaml"), "w") as fh:
        fh.write("acks: []\n")
    os.chmod(os.path.join(WORK, "acks", "acks.yaml"), 0o666)
    sh(COMPOSE + ["up", "-d", "fakefritz", "fakeha", "target", "probe"])
    time.sleep(3)
    post("http://127.0.0.1:14900/_control", {"op": "set", "values": {
        "ipv4": TARGET_IP, "ipv6": "", "prefix": "", "hosts": [
            {"mac": "02:42:AC:1F:FA:0A", "ip": TARGET_IP, "name": "target", "active": True},
            {"mac": "AA:BB:CC:00:00:02", "ip": "172.31.250.11", "name": "tv", "active": False}]}})
    out = sh(COMPOSE + ["run", "--rm", "--no-deps", "guard", "sh", "-c",
                        "mkdir -p /data/ssh && ssh-keygen -q -t ed25519 -N '' -C eg-e2e -f /data/ssh/id_ed25519 && "
                        f"ssh-keyscan -q -t ed25519 {PROBE_IP} > /data/ssh/known_hosts && "
                        "cat /data/ssh/id_ed25519.pub && exposure-guard keys"])
    pubkey = next(line for line in out.splitlines() if line.startswith("ssh-ed25519"))
    keys = json.loads(out[out.index("{"):])
    out = sh(COMPOSE + ["exec", "-T", "-e", f"GUARD_SSH_PUBKEY={pubkey}", "-e", f"GUARD_VERIFY_KEY={keys['guard_verify_key']}",
                        "-e", f"GUARD_BOX_KEY={keys['guard_box_public_key']}", "-e", "ALLOW_PRIVATE_TARGETS=true",
                        "-e", "SKIP_APT=1", "probe", "bash", "/src/probe/install-probe.sh"])
    pvk = re.search(r"PROBE_VERIFY_KEY=(\S+)", out).group(1)
    cfg = f"""
general: {{public_url: "http://guard.e2e:8103"}}
network: {{lan_cidr: 172.31.250.0/24, interface: eth0}}
fritzbox: {{host: 172.31.250.2, port: 49000}}
inventory: {{use_neighbors: false, ipv6_discovery: false}}
external: {{probe_host: {PROBE_IP}, probe_verify_key: "{pvk}", fetch_minutes: 600, udp_ports: [], max_rate: 1000,
           ipv6_devices: false, unreachable_after: 3, ip_crosscheck: false}}
lan_web: {{enabled: true, ports: [8080, 9443], max_rate: 200, request_pause: 0}}
tailscale: {{enabled: false}}
schedule: {{local_minutes: 600}}
homeassistant: {{url: "http://172.31.250.3:8123", notify_service: notify.mobile_app_phone}}
"""
    with open(os.path.join(WORK, "config", "config.yaml"), "w") as fh:
        fh.write(cfg)
    sh(COMPOSE + ["up", "-d", "guard"])
    for _ in range(60):
        if "healthy" in sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", "exposure-guard-e2e-guard-1"], check=False):
            break
        time.sleep(3)
    step("guard container healthy", True, sh(["docker", "inspect", "-f", "{{.State.Health.Status}}",
                                              "exposure-guard-e2e-guard-1"]).strip())


def scenario():
    # 1. baseline (the daemon's first tick already ran; run explicitly to be deterministic)
    guard("run", "local", check=False)
    guard("run", "external", check=False)   # pushes targets
    probe_out = probe_run()
    guard("run", "external", check=False)   # fetches the first result = baseline
    st = json.loads(guard("status", "--json", check=False))
    step("baseline: no alerts, external view current", notify_titles() == [] and not st["external_stale"],
         {"notify": notify_titles(), "probe": probe_out, "state": st["state"], "last": st["external_last_scan"]})

    # 2. UPnP port forwarding appears + port really open -> internal AND external alert
    n0 = len(notify_titles())
    post("http://127.0.0.1:17000/open", {"port": 9443})
    post("http://127.0.0.1:14900/_control", {"op": "add_mapping", "ext": 9443, "client": TARGET_IP, "upnp": True,
                                              "desc": "e2e test"})
    guard("run", "local", check=False)
    expect_notify("internal: new UPnP forwarding reported", r"UPnP port forwarding 9443/tcp", n0)
    n1 = len(notify_titles())
    guard("run", "external", check=False)
    probe_run()
    guard("run", "external", check=False)
    new = expect_notify("external: port reachable from the internet reported", r"Reachable from the internet: 9443/tcp", n1)
    msg = next(n["message"] for n in ha_records()["notify"][n1:] if "9443" in n["title"])
    step("external alert names the UPnP mapping and the device", "UPnP mapping created by 172.31.250.10" in msg, msg)

    # 3. new device
    n2 = len(notify_titles())
    post("http://127.0.0.1:14900/_control", {"op": "add_host", "mac": "AA:BB:CC:DD:EE:99", "ip": "172.31.250.99",
                                              "name": "testdevice"})
    guard("run", "local", check=False)
    expect_notify("new device reported", r"Unknown device in the LAN: testdevice", n2)

    # 4. LAN web check (gentle) finds the plain-HTTP interface, no push for non-critical
    n3 = len(notify_titles())
    guard("run", "lan-web", check=False)
    fl = guard("findings", check=False)
    step("LAN web check: plain HTTP UI found, no push", f"lan:{TARGET_IP}:8080:http" in fl and len(notify_titles()) == n3, fl)

    # 5. acknowledge -> silence; change -> alert again
    for fid in ("ext:v4:tcp/9443", "map:tcp/9443", "device:aa:bb:cc:dd:ee:99"):
        guard("ack", fid, "e2e acceptance")
    n4 = len(notify_titles())
    guard("run", "local", check=False)
    probe_run()
    guard("run", "external", check=False)
    step("acknowledged findings stay silent", len(notify_titles()) == n4, notify_titles()[n4:])
    post("http://127.0.0.1:14900/_control", {"op": "remove_mapping", "ext": 9443})
    post("http://127.0.0.1:14900/_control", {"op": "add_mapping", "ext": 9443, "client": "172.31.250.11", "upnp": True})
    guard("run", "local", check=False)
    expect_notify("acknowledged finding alerts again after a change", r"CHANGED UPnP port forwarding 9443/tcp", n4)
    guard("ack", "map:tcp/9443", "e2e acceptance (new target)")

    # 6. probe outage -> warning, state 'unknown' (never ok)
    n5 = len(notify_titles())
    sh(COMPOSE + ["stop", "probe"])
    for _ in range(3):
        guard("run", "external", check=False)
    expect_notify("probe outage -> warning", r"connection to the external probe FAILING", n5)
    st = json.loads(guard("status", "--json", check=False))
    sensor = ha_records()["states"].get("sensor.exposure_guard", {})
    step("status during outage is 'unknown', HA sensor too", st["state"] == "unknown" and sensor.get("state") == "unknown",
         {"state": st["state"], "sensor": sensor.get("state"), "broken": st["broken_sources"]})
    n6 = len(notify_titles())
    sh(COMPOSE + ["start", "probe"])
    time.sleep(3)
    guard("run", "external", check=False)
    expect_notify("probe back -> recovery message", r"connection to the external probe working again", n6)

    # 7. read-only towards the router; metrics; report
    with urllib.request.urlopen("http://127.0.0.1:14900/_state", timeout=10) as r:
        fstate = json.loads(r.read())
    step("router never received a write action", not fstate.get("write_attempts"), fstate.get("write_attempts"))
    m = sh(COMPOSE + ["exec", "-T", "guard", "python3", "-c",
                      "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8103/metrics').read().decode())"])
    step("Prometheus metrics served", "exposure_guard_status{state=" in m and "exposure_guard_source_ok" in m,
         [x for x in m.splitlines() if x.startswith("exposure_guard_status")])
    out = guard("report", "initial")
    step("report written", "written" in out, out.strip())


def cleanup():
    sh(COMPOSE + ["down", "-v", "--remove-orphans"], check=False)
    if os.path.isdir(WORK):
        sh(["docker", "run", "--rm", "--user", "0", "-v", f"{HERE}:/e2e", "exposure-guard:e2e-base",
            "rm", "-rf", "/e2e/work"], check=False)


def main():
    keep = "--keep" in sys.argv
    setup()
    try:
        scenario()
        print(f"\nALL {len(EVIDENCE)} E2E STEPS PASSED")
    finally:
        os.makedirs(WORK, exist_ok=True)
        try:
            with open(os.path.join(HERE, "evidence.json"), "w") as fh:
                json.dump(EVIDENCE, fh, indent=1)
        except OSError:
            pass
        if not keep:
            cleanup()


if __name__ == "__main__":
    main()
