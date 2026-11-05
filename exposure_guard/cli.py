"""Command line: exposure-guard <command>  (inside the container; on the host via the wrapper script)."""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading

from . import __version__
from .util import setup_logging


def _guard(args):
    from .guard import load
    return load(args.config)


def cmd_serve(args) -> int:
    from . import web
    g = _guard(args)
    setup_logging(g.cfg["general"]["log_level"])
    g.keys.init()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    srv = web.serve(g, stop)
    import logging
    logging.getLogger("exposure_guard").info("exposure-guard %s listening on :%s", __version__,
                                             g.cfg["general"]["listen_port"])
    g.run_forever(stop)
    srv.shutdown()
    return 0


def cmd_status(args) -> int:
    g = _guard(args)
    st = g.status()
    if args.json:
        print(json.dumps(st, indent=1, default=str))
        return 0
    print(f"State: {st['state'].upper()}   (version {st['version']})")
    sev = st["open_by_severity"]
    print(f"Open: critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, low {sev['low']}, info {sev['info']}"
          f" | baseline to review {st['baseline']} | acknowledged {st['acknowledged']}")
    print(f"Public: IPv4 {st['public_ipv4'] or '-'}  IPv6 prefix {st['public_ipv6_prefix'] or '-'}")
    print(f"External: last complete scan {st['external_last_scan'] or 'never'} {st['external_last_profile']}"
          + (f"  !! {st['external_stale']}" if st["external_stale"] else ""))
    print("Checks:")
    for src, h in sorted(st["health"].items()):
        flag = "OK  " if not h["failures"] else f"FAIL x{h['failures']}"
        print(f"  {flag:9} {src:16} last ok {h['last_success'] or '-'}  {h['last_error'] or ''}"[:160])
    return 0 if st["state"] in ("ok", "attention") else 1


def cmd_findings(args) -> int:
    g = _guard(args)
    fs = g.engine.annotate(g.store.findings(None if args.all else "open"))
    from .findings import SEV_RANK
    fs.sort(key=lambda f: (f["state"] != "open", SEV_RANK[f["severity"]], f["id"]))
    for f in fs:
        if args.severity and SEV_RANK[f["severity"]] > SEV_RANK[args.severity]:
            continue
        tag = "ACK " if f["ack"] else ("BASE" if f["baseline"] else ("RES " if f["state"] != "open" else "OPEN"))
        print(f"{tag} {f['severity']:8} {f['id']:42} {f['title']}")
        if args.verbose:
            print(f"      {f['message']}\n      -> {f['action']}")
    return 0


def cmd_ack(args) -> int:
    g = _guard(args)
    f = g.store.finding(args.id)
    if not f:
        print(f"no finding with id {args.id!r} (see: exposure-guard findings --all)", file=sys.stderr)
        return 2
    entry = g.acks.add(args.id, f["fingerprint"], args.reason, by=os.environ.get("EG_USER", "cli"), until=args.until)
    g.store.bind_ack(args.id, f["fingerprint"])
    g.store.event("acknowledged", f"{f['title']} - {args.reason}", args.id, f["severity"])
    print(f"acknowledged {args.id} (state {entry['fingerprint']}); it alerts again when it changes.")
    g.publish()
    return 0


def cmd_unack(args) -> int:
    g = _guard(args)
    ok = g.acks.remove(args.id)
    print("removed" if ok else "no such ack")
    return 0 if ok else 2


def cmd_acks(args) -> int:
    g = _guard(args)
    for e in g.acks.entries:
        print(f"{e['id']:42} {str(e.get('at', ''))[:16]:16} {e.get('reason', '')}")
    return 0


def cmd_run(args) -> int:
    g = _guard(args)
    setup_logging(g.cfg["general"]["log_level"])
    jobs = {"local": g.job_local, "external": g.job_external, "lan-web": g.job_lan_web, "tailscale": g.job_tailscale}
    from .util import iso
    with g.job_lock():
        if not g.store.get("first_start"):
            g.store.set("first_start", iso())
        for name in (list(jobs) if args.job == "all" else [args.job]):
            g.store.set(f"sched:{name.replace('-', '_')}", iso())
            jobs[name]()
        g.publish()
    return cmd_status(argparse.Namespace(config=args.config, json=False))


def cmd_report(args) -> int:
    from . import report
    g = _guard(args)
    name = report.write(g, args.kind)
    if args.kind == "initial":
        g.store.set("report:initial", name)
    print(f"written: reports/{name}.html and .md")
    if args.notify:
        g._push(f"Exposure Guard: {args.kind} report", report.push_summary(g, f"{args.kind.title()} report"),
                tag="eg-report")
    return 0


def cmd_keys(args) -> int:
    g = _guard(args)
    created = g.keys.init()
    pub = g.keys.public()
    print(json.dumps(pub | {"created": created}, indent=1))
    return 0


def cmd_scan_now(args) -> int:
    from .external import ProbeClient
    g = _guard(args)
    print(json.dumps(ProbeClient(g.cfg, g.keys).scan_now()))
    return 0


def cmd_test_notify(args) -> int:
    g = _guard(args)
    ok = g.ha.notify("Exposure Guard: test", "Test notification - delivery works.", "eg-test", g.cfg["general"]["public_url"])
    print("sent" if ok else f"FAILED: {g.ha.last_error}")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="exposure-guard", description="Exposure Guard - internet exposure watcher")
    p.add_argument("--config", default=None, help="config.yaml (default $EXPOSURE_GUARD_CONFIG or /config/config.yaml)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run scheduler + web UI (container entrypoint)").set_defaults(fn=cmd_serve)
    s = sub.add_parser("status", help="overall state and health of every check")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("findings", help="list findings")
    s.add_argument("--all", action="store_true", help="include resolved")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
    s.set_defaults(fn=cmd_findings)
    s = sub.add_parser("ack", help="acknowledge a finding in its current state")
    s.add_argument("id")
    s.add_argument("reason")
    s.add_argument("--until", help="optional expiry date YYYY-MM-DD")
    s.set_defaults(fn=cmd_ack)
    s = sub.add_parser("unack", help="remove an acknowledgement")
    s.add_argument("id")
    s.set_defaults(fn=cmd_unack)
    sub.add_parser("acks", help="list acknowledgements").set_defaults(fn=cmd_acks)
    s = sub.add_parser("run", help="run a check now")
    s.add_argument("job", choices=["local", "external", "lan-web", "tailscale", "all"])
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("report", help="write a report now")
    s.add_argument("kind", choices=["initial", "weekly"])
    s.add_argument("--notify", action="store_true")
    s.set_defaults(fn=cmd_report)
    sub.add_parser("keys", help="create (once) and show the guard's public keys for the probe").set_defaults(fn=cmd_keys)
    sub.add_parser("scan-now", help="ask the probe for an immediate daily scan (max. 1/h)").set_defaults(fn=cmd_scan_now)
    sub.add_parser("test-notify", help="send a test notification").set_defaults(fn=cmd_test_notify)
    args = p.parse_args(argv)
    return args.fn(args)
