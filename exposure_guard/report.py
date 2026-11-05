"""Initial and weekly reports (HTML for the web UI, Markdown for archiving)."""
from __future__ import annotations

import html
import os
from datetime import timedelta

from .findings import SEV_RANK
from .util import atomic_write, iso, now, parse_iso

STATE_TEXT = {"alert": "ALERT - critical change open", "unknown": "UNKNOWN - external view missing/stale",
              "degraded": "DEGRADED - a check is failing", "attention": "Findings to review", "ok": "OK"}


def _local(g, value: str) -> str:
    dt = parse_iso(value)
    return dt.astimezone(g.tz).strftime("%Y-%m-%d %H:%M") if dt else "-"


def collect(g, kind: str) -> dict:
    since = iso(now() - timedelta(days=7)) if kind == "weekly" else None
    findings = g.engine.annotate(g.store.findings("open"))
    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["source"], f["id"]))
    devices = g.devices()
    return {
        "kind": kind, "generated": iso(), "status": g.status(),
        "fritz": g.store.get("fritz:last") or {}, "public_ip": g.store.get("public_ip", {}),
        "seen_v4": g.store.get("external:seen_v4"), "seen_v6": g.store.get("external:seen_v6"),
        "ext_last": g.store.get("external:last"), "ext_good": g.store.get("external:last_good"),
        "ext_full": g.store.get("external:last_full"),
        "findings": findings,
        "open": [f for f in findings if not f["ack"]],
        "acked": [f for f in findings if f["ack"]],
        "devices": devices,
        "new_devices": [d for d in devices.values() if since is None or (d.get("first_seen") or "") >= since],
        "tailscale": (g.store.get("tailscale:last") or {}).get("nodes", []),
        "lan_web": g.store.get("lan_web:last") or {},
        "events": g.store.events(since=since, limit=300),
        "since": since,
    }


def push_summary(g, label: str) -> str:
    st = g.status()
    sev = st["open_by_severity"]
    parts = [f"{label}: {STATE_TEXT[st['state']]}.",
             f"Open: {sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, {sev['low']} low "
             f"(+{st['baseline']} baseline items to review, {st['acknowledged']} acknowledged)."]
    if st["external_stale"]:
        parts.append(f"External view: {st['external_stale']}.")
    else:
        parts.append(f"Last external scan {_local(g, st['external_last_scan'])} ({st['external_last_profile']}).")
    if st["broken_sources"]:
        parts.append("Failing checks: " + ", ".join(st["broken_sources"]) + ".")
    return " ".join(parts)


# -------------------------------------------------------------------------------- markdown
def to_markdown(g, d: dict) -> str:
    st, fr = d["status"], d["fritz"]
    title = "Initial report" if d["kind"] == "initial" else "Weekly report"
    L = [f"# Exposure Guard - {title}", "", f"Generated {_local(g, d['generated'])} - version {st['version']}", "",
         f"**Overall state: {STATE_TEXT[st['state']]}**", ""]
    L += ["## Checks and their health", "", "| Check | Last success | Failures | Last error |", "|---|---|---|---|"]
    for src, h in sorted(st["health"].items()):
        L.append(f"| {src} | {_local(g, h.get('last_success'))} | {h.get('failures')} | {(h.get('last_error') or '').replace('|', '/')[:120]} |")
    if st["external_stale"]:
        L += ["", f"> External view NOT current: {st['external_stale']}. Nothing in this report proves the internet "
                  "side is closed."]
    pub = d["public_ip"]
    L += ["", "## Public addresses", "",
          f"- IPv4 (router): {pub.get('ipv4') or '-'}; seen by probe: {(d['seen_v4'] or {}).get('addr', '-')}",
          f"- IPv6 prefix: {pub.get('ipv6_prefix') or '-'}; router WAN IPv6: {pub.get('ipv6') or '-'}"
          f"; seen by probe: {(d['seen_v6'] or {}).get('addr', '-')}"]
    ip_events = [e for e in d["events"] if e["kind"] == "ip-change"]
    for e in ip_events[:10]:
        L.append(f"- {_local(g, e['t'])}: {e['message']}")
    L += ["", "## External view (what the internet sees)", ""]
    good, full = d["ext_good"], d["ext_full"]
    if good:
        L.append(f"Last complete scan: {_local(g, good['finished'])} ({good['profile']}, {good['targets']} targets); "
                 f"last full TCP scan: {_local(g, full['finished']) if full else 'none yet'}.")
        L.append("")
        ext = [f for f in d["findings"] if f["kind"] == "open_port"]
        if ext:
            L += ["| Address | Port | Service | Cause | State |", "|---|---|---|---|---|"]
            for f in ext:
                x = f["detail"]
                svc = " ".join(v for v in (x.get("service"), x.get("product"), x.get("version")) if v)
                L.append(f"| {x.get('addr')} | {x.get('port')}/{x.get('proto')} | {svc} | {x.get('cause')} | "
                         f"{_state(f)} |")
        else:
            L.append("No open TCP/UDP port found on any target.")
    else:
        L.append("No complete external scan yet.")
    dev = fr.get("device", {})
    L += ["", "## Router", "",
          f"- {dev.get('model', '?')}, FRITZ!OS {dev.get('firmware', '?')}"
          + (f" - update {dev.get('update_version')} available" if dev.get("update_available") else " (no update offered)"),
          f"- Remote access HTTPS: {'on, port ' + str(fr.get('remote_access', {}).get('port')) if fr.get('remote_access', {}).get('enabled') else 'off'}",
          f"- MyFRITZ!: {'on' if fr.get('myfritz', {}).get('enabled') else 'off'}; UPnP: {'on' if fr.get('upnp', {}).get('enabled') else 'off'}",
          ""]
    maps = fr.get("port_mappings", [])
    if maps:
        L += ["| Origin | External | Internal | Description | Enabled |", "|---|---|---|---|---|"]
        for m in maps:
            L.append(f"| {m['origin']} | {m['external_port']}/{m['protocol']} | {m['internal_client']}:{m['internal_port']} "
                     f"| {m['description']} | {m['enabled']} |")
    else:
        L.append("No IPv4 port forwardings (manual or UPnP).")
    L += ["", f"## LAN inventory ({len(d['devices'])} devices)", ""]
    devs = d["devices"].values() if d["kind"] == "initial" else d["new_devices"]
    if d["kind"] == "weekly":
        L.append(f"New this week: {len(d['new_devices'])}")
        L.append("")
    if devs:
        L += ["| MAC | IP | Hostname | Vendor | First seen |", "|---|---|---|---|---|"]
        for x in sorted(devs, key=lambda x: x.get("first_seen") or ""):
            L.append(f"| {x['mac']} | {', '.join(x['ips'][:2])} | {x['hostname']} | {x['vendor']} | {_local(g, x.get('first_seen'))} |")
    if d["tailscale"]:
        L += ["", "## Tailscale", "", "| Node | OS | Online | Key expiry | Exit node | Routes |", "|---|---|---|---|---|---|"]
        for n in d["tailscale"]:
            L.append(f"| {n['host']} | {n['os']} | {n['online']} | {n['key_expiry'][:10] or 'disabled'} | "
                     f"{'offers' if n['exit_node_option'] else '-'} | {', '.join(n['routes']) or '-'} |")
    L += ["", "## Findings (open, not acknowledged)", ""]
    if not d["open"]:
        L.append("None.")
    for f in d["open"]:
        L += [f"### [{f['severity'].upper()}] {f['title']}", "",
              f"- ID: `{f['id']}` - first seen {_local(g, f['first_seen'])}" + (" - **baseline, please review**" if f["baseline"] else ""),
              f"- Assessment: {f['message']}", f"- Action: {f['action']}", ""]
    if d["acked"]:
        L += ["## Acknowledged", "", "| ID | Reason | By / when |", "|---|---|---|"]
        for f in d["acked"]:
            a = f["ack"]
            L.append(f"| `{f['id']}` | {a.get('reason', '')} | {a.get('by', '')} {str(a.get('at', ''))[:10]} |")
    if d["kind"] == "weekly":
        L += ["", "## Events this week", ""]
        for e in d["events"][:80]:
            L.append(f"- {_local(g, e['t'])} {e['kind']}: {e['message']}")
    L += ["", "## Scope and limits", "",
          "- Scans only target the own public addresses and the own LAN; LAN checks are TCP connect scans at -T2 with a "
          "packet-rate cap, plus one GET of each start page. No login attempts.",
          "- IPv6 sharings cannot be read from the router; they are found by the external probe scanning every global "
          "IPv6 address seen in the LAN.",
          f"- LAN web check last run: {_local(g, d['lan_web'].get('at'))}."]
    return "\n".join(L) + "\n"


def _state(f) -> str:
    if f["ack"]:
        return "acknowledged"
    return "baseline" if f["baseline"] else "NEW"


def to_html(md_text: str, title: str) -> str:
    """Tiny Markdown subset -> HTML (headings, tables, lists, quotes, bold, code)."""
    import re
    out, in_table, in_list = [], False, False

    def inline(t):
        t = html.escape(t)
        t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
        return re.sub(r"`(.+?)`", r"<code>\1</code>", t)
    for line in md_text.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= {"-"} for c in cells):
                continue
            if not in_table:
                out.append("<div class='tbl'><table>")
                out.append("<tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>")
                in_table = True
                continue
            out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table></div>")
            in_table = False
        if line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(line[2:])}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if line.startswith("### "):
            sev = re.match(r"### \[(\w+)\]", line)
            cls = f" class='sev-{sev.group(1).lower()}'" if sev else ""
            out.append(f"<h3{cls}>{inline(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.startswith("> "):
            out.append(f"<blockquote>{inline(line[2:])}</blockquote>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    if in_table:
        out.append("</table></div>")
    if in_list:
        out.append("</ul>")
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
            f"content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>"
            "<link rel='stylesheet' href='/static/theme.css'><link rel='stylesheet' href='/static/app.css'>"
            "<script src='/static/boot.js'></script></head>"
            "<body><main class='report'><p><a href='/'>&larr; Exposure Guard</a></p>" + "\n".join(out) +
            "</main></body></html>")


def write(g, kind: str) -> str:
    d = collect(g, kind)
    md = to_markdown(g, d)
    stamp = now().astimezone(g.tz)
    name = f"{kind}-{stamp:%Y-%m-%d}" if kind == "initial" else f"weekly-{stamp:%G-W%V}"
    rdir = os.path.join(g.cfg.data_dir, "reports")
    atomic_write(os.path.join(rdir, name + ".md"), md)
    atomic_write(os.path.join(rdir, name + ".html"), to_html(md, f"Exposure Guard {kind} report"))
    g.store.set("report:latest", name)
    g.store.event("report", f"{kind} report {name}", severity="info")
    return name
