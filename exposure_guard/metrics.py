"""Prometheus text exposition (no client library needed)."""
from __future__ import annotations

from .findings import SEV_RANK
from .util import parse_iso


def _esc(v) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render(g) -> str:
    st = g.status()
    lines: list[str] = []

    def metric(name, help_, typ, samples):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {typ}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    metric("exposure_guard_build_info", "Version", "gauge", [({"version": st["version"]}, 1)])
    metric("exposure_guard_status", "Overall state (1 = current)", "gauge",
           [({"state": s}, int(st["state"] == s)) for s in ("ok", "attention", "degraded", "unknown", "alert")])
    metric("exposure_guard_findings_open", "Open, unacknowledged, non-baseline findings", "gauge",
           [({"severity": s}, st["open_by_severity"][s]) for s in SEV_RANK])
    metric("exposure_guard_findings_acknowledged", "Acknowledged open findings", "gauge", [({}, st["acknowledged"])])
    metric("exposure_guard_findings_baseline", "Baseline findings not yet acknowledged", "gauge", [({}, st["baseline"])])
    health = st["health"].values()
    metric("exposure_guard_source_ok", "1 if the last attempt of the check succeeded", "gauge",
           [({"source": h["source"]}, int(not h["failures"])) for h in health])
    metric("exposure_guard_source_failures", "Consecutive failures of the check", "gauge",
           [({"source": h["source"]}, h["failures"]) for h in health])
    metric("exposure_guard_source_last_success_timestamp_seconds", "Last success of the check", "gauge",
           [({"source": h["source"]}, int(parse_iso(h["last_success"]).timestamp()) if h["last_success"] else 0)
            for h in health])
    last = parse_iso(st["external_last_scan"])
    metric("exposure_guard_external_last_scan_timestamp_seconds", "End of the last complete external scan", "gauge",
           [({}, int(last.timestamp()) if last else 0)])
    metric("exposure_guard_external_stale", "1 if the external view is missing or too old", "gauge",
           [({}, int(bool(st["external_stale"])))])
    ext = [f for f in g.store.findings("open", "external") if f["kind"] == "open_port"]
    metric("exposure_guard_external_open_ports", "Ports reachable from the internet", "gauge",
           [({"family": fam}, sum(1 for f in ext if f["detail"].get("family") == fam)) for fam in ("v4", "v6")])
    fr = g.store.get("fritz:last") or {}
    maps = fr.get("port_mappings", [])
    metric("exposure_guard_port_mappings", "Router port forwardings", "gauge",
           [({"origin": o}, sum(1 for m in maps if m["origin"] == o)) for o in ("upnp", "manual")])
    metric("exposure_guard_upnp_enabled", "UPnP enabled on the router", "gauge",
           [({}, int(bool(fr.get("upnp", {}).get("enabled"))))])
    metric("exposure_guard_devices", "Devices in the LAN inventory", "gauge", [({}, len(g.devices()))])
    tls = [f for f in g.store.findings("open") if f["kind"] == "tls" and f["detail"].get("days_left") is not None]
    metric("exposure_guard_tls_cert_days_left", "Days until certificate expiry", "gauge",
           [({"target": f["id"]}, f["detail"]["days_left"]) for f in tls])
    metric("exposure_guard_public_ip_changes_total", "Detected public IP/prefix changes", "counter",
           [({}, int(g.store.get("public_ip_changes", 0)))])
    pub = g.store.get("published") or {}
    hb = parse_iso(pub.get("at"))
    metric("exposure_guard_last_publish_timestamp_seconds", "Last status publication (heartbeat)", "gauge",
           [({}, int(hb.timestamp()) if hb else 0)])
    return "\n".join(lines) + "\n"
