"""Orchestration: jobs, self-monitoring, status, notifications."""
from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import os
import threading
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from . import __version__, checks, external, fritz, inventory, lanweb, tailscale
from .config import WEEKDAYS, Config
from .crypto import EnvelopeError, GuardKeys
from .findings import SEV_RANK, Acks, Engine
from .ha import HomeAssistant
from .store import Store
from .util import iso, log, now, parse_iso

# consecutive failures before a source counts as broken (and a warning is pushed)
FAIL_THRESHOLD = {"fritz": 2, "inventory": 2, "external": None, "external_scan": 1, "lan_web": 1,
                  "tailscale": 2, "tailscale_api": 2, "external_ipcheck": 1}
SOURCE_TEXT = {
    "fritz": "FRITZ!Box query (TR-064/UPnP)", "inventory": "LAN inventory", "external": "connection to the external probe",
    "external_scan": "external scan results", "lan_web": "LAN web interface check", "tailscale": "Tailscale status",
    "tailscale_api": "Tailscale API (ACL check)", "external_ipcheck": "public IP cross-check (router vs. probe)",
}
DEVICE_FORGET_DAYS = 90
MAX_SINGLE_ALERTS = 8


def _norm(addr: str) -> str:
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return addr


class Guard:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        os.makedirs(cfg.data_dir, exist_ok=True)
        self.store = Store(os.path.join(cfg.data_dir, "state.db"))
        self.acks = Acks(cfg["general"]["acks_file"], self.store)
        self.engine = Engine(self.store, self.acks)
        self.ha = HomeAssistant(cfg)
        self.keys = GuardKeys(os.path.join(cfg.data_dir, "keys"))
        self.tz = ZoneInfo(cfg["general"]["timezone"])
        self.lock = threading.RLock()
        self.started = iso()

    # ================================================================================ helpers
    def devices(self) -> dict:
        return self.store.get("inventory:last", {}).get("devices", {})

    def _health(self, source: str, ok: bool, error: str = "") -> None:
        h = self.store.record_health(source, ok, error)
        threshold = FAIL_THRESHOLD.get(source) or self.cfg["external"]["unreachable_after"]
        if not ok and h["failures"] >= threshold and not h["alerted"]:
            self._push(f"Exposure Guard: {SOURCE_TEXT.get(source, source)} FAILING",
                       f"{SOURCE_TEXT.get(source, source)} failed {h['failures']}x in a row: {error[:300]}. "
                       "Until this works the status is NOT 'all clear'.", tag=f"eg-health-{source}")
            self.store.set_health_alerted(source, True)
            self.store.event("health-fail", f"{source}: {error[:200]}", severity="warning")
        elif ok and h["alerted"]:
            self._push(f"Exposure Guard: {SOURCE_TEXT.get(source, source)} working again",
                       f"{SOURCE_TEXT.get(source, source)} is back to normal.", tag=f"eg-health-{source}")
            self.store.set_health_alerted(source, False)
            self.store.event("health-ok", f"{source} recovered", severity="info")

    def _push(self, title: str, message: str, tag: str = "exposure-guard") -> None:
        """Send now; if HA is unreachable keep it in an outbox and retry on the next cycle (max 24 h)."""
        url = self.cfg["general"]["public_url"]
        if self.ha.notify(title, message, tag, url):
            self.store.event("notified", title, severity="info")
            return
        box = self.store.get("outbox", [])
        box.append({"t": time.time(), "title": title, "message": message, "tag": tag})
        self.store.set("outbox", box[-50:])

    def _flush_outbox(self) -> None:
        box = self.store.get("outbox", [])
        if not box:
            return
        keep = []
        for m in box:
            if time.time() - m["t"] > 86400:
                continue
            if not self.ha.notify(m["title"], m["message"] + " (delayed)", m["tag"], self.cfg["general"]["public_url"]):
                keep.append(m)
        self.store.set("outbox", keep)

    def _send_alerts(self, alerts: list[dict]) -> None:
        if not alerts:
            return
        crit = [a for a in alerts if a["type"] != "resolved"]
        res = [a for a in alerts if a["type"] == "resolved"]
        if len(crit) > MAX_SINGLE_ALERTS:
            lines = "\n".join(f"- {a['finding']['title']}" for a in crit[:6])
            self._push(f"Exposure Guard: {len(crit)} critical changes",
                       f"{lines}\n... and {len(crit) - 6} more. Details in the web UI.", tag="eg-bulk")
        else:
            for a in crit:
                f = a["finding"]
                prefix = {"new": "NEW", "changed": "CHANGED", "reminder": "STILL OPEN"}.get(a["type"], "")
                self._push(f"Exposure Guard: {prefix} {f['title']}"[:180],
                           f"{f['message']}\nAction: {f['action']}\nAcknowledge: exposure-guard ack '{f['id']}' \"reason\"",
                           tag=f"eg-{f['id']}"[:60])
        for a in res[:MAX_SINGLE_ALERTS]:
            f = a["finding"]
            self._push(f"Exposure Guard: resolved - {f['title']}"[:180], "No longer observed.", tag=f"eg-{f['id']}"[:60])

    # =================================================================================== jobs
    def job_local(self) -> None:
        """Router + inventory (every few minutes)."""
        snap = None
        if self.cfg["fritzbox"]["enabled"]:
            try:
                snap = fritz.collect(self.cfg)
                hosts_ok = "hosts_error" not in snap
                self._check_ip_change(snap)
                self.store.set("fritz:last", {k: v for k, v in snap.items() if k != "hosts"} | {"at": iso()})
                devices_prev = self.devices()
                alerts = self.engine.apply("fritz", checks.router_findings(snap, devices_prev, self.store))
                self._send_alerts(alerts)
                if snap["errors"]:
                    log.warning("FRITZ!Box partial errors: %s", "; ".join(snap["errors"])[:500])
                if snap.get("igd_ok"):
                    self._health("fritz", True)
                else:
                    self._health("fritz", False, "UPnP IGD list unreadable - UPnP mappings cannot be told apart")
                if not hosts_ok:
                    snap = None  # inventory must not treat a missing host list as "all devices gone"
            except (fritz.FritzError, OSError, ValueError) as exc:
                self._health("fritz", False, str(exc))
                snap = None
        need_fritz = self.cfg["fritzbox"]["enabled"] and self.cfg["inventory"]["use_fritz_hosts"]
        if need_fritz and snap is None and not self.engine.baseline_done("inventory"):
            log.info("inventory baseline postponed until the router host list is readable")
            return
        try:
            inv = inventory.collect(self.cfg, snap, self.store)
            self.store.set("inventory:last", {"at": iso(), "devices": inv["devices"], "fritz": snap is not None})
            found = checks.device_findings(inv["devices"], self.cfg["inventory"]["known_devices"])

            def resolvable(f):
                if snap is None:
                    return False
                o = self.store.observation(f"dev:{f['detail'].get('mac')}")
                last = parse_iso(o["last_seen"]) if o else None
                return not last or (now() - last).days > DEVICE_FORGET_DAYS
            self._send_alerts(self.engine.apply("inventory", found, resolvable))
            self._health("inventory", True)
        except Exception as exc:  # noqa: BLE001
            log.exception("inventory failed")
            self._health("inventory", False, str(exc))

    def _check_ip_change(self, snap: dict) -> None:
        last = self.store.get("public_ip", {})
        cur = {"ipv4": snap.get("ipv4", ""), "ipv6_prefix": snap.get("ipv6_prefix", ""), "ipv6": snap.get("ipv6", "")}
        if not last:
            self.store.set("public_ip", cur | {"since": iso()})
            return
        changes = [k for k in ("ipv4", "ipv6_prefix") if cur[k] and cur[k] != last.get(k)]
        if not changes:
            if cur["ipv6"] != last.get("ipv6"):
                self.store.set("public_ip", cur | {"since": last.get("since", iso())})
            return
        text = ", ".join(f"{k}: {last.get(k) or '-'} -> {cur[k]}" for k in changes)
        self.store.set("public_ip", cur | {"since": iso(), "previous": last})
        self.store.set("public_ip_changes", int(self.store.get("public_ip_changes", 0)) + 1)
        self.store.event("ip-change", text, severity="info")
        self.store.set("external:force_push", True)
        if self.cfg["homeassistant"]["notify_ip_change"]:
            self._push("Exposure Guard: public IP changed", f"{text}. The external probe gets the new targets "
                       "and rescans.", tag="eg-ip")

    def job_external(self) -> None:
        ext = self.cfg["external"]
        if not ext["enabled"]:
            return
        if not ext["probe_host"] or not ext.get("probe_verify_key") or not self.keys.exists():
            self._health("external", False, "external probe not configured (probe_host / probe_verify_key / keys)")
            self._check_stale()
            return
        client = external.ProbeClient(self.cfg, self.keys)
        try:
            h = client.health()
            self.store.set("external:health", h | {"fetched": iso()})
            self._check_probe_view(h)
            doc = external.build_targets(self.cfg, self.store, None)
            doc["targets"] = [dict(t, addr=_norm(t["addr"])) for t in doc["targets"]]
            force = bool(self.store.get("external:force_push"))
            pushed = external.push_targets_if_needed(client, self.store, doc, force=force)
            if force and pushed:
                self.store.set("external:force_push", False)
                if ext["scan_on_ip_change"]:
                    client.scan_now()
            for run_id, result in client.results_after(self.store.get("external:last_run_id", "")):
                self._process_result(run_id, result)
            ext6 = ext.get("probe_host_v6")
            if ext6:
                h6 = external.ProbeClient(self.cfg, self.keys, host=ext6).health()
                self.store.set("external:health_v6", h6 | {"fetched": iso()})
                self._check_probe_view(h6)
            self._health("external", True)
        except (external.ProbeError, EnvelopeError, OSError, ValueError, KeyError) as exc:
            self._health("external", False, str(exc))
        self._check_stale()

    def _check_probe_view(self, h: dict) -> None:
        """The probe sees the address our SSH connection comes from: an independent public-IP check."""
        seen = _norm(h.get("client_ip") or "")
        fr = self.store.get("fritz:last") or {}
        if not seen or not self.cfg["external"]["ip_crosscheck"]:
            return
        fam = "v6" if ":" in seen else "v4"
        if fam == "v4":
            ok = not fr.get("ipv4") or seen == _norm(fr["ipv4"])
            expected = fr.get("ipv4", "")
        else:
            pfx = fr.get("ipv6_prefix") or ""
            try:
                ok = not pfx or ipaddress.ip_address(seen) in ipaddress.ip_network(pfx, strict=False) \
                    or seen == _norm(fr.get("ipv6", ""))
            except ValueError:
                ok = True
            expected = pfx
        self.store.set(f"external:seen_{fam}", {"addr": seen, "at": iso(), "matches_router": ok})
        if not ok:
            self._health("external_ipcheck", False,
                         f"probe sees us as {seen}, router reports {expected} - external scans may target the wrong address")
            self.store.set("external:force_push", True)
        else:
            if self.store.health("external_ipcheck"):
                self._health("external_ipcheck", True)

    def _process_result(self, run_id: str, result: dict) -> None:
        parsed = external.parse_result(result)
        summary = external.summarize(result, parsed)
        self.store.set("external:last", summary)
        snap = self.store.get("fritz:last") or {}
        found = external.result_findings(result, parsed, snap, self.devices(), self.cfg)
        if result.get("runs"):
            alerts = self.engine.apply("external", found, external.resolvable_for(result, parsed["missing"]))
            self._send_alerts(alerts)
        self.store.set("external:last_run_id", run_id)
        self.store.event("external-result", f"{run_id}: ok={summary['ok']} open={sum(len(v) for v in summary['open'].values())}",
                         severity="info")
        if summary["ok"]:
            self.store.set("external:last_good", summary)
            if summary["profile"] == "full":
                self.store.set("external:last_full", summary)
            self._health("external_scan", True)
        else:
            why = "; ".join(summary["errors"][:3] + ([f"not scanned: {', '.join(summary['missing'][:5])}"]
                                                      if summary["missing"] else []))
            self._health("external_scan", False, f"probe run {run_id} incomplete: {why}")
        if not self.store.get("report:initial") and summary["ok"]:
            self.store.set("report:initial_due", True)

    def _check_stale(self) -> None:
        is_stale, why = external.stale(self.store, self.cfg)
        if is_stale:
            # only escalate staleness once the guard has been running longer than the stale window
            first = parse_iso(self.store.get("first_start") or iso())
            grace = (now() - first).total_seconds() < self.cfg["external"]["stale_hours"] * 3600
            if not grace or self.store.get("external:last"):
                self._health("external_scan", False, "stale: " + why)
            self.store.set("external:stale", why)
        else:
            self.store.set("external:stale", "")

    def job_lan_web(self) -> None:
        if not self.cfg["lan_web"]["enabled"]:
            return
        devices = self.devices()
        if not devices:
            self._health("lan_web", False, "no inventory yet")
            return
        try:
            found, meta = lanweb.run(self.cfg, devices)
            self.store.set("lan_web:last", meta | {"at": iso()})
            self._send_alerts(self.engine.apply("lan_web", found))
            self._health("lan_web", True)
        except Exception as exc:  # noqa: BLE001
            log.exception("LAN web check failed")
            self._health("lan_web", False, str(exc))

    def job_tailscale(self) -> None:
        ts = self.cfg["tailscale"]
        if not ts["enabled"]:
            return
        found, api_ok, local_ok = [], None, False
        try:
            st = tailscale.local_status(ts["socket"])
            nodes = tailscale.nodes_from_status(st)
            self.store.set("tailscale:last", {"at": iso(), "nodes": nodes, "backend": st.get("BackendState")})
            found += tailscale.node_findings(nodes, ts["key_expiry_warn_days"])
            local_ok = True
            self._health("tailscale", True)
        except Exception as exc:  # noqa: BLE001
            self._health("tailscale", False, f"LocalAPI: {exc}")
        api = tailscale.TailscaleAPI(self.cfg)
        if ts["api_enabled"] and api.configured:
            try:
                pol = api.policy()
                found += tailscale.policy_findings(pol)
                found += tailscale.device_api_findings(api.devices())
                api_ok = True
                self.store.set("tailscale:api", {"at": iso(), "ok": True})
                self._health("tailscale_api", True)
            except Exception as exc:  # noqa: BLE001
                api_ok = False
                self._health("tailscale_api", False, str(exc)[:300])
        api_kinds = {"tailnet_acl", "tailnet_update"}

        def resolvable(f):
            if f["kind"] in api_kinds or f["id"].endswith(":external"):
                return bool(api_ok)
            return local_ok
        if local_ok or api_ok:
            self._send_alerts(self.engine.apply("tailscale", found, resolvable))

    # ============================================================================ status
    def status(self) -> dict:
        findings = self.engine.annotate(self.store.findings("open"))
        attention = [f for f in findings if not f["ack"] and not f["baseline"]]
        crit = [f for f in attention if f["severity"] == "critical"]
        notable = [f for f in attention if SEV_RANK[f["severity"]] <= SEV_RANK["medium"]]
        health = {h["source"]: h for h in self.store.health()}
        broken = []
        for src, h in health.items():
            thr = FAIL_THRESHOLD.get(src) or self.cfg["external"]["unreachable_after"]
            if h["failures"] and h["failures"] >= thr:
                broken.append(src)
        stale_why = self.store.get("external:stale", "") if self.cfg["external"]["enabled"] else ""
        if crit:
            state = "alert"
        elif stale_why or "external" in broken or "external_scan" in broken:
            state = "unknown"
        elif broken:
            state = "degraded"
        elif notable:
            state = "attention"
        else:
            state = "ok"
        by_sev = {s: 0 for s in SEV_RANK}
        for f in attention:
            by_sev[f["severity"]] += 1
        last_ext = self.store.get("external:last_good") or {}
        pub = self.store.get("public_ip", {})
        return {
            "version": __version__, "state": state, "generated": iso(),
            "critical_open": len(crit), "open_by_severity": by_sev, "open_total": len(attention),
            "acknowledged": sum(1 for f in findings if f["ack"]), "baseline": sum(1 for f in findings if f["baseline"] and not f["ack"]),
            "broken_sources": broken, "external_stale": stale_why,
            "external_last_scan": last_ext.get("finished", ""), "external_last_profile": last_ext.get("profile", ""),
            "public_ipv4": pub.get("ipv4", ""), "public_ipv6_prefix": pub.get("ipv6_prefix", ""),
            "health": health, "url": self.cfg["general"]["public_url"],
        }

    def publish(self) -> None:
        st = self.status()
        hb = iso()
        names = {"alert": "Alert", "unknown": "Unknown (external view missing)", "degraded": "Degraded",
                 "attention": "Findings", "ok": "OK"}
        common = {"heartbeat": hb, "attribution": "exposure-guard", "url": st["url"]}
        self.ha.state("", st["state"], common | {
            "friendly_name": "Exposure Guard", "icon": "mdi:shield-search", "summary": names[st["state"]],
            "critical_open": st["critical_open"], "open_total": st["open_total"], "acknowledged": st["acknowledged"],
            "broken_sources": st["broken_sources"], "external_stale": st["external_stale"],
            "public_ipv4": st["public_ipv4"], "public_ipv6_prefix": st["public_ipv6_prefix"], "version": st["version"]})
        ext_state = "stale" if st["external_stale"] else ("failing" if {"external", "external_scan"} & set(st["broken_sources"]) else "ok")
        self.ha.state("external", ext_state, common | {"friendly_name": "Exposure Guard external view",
                                                       "icon": "mdi:web", "last_scan": st["external_last_scan"],
                                                       "reason": st["external_stale"]})
        self.ha.state("open_findings", st["open_total"], common | {
            "friendly_name": "Exposure Guard open findings", "icon": "mdi:alert-circle-outline",
            "state_class": "measurement", **{f"sev_{k}": v for k, v in st["open_by_severity"].items()}})
        last = parse_iso(st["external_last_scan"])
        self.ha.state("last_external_scan", last.isoformat() if last else "unknown", common | {
            "friendly_name": "Exposure Guard last external scan", "device_class": "timestamp", "icon": "mdi:radar"})
        self.store.set("published", {"at": hb, "state": st["state"], "ha_error": self.ha.last_error})
        self._flush_outbox()

    # ============================================================================ scheduler
    def _slot_due(self, key: str, weekday: str, hhmm: str) -> bool:
        local = now().astimezone(self.tz)
        h, m = (int(x) for x in hhmm.split(":"))
        days_back = (local.weekday() - WEEKDAYS.index(weekday)) % 7
        slot = (local - timedelta(days=days_back)).replace(hour=h, minute=m, second=0, microsecond=0)
        if slot > local:
            slot -= timedelta(days=7)
        last = parse_iso(self.store.get(f"sched:{key}"))
        return not last or last < slot

    def _every_due(self, key: str, minutes: float) -> bool:
        last = parse_iso(self.store.get(f"sched:{key}"))
        return not last or (now() - last).total_seconds() >= minutes * 60 - 5

    def _mark(self, key: str) -> None:
        self.store.set(f"sched:{key}", iso())

    @contextlib.contextmanager
    def job_lock(self):
        """Serialises jobs between the daemon and CLI invocations (separate processes)."""
        with self.lock, open(os.path.join(self.cfg.data_dir, "jobs.lock"), "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def tick(self) -> None:
        from . import report
        with self.job_lock():
            sc = self.cfg["schedule"]
            ran = False
            if self._every_due("local", sc["local_minutes"]):
                self._mark("local")
                self.job_local()
                ran = True
            if self.cfg["tailscale"]["enabled"] and self._every_due("tailscale", self.cfg["tailscale"]["poll_minutes"]):
                self._mark("tailscale")
                self.job_tailscale()
                ran = True
            if self.cfg["external"]["enabled"] and (self._every_due("external", self.cfg["external"]["fetch_minutes"])
                                                    or self.store.get("external:force_push")):
                self._mark("external")
                self.job_external()
                ran = True
            lw = self.cfg["lan_web"]
            if lw["enabled"] and self.devices() and (not self.store.get("sched:lan_web")
                                                     or self._slot_due("lan_web", lw["weekday"], lw["time"])):
                self._mark("lan_web")
                self.job_lan_web()
                ran = True
            reminders = self.engine.reminders(self.cfg["homeassistant"]["remind_critical_hours"])
            self._send_alerts(reminders)
            first = parse_iso(self.store.get("first_start") or iso())
            if not self.store.get("report:initial") and (
                    self.store.get("report:initial_due") or (now() - first).total_seconds() > 36 * 3600):
                path = report.write(self, "initial")
                self.store.set("report:initial", path)
                self._push("Exposure Guard: initial report ready",
                           report.push_summary(self, "Initial report"), tag="eg-report")
            wr = sc["weekly_report"]
            if self.store.get("report:initial") and self._slot_due("weekly_report", wr["weekday"], wr["time"]):
                if self.store.get("sched:weekly_report"):
                    path = report.write(self, "weekly")
                    self._push("Exposure Guard: weekly report", report.push_summary(self, "Weekly report"),
                               tag="eg-report")
                self._mark("weekly_report")
            if ran or self._every_due("publish", 5):
                self._mark("publish")
                self.publish()
            if self._every_due("prune", 24 * 60):
                self._mark("prune")
                self.store.prune_events(iso(now() - timedelta(days=400)))

    def run_forever(self, stop: threading.Event) -> None:
        if not self.store.get("first_start"):
            self.store.set("first_start", iso())
        while not stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - the loop must survive anything; failures show up as health
                log.exception("scheduler tick failed")
                self.store.record_health("scheduler", False, "tick crashed - see container log")
            stop.wait(20)


def load(cfg_path: str | None = None) -> Guard:
    from .config import load as load_cfg
    return Guard(load_cfg(cfg_path))


def datetime_local(dt_iso: str, tz: ZoneInfo) -> str:
    dt = parse_iso(dt_iso)
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M") if dt else "-"


__all__ = ["Guard", "load", "datetime_local", "datetime"]
