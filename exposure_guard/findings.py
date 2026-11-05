"""Finding model, severities, acknowledgements and the drift engine that turns findings into alerts."""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Callable

import yaml

from .store import Store
from .util import atomic_write, iso, log, now, parse_iso, short_hash

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    id: str                     # stable identity, e.g. "ext:v4:tcp/32400"
    source: str                 # fritz | inventory | external | lan_web | tailscale
    kind: str                   # port_mapping | open_port | device | tls | web | config | tailnet ...
    severity: str
    title: str
    message: str
    action: str = ""
    detail: dict = field(default_factory=dict)
    state_key: dict | list | str | None = None   # what counts as "a change" -> fingerprint

    @property
    def fingerprint(self) -> str:
        return short_hash(self.kind, self.state_key if self.state_key is not None else self.detail)

    def __post_init__(self):
        if self.severity not in SEV_RANK:
            raise ValueError(f"bad severity {self.severity}")


# ------------------------------------------------------------------------------------------ acks
class Acks:
    """Acknowledgements from acks.yaml. Each ack is bound to the state (fingerprint) it was given for:
    when the finding changes, the ack no longer applies and the finding alerts again."""

    def __init__(self, path: str, store: Store):
        self.path, self.store = path, store
        self.entries: list[dict] = []
        self.mtime = None
        self.reload()

    def reload(self) -> None:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            self.entries, self.mtime = [], None
            return
        if mtime == self.mtime:
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError) as exc:
            log.error("acks file unreadable (%s) - keeping previous acks", exc)
            return
        entries = data.get("acks") if isinstance(data, dict) else None
        self.entries = [e for e in (entries or []) if isinstance(e, dict) and e.get("id")]
        self.mtime = mtime

    def match(self, finding: dict) -> dict | None:
        """Return the ack entry that covers this finding in its current state, else None."""
        self.reload()
        fid, fp = finding["id"], finding["fingerprint"]
        for entry in self.entries:
            if not fnmatch.fnmatchcase(fid, str(entry["id"])):
                continue
            until = entry.get("until")
            if until:
                until_dt = _to_dt(until)
                if until_dt and until_dt < now():
                    continue
            bound = str(entry.get("fingerprint") or "")
            if not bound:
                bound = self.store.ack_binding(fid) or ""
                if not bound:
                    # YAML ack without fingerprint: bind it to the state it was first applied to
                    self.store.bind_ack(fid, fp)
                    bound = fp
            if bound == fp:
                return entry
        return None

    def add(self, fid: str, fingerprint: str, reason: str, by: str = "cli", until: str | None = None) -> dict:
        self.reload()
        self.entries = [e for e in self.entries if e.get("id") != fid]
        entry = {"id": fid, "fingerprint": fingerprint, "reason": reason, "by": by, "at": iso()}
        if until:
            entry["until"] = until
        self.entries.append(entry)
        self._write()
        return entry

    def remove(self, fid: str) -> bool:
        self.reload()
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.get("id") != fid]
        self.store.drop_ack_binding(fid)
        if len(self.entries) != before:
            self._write()
            return True
        return False

    def _write(self) -> None:
        header = ("# Exposure Guard - acknowledged findings.\n"
                  "# One entry per finding: id (from the UI/CLI, wildcards * allowed), reason, optional until (date).\n"
                  "# 'fingerprint' binds the ack to the state it was given for; when the finding changes it alerts again.\n"
                  "# Entries without fingerprint are bound to the state seen when they are first applied.\n")
        body = yaml.safe_dump({"acks": self.entries}, sort_keys=False, allow_unicode=True)
        atomic_write(self.path, header + body, 0o664)
        self.mtime = os.path.getmtime(self.path)


def _to_dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, 23, 59, 59, tzinfo=timezone.utc)
    dt = parse_iso(str(value))
    if dt and len(str(value)) <= 10:
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt


# ---------------------------------------------------------------------------------------- engine
class Engine:
    """Applies a source's current findings to the stored state and decides what to alert."""

    def __init__(self, store: Store, acks: Acks):
        self.store, self.acks = store, acks

    def baseline_done(self, source: str) -> bool:
        return bool(self.store.get(f"baseline:{source}"))

    def apply(self, source: str, current: list[Finding],
              resolvable: Callable[[dict], bool] | None = None) -> list[dict]:
        """Store findings of one successful source run. Returns alert dicts (kind new|changed|resolved).

        `resolvable(f)` limits which stored open findings may be resolved by their absence (partial scans)."""
        t = iso()
        first_run = not self.baseline_done(source)
        alerts: list[dict] = []
        seen = set()
        for f in current:
            if f.id in seen:
                continue
            seen.add(f.id)
            old = self.store.finding(f.id)
            row = {
                "id": f.id, "source": source, "kind": f.kind, "severity": f.severity, "title": f.title,
                "message": f.message, "action": f.action, "detail": f.detail, "fingerprint": f.fingerprint,
                "last_seen": t, "state": "open", "resolved_at": None,
            }
            if old and old["state"] == "open":
                row.update(first_seen=old["first_seen"], baseline=old["baseline"], notified_fp=old["notified_fp"],
                           notified_at=old["notified_at"])
                if old["fingerprint"] != f.fingerprint:
                    self.store.event("changed", f"{f.title}", f.id, f.severity, t)
                    if old["baseline"]:
                        row["baseline"] = False  # a baseline item that changes is reviewed like a new one
            else:
                row.update(first_seen=t, baseline=first_run, notified_fp=None, notified_at=None)
                self.store.event("baseline" if first_run else "new", f.title, f.id, f.severity, t)
                if first_run:
                    row["notified_fp"] = f.fingerprint  # baseline: known at start, no alert
            alert = self._decide(row, old)
            if alert:
                alerts.append(alert)
                row["notified_fp"], row["notified_at"] = f.fingerprint, t
            self.store.upsert_finding(row)

        for old in self.store.findings("open", source):
            if old["id"] in seen or (resolvable and not resolvable(old)):
                continue
            old.update(state="resolved", resolved_at=t)
            self.store.event("resolved", old["title"], old["id"], old["severity"], t)
            if old["severity"] == "critical" and old["notified_at"] and not old["baseline"]:
                alerts.append({"type": "resolved", "finding": old})
            old["notified_fp"] = None
            self.store.upsert_finding(old)
        if first_run:
            self.store.set(f"baseline:{source}", t)
        return alerts

    def _decide(self, row: dict, old: dict | None) -> dict | None:
        if row["severity"] != "critical":
            return None
        if self.acks.match(row):
            return None
        if row["notified_fp"] == row["fingerprint"]:
            return None
        return {"type": "changed" if old and old["state"] == "open" else "new", "finding": row}

    def reminders(self, hours: float) -> list[dict]:
        if hours <= 0:
            return []
        out = []
        for f in self.store.findings("open"):
            if f["severity"] != "critical" or self.acks.match(f) or f["baseline"]:
                continue
            last = parse_iso(f["notified_at"])
            if last and (now() - last).total_seconds() > hours * 3600:
                out.append({"type": "reminder", "finding": f})
                f["notified_at"] = iso()
                self.store.upsert_finding(f)
        return out

    def annotate(self, findings: list[dict]) -> list[dict]:
        """Add 'ack' (the matching ack entry or None) to stored finding dicts."""
        for f in findings:
            f["ack"] = self.acks.match(f)
        return findings
