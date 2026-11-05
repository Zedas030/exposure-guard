"""SQLite state: findings, observations (first seen), source health, events, key/value."""
from __future__ import annotations

import json
import os
import sqlite3
import threading

from .util import iso

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    resolved_at TEXT,
    baseline INTEGER NOT NULL DEFAULT 0,
    notified_fp TEXT,
    notified_at TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS source_health (
    source TEXT PRIMARY KEY,
    last_attempt TEXT,
    last_success TEXT,
    last_error TEXT,
    failures INTEGER NOT NULL DEFAULT 0,
    alerted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ack_bindings (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    bound_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    n INTEGER PRIMARY KEY AUTOINCREMENT,
    t TEXT NOT NULL,
    kind TEXT NOT NULL,
    finding_id TEXT,
    severity TEXT,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_t ON events(t);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # -- key/value -------------------------------------------------------------------------
    def get(self, key: str, default=None):
        with self._lock:
            row = self.db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set(self, key: str, value) -> None:
        with self._lock, self.db:
            self.db.execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (key, json.dumps(value, default=str)))

    # -- observations (first-seen bookkeeping) -----------------------------------------------
    def observe(self, key: str, kind: str, data: dict, t: str | None = None) -> str:
        """Record that `key` is present now; returns the first-seen timestamp."""
        t = t or iso()
        with self._lock, self.db:
            row = self.db.execute("SELECT first_seen FROM observations WHERE key=?", (key,)).fetchone()
            if row:
                self.db.execute("UPDATE observations SET last_seen=?, data=? WHERE key=?",
                                (t, json.dumps(data, default=str), key))
                return row["first_seen"]
            self.db.execute("INSERT INTO observations(key,kind,first_seen,last_seen,data) VALUES(?,?,?,?,?)",
                            (key, kind, t, t, json.dumps(data, default=str)))
            return t

    def observation(self, key: str) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM observations WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["data"] = json.loads(d["data"])
        return d

    def forget(self, key: str) -> None:
        with self._lock, self.db:
            self.db.execute("DELETE FROM observations WHERE key=?", (key,))

    def observations(self, kind: str) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM observations WHERE kind=? ORDER BY first_seen", (kind,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["data"] = json.loads(d["data"])
            out.append(d)
        return out

    # -- findings ------------------------------------------------------------------------------
    def finding(self, fid: str) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        return _finding_row(row) if row else None

    def findings(self, state: str | None = "open", source: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM findings WHERE 1=1", []
        if state:
            q += " AND state=?"
            args.append(state)
        if source:
            q += " AND source=?"
            args.append(source)
        with self._lock:
            rows = self.db.execute(q + " ORDER BY first_seen", args).fetchall()
        return [_finding_row(r) for r in rows]

    def upsert_finding(self, f: dict) -> None:
        cols = ["id", "source", "kind", "severity", "title", "message", "action", "detail", "fingerprint",
                "first_seen", "last_seen", "state", "resolved_at", "baseline", "notified_fp", "notified_at"]
        row = {c: f.get(c) for c in cols}
        row["detail"] = json.dumps(f.get("detail") or {}, default=str)
        row["baseline"] = int(bool(f.get("baseline")))
        row["state"] = row["state"] or "open"
        row["action"] = row["action"] or ""
        with self._lock, self.db:
            self.db.execute(
                f"INSERT INTO findings({','.join(cols)}) VALUES({','.join('?' * len(cols))}) "
                f"ON CONFLICT(id) DO UPDATE SET {','.join(f'{c}=excluded.{c}' for c in cols[1:])}",
                [row[c] for c in cols])

    # -- ack bindings -------------------------------------------------------------------------
    def ack_binding(self, fid: str) -> str | None:
        with self._lock:
            row = self.db.execute("SELECT fingerprint FROM ack_bindings WHERE id=?", (fid,)).fetchone()
        return row["fingerprint"] if row else None

    def bind_ack(self, fid: str, fingerprint: str) -> None:
        with self._lock, self.db:
            self.db.execute("INSERT INTO ack_bindings(id,fingerprint,bound_at) VALUES(?,?,?) "
                            "ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint, bound_at=excluded.bound_at",
                            (fid, fingerprint, iso()))

    def drop_ack_binding(self, fid: str) -> None:
        with self._lock, self.db:
            self.db.execute("DELETE FROM ack_bindings WHERE id=?", (fid,))

    # -- source health ------------------------------------------------------------------------
    def health(self, source: str | None = None):
        with self._lock:
            if source:
                row = self.db.execute("SELECT * FROM source_health WHERE source=?", (source,)).fetchone()
                return dict(row) if row else None
            return [dict(r) for r in self.db.execute("SELECT * FROM source_health ORDER BY source").fetchall()]

    def record_health(self, source: str, ok: bool, error: str = "") -> dict:
        t = iso()
        with self._lock, self.db:
            row = self.db.execute("SELECT * FROM source_health WHERE source=?", (source,)).fetchone()
            if not row:
                self.db.execute("INSERT INTO source_health(source) VALUES(?)", (source,))
                row = self.db.execute("SELECT * FROM source_health WHERE source=?", (source,)).fetchone()
            if ok:
                self.db.execute("UPDATE source_health SET last_attempt=?, last_success=?, last_error='', failures=0 "
                                "WHERE source=?", (t, t, source))
            else:
                self.db.execute("UPDATE source_health SET last_attempt=?, last_error=?, failures=failures+1 "
                                "WHERE source=?", (t, error[:500], source))
            return dict(self.db.execute("SELECT * FROM source_health WHERE source=?", (source,)).fetchone())

    def set_health_alerted(self, source: str, alerted: bool) -> None:
        with self._lock, self.db:
            self.db.execute("UPDATE source_health SET alerted=? WHERE source=?", (int(alerted), source))

    # -- events -------------------------------------------------------------------------------
    def event(self, kind: str, message: str, finding_id: str = "", severity: str = "", t: str | None = None) -> None:
        with self._lock, self.db:
            self.db.execute("INSERT INTO events(t,kind,finding_id,severity,message) VALUES(?,?,?,?,?)",
                            (t or iso(), kind, finding_id, severity, message))

    def events(self, since: str | None = None, limit: int = 500) -> list[dict]:
        with self._lock:
            if since:
                rows = self.db.execute("SELECT * FROM events WHERE t>=? ORDER BY n DESC LIMIT ?", (since, limit)).fetchall()
            else:
                rows = self.db.execute("SELECT * FROM events ORDER BY n DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def prune_events(self, before: str) -> None:
        with self._lock, self.db:
            self.db.execute("DELETE FROM events WHERE t<?", (before,))


def _finding_row(row) -> dict:
    d = dict(row)
    d["detail"] = json.loads(d.get("detail") or "{}")
    d["baseline"] = bool(d.get("baseline"))
    return d
