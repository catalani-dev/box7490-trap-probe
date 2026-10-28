"""History: SQLite database, JSON Lines files and CSV files (any combination)."""

from __future__ import annotations

import csv
import json
import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import StoreConf
from .engine import Hit, iso

log = logging.getLogger("lantrap.store")

HIT_COLUMNS = (
    "received_at", "trap_id", "client_id", "peer", "hostname", "rule", "src", "src_mac", "dst", "proto",
    "sport", "dport", "in_if", "flags", "device_time", "excluded", "exclude_reason", "incident_id", "new_attempt", "raw",
)
INCIDENT_COLUMNS = (
    "id", "trap_id", "trap_name", "client_id", "client_name", "source_ip", "source_macs", "destinations",
    "first_seen", "last_seen", "lines", "attempts", "ports", "classification", "status", "alerts_sent",
)
ALERT_COLUMNS = ("id", "created_at", "kind", "trap_id", "client_id", "incident_id", "channel", "status", "error")


class Store:
    kind = "base"

    def write_hit(self, hit: Hit) -> None: ...
    def write_other(self, received_at: datetime, trap_id: str, peer: str, hostname: str | None, tag: str | None, message: str) -> None: ...
    def write_incident(self, snapshot: dict, reason: str) -> None: ...
    def write_alert(self, record: dict) -> None: ...
    def write_trap_state(self, trap_id: str, client_id: str, state: dict) -> None: ...
    def write_unknown(self, peer: str, hostname: str | None, first_seen: datetime, last_seen: datetime, count: int) -> None: ...
    def purge(self, now: datetime) -> int: return 0
    def flush(self) -> None: ...
    def close(self) -> None: ...


# ---------------------------------------------------------------- SQLite

SCHEMA = """
CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL, trap_id TEXT, client_id TEXT, peer TEXT, hostname TEXT, rule TEXT,
    src TEXT, src_mac TEXT, dst TEXT, proto TEXT, sport INTEGER, dport INTEGER, in_if TEXT, flags TEXT,
    device_time TEXT, excluded INTEGER NOT NULL DEFAULT 0, exclude_reason TEXT, incident_id TEXT,
    new_attempt INTEGER NOT NULL DEFAULT 0, raw TEXT
);
CREATE INDEX IF NOT EXISTS hits_received ON hits(received_at);
CREATE INDEX IF NOT EXISTS hits_incident ON hits(incident_id);
CREATE INDEX IF NOT EXISTS hits_src ON hits(src);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, trap_id TEXT, trap_name TEXT, client_id TEXT, client_name TEXT, source_ip TEXT,
    source_macs TEXT, destinations TEXT, first_seen TEXT, last_seen TEXT, lines INTEGER, attempts INTEGER,
    ports TEXT, classification TEXT, status TEXT, alerts_sent INTEGER, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS incidents_last ON incidents(last_seen);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT, created_at TEXT, kind TEXT, trap_id TEXT, client_id TEXT, incident_id TEXT, channel TEXT,
    status TEXT, error TEXT, payload TEXT
);
CREATE INDEX IF NOT EXISTS alerts_created ON alerts(created_at);
CREATE TABLE IF NOT EXISTS traps (
    trap_id TEXT PRIMARY KEY, client_id TEXT, last_seen TEXT, last_peer TEXT, last_hostname TEXT,
    clock_skew REAL, clock_ok INTEGER, silent INTEGER, messages INTEGER, hits INTEGER
);
CREATE TABLE IF NOT EXISTS unknown_senders (
    peer TEXT PRIMARY KEY, hostname TEXT, first_seen TEXT, last_seen TEXT, count INTEGER
);
CREATE TABLE IF NOT EXISTS other_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT, trap_id TEXT, peer TEXT, hostname TEXT, tag TEXT, message TEXT
);
CREATE INDEX IF NOT EXISTS other_received ON other_messages(received_at);
"""


def open_db(path: Path, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=10)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA)
    conn.row_factory = sqlite3.Row
    return conn


class SqliteStore(Store):
    kind = "sqlite"

    def __init__(self, conf: StoreConf) -> None:
        self.conf = conf
        self.db = open_db(conf.path)
        self._pending = 0

    def _commit_soon(self) -> None:
        self._pending += 1
        if self._pending >= 200:
            self.flush()

    def write_hit(self, hit: Hit) -> None:
        d = hit.as_dict()
        d["excluded"] = int(hit.excluded)
        d["new_attempt"] = int(hit.new_attempt)
        self.db.execute(
            f"INSERT INTO hits ({', '.join(HIT_COLUMNS)}) VALUES ({', '.join('?' * len(HIT_COLUMNS))})",
            [d[c] for c in HIT_COLUMNS],
        )
        self._commit_soon()

    def write_other(self, received_at, trap_id, peer, hostname, tag, message) -> None:
        self.db.execute(
            "INSERT INTO other_messages (received_at, trap_id, peer, hostname, tag, message) VALUES (?,?,?,?,?,?)",
            (iso(received_at), trap_id, peer, hostname, tag, message),
        )
        self._commit_soon()

    def write_incident(self, snapshot: dict, reason: str) -> None:
        row = dict(snapshot)
        for key in ("source_macs", "destinations", "ports"):
            row[key] = json.dumps(row[key], ensure_ascii=False)
        row["updated_at"] = iso(datetime.now(timezone.utc))
        cols = INCIDENT_COLUMNS + ("updated_at",)
        self.db.execute(
            f"INSERT INTO incidents ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
            f"ON CONFLICT(id) DO UPDATE SET {', '.join(f'{c}=excluded.{c}' for c in cols if c != 'id')}",
            [row[c] for c in cols],
        )
        self._commit_soon()

    def write_alert(self, record: dict) -> None:
        self.db.execute(
            f"INSERT INTO alerts ({', '.join(ALERT_COLUMNS)}, payload) VALUES ({', '.join('?' * (len(ALERT_COLUMNS) + 1))})",
            [record.get(c) for c in ALERT_COLUMNS] + [json.dumps(record.get("payload"), ensure_ascii=False)],
        )
        self.flush()

    def write_trap_state(self, trap_id, client_id, state) -> None:
        self.db.execute(
            "INSERT INTO traps (trap_id, client_id, last_seen, last_peer, last_hostname, clock_skew, clock_ok, silent, messages, hits) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(trap_id) DO UPDATE SET client_id=excluded.client_id, "
            "last_seen=excluded.last_seen, last_peer=excluded.last_peer, last_hostname=excluded.last_hostname, "
            "clock_skew=excluded.clock_skew, clock_ok=excluded.clock_ok, silent=excluded.silent, "
            "messages=excluded.messages, hits=excluded.hits",
            (trap_id, client_id, state.get("last_seen"), state.get("last_peer"), state.get("last_hostname"),
             state.get("clock_skew"), None if state.get("clock_ok") is None else int(state["clock_ok"]),
             int(bool(state.get("silent"))), state.get("messages", 0), state.get("hits", 0)),
        )
        self._commit_soon()

    def write_unknown(self, peer, hostname, first_seen, last_seen, count) -> None:
        self.db.execute(
            "INSERT INTO unknown_senders (peer, hostname, first_seen, last_seen, count) VALUES (?,?,?,?,?) "
            "ON CONFLICT(peer) DO UPDATE SET hostname=excluded.hostname, last_seen=excluded.last_seen, count=excluded.count",
            (peer, hostname, iso(first_seen), iso(last_seen), count),
        )
        self._commit_soon()

    def close_stale_incidents(self) -> int:
        cur = self.db.execute("UPDATE incidents SET status='closed' WHERE status='open'")
        self.flush()
        return cur.rowcount

    def purge(self, now: datetime) -> int:
        if not self.conf.retention_days:
            return 0
        cutoff = iso(now - timedelta(days=self.conf.retention_days))
        removed = 0
        for table, column in (("hits", "received_at"), ("incidents", "last_seen"), ("alerts", "created_at"),
                              ("other_messages", "received_at"), ("unknown_senders", "last_seen")):
            removed += self.db.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,)).rowcount
        self.flush()
        return removed

    def flush(self) -> None:
        if self.db.in_transaction:
            self.db.commit()
        self._pending = 0

    def close(self) -> None:
        self.flush()
        self.db.close()


# ---------------------------------------------------------------- files

_DATED = re.compile(r"^(hits|incidents|alerts|other)-(\d{4}-\d{2}-\d{2})\.(jsonl|csv)$")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> object:
    """Spreadsheets run cells that start with = + - @ as formulas: prefix them with a quote."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


class _FileStore(Store):
    extension = ""

    def __init__(self, conf: StoreConf) -> None:
        self.conf = conf
        self.dir = conf.path
        self.dir.mkdir(parents=True, exist_ok=True)

    def _file(self, name: str, when: datetime) -> Path:
        return self.dir / f"{name}-{when.astimezone():%Y-%m-%d}.{self.extension}"

    def _write(self, name: str, when: datetime, row: dict, columns: tuple) -> None:
        raise NotImplementedError

    def write_hit(self, hit: Hit) -> None:
        self._write("hits", hit.received_at, hit.as_dict(), HIT_COLUMNS)

    def write_other(self, received_at, trap_id, peer, hostname, tag, message) -> None:
        row = {"received_at": iso(received_at), "trap_id": trap_id, "peer": peer, "hostname": hostname, "tag": tag, "message": message}
        self._write("other", received_at, row, tuple(row))

    def write_incident(self, snapshot: dict, reason: str) -> None:
        # files are append-only: write a snapshot when an alert goes out and when the incident closes
        if reason not in ("alert", "closed"):
            return
        self._write("incidents", datetime.now(timezone.utc), snapshot, INCIDENT_COLUMNS)

    def write_alert(self, record: dict) -> None:
        self._write("alerts", datetime.now(timezone.utc), record, ALERT_COLUMNS)

    def purge(self, now: datetime) -> int:
        if not self.conf.retention_days:
            return 0
        cutoff = (now - timedelta(days=self.conf.retention_days)).astimezone().date()
        removed = 0
        for f in self.dir.iterdir():
            m = _DATED.match(f.name)
            if m and m.group(3) == self.extension and datetime.strptime(m.group(2), "%Y-%m-%d").date() < cutoff:
                try:
                    f.unlink()
                    removed += 1
                except OSError as exc:
                    log.warning("cannot remove %s: %s", f, exc)
        return removed


class JsonlStore(_FileStore):
    kind = "jsonl"
    extension = "jsonl"

    def _write(self, name, when, row, columns) -> None:
        with self._file(name, when).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


class CsvStore(_FileStore):
    kind = "csv"
    extension = "csv"

    def _write(self, name, when, row, columns) -> None:
        path = self._file(name, when)
        new = not path.exists()
        with path.open("a", encoding="utf-8-sig" if new else "utf-8", newline="") as fh:
            writer = csv.writer(fh)
            if new:
                writer.writerow(columns)
            writer.writerow([csv_safe(row.get(c)) for c in columns])


def build_stores(confs: list[StoreConf]) -> list[Store]:
    kinds = {"sqlite": SqliteStore, "jsonl": JsonlStore, "csv": CsvStore}
    return [kinds[c.type](c) for c in confs]


# ---------------------------------------------------------------- reports (SQLite)

def recent_incidents(path: Path, limit: int = 20) -> list[dict]:
    conn = open_db(path, readonly=True)
    try:
        rows = conn.execute("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        for key in ("source_macs", "destinations", "ports"):
            try:
                d[key] = json.loads(d[key] or "[]")
            except ValueError:
                d[key] = []
        out.append(d)
    return out


def trap_rows(path: Path) -> list[dict]:
    conn = open_db(path, readonly=True)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM traps ORDER BY trap_id")]
    finally:
        conn.close()


def unknown_rows(path: Path) -> list[dict]:
    conn = open_db(path, readonly=True)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM unknown_senders ORDER BY last_seen DESC")]
    finally:
        conn.close()
