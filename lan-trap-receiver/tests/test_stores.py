import csv
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from lantrap.config import StoreConf, parse_config
from lantrap.engine import Engine
from lantrap.stores import CsvStore, JsonlStore, SqliteStore, csv_safe, recent_incidents, trap_rows, unknown_rows
from lantrap.syslogparse import parse_syslog

from helpers import T0, base_raw, logd_network, windows_scan


def hits_and_incident():
    eng = Engine(parse_config(base_raw()), T0)
    hits = [eng.receive("10.99.0.11", parse_syslog(logd_network(line), when), when).hit for when, line in windows_scan()]
    inc = next(iter(eng.incidents.values()))
    return hits, eng.snapshot(inc)


class Sqlite(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.store = SqliteStore(StoreConf("sqlite", self.dir / "db" / "x.sqlite3", 30))

    def tearDown(self):
        self.store.close()

    def test_hits_incidents_alerts_traps(self):
        hits, snap = hits_and_incident()
        for h in hits:
            self.store.write_hit(h)
        self.store.write_incident(snap, "alert")
        snap["lines"] = 99
        self.store.write_incident(snap, "update")
        self.store.write_alert({"id": "a1", "created_at": "2026-10-23T12:01:00+00:00", "kind": "incident",
                                "channel": "mail", "status": "sent", "payload": {"x": 1}})
        self.store.write_trap_state("acme-hq", "acme", {"last_seen": "2026-10-23T12:00:00+00:00", "clock_ok": False, "messages": 3})
        self.store.write_unknown("172.16.0.9", "stranger", T0, T0, 4)
        self.store.flush()
        path = self.store.conf.path
        (row,) = recent_incidents(path)
        self.assertEqual((row["lines"], row["attempts"], len(row["ports"])), (99, 5, 5))
        self.assertEqual(trap_rows(path)[0]["clock_ok"], 0)
        self.assertEqual(unknown_rows(path)[0]["count"], 4)
        count = self.store.db.execute("SELECT COUNT(*), SUM(new_attempt) FROM hits").fetchone()
        self.assertEqual(tuple(count), (25, 5))

    def test_purge_and_stale_incidents(self):
        hits, snap = hits_and_incident()
        self.store.write_hit(hits[0])
        self.store.write_incident(snap, "update")
        self.assertEqual(self.store.close_stale_incidents(), 1)
        self.assertEqual(recent_incidents(self.store.conf.path)[0]["status"], "closed")
        self.assertEqual(self.store.purge(T0 + timedelta(days=10)), 0)
        self.assertEqual(self.store.purge(T0 + timedelta(days=31)), 2)


class Files(unittest.TestCase):
    def test_jsonl(self):
        d = Path(tempfile.mkdtemp())
        store = JsonlStore(StoreConf("jsonl", d, 7))
        hits, snap = hits_and_incident()
        store.write_hit(hits[0])
        store.write_incident(snap, "update")   # not written: files keep alert and closing snapshots only
        store.write_incident(snap, "closed")
        files = sorted(p.name for p in d.iterdir())
        self.assertEqual(len(files), 2)
        hit_file = next(d.glob("hits-*.jsonl"))
        self.assertEqual(json.loads(hit_file.read_text(encoding="utf-8").splitlines()[0])["dport"], 21)
        inc_file = next(d.glob("incidents-*.jsonl"))
        self.assertEqual(len(inc_file.read_text(encoding="utf-8").splitlines()), 1)
        (d / "hits-2020-01-01.jsonl").write_text("{}\n", encoding="utf-8")
        (d / "notes.txt").write_text("keep", encoding="utf-8")
        self.assertEqual(store.purge(T0), 1)
        self.assertTrue((d / "notes.txt").exists())

    def test_csv_header_and_formula_guard(self):
        d = Path(tempfile.mkdtemp())
        store = CsvStore(StoreConf("csv", d, 0))
        hits, _ = hits_and_incident()
        hits[0].hostname = "=HYPERLINK(\"http://evil\")"
        store.write_hit(hits[0])
        store.write_hit(hits[1])
        with next(d.glob("hits-*.csv")).open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(rows[0][0], "received_at")
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[1][rows[0].index("hostname")].startswith("'="))
        self.assertEqual(csv_safe(-5), -5)
        self.assertEqual(csv_safe("-cmd"), "'-cmd")
        self.assertEqual(csv_safe(None), "")


if __name__ == "__main__":
    unittest.main()
