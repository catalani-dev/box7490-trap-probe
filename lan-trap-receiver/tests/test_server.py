"""End to end: real sockets, real stores, a local webhook."""

import asyncio
import json
import os
import socket
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from datetime import datetime, timedelta, timezone

from lantrap import notify, simulate
from lantrap.config import load_config, save_raw
from lantrap.engine import Alert
from lantrap.server import Receiver

from helpers import HttpSink, base_raw, logd_network, make_config, real_line


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EndToEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.sink = HttpSink()
        self.dir = Path(tempfile.mkdtemp(prefix="lantrap-e2e-"))
        self.port = free_port()
        self.raw = base_raw(
            listen=[{"protocol": "udp", "address": "127.0.0.1", "port": self.port},
                    {"protocol": "tcp", "address": "127.0.0.1", "port": self.port}],
            store=[{"type": "sqlite", "path": "data/db.sqlite3"}, {"type": "jsonl", "directory": "data/jsonl"},
                   {"type": "csv", "directory": "data/csv"}],
            notify=[{"name": "hook", "type": "webhook", "url": self.sink.url}],
            grouping={"collect_seconds": 1, "quiet_minutes": 15},
            heartbeat={"enabled": False},
        )
        self.raw["trap"][0]["source"] = ["127.0.0.1"]
        self.path = self.dir / "lantrap.toml"
        save_raw(self.raw, self.path)
        self.receiver = Receiver(load_config(self.path), tick_seconds=0.05)
        await self.receiver.start()
        self.stop = asyncio.Event()
        self.task = asyncio.create_task(self.receiver.serve(self.stop))

    async def asyncTearDown(self):
        if not self.stop.is_set():
            await self.finish()
        self.sink.stop()

    async def finish(self):
        self.stop.set()
        await self.task
        await self.receiver.close()

    async def wait_requests(self, n: int, timeout: float = 5) -> list:
        deadline = time.monotonic() + timeout
        while len(self.sink.requests) < n and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        return [json.loads(r["body"]) for r in self.sink.requests]

    async def test_udp_scan_grouped_excluded_and_tcp(self):
        lines = [logd_network(real_line(dport=port, sport=50000 + i, ident=i * 10 + r))
                 for i, port in enumerate((21, 23, 445, 3389, 8080)) for r in range(5)]
        await asyncio.to_thread(simulate.send, lines, "127.0.0.1", self.port, "udp")
        alerts = await self.wait_requests(1)
        self.assertEqual(len(alerts), 1)
        inc = alerts[0]["incident"]
        self.assertEqual((inc["lines"], inc["attempts"], inc["trap_id"], inc["client_id"]), (25, 5, "acme-hq", "acme"))
        self.assertEqual(alerts[0]["title"], "[ACME Ltd] Port scan from 192.168.1.2")

        # the client's scanner: recorded, no alert
        await asyncio.to_thread(simulate.send, [logd_network(real_line(src="192.168.1.250"))], "127.0.0.1", self.port, "udp")
        # same source again within the quiet period: same incident, no new alert
        await asyncio.to_thread(simulate.send, [logd_network(real_line(dport=5900))], "127.0.0.1", self.port, "udp")
        await asyncio.sleep(0.4)
        self.assertEqual(len(self.sink.requests), 1)

        # TCP with LF trailers, NUL trailers and octet counting
        frame = logd_network(real_line(src="192.168.1.3", dport=1433)).encode()
        payload = frame + b"\n" + frame + b"\0" + str(len(frame)).encode() + b" " + frame
        def tcp_send():
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
                s.sendall(payload)
        await asyncio.to_thread(tcp_send)
        alerts = await self.wait_requests(2)
        self.assertEqual(len(alerts), 2)
        self.assertEqual((alerts[1]["incident"]["source_ip"], alerts[1]["incident"]["lines"]), ("192.168.1.3", 3))
        self.assertEqual(alerts[1]["incident"]["classification"], "connection_attempt")

        await self.finish()
        db = sqlite3.connect(self.dir / "data" / "db.sqlite3")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM hits").fetchone()[0], 25 + 1 + 1 + 3)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM hits WHERE excluded=1").fetchone()[0], 1)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 2)
        self.assertEqual(db.execute("SELECT lines FROM incidents WHERE source_ip='192.168.1.2'").fetchone()[0], 26)
        self.assertEqual(db.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall(), [("sent", 2)])
        db.close()
        jsonl = list((self.dir / "data" / "jsonl").glob("hits-*.jsonl"))
        self.assertEqual(sum(len(p.read_text(encoding="utf-8").splitlines()) for p in jsonl), 30)
        csv_files = list((self.dir / "data" / "csv").glob("hits-*.csv"))
        self.assertEqual(sum(len(p.read_text(encoding="utf-8-sig").splitlines()) for p in csv_files), 31)

    async def test_configuration_reload_applies_new_exclusion(self):
        self.raw["client"][0]["exclude"].append("192.168.1.0/24")
        save_raw(self.raw, self.path)
        stamp = time.time() + 5
        os.utime(self.path, (stamp, stamp))
        self.assertTrue(self.receiver.check_reload())
        await asyncio.to_thread(simulate.send, [logd_network(real_line())], "127.0.0.1", self.port, "udp")
        await asyncio.sleep(0.4)
        self.assertEqual(self.sink.requests, [])

    async def test_broken_configuration_keeps_the_old_one(self):
        self.path.write_text("this is = = not toml", encoding="utf-8")
        stamp = time.time() + 5
        os.utime(self.path, (stamp, stamp))
        with self.assertLogs("lantrap", "ERROR"):
            self.assertFalse(self.receiver.check_reload())
        await asyncio.to_thread(simulate.send, [logd_network(real_line())], "127.0.0.1", self.port, "udp")
        self.assertEqual(len(await self.wait_requests(1)), 1)


class Robustness(unittest.IsolatedAsyncioTestCase):
    """Receiver behaviour without sockets: frames are handed in directly."""

    def setUp(self):
        notify.RETRY_DELAYS = (0.0, 0.0)
        self.sink = HttpSink()
        self.addCleanup(self.sink.stop)

    def receiver(self, **grouping):
        raw = base_raw(grouping={"collect_seconds": 60, **grouping}, heartbeat={"enabled": False},
                       notify=[{"name": "hook", "type": "webhook", "url": self.sink.url}])
        raw["trap"][0]["source"] = ["127.0.0.1"]
        return Receiver(make_config(raw), tick_seconds=0.05)

    async def test_alerts_still_collecting_are_sent_at_shutdown(self):
        r = self.receiver()
        for i, port in enumerate((21, 23, 445, 3389, 8080)):
            for _ in range(5):
                r.handle_frame(logd_network(real_line(dport=port, sport=50000 + i)).encode(), "127.0.0.1")
        r.tick()
        await asyncio.sleep(0.2)
        self.assertEqual(self.sink.requests, [], "collect window of 60 s not over")
        await r.close()
        (req,) = self.sink.requests
        self.assertEqual(json.loads(req["body"])["incident"]["lines"], 25)

    async def test_failed_delivery_is_retried_later(self):
        r = self.receiver()
        self.sink.status = 500
        await r._send(Alert("test", datetime.now(timezone.utc), None, None))
        self.assertEqual([(attempt, name) for _, attempt, _, name in r._redeliveries], [(1, "hook")])
        self.sink.status = 200
        r._redeliver(datetime.now(timezone.utc) + timedelta(minutes=2))
        await asyncio.gather(*r._tasks)
        self.assertEqual(r._redeliveries, [])
        self.assertEqual(len(self.sink.requests), 4, "3 tries, then the later successful one")

    async def test_a_message_that_breaks_the_engine_does_not_stop_the_receiver(self):
        r = self.receiver()
        def boom(*args, **kwargs):
            raise RuntimeError("unexpected")
        r.engine.receive = boom
        with self.assertLogs("lantrap", "ERROR"):
            r.handle_frame(b"<4>whatever", "127.0.0.1")
        r.handle_frame(b"<4>again", "127.0.0.1")
        self.assertEqual(r._frame_errors, 2)


if __name__ == "__main__":
    unittest.main()
