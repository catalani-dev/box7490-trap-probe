import email
import hashlib
import hmac
import json
import os
import sys
import tempfile
import unittest
import urllib.parse
from datetime import timedelta
from email import policy
from pathlib import Path

from lantrap import notify
from lantrap.config import ConfigError, parse_config
from lantrap.engine import Alert, Engine
from lantrap.syslogparse import parse_syslog

from helpers import T0, FakeSmtp, HttpSink, base_raw, logd_network, windows_scan

notify.RETRY_DELAYS = (0.0, 0.0)


def incident_alert(raw=None):
    cfg = parse_config(raw or base_raw(grouping={"collect_seconds": 0}))
    eng = Engine(cfg, T0)
    for when, line in windows_scan():
        eng.receive("10.99.0.11", parse_syslog(logd_network(line), when), when)
    alerts, _ = eng.tick(T0 + timedelta(seconds=10))
    return cfg, alerts[0]


class Rendering(unittest.TestCase):
    def test_english_and_italian(self):
        _, alert = incident_alert()
        title, body = notify.render(alert, "en")
        self.assertEqual(title, "[ACME Ltd] Port scan from 192.168.1.2")
        for text in ("Trap:", "ACME HQ (acme-hq)", "port scan (5 ports)", "445/tcp SMB", "5 (25 log lines)", "MAC 00:11:22:33:44:55"):
            self.assertIn(text, body)
        title, body = notify.render(alert, "it")
        self.assertEqual(title, "[ACME Ltd] Scansione di porte da 192.168.1.2")
        self.assertIn("Tentativi:", body)
        self.assertIn("5 (25 righe di log)", body)

    def test_payload_schema(self):
        _, alert = incident_alert()
        data = notify.payload(alert, "en")
        self.assertEqual(data["schema"], "lantrap.alert/1")
        self.assertEqual(data["kind"], "incident")
        self.assertEqual(data["client"], {"id": "acme", "name": "ACME Ltd"})
        self.assertEqual(data["incident"]["attempts"], 5)
        json.dumps(data)

    def test_heartbeat_and_test_texts(self):
        cfg = parse_config(base_raw())
        trap, client = cfg.traps["acme-hq"], cfg.clients["acme"]
        title, body = notify.render(Alert("trap_silent", T0, trap, client, details={"last_seen": None, "missing_minutes": 30}), "it")
        self.assertIn("ACME HQ", title)
        self.assertIn("30 minuti", body)
        title, _ = notify.render(Alert("test", T0, None, None), "en")
        self.assertEqual(title, "Test alert")


class Channels(unittest.TestCase):
    def test_webhook_with_signature(self):
        sink = HttpSink()
        self.addCleanup(sink.stop)
        raw = base_raw(grouping={"collect_seconds": 0},
                       notify=[{"name": "hook", "type": "webhook", "url": sink.url, "secret": "s3cret",
                                "headers": {"X-Custom": "yes"}}])
        cfg, alert = incident_alert(raw)
        (record,) = notify.deliver(alert, notify.build_notifiers(cfg), cfg)
        self.assertEqual(record["status"], "sent", record["error"])
        req = sink.requests[0]
        body = req["body"]
        expected = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        self.assertEqual(req["headers"]["X-Lantrap-Signature"], expected)
        self.assertEqual(req["headers"]["X-Lantrap-Event"], "incident")
        self.assertEqual(req["headers"]["X-Custom"], "yes")
        self.assertEqual(json.loads(body)["incident"]["lines"], 25)

    def test_google_chat_threads_by_incident(self):
        sink = HttpSink()
        self.addCleanup(sink.stop)
        os.environ["LANTRAP_TEST_CHAT"] = sink.url + "?key=k&token=t"
        self.addCleanup(os.environ.pop, "LANTRAP_TEST_CHAT")
        raw = base_raw(grouping={"collect_seconds": 0}, language="it",
                       notify=[{"name": "chat", "type": "google_chat", "url_env": "LANTRAP_TEST_CHAT"}])
        cfg, alert = incident_alert(raw)
        (record,) = notify.deliver(alert, notify.build_notifiers(cfg), cfg)
        self.assertEqual(record["status"], "sent", record["error"])
        req = sink.requests[0]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(req["path"]).query)
        self.assertEqual(query["threadKey"], [f"lantrap-{alert.incident['id']}"])
        self.assertEqual(query["key"], ["k"])
        self.assertIn("Scansione di porte", json.loads(req["body"])["text"])

    def test_smtp(self):
        smtp = FakeSmtp()
        self.addCleanup(smtp.stop)
        raw = base_raw(grouping={"collect_seconds": 0},
                       notify=[{"name": "mail", "type": "smtp", "host": "127.0.0.1", "port": smtp.port, "security": "none",
                                "from": "alerts@example.com", "to": ["a@example.com", "b@example.com"]}])
        cfg, alert = incident_alert(raw)
        (record,) = notify.deliver(alert, notify.build_notifiers(cfg), cfg)
        self.assertEqual(record["status"], "sent", record["error"])
        msg = email.message_from_bytes(smtp.messages[0], policy=policy.default)
        self.assertEqual(msg["Subject"], "[LAN Trap] [ACME Ltd] Port scan from 192.168.1.2")
        self.assertEqual(msg["X-Lantrap-Kind"], "incident")
        self.assertIn("3389/tcp RDP", msg.get_content())
        self.assertEqual(len(smtp.envelopes[0][1]), 2)

    def test_command(self):
        out = Path(tempfile.mkdtemp()) / "alert.json"
        script = "import sys, pathlib; pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())"
        raw = base_raw(grouping={"collect_seconds": 0},
                       notify=[{"name": "ticket", "type": "command", "argv": [sys.executable, "-c", script, str(out)]}])
        cfg, alert = incident_alert(raw)
        (record,) = notify.deliver(alert, notify.build_notifiers(cfg), cfg)
        self.assertEqual(record["status"], "sent", record["error"])
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["incident"]["id"], alert.incident["id"])

    def test_failures_are_recorded_and_do_not_stop_other_channels(self):
        bad, good = HttpSink(status=500), HttpSink()
        self.addCleanup(bad.stop)
        self.addCleanup(good.stop)
        raw = base_raw(grouping={"collect_seconds": 0}, notify=[
            {"name": "bad", "type": "webhook", "url": bad.url},
            {"name": "missing", "type": "command", "argv": ["lantrap-no-such-command-xyz"]},
            {"name": "good", "type": "webhook", "url": good.url},
        ])
        cfg, alert = incident_alert(raw)
        records = {r["channel"]: r for r in notify.deliver(alert, notify.build_notifiers(cfg), cfg)}
        self.assertEqual(records["bad"]["status"], "failed")
        self.assertIn("HTTP 500", records["bad"]["error"])
        self.assertEqual(len(bad.requests), 3, "two retries")
        self.assertIn("not found", records["missing"]["error"])
        self.assertEqual(records["good"]["status"], "sent")

    def test_filters_by_event_and_client(self):
        sink = HttpSink()
        self.addCleanup(sink.stop)
        raw = base_raw(grouping={"collect_seconds": 0}, notify=[
            {"name": "beta-only", "type": "webhook", "url": sink.url, "clients": ["beta"]},
            {"name": "silent-only", "type": "webhook", "url": sink.url, "events": ["trap_silent"]},
            {"name": "all", "type": "webhook", "url": sink.url},
        ])
        cfg, alert = incident_alert(raw)
        records = notify.deliver(alert, notify.build_notifiers(cfg), cfg)
        self.assertEqual([r["channel"] for r in records], ["all"])
        test = notify.deliver(Alert("test", T0, None, None), notify.build_notifiers(cfg), cfg)
        self.assertEqual(len(test), 3, "a test alert goes to every channel")

    def test_unreadable_certificate_disables_only_that_channel(self):
        raw = base_raw(notify=[
            {"name": "bad-ca", "type": "webhook", "url": "https://example.com/x", "cafile": "missing-ca.pem"},
            {"name": "ok", "type": "webhook", "url": "https://example.com/y"},
        ])
        cfg = parse_config(raw)
        self.assertEqual([n.name for n in notify.build_notifiers(cfg, strict=False)], ["ok"])
        with self.assertRaises(ConfigError):
            notify.build_notifiers(cfg, strict=True)

    def test_long_port_lists_are_shortened(self):
        cfg, alert = incident_alert()
        alert.incident["ports"] = [{"proto": "tcp", "port": p, "service": None, "attempts": 1, "lines": 1} for p in range(1, 101)]
        alert.incident["ports_untracked"] = 7
        _, body = notify.render(alert, "it")
        self.assertIn("+70", body)
        self.assertIn("(+7 righe su altre porte)", body)

    def test_missing_secret(self):
        raw = base_raw(notify=[{"name": "chat", "type": "google_chat", "url_env": "LANTRAP_TEST_UNSET_VAR"}])
        cfg = parse_config(raw)
        with self.assertRaises(ConfigError):
            notify.build_notifiers(cfg, strict=True)
        self.assertEqual(notify.build_notifiers(cfg, strict=False), [])


if __name__ == "__main__":
    unittest.main()
