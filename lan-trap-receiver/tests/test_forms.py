"""The menu forms must reach every setting the configuration accepts."""

import dataclasses
import tomllib
import unittest
from pathlib import Path

from lantrap import forms
from lantrap.config import Grouping, Heartbeat, OpenWrtConf, WireGuardConf, parse_config

from helpers import base_raw

# every key the parser reads, by section (kept in step with config.parse_config)
ACCEPTED = {
    "top": {"language", "prefixes", "unknown_sources", "store_excluded", "store_other", "exclude"},
    "listen": {"protocol", "address", "port", "allow", "certfile", "keyfile", "cafile"},
    "store": {"type", "path", "directory", "retention_days"},
    "notify": {"name", "enabled", "events", "clients", "language", "timeout"},
    "smtp": {"host", "security", "port", "username", "password", "from", "to", "subject_prefix"},
    "google_chat": {"url", "thread_by_incident"},
    "webhook": {"url", "secret", "headers", "headers_env", "cafile"},
    "command": {"argv"},
    "client": {"id", "name", "exclude"},
    "trap": {"id", "name", "client", "source", "hostname", "exclude", "heartbeat", "tunnel_ip"},
}


def keys(fields):
    return {f.key for f in fields}


class Coverage(unittest.TestCase):
    def test_every_accepted_setting_has_a_field(self):
        schema = {
            "top": keys(forms.GENERAL) | keys(forms.GLOBAL_EXCLUDE),
            "listen": keys(forms.LISTEN),
            "store": keys(forms.STORE),
            "notify": keys(forms.NOTIFY_COMMON),
            "client": keys(forms.CLIENT),
            "trap": keys(forms.TRAP),
            **{kind: keys(fields) for kind, fields in forms.NOTIFY_BY_TYPE.items()},
        }
        for section, accepted in ACCEPTED.items():
            with self.subTest(section=section):
                self.assertEqual(accepted - schema[section], set())

    def test_every_table_setting_has_a_field(self):
        for conf, fields in ((Grouping, forms.GROUPING), (Heartbeat, forms.HEARTBEAT),
                             (OpenWrtConf, forms.OPENWRT), (WireGuardConf, forms.WIREGUARD)):
            with self.subTest(table=conf.__name__):
                self.assertEqual({f.name for f in dataclasses.fields(conf)} - keys(fields), set())

    def test_example_configuration_is_covered(self):
        raw = tomllib.loads((Path(__file__).resolve().parent.parent / "config.example.toml").read_text(encoding="utf-8"))
        tables = {"grouping": forms.GROUPING, "heartbeat": forms.HEARTBEAT, "openwrt": forms.OPENWRT, "wireguard": forms.WIREGUARD}
        lists = {"listen": forms.LISTEN, "store": forms.STORE, "client": forms.CLIENT, "trap": forms.TRAP}
        top = keys(forms.GENERAL) | keys(forms.GLOBAL_EXCLUDE)
        for key, value in raw.items():
            if key in tables:
                self.assertEqual(set(value) - keys(tables[key]), set(), key)
            elif key in lists:
                for entry in value:
                    self.assertEqual(set(entry) - keys(lists[key]), set(), key)
            elif key == "notify":
                for entry in value:
                    known = keys(forms.notify_fields(entry)) | {"type"}
                    known |= {f"{f.key}{s}" for f in forms.notify_fields(entry) if f.kind == "secret" for s in ("_env", "_file")}
                    self.assertEqual(set(entry) - known, set(), entry.get("name"))
            else:
                self.assertIn(key, top)

    def test_defaults_shown_match_the_parser(self):
        cfg = parse_config({})
        for conf, fields in ((cfg.grouping, forms.GROUPING), (cfg.heartbeat, forms.HEARTBEAT), (cfg.openwrt, forms.OPENWRT)):
            for f in fields:
                expected = getattr(conf, f.key)
                default = list(f.default) if isinstance(f.default, list) else f.default
                expected = list(expected) if isinstance(expected, tuple) else expected
                if default is None:
                    expected = expected or None  # "not set" in the form, empty in the parsed configuration
                with self.subTest(field=f.key):
                    self.assertEqual(default, expected)


class Values(unittest.TestCase):
    def field(self, fields, key):
        return next(f for f in fields if f.key == key)

    def test_display_default_and_set(self):
        f = self.field(forms.GROUPING, "collect_seconds")
        self.assertEqual(forms.display(f, {}, "en"), "60  (default)")
        self.assertEqual(forms.display(f, {}, "it"), "60  (predefinito)")
        self.assertEqual(forms.display(f, {"collect_seconds": 30}, "en"), "30")
        b = self.field(forms.GENERAL, "store_other")
        self.assertEqual(forms.display(b, {"store_other": True}, "it"), "sì")

    def test_parse_and_limits(self):
        f = self.field(forms.GROUPING, "quiet_minutes")
        self.assertEqual(forms.parse_text(f, "20"), 20)
        for bad in ("0", "abc", "99999"):
            with self.assertRaises(ValueError):
                forms.parse_text(f, bad)
        ports = self.field(forms.OPENWRT, "ports")
        self.assertEqual(forms.parse_text(ports, "21, 445"), [21, 445])
        with self.assertRaises(ValueError):
            forms.parse_text(ports, "21, x")
        headers = forms.NOTIFY_BY_TYPE["webhook"][2]
        self.assertEqual(forms.parse_text(headers, "Authorization: Bearer x; X-A: b"), {"Authorization": "Bearer x", "X-A": "b"})
        argv = forms.NOTIFY_BY_TYPE["command"][0]
        self.assertEqual(forms.parse_text(argv, '/usr/bin/tool --queue "security team"'), ["/usr/bin/tool", "--queue", "security team"])
        prefixes = self.field(forms.GENERAL, "prefixes")
        self.assertEqual(forms.parse_text(prefixes, "*"), [])

    def test_apply_and_clear(self):
        entry = {}
        f = self.field(forms.GENERAL, "prefixes")
        forms.apply(entry, f, [])
        self.assertEqual(entry, {"prefixes": []}, "an empty list is a real value here (any prefix)")
        forms.apply(entry, f, None)
        self.assertEqual(entry, {})

    def test_secret_modes(self):
        entry = {"url": "https://x"}
        forms.set_secret(entry, "url", "env", "HOOK_URL")
        self.assertEqual(entry, {"url_env": "HOOK_URL"})
        self.assertEqual(forms.secret_mode(entry, "url"), ("env", "HOOK_URL"))
        f = forms.NOTIFY_BY_TYPE["smtp"][4]
        self.assertEqual(forms.display(f, {"password": "s3cret"}, "en"), "******")
        forms.set_secret(entry, "url", None, None)
        self.assertEqual(entry, {})

    def test_visibility_follows_the_entry(self):
        self.assertNotIn("certfile", keys(forms.visible(forms.LISTEN, {"protocol": "udp"})))
        self.assertIn("certfile", keys(forms.visible(forms.LISTEN, {"protocol": "tls"})))
        self.assertIn("directory", keys(forms.visible(forms.STORE, {"type": "csv"})))
        self.assertNotIn("path", keys(forms.visible(forms.STORE, {"type": "csv"})))

    def test_summaries(self):
        raw = base_raw()
        self.assertEqual(forms.summary("listen", raw["listen"][0], "en"), "udp://0.0.0.0:5514")
        self.assertIn("env HOOK", forms.summary("notify", {"name": "chat", "type": "google_chat", "url_env": "HOOK"}, "en"))
        self.assertIn("(spento)", forms.summary("notify", {"name": "m", "type": "smtp", "enabled": False}, "it"))


if __name__ == "__main__":
    unittest.main()
