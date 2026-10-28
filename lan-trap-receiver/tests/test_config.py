import copy
import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path

from lantrap import tomlw
from lantrap.config import (ConfigError, Matcher, default_raw, load_config, parse_config, resolve_secret, save_raw)

from helpers import base_raw


class Toml(unittest.TestCase):
    def test_round_trip(self):
        raw = base_raw()
        raw["notify"] = [{"name": "hook", "type": "webhook", "url": "https://example.com/x?a=1&b=\"q\"",
                          "headers": {"Authorization": "Bearer abc", "X-Two Words": "ok"}, "events": ["incident"]}]
        raw["weird"] = "line1\nline2\t\\ è \x01"
        raw["openwrt"] = {"receiver": "10.99.0.1", "ports": [21, 445], "ipv6": False}
        self.assertEqual(tomllib.loads(tomlw.dumps(raw, "header\nsecond line")), raw)

    def test_top_level_scalars_come_before_tables(self):
        text = tomlw.dumps({"grouping": {"a": 1}, "language": "it"})
        self.assertLess(text.index("language"), text.index("[grouping]"))

    def test_rejects_unsupported_values(self):
        with self.assertRaises(ValueError):
            tomlw.dumps({"x": float("nan")})
        with self.assertRaises(TypeError):
            tomlw.dumps({"x": object()})


class Parsing(unittest.TestCase):
    def test_defaults_are_valid(self):
        cfg = parse_config(default_raw())
        self.assertEqual(cfg.language, "en")
        self.assertEqual(cfg.listeners[0].label, "udp://0.0.0.0:5514")
        self.assertEqual(cfg.stores[0].type, "sqlite")
        self.assertEqual(cfg.grouping.collect_seconds, 60)

    def test_full_example(self):
        cfg = parse_config(base_raw())
        self.assertEqual(set(cfg.traps), {"acme-hq", "beta-1"})
        self.assertEqual(cfg.traps["acme-hq"].hostname, "trap-acme")
        self.assertEqual(cfg.clients["acme"].exclude.match("192.168.1.250"), "192.168.1.250")
        self.assertEqual(cfg.exclude.match(None, "AA-AA-AA-AA-AA-AA"), "aa:aa:aa:aa:aa:aa")

    def test_example_file_in_repository_is_valid(self):
        path = Path(__file__).resolve().parent.parent / "config.example.toml"
        cfg = load_config(path)
        self.assertTrue(cfg.listeners)
        self.assertTrue(cfg.notifiers)

    def test_relative_paths_follow_the_config_file(self):
        d = Path(tempfile.mkdtemp())
        raw = default_raw()
        save_raw(raw, d / "lantrap.toml")
        cfg = load_config(d / "lantrap.toml")
        self.assertEqual(cfg.stores[0].path, d.resolve() / "data" / "lantrap.sqlite3")

    def test_json_format(self):
        d = Path(tempfile.mkdtemp())
        (d / "lantrap.json").write_text(json.dumps(base_raw()), encoding="utf-8")
        cfg = load_config(d / "lantrap.json")
        self.assertEqual(cfg.format, "json")
        self.assertEqual(len(cfg.traps), 2)

    def test_errors_name_the_setting(self):
        cases = [
            ("trap", lambda r: r["trap"].append(dict(r["trap"][0])), "duplicate trap"),
            ("trap", lambda r: r["trap"][0].update(client="nobody"), "unknown client"),
            ("trap", lambda r: r["trap"][0].update(source=[], hostname=None), "set source"),
            ("trap", lambda r: r["trap"][0].update(source=["10.0.0.300"]), "not a valid IP"),
            ("listen", lambda r: r["listen"].append({"protocol": "tls", "port": 6514}), "certfile"),
            ("listen", lambda r: r["listen"].append(dict(r["listen"][0])), "configured twice"),
            ("notify", lambda r: r.update(notify=[{"type": "webhook"}]), "url"),
            ("notify", lambda r: r.update(notify=[{"type": "smtp", "host": "h", "from": "a@b", "to": ["c@d"], "username": "u"}]), "password"),
            ("notify", lambda r: r.update(notify=[{"type": "pager"}]), "must be one of"),
            ("grouping", lambda r: r["grouping"].update(quiet_minutes=0), "between"),
            ("grouping", lambda r: r["grouping"].update(collect_seconds=True), "boolean"),
            ("language", lambda r: r.update(language="fr"), "language"),
            ("client", lambda r: r["client"].append({"id": "bad id!"}), "id must be"),
            ("prefixes", lambda r: r.update(prefixes=['LAN "x":']), "printable ASCII"),
            ("prefixes", lambda r: r.update(prefixes=["X" * 121]), "120 characters"),
            ("tunnel_ip", lambda r: r["trap"][0].update(tunnel_ip="fe80::1%eth0'"), "not an IP address"),
            ("name", lambda r: r["trap"][0].update(name="line\nrm -rf /"), "control characters"),
            ("client name", lambda r: r["client"][0].update(name="a\x1b[2J"), "control characters"),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name, expected=expected):
                raw = copy.deepcopy(base_raw())
                mutate(raw)
                with self.assertRaises(ConfigError) as ctx:
                    parse_config(raw)
                self.assertIn(expected, str(ctx.exception))

    def test_disabled_notifier_is_ignored(self):
        raw = base_raw(notify=[{"type": "webhook", "url": "https://x", "enabled": False}])
        self.assertEqual(parse_config(raw).notifiers, [])

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_new_file_is_private_and_existing_mode_is_kept(self):
        d = Path(tempfile.mkdtemp())
        path = d / "lantrap.toml"
        save_raw(base_raw(), path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        os.chmod(path, 0o640)
        save_raw(base_raw(), path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_save_is_atomic_and_validates(self):
        d = Path(tempfile.mkdtemp())
        path = d / "lantrap.toml"
        save_raw(base_raw(), path)
        before = path.read_text(encoding="utf-8")
        bad = base_raw()
        bad["trap"][0]["client"] = "nobody"
        with self.assertRaises(ConfigError):
            save_raw(bad, path)
        self.assertEqual(path.read_text(encoding="utf-8"), before)


class Matching(unittest.TestCase):
    def test_addresses_networks_macs(self):
        m = Matcher.parse(["10.0.0.5", "192.168.0.0/24", "fd00::/64", "00:11:22:33:44:55"], "x")
        self.assertEqual(m.match("10.0.0.5"), "10.0.0.5")
        self.assertEqual(m.match("192.168.0.77"), "192.168.0.0/24")
        self.assertEqual(m.match("fd00::1"), "fd00::/64")
        self.assertEqual(m.match("8.8.8.8", "00:11:22:33:44:55"), "00:11:22:33:44:55")
        self.assertIsNone(m.match("8.8.8.8", "00:11:22:33:44:56"))
        self.assertEqual(m.best_prefix("192.168.0.1"), 24)
        self.assertEqual(m.best_prefix("1.1.1.1"), -1)


class Secrets(unittest.TestCase):
    def test_inline_env_file(self):
        d = Path(tempfile.mkdtemp())
        (d / "secret.txt").write_text("from-file\n", encoding="utf-8")
        os.environ["LANTRAP_TEST_SECRET"] = "from-env"
        try:
            self.assertEqual(resolve_secret({"url": "inline"}, "url", d), "inline")
            self.assertEqual(resolve_secret({"url_env": "LANTRAP_TEST_SECRET"}, "url", d), "from-env")
            self.assertEqual(resolve_secret({"url_file": "secret.txt"}, "url", d), "from-file")
            self.assertIsNone(resolve_secret({}, "url", d, required=False))
            with self.assertRaises(ConfigError):
                resolve_secret({"url_env": "LANTRAP_TEST_MISSING"}, "url", d)
        finally:
            del os.environ["LANTRAP_TEST_SECRET"]


if __name__ == "__main__":
    unittest.main()
