import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from lantrap import i18n, service
from lantrap.cli import main
from lantrap.config import ConfigError, load_config, parse_config, save_raw
from lantrap.menu import Item, check_step, menu_step, render
from lantrap.openwrt import box_script

from helpers import DATA, base_raw


def run_cli(*args) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class OpenWrt(unittest.TestCase):
    def config(self, **openwrt):
        raw = base_raw(openwrt={"receiver": "10.99.0.1", **openwrt})
        raw["client"][0]["exclude"].append("aa:bb:cc:00:11:22")
        return parse_config(raw)

    def test_script_contents(self):
        cfg = self.config()
        script = box_script(cfg, cfg.traps["acme-hq"])
        self.assertIn('log prefix "TRAPPOLA: " level warn', script)
        self.assertIn("tcp dport { 21, 23, 139, 445, 1433, 3306, 3389, 5900, 8080 }", script)
        self.assertIn("ct state new limit rate 60/minute burst 20 packets", script)
        self.assertIn("elements = { 192.168.1.96/30, 192.168.1.250 }", script)
        self.assertNotIn("aa:bb:cc:00:11:22", script.split("EOF")[1], "MACs are not put in the nft set")
        self.assertIn("MAC exclusions are applied by the receiver only", script)
        self.assertIn("uci set system.@system[0].log_ip=10.99.0.1", script)
        self.assertIn("uci set system.@system[0].log_hostname=trap-acme", script)
        self.assertIn("*/10 * * * * logger -t lantrap heartbeat", script)
        self.assertIn("if ! fw4 check; then", script)
        self.assertIn("mv /tmp/10-lantrap.nft.previous /etc/nftables.d/10-lantrap.nft", script)
        self.assertIn("\nfw4 reload\n", script)
        self.assertNotIn("wireguard", script)
        self.assertNotIn("ip6 saddr", script)

    def test_ipv6_and_no_exclusions(self):
        cfg = self.config(ipv6=True)
        script = box_script(cfg, cfg.traps["beta-1"])
        self.assertIn("ip6 saddr != @lantrap_exclude6", script)
        self.assertNotIn("elements", script.split("set lantrap_exclude6")[1].split("}")[0])

    def test_wireguard(self):
        raw = base_raw(wireguard={"endpoint": "vpn.example.com:51820", "public_key": "PUBKEY=", "receiver_ip": "10.99.0.1"})
        raw["trap"][0]["tunnel_ip"] = "10.99.0.11"
        cfg = parse_config(raw)
        script = box_script(cfg, cfg.traps["acme-hq"])
        self.assertIn("apk add wireguard-tools kmod-wireguard", script)
        self.assertIn("uci add_list network.lantrap.addresses=10.99.0.11/32", script)
        self.assertIn("uci set network.lantrap_receiver.endpoint_host=vpn.example.com", script)
        self.assertIn("uci add_list network.lantrap_receiver.allowed_ips=10.99.0.1/32", script)
        self.assertIn("uci set system.@system[0].log_ip=10.99.0.1", script)
        self.assertIn("AllowedIPs = 10.99.0.11/32", script)

    def test_needs_a_receiver_address(self):
        cfg = parse_config(base_raw())
        with self.assertRaises(ConfigError):
            box_script(cfg, cfg.traps["acme-hq"])

    def test_values_are_shell_quoted(self):
        cfg = self.config(ntp_servers=["pool.ntp.org", "a'b"])
        script = box_script(cfg, cfg.traps["acme-hq"])
        self.assertIn("uci add_list system.ntp.server='a'\"'\"'b'", script)


class Menu(unittest.TestCase):
    def test_keys(self):
        self.assertEqual(menu_step(0, 3, "up"), (2, None))
        self.assertEqual(menu_step(2, 3, "down"), (0, None))
        self.assertEqual(menu_step(0, 3, "3"), (2, None))
        self.assertEqual(menu_step(0, 3, "7"), (0, None))
        self.assertEqual(menu_step(1, 3, "enter"), (1, "enter"))
        self.assertEqual(menu_step(1, 3, "esc"), (1, "esc"))

    def test_checklist(self):
        states = [False, True]
        self.assertEqual(check_step(0, states, "space"), (0, None))
        self.assertEqual(states, [True, True])
        self.assertEqual(check_step(0, states, "down"), (1, None))

    def test_render(self):
        items = [Item("a", "First", "A long description " * 5, "info line"), Item("b", "Second", "B")]
        text = render(["HEADER"], "Title", items, 1, "help", [True, False])
        self.assertIn("HEADER", text)
        self.assertIn("1)  [x] First", text)
        self.assertIn("> 2)  [ ] Second", text)
        self.assertIn("help", text)

    def test_english_by_default_italian_on_request(self):
        from lantrap.config import default_raw
        from lantrap.menu import App
        path = Path(tempfile.mkdtemp(prefix="lantrap-lang-")) / "lantrap.toml"
        save_raw(default_raw(), path)
        app = App(path)
        self.assertTrue(app.load())
        self.assertEqual(app.lang, "en")
        self.assertEqual(app.tr("menu.main"), "Choose an action:")
        self.assertEqual(App(path, "it").tr("menu.main"), "Scegli un'azione:")

    def test_language_is_chosen_from_the_menu(self):
        from unittest import mock
        from lantrap.config import default_raw
        from lantrap.menu import App
        path = Path(tempfile.mkdtemp(prefix="lantrap-lang-")) / "lantrap.toml"
        save_raw(default_raw(), path)
        keys = iter(["8", "enter", "2", "enter", "8", "enter", "esc", "9", "enter"])
        with mock.patch("lantrap.menu.read_key", lambda: next(keys)), contextlib.redirect_stdout(io.StringIO()):
            app = App(path)
            self.assertEqual(app.main(), 0)
        self.assertEqual(app.lang, "it")
        self.assertEqual(load_config(path).language, "it")

    def test_first_start_asks_the_language_with_english_preselected(self):
        from unittest import mock
        from lantrap.menu import App
        path = Path(tempfile.mkdtemp(prefix="lantrap-first-")) / "lantrap.toml"
        keys = iter(["enter", "9", "enter"])  # Enter keeps English, then exit
        with mock.patch("lantrap.menu.read_key", lambda: next(keys)), \
                mock.patch("builtins.input", lambda prompt="": ""), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(App(path).main(), 0)
        self.assertEqual(load_config(path).language, "en")
        self.assertIn("English (default)", out.getvalue())
        self.assertIn("Choose an action:", out.getvalue())

    def test_translations_are_complete(self):
        en, it = set(i18n.TEXT["en"]), set(i18n.TEXT["it"])
        self.assertEqual(en - it, set())
        self.assertEqual(it - en, set())
        for key in en:
            self.assertEqual(set(re.findall(r"{(\w+)}", i18n.TEXT["en"][key])), set(re.findall(r"{(\w+)}", i18n.TEXT["it"][key])), key)


class MenuFlow(unittest.TestCase):
    """Drive the menu with scripted keys and answers, then check the saved configuration."""

    def run_menu(self, raw, keys, answers):
        from unittest import mock
        from lantrap.menu import App
        path = Path(tempfile.mkdtemp(prefix="lantrap-menu-")) / "lantrap.toml"
        save_raw(raw, path)
        keys, answers = iter(keys), iter(answers)
        with mock.patch("lantrap.menu.read_key", lambda: next(keys)), \
                mock.patch("builtins.input", lambda prompt="": next(answers)), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(App(path).main(), 0)
        self.assertIsNone(next(keys, None), "every scripted key was used")
        self.assertIsNone(next(answers, None), "every scripted answer was used")
        return load_config(path)

    def test_configure_what_you_want(self):
        keys = [
            "4", "enter",                           # Settings
            "3", "enter",                           # Alert channels
            "1", "enter",                           # + Add
            "3", "enter",                           # type: webhook
            "7", "enter", "3", "enter",             # URL: type it here
            "3", "enter",                           # Events
            "space", "down", "space", "enter",      # tick the first two
            *["down"] * 9, "enter",                 # Save
            "esc",                                  # back to Settings
            "5", "enter",                           # Grouping
            "1", "enter",                           # collect_seconds
            "8", "enter",                           # Save
            "1", "enter",                           # General
            "5", "enter",                           # store_other: toggle
            "2", "enter",                           # prefixes
            "6", "enter",                           # Save
            "esc",                                  # main menu
            "3", "enter",                           # Clients
            "3", "enter",                           # + Add (after acme, beta)
            "1", "enter", "2", "enter", "3", "enter",  # id, name, exclusions
            "4", "enter",                           # Save
            "3", "enter",                           # gamma
            "2", "enter",                           # Traps of this client
            "1", "enter",                           # + Add
            "1", "enter",                           # id
            "4", "enter",                           # sender addresses
            "7", "enter", "3", "enter",             # heartbeat: off
            "9", "enter",                           # Save
            "esc", "esc",                           # back to the client list
            "2", "enter",                           # beta
            "3", "enter", "2", "enter",             # Remove, Yes
            "esc",                                  # main menu
            "8", "enter", "2", "enter",             # Language / Lingua: Italiano
            "9", "enter",                           # exit
        ]
        answers = [
            "https://example.com/hook",
            "30",
            "LANTRAP:, TRAPPOLA:",
            "gamma", "Gamma Spa", "192.168.5.5, 00:11:22:33:44:66",
            "gamma-1", "10.99.0.50",
        ]
        cfg = self.run_menu(base_raw(), keys, answers)
        (hook,) = cfg.notifiers
        self.assertEqual((hook.type, hook.options["url"], hook.events), ("webhook", "https://example.com/hook", ("incident", "incident_update")))
        self.assertEqual(cfg.grouping.collect_seconds, 30)
        self.assertEqual(cfg.grouping.quiet_minutes, 15, "settings not touched keep their default")
        self.assertTrue(cfg.store_other)
        self.assertEqual(cfg.prefixes, ("LANTRAP:", "TRAPPOLA:"))
        self.assertEqual(cfg.clients["gamma"].name, "Gamma Spa")
        self.assertEqual(cfg.clients["gamma"].exclude.entries, ("192.168.5.5", "00:11:22:33:44:66"))
        self.assertEqual(cfg.traps["gamma-1"].client, "gamma")
        self.assertEqual(cfg.traps["gamma-1"].source.entries, ("10.99.0.50",))
        self.assertIs(cfg.traps["gamma-1"].heartbeat, False)
        self.assertNotIn("beta", cfg.clients)
        self.assertEqual(set(cfg.traps), {"acme-hq", "gamma-1"}, "the traps of the removed client go with it")
        self.assertEqual(cfg.language, "it")

    def test_invalid_value_is_refused_and_nothing_is_saved(self):
        keys = [
            "4", "enter", "5", "enter",             # Settings > Grouping
            "2", "enter",                           # quiet_minutes
            "8", "enter",                           # Save (nothing changed)
            "5", "enter", "2", "enter",             # Grouping again, quiet_minutes
            "9", "enter",                           # Cancel
            "esc", "9", "enter",
        ]
        cfg = self.run_menu(base_raw(), keys, ["0", "45"])
        self.assertEqual(cfg.grouping.quiet_minutes, 15)


class Cli(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="lantrap-cli-"))
        self.path = self.dir / "lantrap.toml"

    def test_init_check(self):
        self.assertEqual(run_cli("-c", str(self.path), "init")[0], 0)
        self.assertEqual(run_cli("-c", str(self.path), "init")[0], 1)
        code, out, _ = run_cli("-c", str(self.path), "check")
        self.assertEqual(code, 0)
        self.assertIn("udp://0.0.0.0:5514", out)

    def test_missing_and_invalid_configuration(self):
        self.assertEqual(run_cli("-c", str(self.dir / "none.toml"), "check")[0], 2)
        self.path.write_text("[[trap]]\nid='x'\n", encoding="utf-8")
        code, _, err = run_cli("-c", str(self.path), "check")
        self.assertEqual(code, 2)
        self.assertIn("trap[0].client", err)

    def test_import_real_logread_lines(self):
        save_raw(base_raw(), self.path)
        code, out, _ = run_cli("-c", str(self.path), "import", str(DATA / "logread-trappola.txt"), "--trap", "acme-hq")
        self.assertEqual(code, 0)
        self.assertIn("[ACME Ltd] Port scan from 192.168.1.2", out)
        self.assertIn("5 (25 log lines)", out)
        self.assertIn("lines: 26, trap hits: 25, excluded: 0, other: 1", out)
        code, out, _ = run_cli("-c", str(self.path), "--lang", "it", "import", str(DATA / "logread-trappola.txt"), "--trap", "acme-hq")
        self.assertIn("Scansione di porte da 192.168.1.2", out)

    def test_import_with_exclusion(self):
        raw = base_raw()
        raw["client"][0]["exclude"].append("192.168.1.2")
        save_raw(raw, self.path)
        code, out, _ = run_cli("-c", str(self.path), "import", str(DATA / "logread-trappola.txt"), "--trap", "acme-hq")
        self.assertIn("trap hits: 0, excluded: 25", out)
        self.assertNotIn("Port scan", out)

    def test_import_save_then_status(self):
        raw = base_raw(store=[{"type": "sqlite", "path": "db.sqlite3"}])
        save_raw(raw, self.path)
        self.assertEqual(run_cli("-c", str(self.path), "import", str(DATA / "logread-trappola.txt"), "--trap", "acme-hq", "--save")[0], 0)
        code, out, _ = run_cli("-c", str(self.path), "incidents", "--json")
        self.assertEqual(code, 0)
        (inc,) = json.loads(out)
        self.assertEqual((inc["attempts"], inc["lines"], inc["status"]), (5, 25, "closed"))
        code, out, _ = run_cli("-c", str(self.path), "status")
        self.assertEqual(code, 0)
        self.assertIn("acme-hq", out)

    def test_openwrt_and_service(self):
        save_raw(base_raw(openwrt={"receiver": "10.99.0.1"}), self.path)
        code, out, _ = run_cli("-c", str(self.path), "openwrt", "acme-hq")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("#!/bin/sh"))
        self.assertEqual(run_cli("-c", str(self.path), "openwrt", "nope")[0], 1)
        code, out, _ = run_cli("-c", str(self.path), "service", "systemd")
        self.assertIn("ExecStart=", out)
        self.assertIn("CapabilityBoundingSet=\n", out, "port 5514 needs no privilege")
        code, out, _ = run_cli("-c", str(self.path), "service", "windows", "--write")
        self.assertIn("schtasks /Create", out)
        self.assertTrue((self.dir / "lantrap-service.cmd").exists())

    def test_test_alert_without_channels(self):
        save_raw(base_raw(), self.path)
        self.assertEqual(run_cli("-c", str(self.path), "test-alert")[0], 1)

    def test_systemd_unit_for_privileged_port(self):
        cfg = load_config(self._save(base_raw(listen=[{"protocol": "udp", "port": 514}])))
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", service.systemd_unit(cfg))

    def _save(self, raw):
        save_raw(raw, self.path)
        return self.path


if __name__ == "__main__":
    unittest.main()
