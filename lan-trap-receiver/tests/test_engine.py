import random
import unittest
from datetime import timedelta

from lantrap.config import parse_config
from lantrap.engine import Engine, clock_plausible
from lantrap.syslogparse import parse_syslog

from helpers import T0, base_raw, logd_network, real_line, windows_scan

ACME = "10.99.0.11"   # tunnel address of trap acme-hq
BETA = "10.99.0.42"   # inside 10.99.0.0/24 of trap beta-1


def engine(**overrides):
    raw = base_raw(**overrides)
    return Engine(parse_config(raw), T0)


def feed(eng, pairs, peer=ACME, hostname="trap-acme"):
    return [eng.receive(peer, parse_syslog(logd_network(line, hostname), when), when) for when, line in pairs]


class Grouping(unittest.TestCase):
    def test_windows_retries_make_one_attempt_per_port_and_one_alert(self):
        eng = engine()
        results = feed(eng, windows_scan())
        self.assertEqual([r.status for r in results], ["hit"] * 25)
        self.assertEqual(len(eng.incidents), 1)
        inc = next(iter(eng.incidents.values()))
        self.assertEqual((inc.lines, inc.attempts, len(inc.ports)), (25, 5, 5))
        self.assertEqual(inc.classification(3), "port_scan")
        self.assertEqual(sum(r.hit.new_attempt for r in results), 5)

        alerts, _ = eng.tick(T0 + timedelta(seconds=30))
        self.assertEqual(alerts, [], "collect window not over yet")
        alerts, _ = eng.tick(T0 + timedelta(seconds=61))
        self.assertEqual([a.kind for a in alerts], ["incident"])
        snap = alerts[0].incident
        self.assertEqual((snap["attempts"], snap["lines"], snap["source_ip"]), (5, 25, "192.168.1.2"))
        self.assertEqual([p["port"] for p in snap["ports"]], [21, 23, 445, 3389, 8080])
        self.assertEqual(snap["ports"][2]["service"], "SMB")
        self.assertEqual(snap["client_name"], "ACME Ltd")
        self.assertEqual(snap["source_macs"], ["00:11:22:33:44:55"])

        alerts, closed = eng.tick(T0 + timedelta(minutes=5))
        self.assertEqual((alerts, closed), ([], []))
        alerts, closed = eng.tick(T0 + timedelta(minutes=16))
        self.assertEqual(alerts, [], "no alert on close unless notify_on_close")
        self.assertEqual([c.status for c in closed], ["closed"])
        self.assertEqual(eng.incidents, {})

    def test_single_port_is_a_connection_attempt(self):
        eng = engine(grouping={"collect_seconds": 0})
        feed(eng, windows_scan(ports=(3389,)))
        alerts, _ = eng.tick(T0 + timedelta(seconds=5))
        self.assertEqual(alerts[0].incident["classification"], "connection_attempt")

    def test_same_port_later_is_a_new_attempt(self):
        eng = engine()
        feed(eng, [(T0, real_line(dport=445)), (T0 + timedelta(seconds=30), real_line(dport=445, sport=1))])
        inc = next(iter(eng.incidents.values()))
        self.assertEqual((inc.attempts, inc.lines), (2, 2))

    def test_quiet_period_starts_a_new_incident(self):
        eng = engine(grouping={"collect_seconds": 0, "quiet_minutes": 15})
        feed(eng, [(T0, real_line())])
        first = next(iter(eng.incidents.values())).id
        later = T0 + timedelta(minutes=20)
        feed(eng, [(later, real_line())])
        alerts, closed = eng.tick(later)
        self.assertEqual([c.id for c in closed], [first])
        self.assertNotEqual(next(iter(eng.incidents.values())).id, first)
        self.assertEqual([a.kind for a in alerts], ["incident", "incident"])

    def test_separate_sources_and_traps_are_separate_incidents(self):
        eng = engine()
        feed(eng, [(T0, real_line(src="192.168.1.2")), (T0, real_line(src="192.168.1.3"))])
        feed(eng, [(T0, real_line(src="192.168.1.2"))], peer=BETA, hostname="x")
        self.assertEqual(len(eng.incidents), 3)

    def test_reminder_while_activity_goes_on(self):
        eng = engine(grouping={"collect_seconds": 0, "reminder_minutes": 10, "quiet_minutes": 15})
        feed(eng, [(T0, real_line())])
        self.assertEqual([a.kind for a in eng.tick(T0)[0]], ["incident"])
        t = T0
        kinds = []
        for minute in range(1, 25):
            t = T0 + timedelta(minutes=minute)
            feed(eng, [(t, real_line(dport=1000 + minute))])
            kinds += [a.kind for a in eng.tick(t)[0]]
        self.assertEqual(kinds, ["incident_update", "incident_update"])

    def test_notify_on_close(self):
        eng = engine(grouping={"collect_seconds": 0, "notify_on_close": True})
        feed(eng, [(T0, real_line())])
        eng.tick(T0)
        alerts, _ = eng.tick(T0 + timedelta(minutes=16))
        self.assertEqual([a.kind for a in alerts], ["incident_closed"])
        self.assertEqual(alerts[0].incident["status"], "closed")

    def test_incident_shorter_than_collect_window_still_alerts_once(self):
        eng = engine(grouping={"collect_seconds": 3600, "quiet_minutes": 1})
        feed(eng, [(T0, real_line())])
        alerts, closed = eng.tick(T0 + timedelta(minutes=2))
        self.assertEqual([a.kind for a in alerts], ["incident"])
        self.assertEqual(alerts[0].incident["status"], "closed")

    def test_hourly_alert_limit_delays_but_never_drops(self):
        eng = engine(grouping={"collect_seconds": 0, "max_alerts_per_hour": 1, "quiet_minutes": 15},
                     heartbeat={"enabled": False})

        def incident_alerts(at):
            return [a for a in eng.tick(at)[0] if a.kind.startswith("incident")]

        feed(eng, [(T0, real_line(src=f"192.168.1.{i}")) for i in (10, 11, 12)])
        self.assertEqual([a.incident["source_ip"] for a in incident_alerts(T0)], ["192.168.1.10"])
        self.assertEqual(incident_alerts(T0 + timedelta(minutes=10)), [])
        # another client has its own budget
        t = T0 + timedelta(minutes=10)
        feed(eng, [(t, real_line(src="192.168.1.10"))], peer=BETA, hostname="beta")
        self.assertEqual([a.client.id for a in incident_alerts(t)], ["beta"])
        # the waiting incidents end meanwhile (quiet period) and still get their alert, one per hour
        self.assertEqual(incident_alerts(T0 + timedelta(minutes=20)), [])
        first = incident_alerts(T0 + timedelta(hours=1, seconds=1))
        self.assertEqual([(a.incident["source_ip"], a.incident["status"], a.waiting) for a in first],
                         [("192.168.1.11", "closed", 1)])
        second = incident_alerts(T0 + timedelta(hours=2, seconds=2))
        self.assertEqual([(a.incident["source_ip"], a.waiting) for a in second], [("192.168.1.12", 0)])

    def test_pending_alerts_at_shutdown(self):
        eng = engine(grouping={"collect_seconds": 60})
        feed(eng, windows_scan())
        self.assertEqual([a.kind for a in eng.tick(T0 + timedelta(seconds=30))[0]], [])
        pending = eng.pending_alerts(T0 + timedelta(seconds=30))
        self.assertEqual([(a.kind, a.incident["lines"]) for a in pending], [("incident", 25)])
        self.assertEqual(eng.pending_alerts(T0 + timedelta(seconds=31)), [], "only once")

    def test_floods_are_bounded(self):
        from lantrap import engine as engine_module
        eng = engine(unknown_sources="drop")
        lines = [(T0, real_line(dport=1 + i, sport=7)) for i in range(engine_module.MAX_PORTS_PER_INCIDENT + 50)]
        feed(eng, lines)
        inc = next(iter(eng.incidents.values()))
        self.assertEqual(len(inc.ports), engine_module.MAX_PORTS_PER_INCIDENT)
        self.assertEqual(inc.ports_untracked, 50)
        self.assertEqual(inc.lines, len(lines))
        for i in range(engine_module.MAX_UNKNOWN_SENDERS + 10):
            eng.receive(f"172.16.{i // 250}.{i % 250}", parse_syslog("<14>Oct 23 14:01:02 x y: z", T0), T0)
        self.assertEqual(len(eng.unknown), engine_module.MAX_UNKNOWN_SENDERS)

    def test_invariants_on_random_traffic(self):
        rng = random.Random(7)
        eng = engine(grouping={"collect_seconds": 0, "retry_seconds": 3})
        t = T0
        for _ in range(500):
            t += timedelta(seconds=rng.choice((0, 0.5, 1, 4, 30)))
            line = real_line(src=f"192.168.1.{rng.randint(2, 6)}", dport=rng.choice((21, 445, 3389)), sport=rng.randint(1, 3))
            feed(eng, [(t, line)])
        for inc in eng.incidents.values():
            self.assertEqual(inc.lines, sum(p.lines for p in inc.ports.values()))
            self.assertEqual(inc.attempts, sum(p.attempts for p in inc.ports.values()))
            self.assertLessEqual(len(inc.ports), inc.attempts)
            self.assertLessEqual(inc.attempts, inc.lines)


class Exclusions(unittest.TestCase):
    def test_scopes(self):
        eng = engine()
        cases = {
            real_line(src="192.168.1.97"): "trap:192.168.1.96/30",
            real_line(src="192.168.1.250"): "client:192.168.1.250",
            real_line(src="192.168.1.30").replace("00:11:22:33:44:55", "aa:aa:aa:aa:aa:aa"): "global:aa:aa:aa:aa:aa:aa",
        }
        for line, reason in cases.items():
            with self.subTest(reason=reason):
                (res,) = feed(eng, [(T0, line)])
                self.assertEqual(res.status, "excluded")
                self.assertTrue(res.hit.excluded)
                self.assertEqual(res.hit.exclude_reason, reason)
        self.assertEqual(eng.incidents, {})

    def test_client_exclusion_does_not_leak_to_other_clients(self):
        eng = engine()
        (res,) = feed(eng, [(T0, real_line(src="192.168.1.250"))], peer=BETA, hostname="beta")
        self.assertEqual(res.status, "hit")

    def test_reload_applies_new_exclusions(self):
        eng = engine()
        raw = base_raw()
        raw["client"][0]["exclude"].append("192.168.1.2")
        eng.reload(parse_config(raw))
        (res,) = feed(eng, [(T0, real_line())])
        self.assertEqual(res.status, "excluded")


class Identity(unittest.TestCase):
    def test_source_address_and_hostname(self):
        eng = engine()
        self.assertEqual(eng.identify(ACME, "trap-acme").id, "acme-hq")
        self.assertIsNone(eng.identify(ACME, "someone-else"), "no fallback to the broader network of another client")
        self.assertEqual(eng.identify(BETA, None).id, "beta-1")
        self.assertIsNone(eng.identify("172.16.0.1", "trap-acme"))

    def test_hostname_only_trap(self):
        raw = base_raw()
        raw["trap"].append({"id": "gamma", "client": "beta", "hostname": "gamma-box"})
        eng = Engine(parse_config(raw), T0)
        self.assertEqual(eng.identify("172.16.0.1", "GAMMA-BOX").id, "gamma")
        self.assertIsNone(eng.identify("172.16.0.1", "other"))
        self.assertEqual(eng.identify(BETA, "gamma-box").id, "beta-1", "a matching source address wins")

    def test_most_specific_source_wins(self):
        raw = base_raw()
        raw["trap"][0]["hostname"] = None
        raw["trap"][0]["source"] = ["10.99.0.11"]
        eng = Engine(parse_config(raw), T0)
        self.assertEqual(eng.identify("10.99.0.11", None).id, "acme-hq")
        self.assertEqual(eng.identify("10.99.0.12", None).id, "beta-1")

    def test_unknown_sender_dropped_or_accepted(self):
        eng = engine()
        (res,) = feed(eng, [(T0, real_line())], peer="172.16.0.9", hostname="stranger")
        self.assertEqual(res.status, "unknown")
        self.assertEqual(eng.unknown["172.16.0.9"].hostname, "stranger")
        eng = engine(unknown_sources="accept")
        (res,) = feed(eng, [(T0, real_line())], peer="172.16.0.9", hostname="stranger")
        self.assertEqual((res.status, res.trap.id, res.trap.client), ("hit", "unknown-172.16.0.9", "unknown"))

    def test_other_prefixes_and_messages_are_not_hits(self):
        eng = engine()
        (res,) = feed(eng, [(T0, real_line().replace("TRAPPOLA:", "reject lan in:"))])
        self.assertEqual(res.status, "other")
        res = eng.receive(ACME, parse_syslog("<14>Oct 23 14:01:02 trap-acme lantrap: heartbeat", T0), T0)
        self.assertEqual(res.status, "other")


class Heartbeat(unittest.TestCase):
    def test_silent_then_back(self):
        eng = engine(heartbeat={"enabled": True, "missing_minutes": 30})
        eng.receive(ACME, parse_syslog("<14>Oct 23 14:01:02 trap-acme lantrap: heartbeat", T0), T0)
        alerts, _ = eng.tick(T0 + timedelta(minutes=20))
        self.assertEqual(alerts, [])
        alerts, _ = eng.tick(T0 + timedelta(minutes=31))
        silent = [a for a in alerts if a.kind == "trap_silent"]
        self.assertEqual({a.trap.id for a in silent}, {"acme-hq", "beta-1"})
        self.assertEqual(eng.tick(T0 + timedelta(minutes=40))[0], [], "only once")
        t = T0 + timedelta(minutes=45)
        res = eng.receive(ACME, parse_syslog("<14>Oct 23 14:46:02 trap-acme lantrap: heartbeat", t), t)
        self.assertEqual([a.kind for a in res.alerts], ["trap_back"])

    def test_trap_added_while_running_is_watched_from_then(self):
        eng = engine(heartbeat={"enabled": True, "missing_minutes": 30})
        for trap_id in ("acme-hq", "beta-1"):
            eng.state(trap_id).last_seen = T0 + timedelta(hours=2)
        raw = base_raw(heartbeat={"enabled": True, "missing_minutes": 30})
        raw["trap"].append({"id": "gamma", "client": "beta", "source": ["10.99.1.5"]})
        eng.reload(parse_config(raw), T0 + timedelta(hours=2))
        alerts, _ = eng.tick(T0 + timedelta(hours=2, minutes=1))
        self.assertEqual(alerts, [], "not 'silent' just because the receiver started long ago")
        alerts, _ = eng.tick(T0 + timedelta(hours=2, minutes=31))
        self.assertIn("gamma", [a.trap.id for a in alerts])

    def test_disabled_globally_or_per_trap(self):
        raw = base_raw(heartbeat={"enabled": False})
        raw["trap"][1]["heartbeat"] = True
        eng = Engine(parse_config(raw), T0)
        alerts, _ = eng.tick(T0 + timedelta(hours=2))
        self.assertEqual([a.trap.id for a in alerts], ["beta-1"])

    def test_clock_check_tolerates_time_zones(self):
        self.assertTrue(clock_plausible(0))
        self.assertTrue(clock_plausible(7200 + 20))
        self.assertTrue(clock_plausible(-3600 * 5.5))
        self.assertFalse(clock_plausible(7200 + 450))
        self.assertFalse(clock_plausible(-86400 * 300))


if __name__ == "__main__":
    unittest.main()
