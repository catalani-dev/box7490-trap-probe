import unittest
from datetime import datetime, timezone

from lantrap.syslogparse import (FramingError, StreamFramer, match_prefix, parse_netfilter, parse_syslog,
                                 split_datagram)

from helpers import logd_network, real_line

NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)


class RealFormat(unittest.TestCase):
    def test_line_as_seen_with_logread(self):
        msg = parse_syslog(real_line(), NOW)
        self.assertEqual(msg.pri, 4)  # kern.warn
        self.assertEqual(msg.tag, "kernel")
        self.assertIsNone(msg.hostname)
        self.assertAlmostEqual(msg.uptime, 19765.02)
        nf = parse_netfilter(msg.message)
        self.assertEqual(nf.prefix, "TRAPPOLA:")
        self.assertEqual((nf.src, nf.dst, nf.proto, nf.sport, nf.dport), ("192.168.1.2", "192.168.1.1", "tcp", 53463, 8080))
        self.assertEqual(nf.in_if, "br-lan")
        self.assertEqual(nf.src_mac, "00:11:22:33:44:55")
        self.assertIn("SYN", nf.flags)

    def test_line_as_sent_by_logd_over_the_network(self):
        msg = parse_syslog(logd_network(real_line()), NOW)
        self.assertEqual(msg.pri, 4)
        self.assertEqual(msg.hostname, "trap-acme")
        self.assertEqual(msg.tag, "kernel")
        self.assertEqual(msg.device_time.month, 10)
        self.assertEqual(msg.device_time.day, 23)
        self.assertEqual(parse_netfilter(msg.message).dport, 8080)

    def test_logd_single_digit_day_and_no_hostname(self):
        msg = parse_syslog("<4>Oct  3 14:01:02 kernel: [1.000000] TRAPPOLA: IN=br-lan OUT= SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=23", NOW)
        self.assertIsNone(msg.hostname)
        self.assertEqual(msg.device_time.day, 3)
        self.assertEqual(parse_netfilter(msg.message).dport, 23)

    def test_logd_extra_timestamp_and_prefix_option(self):
        msg = parse_syslog("<4>Oct 23 14:01:02 [1729680062.123] box custom: kernel: [5.0] TRAPPOLA: IN=br-lan OUT= SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP DPT=445", NOW)
        self.assertEqual(msg.hostname, "box")
        self.assertEqual(msg.tag, "custom")
        self.assertEqual(msg.uptime, 5.0)
        self.assertEqual(parse_netfilter(msg.message).dport, 445)

    def test_logread_display_with_date(self):
        msg = parse_syslog("Thu Oct 23 14:01:02 2026 " + real_line(), NOW)
        self.assertEqual(msg.device_time.year, 2026)
        self.assertEqual(msg.pri, 4)
        self.assertIsNotNone(parse_netfilter(msg.message))

    def test_rfc5424(self):
        line = ("<4>1 2026-10-23T14:01:02.5+02:00 trap-acme kernel - - [meta x=\"a]b\"] "
                "TRAPPOLA: IN=br-lan OUT= SRC=192.168.1.2 DST=192.168.1.1 PROTO=TCP SPT=1 DPT=3389")
        msg = parse_syslog(line, NOW)
        self.assertEqual(msg.hostname, "trap-acme")
        self.assertEqual(msg.tag, "kernel")
        self.assertEqual(msg.device_time, datetime(2026, 10, 23, 12, 1, 2, 500000, tzinfo=timezone.utc))
        self.assertEqual(parse_netfilter(msg.message).dport, 3389)

    def test_unsynchronised_box_clock_still_parses(self):
        msg = parse_syslog(logd_network(real_line(), stamp="Jan  1 00:05:00"), NOW)
        self.assertEqual((msg.device_time.month, msg.device_time.day), (1, 1))

    def test_hostname_and_tag_cannot_carry_control_characters(self):
        msg = parse_syslog("<4>Oct 23 14:01:02 evil\x1b[2Jhost kernel: x", NOW)
        self.assertIsNone(msg.hostname)
        msg = parse_syslog("<4>Oct 23 14:01:02 " + "h" * 300 + " kernel: x", NOW)
        self.assertIsNone(msg.hostname)

    def test_extreme_timestamps_do_not_raise(self):
        for line in ("<4>1 0001-01-01T00:00:00 h a - - - x", "<4>1 9999-12-31T23:59:59 h a - - - x",
                     "<4>Feb 30 14:01:02 h kernel: x"):
            with self.subTest(line=line):
                self.assertIsNone(parse_syslog(line, NOW).device_time)

    def test_other_messages(self):
        msg = parse_syslog("<14>Oct 23 14:01:02 trap-acme lantrap: heartbeat", NOW)
        self.assertEqual(msg.tag, "lantrap")
        self.assertEqual(msg.message, "heartbeat")
        self.assertIsNone(parse_netfilter(msg.message))


class Netfilter(unittest.TestCase):
    def test_ipv6_and_udp(self):
        nf = parse_netfilter("TRAPPOLA: IN=br-lan OUT= SRC=fd00::5 DST=fd00::1 LEN=60 PROTO=UDP SPT=5353 DPT=161 LEN=20")
        self.assertEqual((nf.src, nf.proto, nf.dport), ("fd00::5", "udp", 161))

    def test_icmp_error_quotes_original_packet(self):
        nf = parse_netfilter("P: IN=br-lan OUT= SRC=10.0.0.9 DST=10.0.0.1 PROTO=ICMP TYPE=3 CODE=3 [SRC=10.0.0.1 DST=10.0.0.9 PROTO=UDP SPT=1 DPT=2 ]")
        self.assertEqual(nf.src, "10.0.0.9")
        self.assertIsNone(nf.dport)
        self.assertEqual(nf.proto, "icmp")

    def test_rejects_garbage(self):
        self.assertIsNone(parse_netfilter("IN=br-lan OUT= SRC=not-an-ip DST=1.2.3.4"))
        self.assertIsNone(parse_netfilter("nothing to see"))

    def test_prefix_matching(self):
        self.assertEqual(match_prefix("TRAPPOLA:", ["TRAPPOLA: "]), "TRAPPOLA:")
        self.assertEqual(match_prefix("trappola:", ["TRAPPOLA"]), "TRAPPOLA")
        self.assertIsNone(match_prefix("reject wan in:", ["TRAPPOLA:"]))
        self.assertIsNone(match_prefix("MYTRAPPOLA:", ["TRAPPOLA:"]))
        self.assertEqual(match_prefix("anything:", []), "anything:")


class Framing(unittest.TestCase):
    def test_datagram_with_several_lines(self):
        self.assertEqual(split_datagram(b"a\nb\0c\r\n\n"), [b"a", b"b", b"c"])

    def test_lf_and_nul_trailers_across_reads(self):
        f = StreamFramer()
        self.assertEqual(f.feed(b"<4>one\n<4>tw"), [b"<4>one"])
        self.assertEqual(f.feed(b"o\0<4>three\r\n"), [b"<4>two", b"<4>three"])

    def test_octet_counting(self):
        f = StreamFramer()
        frame = b"<4>Oct 23 14:01:02 h kernel: x"
        data = str(len(frame)).encode() + b" " + frame
        self.assertEqual(f.feed(data[:10]), [])
        self.assertEqual(f.feed(data[10:] + data), [frame, frame])

    def test_digits_without_frame_are_a_line(self):
        self.assertEqual(StreamFramer().feed(b"12 not a frame\n"), [b"12 not a frame"])

    def test_limits(self):
        with self.assertRaises(FramingError):
            StreamFramer(max_frame=10).feed(b"99999 <4>x")
        with self.assertRaises(FramingError):
            StreamFramer(max_frame=10).feed(b"x" * 20)


if __name__ == "__main__":
    unittest.main()
