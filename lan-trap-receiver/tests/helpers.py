"""Shared fixtures: configurations, fake SMTP and HTTP servers, real-format log lines."""

from __future__ import annotations

import copy
import http.server
import logging
import socketserver
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lantrap.config import default_raw, parse_config, save_raw

logging.getLogger("lantrap").addHandler(logging.NullHandler())

DATA = Path(__file__).parent / "data"
T0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)

# The format seen on the box with `logread` (fields between MAC and PROTO as the kernel prints them)
REAL_LINE = ("kern.warn kernel: [{uptime:.6f}] TRAPPOLA: IN=br-lan OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 "
             "SRC={src} DST=192.168.1.1 LEN=52 TOS=0x00 PREC=0x00 TTL=128 ID={ident} DF PROTO=TCP SPT={sport} "
             "DPT={dport} WINDOW=65535 RES=0x00 SYN URGP=0")


def real_line(src: str = "192.168.1.2", dport: int = 8080, sport: int = 53463, uptime: float = 19765.02, ident: int = 1) -> str:
    return REAL_LINE.format(src=src, dport=dport, sport=sport, uptime=uptime, ident=ident)


def logd_network(line: str, hostname: str = "trap-acme", stamp: str = "Oct 23 14:01:02") -> str:
    """What OpenWrt logread -r sends for a kernel message: "<4>Mmm dd hh:mm:ss host kernel: ..."."""
    body = line.split("kernel: ", 1)[1]
    return f"<4>{stamp} {hostname} kernel: {body}"


def windows_scan(src: str = "192.168.1.2", ports=(21, 23, 445, 3389, 8080), retries: int = 5, start: datetime = T0):
    """(time, line) pairs: each port tried once, the SYN logged `retries` times half a second apart."""
    out = []
    for i, port in enumerate(ports):
        sport = 50000 + i
        for r in range(retries):
            when = start + timedelta(seconds=i * 2 + r * 0.5)
            out.append((when, real_line(src, port, sport, 19765.02 + i * 2 + r * 0.5, i * 10 + r)))
    return out


def base_raw(**overrides) -> dict:
    raw = default_raw()
    raw["prefixes"] = ["TRAPPOLA:"]
    raw["client"] = [
        {"id": "acme", "name": "ACME Ltd", "exclude": ["192.168.1.250"]},
        {"id": "beta", "name": "Beta Srl", "exclude": []},
    ]
    raw["trap"] = [
        {"id": "acme-hq", "name": "ACME HQ", "client": "acme", "source": ["10.99.0.11"], "hostname": "trap-acme",
         "exclude": ["192.168.1.96/30"]},
        {"id": "beta-1", "name": "Beta office", "client": "beta", "source": ["10.99.0.0/24"]},
    ]
    raw["exclude"] = ["aa:aa:aa:aa:aa:aa"]
    raw["store"] = []
    for key, value in overrides.items():
        raw[key] = value
    return raw


def make_config(raw: dict | None = None, directory: Path | None = None, fmt: str = "toml"):
    raw = copy.deepcopy(raw if raw is not None else base_raw())
    directory = directory or Path(tempfile.mkdtemp(prefix="lantrap-test-"))
    path = directory / f"lantrap.{fmt}"
    save_raw(raw, path)
    return parse_config(raw, path.resolve(), fmt)


class FakeSmtp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.envelopes: list[tuple] = []
        super().__init__(("127.0.0.1", 0), _SmtpHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


class _SmtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(b"220 fake ESMTP\r\n")
        data_mode, buf, mail_from, rcpts = False, [], None, []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if data_mode:
                if line in (b".\r\n", b".\n"):
                    data_mode = False
                    self.server.messages.append(b"".join(buf))
                    self.server.envelopes.append((mail_from, list(rcpts)))
                    buf, rcpts = [], []
                    self.wfile.write(b"250 queued\r\n")
                else:
                    buf.append(line[1:] if line.startswith(b"..") else line)
                continue
            cmd = line.strip().upper()
            if cmd.startswith(b"EHLO"):
                self.wfile.write(b"250-fake\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n")
            elif cmd.startswith(b"MAIL"):
                mail_from = line.strip()[10:]
                self.wfile.write(b"250 ok\r\n")
            elif cmd.startswith(b"RCPT"):
                rcpts.append(line.strip()[8:])
                self.wfile.write(b"250 ok\r\n")
            elif cmd == b"DATA":
                data_mode = True
                self.wfile.write(b"354 go\r\n")
            elif cmd == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class HttpSink(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.requests: list[dict] = []
        self.event = threading.Event()
        super().__init__(("127.0.0.1", 0), _HttpHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/hook"

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


class _HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
        self.send_response(self.server.status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
        self.server.event.set()

    def log_message(self, *args) -> None:
        pass
