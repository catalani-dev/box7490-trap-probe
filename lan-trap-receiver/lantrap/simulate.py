"""Fake trap traffic in the exact format OpenWrt logd sends (for tests and demonstrations)."""

from __future__ import annotations

import random
import socket
from datetime import datetime

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def logd_line(now: datetime, hostname: str, uptime: float, message: str, pri: int = 4) -> str:
    """"<PRI>Mmm dd hh:mm:ss host kernel: [uptime] message", as built by OpenWrt logread -r."""
    local = now.astimezone()
    stamp = f"{MONTHS[local.month - 1]} {local.day:>2} {local:%H:%M:%S}"
    return f"<{pri}>{stamp} {hostname} kernel: [{uptime:.6f}] {message}"


def netfilter_message(prefix: str, src: str, dst: str, sport: int, dport: int, src_mac: str = "00:11:22:33:44:55",
                      dst_mac: str = "aa:bb:cc:dd:ee:ff", interface: str = "br-lan") -> str:
    return (f"{prefix.strip()} IN={interface} OUT= MAC={dst_mac}:{src_mac}:08:00 SRC={src} DST={dst} LEN=52 "
            f"TOS=0x00 PREC=0x00 TTL=128 ID={random.randint(1, 65535)} DF PROTO=TCP SPT={sport} DPT={dport} "
            f"WINDOW=65535 RES=0x00 SYN URGP=0")


def scan_lines(ports: list[int], src: str = "192.168.1.2", dst: str = "192.168.1.1", retries: int = 5,
               prefix: str = "LANTRAP:", hostname: str = "OpenWrt", now: datetime | None = None,
               uptime: float = 19765.02) -> list[str]:
    """One connection attempt per port, each logged `retries` times with the same source port (SYN retries)."""
    now = now or datetime.now().astimezone()
    lines = []
    for i, port in enumerate(ports):
        sport = 49152 + random.randint(0, 16000)
        for r in range(retries):
            lines.append(logd_line(now, hostname, uptime + i + r * 0.5, netfilter_message(prefix, src, dst, sport, port)))
    return lines


def send(lines: list[str], host: str, port: int, proto: str = "udp", timeout: float = 5) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    if proto == "udp":
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            for line in lines:
                s.sendto(line.encode("utf-8"), (host, port))
    else:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall("".join(line + "\n" for line in lines).encode("utf-8"))
