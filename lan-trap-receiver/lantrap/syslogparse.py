"""Syslog framing and parsing, and netfilter LOG lines inside syslog messages.

Accepted forms:
- RFC 3164 as sent by OpenWrt logd: "<4>Oct 23 14:01:02 host kernel: [19765.02] PREFIX: IN=..."
- RFC 5424: "<4>1 2026-10-23T14:01:02+02:00 host kernel - - - PREFIX: IN=..."
- lines copied from `logread`: "Thu Oct 23 14:01:02 2026 kern.warn kernel: [...] PREFIX: IN=..."
  or without the date: "kern.warn kernel: [...] PREFIX: IN=..."
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
    "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "ntp": 12, "security": 13, "console": 14,
    "clock": 15, "local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20,
    "local5": 21, "local6": 22, "local7": 23,
}
SEVERITIES = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "warning": 4, "notice": 5, "info": 6, "debug": 7}

MAX_FRAME = 64 * 1024

_PRI = re.compile(r"^<(\d{1,3})>")
_BSD_TIME = re.compile(r"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d)(?:\.\d+)?(?: (\d{4}))? ")
_ISO_TIME = re.compile(r"^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) ")
_DISPLAY_TIME = re.compile(r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d) (\d{4}) ")
_FAC_SEV = re.compile(r"^([a-z0-9]+)\.([a-z]+) ")
_LOGD_STAMP = re.compile(r"^\[\d+\.\d+\] ")
_UPTIME = re.compile(r"^\[\s*(\d+\.\d+)\]\s*")
_TAG = re.compile(r"^[^\s:\[]{1,64}(?:\[\d+\])?:$")
_NF_START = re.compile(r"(?:^|\s)IN=\S*\s+OUT=")
_NF_HEAD_NOISE = re.compile(r"^(?:kernel:\s*)?(?:\[\s*\d+\.\d+\]\s*)?")
_PRINTABLE_TOKEN = re.compile(r"^[\x21-\x7e]{1,255}$")


class FramingError(ValueError):
    """The peer sent a frame that is too large or malformed."""


@dataclass
class SyslogMessage:
    raw: str
    message: str
    pri: int | None = None
    hostname: str | None = None
    tag: str | None = None
    device_time: datetime | None = None
    uptime: float | None = None

    @property
    def facility(self) -> int | None:
        return None if self.pri is None else self.pri >> 3

    @property
    def severity(self) -> int | None:
        return None if self.pri is None else self.pri & 7


@dataclass
class NetfilterHit:
    prefix: str
    fields: dict
    flags: tuple

    @property
    def src(self) -> str:
        return self.fields["SRC"]

    @property
    def dst(self) -> str:
        return self.fields["DST"]

    @property
    def proto(self) -> str:
        return self.fields.get("PROTO", "").lower() or "ip"

    @property
    def sport(self) -> int | None:
        return _int_or_none(self.fields.get("SPT"))

    @property
    def dport(self) -> int | None:
        return _int_or_none(self.fields.get("DPT"))

    @property
    def in_if(self) -> str:
        return self.fields.get("IN", "")

    @property
    def src_mac(self) -> str | None:
        parts = self.fields.get("MAC", "").split(":")
        if len(parts) >= 12 and all(len(p) == 2 for p in parts[:12]):
            return ":".join(parts[6:12]).lower()
        return None


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


# ---------------------------------------------------------------- framing

def split_datagram(data: bytes) -> list[bytes]:
    """One UDP datagram may carry one message or several separated by LF or NUL."""
    return [p.rstrip(b"\r") for p in re.split(rb"[\n\0]", data) if p.strip()]


class StreamFramer:
    """TCP/TLS framing: LF or NUL trailers (OpenWrt logd) and RFC 6587 octet counting."""

    def __init__(self, max_frame: int = MAX_FRAME) -> None:
        self.max_frame = max_frame
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self.buf += data
        out: list[bytes] = []
        while self.buf:
            m = re.match(rb"(\d{1,6}) ", self.buf)
            if m:
                if len(self.buf) <= m.end():
                    break
                if self.buf[m.end()] == ord("<"):
                    size = int(m.group(1))
                    if size > self.max_frame:
                        raise FramingError(f"frame of {size} bytes is too large")
                    if len(self.buf) < m.end() + size:
                        break
                    frame = bytes(self.buf[m.end():m.end() + size])
                    del self.buf[:m.end() + size]
                    if frame.strip():
                        out.append(frame.rstrip(b"\r\n\0"))
                    continue
            nl = self.buf.find(b"\n")
            nul = self.buf.find(b"\0")
            ends = [i for i in (nl, nul) if i >= 0]
            if not ends:
                if len(self.buf) > self.max_frame:
                    raise FramingError("line without a terminator is too long")
                break
            end = min(ends)
            frame = bytes(self.buf[:end]).rstrip(b"\r")
            del self.buf[:end + 1]
            if frame.strip():
                out.append(frame)
        return out


# ---------------------------------------------------------------- syslog

def _bsd_time(month: str, day: str, hh: str, mm: str, ss: str, year: str | None, now: datetime) -> datetime | None:
    if month not in MONTHS:
        return None
    local_now = now.astimezone()
    tz = local_now.tzinfo
    try:
        if year:
            return datetime(int(year), MONTHS[month], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
        candidate = datetime(local_now.year, MONTHS[month], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    except ValueError:
        return None
    # no year in RFC 3164: pick the year that puts the time closest to now
    if candidate - local_now > timedelta(days=183):
        candidate = candidate.replace(year=candidate.year - 1)
    elif local_now - candidate > timedelta(days=183):
        try:
            candidate = candidate.replace(year=candidate.year + 1)
        except ValueError:
            pass
    return candidate


def _iso_time(text: str) -> datetime | None:
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return value if value.tzinfo else value.astimezone()
    except (ValueError, OverflowError, OSError):
        return None


def _skip_structured_data(rest: str) -> str:
    if rest.startswith("- "):
        return rest[2:]
    if rest == "-":
        return ""
    i = 0
    while i < len(rest) and rest[i] == "[":
        i += 1
        while i < len(rest) and rest[i] != "]":
            i += 2 if rest[i] == "\\" else 1
        i += 1
    return rest[i:].lstrip(" ")


def _split_host_tag(rest: str, has_host: bool) -> tuple[str | None, str | None, str]:
    parts = rest.split(" ", 1)
    first = parts[0]
    tail = parts[1] if len(parts) > 1 else ""
    if _TAG.match(first):
        return None, first[:-1].split("[")[0], tail
    if not has_host:
        return None, None, rest
    hostname = first or None
    parts = tail.split(" ", 1)
    if parts and _TAG.match(parts[0]):
        return hostname, parts[0][:-1].split("[")[0], parts[1] if len(parts) > 1 else ""
    return hostname, None, tail


def parse_syslog(text: str, now: datetime | None = None) -> SyslogMessage:
    now = now or datetime.now(timezone.utc)
    raw = text.strip("\r\n\0 \ufeff")
    rest = raw
    msg = SyslogMessage(raw=raw, message=raw)

    m = _PRI.match(rest)
    if m and int(m.group(1)) <= 191:
        msg.pri = int(m.group(1))
        rest = rest[m.end():]

    has_header = False
    if msg.pri is not None and rest.startswith("1 "):
        # RFC 5424: VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
        fields = rest[2:].split(" ", 5)
        if len(fields) == 6:
            ts, host, app, _procid, _msgid, tail = fields
            msg.device_time = None if ts == "-" else _iso_time(ts)
            msg.hostname = None if host == "-" else host
            msg.tag = None if app == "-" else app
            body = _skip_structured_data(tail)
            if body.startswith("\ufeff"):
                body = body[1:]
            msg.message = body
            return _finish(msg)
    if (m := _BSD_TIME.match(rest)):
        msg.device_time = _bsd_time(*m.groups(), now=now)
        rest = rest[m.end():]
        has_header = True
    elif (m := _ISO_TIME.match(rest)):
        msg.device_time = _iso_time(m.group(1))
        rest = rest[m.end():]
        has_header = True
    elif msg.pri is None and (m := _DISPLAY_TIME.match(rest)):
        mon, day, hh, mm, ss, year = m.groups()
        msg.device_time = _bsd_time(mon, day, hh, mm, ss, year, now=now)
        rest = rest[m.end():]

    if (m := _LOGD_STAMP.match(rest)):
        rest = rest[m.end():]

    if msg.pri is None and (m := _FAC_SEV.match(rest)):
        fac, sev = m.groups()
        if fac in FACILITIES and sev in SEVERITIES:
            msg.pri = FACILITIES[fac] * 8 + SEVERITIES[sev]
            rest = rest[m.end():]

    msg.hostname, msg.tag, msg.message = _split_host_tag(rest, has_header and msg.pri is not None)
    return _finish(msg)


def _clean_token(value: str | None) -> str | None:
    """Hostname and tag come from the network: printable ASCII only, so they cannot carry terminal escapes."""
    return value if value and _PRINTABLE_TOKEN.match(value) else None


def _finish(msg: SyslogMessage) -> SyslogMessage:
    msg.hostname = _clean_token(msg.hostname)
    msg.tag = _clean_token(msg.tag)
    body = msg.message
    if msg.tag != "kernel" and body.startswith("kernel: "):
        body = body[len("kernel: "):]
        msg.tag = msg.tag or "kernel"
    if (m := _UPTIME.match(body)):
        msg.uptime = float(m.group(1))
        body = body[m.end():]
    msg.message = body
    return msg


# ---------------------------------------------------------------- netfilter

def parse_netfilter(message: str) -> NetfilterHit | None:
    """Fields of a netfilter LOG line ("PREFIX: IN=br-lan OUT= MAC=... SRC=... DST=... PROTO=TCP ...")."""
    m = _NF_START.search(message)
    if not m:
        return None
    head = _NF_HEAD_NOISE.sub("", message[:m.start()].strip()).strip()
    fields: dict[str, str] = {}
    flags: list[str] = []
    for token in message[m.start():].split():
        if token.startswith("["):
            break  # ICMP errors quote the original packet in brackets
        if "=" in token:
            key, value = token.split("=", 1)
            fields.setdefault(key, value)
        else:
            flags.append(token)
    try:
        ipaddress.ip_address(fields.get("SRC", ""))
        ipaddress.ip_address(fields.get("DST", ""))
    except ValueError:
        return None
    return NetfilterHit(head, fields, tuple(flags))


def _norm_prefix(value: str) -> str:
    return value.strip().rstrip(":").strip().lower()


def match_prefix(hit_prefix: str, prefixes: tuple | list) -> str | None:
    """The configured prefix that this log line carries; any prefix when none is configured."""
    text = _norm_prefix(hit_prefix)
    if not prefixes:
        return hit_prefix.strip() or "-"
    for prefix in prefixes:
        p = _norm_prefix(prefix)
        if p and text.endswith(p) and (len(text) == len(p) or text[-len(p) - 1] in " :]"):
            return prefix.strip()
    return None
