"""Trap identification, exclusions, grouping of hits into incidents, heartbeat and alert throttling.

No I/O here: the receiver passes the current time in, which keeps the logic testable.
"""

from __future__ import annotations

import secrets
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .config import Client, Config, Trap
from .syslogparse import SyslogMessage, match_prefix, parse_netfilter

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 137: "NetBIOS-NS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 502: "Modbus", 514: "Syslog", 587: "Submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MS-SQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-TLS",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Printer", 27017: "MongoDB",
}

UNKNOWN_CLIENT = "unknown"

# bounds against floods of spoofed or unusual traffic
MAX_PORTS_PER_INCIDENT = 1024
MAX_DESTINATIONS = 64
MAX_MACS = 16
MAX_UNKNOWN_SENDERS = 1024
MAX_RAW = 2048


def iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") if value else None


def clock_plausible(skew_seconds: float, tolerance: float = 300) -> bool:
    """True when the device clock differs from ours only by a time-zone offset (multiples of 15 minutes)."""
    if abs(skew_seconds) > 14 * 3600 + tolerance:
        return False
    quarter = 900
    nearest = round(skew_seconds / quarter) * quarter
    return abs(skew_seconds - nearest) <= tolerance


@dataclass
class Hit:
    received_at: datetime
    trap_id: str
    client_id: str
    peer: str
    hostname: str | None
    rule: str
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None
    src_mac: str | None
    in_if: str
    flags: str
    device_time: datetime | None
    raw: str
    excluded: bool = False
    exclude_reason: str | None = None
    incident_id: str | None = None
    new_attempt: bool = False

    def as_dict(self) -> dict:
        return {
            "received_at": iso(self.received_at),
            "trap_id": self.trap_id,
            "client_id": self.client_id,
            "peer": self.peer,
            "hostname": self.hostname,
            "rule": self.rule,
            "src": self.src,
            "src_mac": self.src_mac,
            "dst": self.dst,
            "proto": self.proto,
            "sport": self.sport,
            "dport": self.dport,
            "in_if": self.in_if,
            "flags": self.flags,
            "device_time": iso(self.device_time),
            "excluded": self.excluded,
            "exclude_reason": self.exclude_reason,
            "incident_id": self.incident_id,
            "new_attempt": self.new_attempt,
            "raw": self.raw,
        }


@dataclass
class PortStat:
    proto: str
    port: int | None
    attempts: int = 0
    lines: int = 0
    last_line: datetime | None = None


@dataclass
class Incident:
    id: str
    trap_id: str
    client_id: str
    src: str
    first_seen: datetime
    last_seen: datetime
    due_at: datetime
    macs: set = field(default_factory=set)
    destinations: set = field(default_factory=set)
    ports: dict = field(default_factory=dict)
    lines: int = 0
    attempts: int = 0
    status: str = "open"
    ports_untracked: int = 0
    alerts_sent: int = 0
    last_alert_at: datetime | None = None
    lines_at_last_alert: int = 0
    throttled: bool = False
    dirty: bool = True

    def classification(self, scan_ports: int) -> str:
        return "port_scan" if len(self.ports) >= scan_ports else "connection_attempt"


@dataclass
class TrapState:
    trap_id: str
    last_seen: datetime | None = None
    last_peer: str | None = None
    last_hostname: str | None = None
    clock_skew: float | None = None
    clock_ok: bool | None = None
    silent: bool = False
    messages: int = 0
    hits: int = 0
    watch_since: datetime | None = None


@dataclass
class UnknownSender:
    peer: str
    hostname: str | None
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    warned_at: datetime | None = None
    saved_at: datetime | None = None


@dataclass
class Alert:
    kind: str
    created_at: datetime
    trap: Trap | None
    client: Client | None
    incident: dict | None = None
    details: dict = field(default_factory=dict)
    waiting: int = 0
    id: str = field(default_factory=lambda: secrets.token_hex(8))


@dataclass
class Received:
    status: str  # unknown | other | hit | excluded
    trap: Trap | None = None
    hit: Hit | None = None
    message: SyslogMessage | None = None
    alerts: list = field(default_factory=list)
    unknown: UnknownSender | None = None


class Engine:
    def __init__(self, config: Config, now: datetime) -> None:
        self.config = config
        self.started_at = now
        self.incidents: dict[tuple[str, str], Incident] = {}
        self.trap_states: dict[str, TrapState] = {}
        self.unknown: dict[str, UnknownSender] = {}
        self._closed: list[Incident] = []
        self._waiting: list[Incident] = []
        self._alert_times: dict[str, deque] = {}

    # ------------------------------------------------------------ lookups

    def reload(self, config: Config, now: datetime | None = None) -> None:
        self.config = config
        for trap_id in config.traps:
            if trap_id not in self.trap_states:
                # a trap added while running is watched from now, not from the start of the receiver
                self.trap_states[trap_id] = TrapState(trap_id, watch_since=now)

    def client(self, client_id: str) -> Client:
        return self.config.clients.get(client_id) or Client(client_id, client_id)

    def trap(self, trap_id: str) -> Trap | None:
        if trap_id in self.config.traps:
            return self.config.traps[trap_id]
        if trap_id.startswith("unknown-"):
            peer = trap_id[len("unknown-"):]
            return Trap(trap_id, peer, UNKNOWN_CLIENT)
        return None

    def identify(self, peer: str, hostname: str | None) -> Trap | None:
        """The configured trap for a sender.

        The most specific source address decides; when that trap also names a hostname, the hostname must
        match, and there is no fallback to a broader network (that would credit another client).
        Traps configured with a hostname only are used when no source address matches.
        """
        def host_ok(trap: Trap) -> bool:
            return not trap.hostname or bool(hostname and trap.hostname.lower() == hostname.lower())

        with_source = [(trap.source.best_prefix(peer), trap) for trap in self.config.traps.values() if trap.source]
        best = max((p for p, _ in with_source), default=-1)
        if best >= 0:
            tied = [trap for p, trap in with_source if p == best and host_ok(trap)]
            tied.sort(key=lambda trap: not trap.hostname)
            return tied[0] if tied else None
        by_name = [trap for trap in self.config.traps.values() if not trap.source and trap.hostname and host_ok(trap)]
        return by_name[0] if by_name else None

    def state(self, trap_id: str) -> TrapState:
        st = self.trap_states.get(trap_id)
        if st is None:
            st = self.trap_states[trap_id] = TrapState(trap_id)
        return st

    def exclusion(self, trap: Trap, src: str, mac: str | None) -> str | None:
        for scope, matcher in (("trap", trap.exclude), ("client", self.client(trap.client).exclude), ("global", self.config.exclude)):
            entry = matcher.match(src, mac)
            if entry:
                return f"{scope}:{entry}"
        return None

    # ------------------------------------------------------------ input

    def receive(self, peer: str, msg: SyslogMessage, now: datetime, trap: Trap | None = None) -> Received:
        """Handle one message; `trap` forces the sender (used when importing saved logs)."""
        trap = trap or self.identify(peer, msg.hostname)
        if trap is None:
            if self.config.unknown_sources != "accept":
                u = self.unknown.get(peer)
                if u is None:
                    if len(self.unknown) >= MAX_UNKNOWN_SENDERS:
                        oldest = min(self.unknown.values(), key=lambda x: x.last_seen)
                        del self.unknown[oldest.peer]
                    u = self.unknown[peer] = UnknownSender(peer, msg.hostname, now, now)
                u.last_seen, u.hostname = now, msg.hostname or u.hostname
                u.count += 1
                return Received("unknown", message=msg, unknown=u)
            trap = Trap(f"unknown-{peer}", peer, UNKNOWN_CLIENT)

        result = Received("other", trap=trap, message=msg)
        st = self.state(trap.id)
        if st.silent:
            st.silent = False
            result.alerts.append(Alert("trap_back", now, trap, self.client(trap.client),
                                       details={"silent_since": iso(st.last_seen)}))
        st.last_seen, st.last_peer, st.last_hostname = now, peer, msg.hostname
        st.messages += 1
        if msg.device_time:
            skew = (msg.device_time - now).total_seconds()
            st.clock_skew, st.clock_ok = skew, clock_plausible(skew)

        nf = parse_netfilter(msg.message)
        if nf is None:
            return result
        rule = match_prefix(nf.prefix, self.config.prefixes)
        if rule is None:
            return result
        hit = Hit(
            received_at=now, trap_id=trap.id, client_id=trap.client, peer=peer, hostname=msg.hostname,
            rule=rule, src=nf.src, dst=nf.dst, proto=nf.proto, sport=nf.sport, dport=nf.dport,
            src_mac=nf.src_mac, in_if=nf.in_if, flags=" ".join(nf.flags)[:200], device_time=msg.device_time,
            raw=msg.raw[:MAX_RAW],
        )
        result.hit = hit
        st.hits += 1
        reason = self.exclusion(trap, hit.src, hit.src_mac)
        if reason:
            hit.excluded, hit.exclude_reason = True, reason
            result.status = "excluded"
            return result
        self._group(trap, hit, now)
        result.status = "hit"
        return result

    def _group(self, trap: Trap, hit: Hit, now: datetime) -> None:
        g = self.config.grouping
        key = (trap.id, hit.src)
        inc = self.incidents.get(key)
        if inc and now - inc.last_seen > timedelta(minutes=g.quiet_minutes):
            self._closed.append(self._close(key))
            inc = None
        if inc is None:
            stamp = now.astimezone().strftime("%Y%m%d-%H%M%S")
            inc = Incident(
                id=f"{stamp}-{secrets.token_hex(3)}", trap_id=trap.id, client_id=trap.client, src=hit.src,
                first_seen=now, last_seen=now, due_at=now + timedelta(seconds=g.collect_seconds),
            )
            self.incidents[key] = inc
        inc.lines += 1
        inc.last_seen = now
        if hit.src_mac and len(inc.macs) < MAX_MACS:
            inc.macs.add(hit.src_mac)
        if len(inc.destinations) < MAX_DESTINATIONS:
            inc.destinations.add(hit.dst)
        inc.dirty = True
        hit.incident_id = inc.id
        pkey = f"{hit.proto}/{hit.dport}" if hit.dport is not None else hit.proto
        ps = inc.ports.get(pkey)
        if ps is None:
            if len(inc.ports) >= MAX_PORTS_PER_INCIDENT:
                inc.ports_untracked += 1
                return
            ps = inc.ports[pkey] = PortStat(hit.proto, hit.dport)
        # repeated lines for the same port within retry_seconds are one attempt (for example the
        # SYN retries of a Windows client after a reset), whatever their source port
        if ps.last_line is None or now - ps.last_line > timedelta(seconds=g.retry_seconds):
            ps.attempts += 1
            inc.attempts += 1
            hit.new_attempt = True
        ps.lines += 1
        ps.last_line = now

    def _close(self, key: tuple[str, str]) -> Incident:
        inc = self.incidents.pop(key)
        inc.status = "closed"
        inc.dirty = True
        return inc

    # ------------------------------------------------------------ time

    def tick(self, now: datetime) -> tuple[list[Alert], list[Incident]]:
        """Alerts that are due and incidents closed since the last call."""
        g = self.config.grouping
        alerts: list[Alert] = []
        closed, self._closed = self._closed, []
        for inc in closed:
            alerts.extend(self._on_close(inc, now))
        quiet = timedelta(minutes=g.quiet_minutes)
        for key, inc in list(self.incidents.items()):
            if now - inc.last_seen > quiet:
                inc = self._close(key)
                closed.append(inc)
                alerts.extend(self._on_close(inc, now))
            elif inc.alerts_sent == 0 and now >= inc.due_at:
                alerts.extend(self._incident_alert("incident", inc, now))
            elif (inc.alerts_sent and g.reminder_minutes and inc.last_alert_at
                  and now - inc.last_alert_at >= timedelta(minutes=g.reminder_minutes)
                  and inc.lines > inc.lines_at_last_alert):
                alerts.extend(self._incident_alert("incident_update", inc, now))
        for inc in list(self._waiting):
            first = self._incident_alert("incident", inc, now)
            if first:
                self._waiting.remove(inc)
                alerts.extend(first)
        alerts.extend(self._heartbeat(now))
        return alerts, closed

    def _on_close(self, inc: Incident, now: datetime) -> list[Alert]:
        if inc.alerts_sent == 0:
            first = self._incident_alert("incident", inc, now)
            if not first and inc not in self._waiting:
                self._waiting.append(inc)  # hourly limit: the first alert of an ended incident waits, it is not dropped
            return first
        if self.config.grouping.notify_on_close:
            return self._incident_alert("incident_closed", inc, now)
        return []

    def _incident_alert(self, kind: str, inc: Incident, now: datetime) -> list[Alert]:
        """One alert, unless the client used up its hourly budget: then it waits and is retried at each tick."""
        limit = self.config.grouping.max_alerts_per_hour
        if limit:
            times = self._alert_times.setdefault(inc.client_id, deque())
            while times and now - times[0] >= timedelta(hours=1):
                times.popleft()
            if len(times) >= limit:
                inc.throttled = True
                return []
            times.append(now)
        inc.throttled = False
        inc.alerts_sent += 1
        inc.last_alert_at = now
        inc.lines_at_last_alert = inc.lines
        inc.dirty = True
        waiting = sum(1 for i in list(self.incidents.values()) + self._waiting
                      if i.throttled and i.client_id == inc.client_id)
        return [Alert(kind, now, self.trap(inc.trap_id), self.client(inc.client_id), self.snapshot(inc), waiting=waiting)]

    def pending_alerts(self, now: datetime) -> list[Alert]:
        """First alerts not sent yet (collect window or hourly limit), sent at shutdown so that none is lost."""
        out = []
        for inc in list(self.incidents.values()) + self._waiting:
            if inc.alerts_sent == 0:
                inc.throttled = False
                inc.alerts_sent = 1
                inc.last_alert_at = now
                inc.lines_at_last_alert = inc.lines
                inc.dirty = True
                out.append(Alert("incident", now, self.trap(inc.trap_id), self.client(inc.client_id), self.snapshot(inc)))
        self._waiting = []
        return out

    def _heartbeat(self, now: datetime) -> list[Alert]:
        hb = self.config.heartbeat
        missing = timedelta(minutes=hb.missing_minutes)
        alerts = []
        for trap in self.config.traps.values():
            enabled = trap.heartbeat if trap.heartbeat is not None else hb.enabled
            if not enabled:
                continue
            st = self.state(trap.id)
            reference = st.last_seen or st.watch_since or self.started_at
            if not st.silent and now - reference > missing:
                st.silent = True
                alerts.append(Alert("trap_silent", now, trap, self.client(trap.client),
                                    details={"last_seen": iso(st.last_seen), "missing_minutes": hb.missing_minutes}))
        return alerts

    # ------------------------------------------------------------ output

    def take_dirty(self) -> list[Incident]:
        out = [i for i in self.incidents.values() if i.dirty]
        for inc in out:
            inc.dirty = False
        return out

    def snapshot(self, inc: Incident) -> dict:
        trap = self.trap(inc.trap_id)
        client = self.client(inc.client_id)
        ports = sorted(inc.ports.values(), key=lambda p: (p.port is None, p.port or 0, p.proto))
        return {
            "id": inc.id,
            "trap_id": inc.trap_id,
            "trap_name": trap.name if trap else inc.trap_id,
            "client_id": inc.client_id,
            "client_name": client.name,
            "source_ip": inc.src,
            "source_macs": sorted(inc.macs),
            "destinations": sorted(inc.destinations),
            "first_seen": iso(inc.first_seen),
            "last_seen": iso(inc.last_seen),
            "lines": inc.lines,
            "attempts": inc.attempts,
            "ports": [
                {"proto": p.proto, "port": p.port, "service": SERVICES.get(p.port or -1), "attempts": p.attempts, "lines": p.lines}
                for p in ports
            ],
            "ports_untracked": inc.ports_untracked,
            "classification": inc.classification(self.config.grouping.scan_ports),
            "status": inc.status,
            "alerts_sent": inc.alerts_sent,
        }

    def close_all(self) -> list[Incident]:
        """Incidents still open at shutdown (they are saved as open and closed at the next start)."""
        return list(self.incidents.values())
