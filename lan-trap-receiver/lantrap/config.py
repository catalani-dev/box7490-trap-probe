"""Configuration: load, validate and save (TOML or JSON)."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import tomlw

LANGUAGES = ("en", "it")
PROTOCOLS = ("udp", "tcp", "tls")
STORE_TYPES = ("sqlite", "jsonl", "csv")
NOTIFIER_TYPES = ("smtp", "google_chat", "webhook", "command")
ALERT_KINDS = ("incident", "incident_update", "incident_closed", "trap_silent", "trap_back", "test")
SMTP_SECURITY = ("starttls", "ssl", "none")

DEFAULT_TRAP_PORTS = [21, 23, 139, 445, 1433, 3306, 3389, 5900, 8080]
DEFAULT_PREFIX = "LANTRAP:"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)
_PREFIX_RE = re.compile(r"^[\x20\x21\x23-\x5b\x5d-\x7e]+$")  # printable ASCII except " and \
_NAME_BAD = re.compile(r"[\x00-\x1f\x7f]")

CONFIG_HEADER = "LAN Trap Receiver configuration. Reloaded automatically when the file changes."


class ConfigError(ValueError):
    """Invalid configuration; the message names the offending setting."""


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


@dataclass(frozen=True)
class Matcher:
    """IP addresses, networks and MAC addresses (used by exclusions and allow lists)."""

    networks: tuple = ()
    macs: frozenset = frozenset()
    entries: tuple = ()

    @classmethod
    def parse(cls, items: Any, where: str, allow_mac: bool = True) -> Matcher:
        if items is None:
            return cls()
        if not isinstance(items, list):
            raise ConfigError(f"{where}: expected a list")
        networks, macs = [], set()
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ConfigError(f"{where}: invalid entry {item!r}")
            text = item.strip()
            if allow_mac and _MAC_RE.match(text):
                macs.add(normalize_mac(text))
                continue
            try:
                networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                kind = "IP address, network or MAC address" if allow_mac else "IP address or network"
                raise ConfigError(f"{where}: {text!r} is not a valid {kind}") from None
        return cls(tuple(networks), frozenset(macs), tuple(i.strip() for i in items))

    def __bool__(self) -> bool:
        return bool(self.networks or self.macs)

    def match(self, ip: str | None, mac: str | None = None) -> str | None:
        """Return the entry that matches, or None."""
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = None
            if addr is not None:
                for net in self.networks:
                    if addr.version == net.version and addr in net:
                        return str(net) if net.num_addresses > 1 else str(net.network_address)
        if mac and normalize_mac(mac) in self.macs:
            return normalize_mac(mac)
        return None

    def best_prefix(self, ip: str) -> int:
        """Longest matching prefix length, or -1."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return -1
        best = -1
        for net in self.networks:
            if addr.version == net.version and addr in net:
                best = max(best, net.prefixlen)
        return best


@dataclass
class Listener:
    protocol: str
    address: str
    port: int
    certfile: Path | None = None
    keyfile: Path | None = None
    cafile: Path | None = None
    allow: Matcher = field(default_factory=Matcher)

    @property
    def label(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{self.protocol}://{host}:{self.port}"


@dataclass
class Client:
    id: str
    name: str
    exclude: Matcher = field(default_factory=Matcher)


@dataclass
class Trap:
    id: str
    name: str
    client: str
    source: Matcher = field(default_factory=Matcher)
    hostname: str | None = None
    exclude: Matcher = field(default_factory=Matcher)
    heartbeat: bool | None = None
    tunnel_ip: str | None = None


@dataclass
class Grouping:
    collect_seconds: int = 60
    quiet_minutes: int = 15
    retry_seconds: int = 5
    reminder_minutes: int = 60
    scan_ports: int = 3
    notify_on_close: bool = False
    max_alerts_per_hour: int = 30


@dataclass
class Heartbeat:
    enabled: bool = True
    missing_minutes: int = 30


@dataclass
class StoreConf:
    type: str
    path: Path
    retention_days: int = 365


@dataclass
class NotifierConf:
    name: str
    type: str
    events: tuple = ALERT_KINDS
    clients: tuple = ()
    language: str | None = None
    options: dict = field(default_factory=dict)
    base_dir: Path = Path(".")

    def wants(self, kind: str, client_id: str | None) -> bool:
        if kind != "test" and kind not in self.events:
            return False
        if self.clients and client_id and client_id not in self.clients:
            return False
        return True


@dataclass
class OpenWrtConf:
    receiver: str = ""
    log_port: int = 5514
    log_proto: str = "udp"
    ports: tuple = tuple(DEFAULT_TRAP_PORTS)
    interface: str = "br-lan"
    set_name: str = "lantrap_exclude"
    rate_per_minute: int = 60
    heartbeat_minutes: int = 10
    ntp_servers: tuple = ()
    ipv6: bool = False


@dataclass
class WireGuardConf:
    endpoint: str = ""
    public_key: str = ""
    receiver_ip: str = ""
    network: str = ""
    keepalive: int = 25


@dataclass
class Config:
    language: str = "en"
    prefixes: tuple = (DEFAULT_PREFIX,)
    unknown_sources: str = "drop"
    store_excluded: bool = True
    store_other: bool = False
    exclude: Matcher = field(default_factory=Matcher)
    listeners: list = field(default_factory=list)
    clients: dict = field(default_factory=dict)
    traps: dict = field(default_factory=dict)
    grouping: Grouping = field(default_factory=Grouping)
    heartbeat: Heartbeat = field(default_factory=Heartbeat)
    stores: list = field(default_factory=list)
    notifiers: list = field(default_factory=list)
    openwrt: OpenWrtConf = field(default_factory=OpenWrtConf)
    wireguard: WireGuardConf | None = None
    path: Path | None = None
    format: str = "toml"
    raw: dict = field(default_factory=dict)

    @property
    def base_dir(self) -> Path:
        return self.path.parent if self.path else Path.cwd()

    def sqlite_path(self) -> Path | None:
        for store in self.stores:
            if store.type == "sqlite":
                return store.path
        return None


def default_raw() -> dict:
    """Settings for a new configuration file."""
    return {
        "language": "en",
        "prefixes": [DEFAULT_PREFIX],
        "unknown_sources": "drop",
        "store_excluded": True,
        "store_other": False,
        "exclude": [],
        "grouping": {
            "collect_seconds": 60,
            "quiet_minutes": 15,
            "retry_seconds": 5,
            "reminder_minutes": 60,
            "scan_ports": 3,
            "notify_on_close": False,
            "max_alerts_per_hour": 30,
        },
        "heartbeat": {"enabled": True, "missing_minutes": 30},
        "listen": [{"protocol": "udp", "address": "0.0.0.0", "port": 5514}],
        "store": [{"type": "sqlite", "path": "data/lantrap.sqlite3", "retention_days": 365}],
        "notify": [],
        "client": [],
        "trap": [],
    }


# ---------------------------------------------------------------- helpers

def _get(d: dict, key: str, kind: type | tuple, default: Any, where: str) -> Any:
    if key not in d or d[key] is None:
        return default
    value = d[key]
    kinds = kind if isinstance(kind, tuple) else (kind,)
    if bool not in kinds and isinstance(value, bool):
        raise ConfigError(f"{where}.{key}: expected {kinds[0].__name__}, got a boolean")
    if not isinstance(value, kinds):
        raise ConfigError(f"{where}.{key}: expected {kinds[0].__name__}, got {type(value).__name__}")
    return value


def _int(d: dict, key: str, default: int, where: str, minimum: int = 0, maximum: int | None = None) -> int:
    value = _get(d, key, int, default, where)
    if maximum is not None and not minimum <= value <= maximum:
        raise ConfigError(f"{where}.{key}: must be between {minimum} and {maximum}")
    if value < minimum:
        raise ConfigError(f"{where}.{key}: must be at least {minimum}")
    return value


def _choice(d: dict, key: str, choices: tuple, default: str, where: str) -> str:
    value = _get(d, key, str, default, where)
    if value not in choices:
        raise ConfigError(f"{where}.{key}: must be one of {', '.join(choices)}")
    return value


def _str_list(d: dict, key: str, where: str, default: tuple = ()) -> tuple:
    value = d.get(key)
    if value is None:
        return tuple(default)
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}.{key}: expected a list of strings")
    return tuple(value)


def _table_list(raw: dict, key: str) -> list:
    value = raw.get(key, [])
    if value is None:
        return []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ConfigError(f"{key}: expected a list of tables")
    return value


def resolve_path(value: str | None, base: Path) -> Path | None:
    if not value:
        return None
    p = Path(os.path.expandvars(os.path.expanduser(value)))
    return p if p.is_absolute() else (base / p)


def _check_id(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise ConfigError(f"{where}: id must be 1-64 letters, digits, '.', '_' or '-'")
    return value


def _has_secret(opts: dict, key: str) -> bool:
    return any(opts.get(k) for k in (key, f"{key}_env", f"{key}_file"))


# ---------------------------------------------------------------- parsing

def _parse_listener(item: dict, i: int, base: Path) -> Listener:
    where = f"listen[{i}]"
    protocol = _choice(item, "protocol", PROTOCOLS, "udp", where)
    address = _get(item, "address", str, "0.0.0.0", where)
    try:
        ipaddress.ip_address(address)
    except ValueError:
        raise ConfigError(f"{where}.address: {address!r} is not an IP address") from None
    port = _int(item, "port", 6514 if protocol == "tls" else 5514, where, 1, 65535)
    listener = Listener(protocol, address, port, allow=Matcher.parse(item.get("allow"), f"{where}.allow", allow_mac=False))
    if protocol == "tls":
        listener.certfile = resolve_path(_get(item, "certfile", str, None, where), base)
        listener.keyfile = resolve_path(_get(item, "keyfile", str, None, where), base)
        listener.cafile = resolve_path(_get(item, "cafile", str, None, where), base)
        if not listener.certfile or not listener.keyfile:
            raise ConfigError(f"{where}: a tls listener needs certfile and keyfile")
    return listener


def _parse_store(item: dict, i: int, base: Path) -> StoreConf:
    where = f"store[{i}]"
    if "type" not in item:
        raise ConfigError(f"{where}.type: required ({', '.join(STORE_TYPES)})")
    kind = _choice(item, "type", STORE_TYPES, "sqlite", where)
    key = "path" if kind == "sqlite" else "directory"
    default = "data/lantrap.sqlite3" if kind == "sqlite" else f"data/{kind}"
    location = resolve_path(_get(item, key, str, default, where), base) or base / default
    return StoreConf(kind, location, _int(item, "retention_days", 365, where, 0))


def _validate_notifier_options(kind: str, opts: dict, where: str) -> None:
    if kind == "smtp":
        if not isinstance(opts.get("host"), str) or not opts["host"]:
            raise ConfigError(f"{where}.host: required")
        _choice(opts, "security", SMTP_SECURITY, "starttls", where)
        if "port" in opts:
            _int(opts, "port", 587, where, 1, 65535)
        if not isinstance(opts.get("from"), str) or "@" not in opts["from"]:
            raise ConfigError(f"{where}.from: a sender address is required")
        to = _str_list(opts, "to", where)
        if not to or not all("@" in t for t in to):
            raise ConfigError(f"{where}.to: at least one recipient address is required")
        if opts.get("username") and not _has_secret(opts, "password"):
            raise ConfigError(f"{where}: username given without password, password_env or password_file")
    elif kind in ("google_chat", "webhook"):
        if not _has_secret(opts, "url"):
            raise ConfigError(f"{where}: url, url_env or url_file is required")
        url = opts.get("url")
        if isinstance(url, str) and not url.lower().startswith(("https://", "http://")):
            raise ConfigError(f"{where}.url: must start with https:// or http://")
        for key in ("headers", "headers_env"):
            value = opts.get(key, {})
            if not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values()):
                raise ConfigError(f"{where}.{key}: expected a table of strings")
    elif kind == "command":
        argv = opts.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
            raise ConfigError(f"{where}.argv: expected a non-empty list of strings")
    if "timeout" in opts:
        _int(opts, "timeout", 20, where, 1, 600)


def _parse_notifier(item: dict, i: int, base: Path, names: set) -> NotifierConf | None:
    where = f"notify[{i}]"
    kind = item.get("type")
    if kind not in NOTIFIER_TYPES:
        raise ConfigError(f"{where}.type: must be one of {', '.join(NOTIFIER_TYPES)}")
    name = _get(item, "name", str, f"{kind}-{i + 1}", where)
    if name in names:
        raise ConfigError(f"{where}.name: duplicate name {name!r}")
    names.add(name)
    events = _str_list(item, "events", where, ALERT_KINDS)
    for e in events:
        if e not in ALERT_KINDS:
            raise ConfigError(f"{where}.events: unknown event {e!r} ({', '.join(ALERT_KINDS)})")
    language = item.get("language")
    if language is not None and language not in LANGUAGES:
        raise ConfigError(f"{where}.language: must be one of {', '.join(LANGUAGES)}")
    if not _get(item, "enabled", bool, True, where):
        return None
    opts = {k: v for k, v in item.items() if k not in ("name", "type", "events", "clients", "language", "enabled")}
    _validate_notifier_options(kind, opts, where)
    return NotifierConf(name, kind, events, _str_list(item, "clients", where), language, opts, base)


def _parse_openwrt(raw: dict) -> OpenWrtConf:
    where = "openwrt"
    d = raw.get(where) or {}
    if not isinstance(d, dict):
        raise ConfigError("openwrt: expected a table")
    ports = d.get("ports", DEFAULT_TRAP_PORTS)
    if not isinstance(ports, list) or not ports or not all(isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in ports):
        raise ConfigError("openwrt.ports: expected a list of TCP ports")
    set_name = _get(d, "set_name", str, "lantrap_exclude", where)
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,30}$", set_name):
        raise ConfigError("openwrt.set_name: letters, digits and '_' only")
    interface = _get(d, "interface", str, "br-lan", where)
    if not re.match(r"^[A-Za-z0-9._@-]{1,15}$", interface):
        raise ConfigError("openwrt.interface: invalid interface name")
    return OpenWrtConf(
        receiver=_get(d, "receiver", str, "", where),
        log_port=_int(d, "log_port", 5514, where, 1, 65535),
        log_proto=_choice(d, "log_proto", ("udp", "tcp"), "udp", where),
        ports=tuple(ports),
        interface=interface,
        set_name=set_name,
        rate_per_minute=_int(d, "rate_per_minute", 60, where, 1, 10000),
        heartbeat_minutes=_int(d, "heartbeat_minutes", 10, where, 0, 59),
        ntp_servers=_str_list(d, "ntp_servers", where),
        ipv6=_get(d, "ipv6", bool, False, where),
    )


def _parse_wireguard(raw: dict) -> WireGuardConf | None:
    d = raw.get("wireguard")
    if not d:
        return None
    if not isinstance(d, dict):
        raise ConfigError("wireguard: expected a table")
    where = "wireguard"
    wg = WireGuardConf(
        endpoint=_get(d, "endpoint", str, "", where),
        public_key=_get(d, "public_key", str, "", where),
        receiver_ip=_get(d, "receiver_ip", str, "", where),
        network=_get(d, "network", str, "", where),
        keepalive=_int(d, "keepalive", 25, where, 0, 3600),
    )
    for key in ("receiver_ip",):
        value = getattr(wg, key)
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ConfigError(f"wireguard.{key}: not an IP address") from None
    if wg.network:
        try:
            ipaddress.ip_network(wg.network, strict=False)
        except ValueError:
            raise ConfigError("wireguard.network: not a network") from None
    return wg


def parse_config(raw: dict, path: Path | None = None, fmt: str = "toml") -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("the configuration must be a table/object")
    base = path.parent if path else Path.cwd()
    cfg = Config(path=path, format=fmt, raw=raw)
    cfg.language = _choice(raw, "language", LANGUAGES, "en", "settings")
    prefixes = _str_list(raw, "prefixes", "settings", (DEFAULT_PREFIX,))
    cfg.prefixes = tuple(p.strip() for p in prefixes if p.strip())
    for prefix in cfg.prefixes:
        # it ends up in an nft "log prefix" string on the boxes
        if len(prefix) > 120 or not _PREFIX_RE.match(prefix):
            raise ConfigError(f"settings.prefixes: {prefix!r} must be printable ASCII without quotes or backslashes, at most 120 characters")
    cfg.unknown_sources = _choice(raw, "unknown_sources", ("drop", "accept"), "drop", "settings")
    cfg.store_excluded = _get(raw, "store_excluded", bool, True, "settings")
    cfg.store_other = _get(raw, "store_other", bool, False, "settings")
    cfg.exclude = Matcher.parse(raw.get("exclude"), "exclude")

    g = raw.get("grouping") or {}
    if not isinstance(g, dict):
        raise ConfigError("grouping: expected a table")
    cfg.grouping = Grouping(
        collect_seconds=_int(g, "collect_seconds", 60, "grouping", 0, 3600),
        quiet_minutes=_int(g, "quiet_minutes", 15, "grouping", 1, 1440),
        retry_seconds=_int(g, "retry_seconds", 5, "grouping", 0, 600),
        reminder_minutes=_int(g, "reminder_minutes", 60, "grouping", 0, 10080),
        scan_ports=_int(g, "scan_ports", 3, "grouping", 2, 65535),
        notify_on_close=_get(g, "notify_on_close", bool, False, "grouping"),
        max_alerts_per_hour=_int(g, "max_alerts_per_hour", 30, "grouping", 0),
    )
    h = raw.get("heartbeat") or {}
    if not isinstance(h, dict):
        raise ConfigError("heartbeat: expected a table")
    cfg.heartbeat = Heartbeat(
        enabled=_get(h, "enabled", bool, True, "heartbeat"),
        missing_minutes=_int(h, "missing_minutes", 30, "heartbeat", 1, 10080),
    )

    cfg.listeners = [_parse_listener(item, i, base) for i, item in enumerate(_table_list(raw, "listen"))]
    seen = set()
    for lst in cfg.listeners:
        key = (lst.protocol in ("tcp", "tls"), lst.address, lst.port)
        if key in seen:
            raise ConfigError(f"listen: {lst.label} is configured twice")
        seen.add(key)
    cfg.stores = [_parse_store(item, i, base) for i, item in enumerate(_table_list(raw, "store"))]
    if sum(1 for s in cfg.stores if s.type == "sqlite") > 1:
        raise ConfigError("store: only one sqlite store is supported")
    names: set = set()
    cfg.notifiers = [n for n in (_parse_notifier(item, i, base, names) for i, item in enumerate(_table_list(raw, "notify"))) if n]

    for i, item in enumerate(_table_list(raw, "client")):
        where = f"client[{i}]"
        cid = _check_id(item.get("id"), f"{where}.id")
        if cid in cfg.clients:
            raise ConfigError(f"{where}.id: duplicate client {cid!r}")
        name = _get(item, "name", str, cid, where)
        if _NAME_BAD.search(name):
            raise ConfigError(f"{where}.name: control characters are not allowed")
        cfg.clients[cid] = Client(cid, name, Matcher.parse(item.get("exclude"), f"{where}.exclude"))

    for i, item in enumerate(_table_list(raw, "trap")):
        where = f"trap[{i}]"
        tid = _check_id(item.get("id"), f"{where}.id")
        if tid in cfg.traps:
            raise ConfigError(f"{where}.id: duplicate trap {tid!r}")
        client = _get(item, "client", str, None, where)
        if not client or client not in cfg.clients:
            raise ConfigError(f"{where}.client: unknown client {client!r}")
        trap = Trap(
            id=tid,
            name=_get(item, "name", str, tid, where),
            client=client,
            source=Matcher.parse(list(_str_list(item, "source", where)), f"{where}.source", allow_mac=False),
            hostname=_get(item, "hostname", str, None, where) or None,
            exclude=Matcher.parse(item.get("exclude"), f"{where}.exclude"),
            heartbeat=_get(item, "heartbeat", bool, None, where),
            tunnel_ip=_get(item, "tunnel_ip", str, None, where) or None,
        )
        if trap.tunnel_ip:
            try:
                if "%" in trap.tunnel_ip:
                    raise ValueError
                trap.tunnel_ip = str(ipaddress.ip_address(trap.tunnel_ip))
            except ValueError:
                raise ConfigError(f"{where}.tunnel_ip: {trap.tunnel_ip!r} is not an IP address") from None
        if _NAME_BAD.search(trap.name):
            raise ConfigError(f"{where}.name: control characters are not allowed")
        if not trap.source and not trap.hostname:
            raise ConfigError(f"{where}: set source (IP address or network of the sender) and/or hostname")
        cfg.traps[tid] = trap

    cfg.openwrt = _parse_openwrt(raw)
    cfg.wireguard = _parse_wireguard(raw)
    return cfg


def detect_format(path: Path) -> str:
    return "json" if path.suffix.lower() == ".json" else "toml"


def load_raw(path: Path) -> tuple[dict, str]:
    fmt = detect_format(path)
    data = path.read_bytes()
    try:
        if fmt == "json":
            raw = json.loads(data.decode("utf-8-sig"))
        else:
            raw = tomllib.loads(data.decode("utf-8-sig"))
    except (tomllib.TOMLDecodeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path.name}: cannot read {fmt.upper()}: {exc}") from None
    return raw, fmt


def load_config(path: Path) -> Config:
    path = Path(path).resolve()
    raw, fmt = load_raw(path)
    return parse_config(raw, path, fmt)


def dumps(raw: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(raw, indent=2, ensure_ascii=False) + "\n"
    return tomlw.dumps(raw, CONFIG_HEADER)


def save_raw(raw: dict, path: Path, fmt: str | None = None) -> Config:
    """Validate and write atomically; returns the parsed configuration."""
    path = Path(path).resolve()
    fmt = fmt or detect_format(path)
    cfg = parse_config(copy.deepcopy(raw), path, fmt)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    # the file may hold secrets: new files are private, existing ones keep their permissions
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dumps(raw, fmt))
    os.replace(tmp, path)
    return cfg


def find_config(explicit: str | None) -> Path:
    """--config, then LANTRAP_CONFIG, then ./lantrap.toml or ./lantrap.json, then /etc/lantrap/lantrap.toml."""
    if explicit:
        return Path(explicit)
    env = os.environ.get("LANTRAP_CONFIG")
    if env:
        return Path(env)
    for name in ("lantrap.toml", "lantrap.json"):
        if Path(name).exists():
            return Path(name)
    system = Path("/etc/lantrap/lantrap.toml")
    if os.name != "nt" and system.exists():
        return system
    return Path("lantrap.toml")


def resolve_secret(opts: dict, key: str, base: Path, required: bool = True) -> str | None:
    """A secret given inline (key), in an environment variable (key_env) or in a file (key_file)."""
    if opts.get(key):
        return str(opts[key])
    env = opts.get(f"{key}_env")
    if env:
        value = os.environ.get(env)
        if value:
            return value
        if required:
            raise ConfigError(f"environment variable {env} ({key}) is empty or not set")
    file = opts.get(f"{key}_file")
    p = resolve_path(file, base) if file else None
    if p:
        try:
            return p.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"cannot read {key}_file {p}: {exc.strerror}") from None
    if required:
        raise ConfigError(f"{key} is not set")
    return None
