"""Command line: the interactive menu by default, subcommands for scripts and services."""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__, openwrt, service, simulate, stores
from .config import Config, ConfigError, default_raw, find_config, load_config, save_raw
from .engine import Engine
from .i18n import t
from .notify import build_notifiers, describe, render
from .syslogparse import parse_syslog


def _setup_logging(verbose: bool, log_file: str | None) -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # a hostname must never break a log line
        except (AttributeError, ValueError):
            pass
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8"))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lantrap", description="Syslog receiver for OpenWrt LAN traps.")
    p.add_argument("-c", "--config", help="configuration file, .toml or .json (default: ./lantrap.toml)")
    p.add_argument("--lang", choices=("en", "it"), help="menu and output language (default: from the configuration)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--log-file", help="also write the log to this file (rotated at 5 MB)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", metavar="command")
    sub.add_parser("menu", help="interactive menu (default)")
    sub.add_parser("run", help="run the receiver in the foreground")
    i = sub.add_parser("init", help="create a configuration file with default settings")
    i.add_argument("--force", action="store_true", help="overwrite an existing file")
    sub.add_parser("check", help="validate the configuration and the alert channels")
    s = sub.add_parser("status", help="traps, unknown senders and latest incidents")
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("incidents", help="latest incidents")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("test-alert", help="send a test alert")
    s.add_argument("--channel", action="append", help="channel name (repeatable; default: all)")
    s = sub.add_parser("simulate", help="send fake trap lines to a running receiver")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5514)
    s.add_argument("--proto", choices=("udp", "tcp"), default="udp")
    s.add_argument("--src", default="192.168.1.2", help="source address of the fake scan")
    s.add_argument("--dst", default="192.168.1.1", help="address of the trap in the LAN")
    s.add_argument("--ports", default="21,23,445,3389,8080")
    s.add_argument("--retries", type=int, default=5, help="log lines per attempt (Windows retries a refused SYN)")
    s.add_argument("--hostname", default="OpenWrt")
    s.add_argument("--prefix", help="log prefix (default: the first configured prefix)")
    s = sub.add_parser("import", help="analyse saved log lines (logread output or syslog) offline")
    s.add_argument("file", help="text file, one line per message ('-' = standard input)")
    s.add_argument("--trap", help="trap id the lines come from (default: recognised from --peer and the hostname)")
    s.add_argument("--peer", default="127.0.0.1", help="sender address to assume")
    s.add_argument("--save", action="store_true", help="write hits and incidents to the configured history")
    s = sub.add_parser("openwrt", help="print the setup script for a trap box")
    s.add_argument("trap", help="trap id")
    s.add_argument("-o", "--output", help="write the script to this file")
    s = sub.add_parser("service", help="how to keep the receiver running")
    s.add_argument("kind", choices=("systemd", "windows", "docker"))
    s.add_argument("--write", action="store_true", help="windows: write the start file next to the configuration")
    return p


def _load(path: Path) -> Config:
    return load_config(path)


def cmd_init(path: Path, force: bool) -> int:
    if path.exists() and not force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    save_raw(default_raw(), path)
    print(f"created {path.resolve()}")
    return 0


def cmd_check(cfg: Config) -> int:
    notifiers = build_notifiers(cfg, strict=True)
    print(f"configuration: {cfg.path} ({cfg.format})")
    print(f"listeners: {', '.join(lst.label for lst in cfg.listeners) or 'none'}")
    print(f"storage: {', '.join(f'{s.type} {s.path}' for s in cfg.stores) or 'none'}")
    print(f"alert channels: {', '.join(describe(n) for n in notifiers) or 'none'}")
    print(f"clients: {len(cfg.clients)}, traps: {len(cfg.traps)}, prefixes: {', '.join(cfg.prefixes) or 'any'}")
    if not cfg.listeners:
        print("warning: no listener configured", file=sys.stderr)
    return 0


def cmd_status(cfg: Config, lang: str, as_json: bool) -> int:
    from .menu import status_lines
    db = cfg.sqlite_path()
    if not db or not db.exists():
        print(t(lang, "msg.no_sqlite" if not db else "msg.no_db"), file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps({"traps": stores.trap_rows(db), "unknown_senders": stores.unknown_rows(db),
                          "incidents": stores.recent_incidents(db, 10)}, indent=2, ensure_ascii=False))
    else:
        print("\n".join(status_lines(cfg, lang)))
    return 0


def cmd_incidents(cfg: Config, limit: int, as_json: bool) -> int:
    db = cfg.sqlite_path()
    if not db or not db.exists():
        print("no SQLite history", file=sys.stderr)
        return 1
    rows = stores.recent_incidents(db, limit)
    if as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    for r in rows:
        ports = ", ".join(f"{p['port']}/{p['proto']}" for p in r["ports"])
        last = datetime.fromisoformat(r["last_seen"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{last}  {r['id']}  {r['client_name']} / {r['trap_name']}  {r['source_ip']}  "
              f"{r['classification']}  {r['attempts']} attempts ({r['lines']} lines)  [{ports}]  {r['status']}")
    return 0


def cmd_test_alert(cfg: Config, channels: list[str] | None) -> int:
    from .menu import send_test
    if not cfg.notifiers:
        print(t(cfg.language, "msg.no_notifiers"), file=sys.stderr)
        return 1
    unknown = [c for c in channels or [] if c not in {n.name for n in cfg.notifiers}]
    if unknown:
        print(f"unknown channel: {', '.join(unknown)}", file=sys.stderr)
        return 1
    results = send_test(cfg, channels)
    print("\n".join(line for _, line in results))
    return 0 if all(ok for ok, _ in results) else 1


def cmd_import(cfg: Config, file: str, trap_id: str | None, peer: str, save: bool, lang: str) -> int:
    from .stores import build_stores
    trap = None
    if trap_id:
        trap = cfg.traps.get(trap_id)
        if trap is None:
            print(f"unknown trap {trap_id}", file=sys.stderr)
            return 1
    text = sys.stdin.read() if file == "-" else Path(file).read_text(encoding="utf-8-sig", errors="replace")
    now = datetime.now(timezone.utc)
    engine = Engine(cfg, now)
    history = build_stores(cfg.stores) if save else []
    counts = {"hit": 0, "excluded": 0, "other": 0, "unknown": 0}
    clock: datetime | None = None
    first_uptime: float | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        msg = parse_syslog(line, now)
        # saved logs are grouped by their own time: the date in the line, else the kernel uptime
        if msg.device_time:
            when = msg.device_time.astimezone(timezone.utc)
        elif msg.uptime is not None:
            first_uptime = msg.uptime if first_uptime is None else first_uptime
            when = now + timedelta(seconds=msg.uptime - first_uptime)
        else:
            when = clock or now
        clock = max(clock, when) if clock else when
        res = engine.receive(peer, msg, clock, trap=trap)
        counts[res.status] += 1
        if save and res.hit and (not res.hit.excluded or cfg.store_excluded):
            for s in history:
                s.write_hit(res.hit)
    end = (clock or now) + timedelta(minutes=cfg.grouping.quiet_minutes, seconds=cfg.grouping.collect_seconds + 1)
    alerts, closed = engine.tick(end)
    for alert in alerts:
        if alert.kind.startswith("incident"):
            title, body = render(alert, lang)
            print(title)
            print(body)
            print()
    for s in history:
        for inc in closed:
            s.write_incident(engine.snapshot(inc), "closed")
        s.close()
    print(f"lines: {sum(counts.values())}, trap hits: {counts['hit']}, excluded: {counts['excluded']}, "
          f"other: {counts['other']}, unknown sender: {counts['unknown']}, incidents: {len(closed)}")
    return 0


def cmd_openwrt(cfg: Config, trap_id: str, output: str | None) -> int:
    trap = cfg.traps.get(trap_id)
    if trap is None:
        print(f"unknown trap {trap_id}", file=sys.stderr)
        return 1
    script = openwrt.box_script(cfg, trap)
    if output:
        Path(output).write_text(script, encoding="utf-8", newline="\n")
        print(f"written {output}")
    else:
        sys.stdout.write(script)
    return 0


def cmd_service(cfg: Config, kind: str, write: bool) -> int:
    if kind == "systemd":
        print(service.systemd_unit(cfg))
    elif kind == "windows":
        if write:
            path, content = service.windows_wrapper(cfg)
            path.write_text(content, encoding="utf-8", newline="")
            print(f"written {path}")
        print(service.windows_task(cfg))
    else:
        print(service.docker_hint())
    return 0


def cmd_simulate(cfg: Config | None, args) -> int:
    prefix = args.prefix or (cfg.prefixes[0] if cfg and cfg.prefixes else "LANTRAP:")
    ports = [int(p) for p in args.ports.split(",") if p.strip().isdigit()]
    lines = simulate.scan_lines(ports, src=args.src, dst=args.dst, retries=args.retries, prefix=prefix, hostname=args.hostname)
    simulate.send(lines, args.host, args.port, args.proto)
    print(f"sent {len(lines)} lines to {args.proto}://{args.host}:{args.port}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = args.command or "menu"
    path = find_config(args.config)
    if command == "menu":
        if not sys.stdin.isatty():
            print(t(args.lang or "en", "msg.interactive_only"), file=sys.stderr)
            return 2
        from .menu import App
        _setup_logging(args.verbose, args.log_file)
        return App(path, args.lang).main()
    _setup_logging(args.verbose, args.log_file)
    if command == "init":
        return cmd_init(path, args.force)
    try:
        if command == "simulate":
            return cmd_simulate(load_config(path) if path.exists() else None, args)
        cfg = _load(path)
        lang = args.lang or cfg.language
        if command == "run":
            from .server import run
            return run(path)
        if command == "check":
            return cmd_check(cfg)
        if command == "status":
            return cmd_status(cfg, lang, args.json)
        if command == "incidents":
            return cmd_incidents(cfg, args.limit, args.json)
        if command == "test-alert":
            return cmd_test_alert(cfg, args.channel)
        if command == "import":
            return cmd_import(cfg, args.file, args.trap, args.peer, args.save, lang)
        if command == "openwrt":
            return cmd_openwrt(cfg, args.trap, args.output)
        if command == "service":
            return cmd_service(cfg, args.kind, args.write)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"{exc.filename}: file not found (create one with: lantrap init)", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
