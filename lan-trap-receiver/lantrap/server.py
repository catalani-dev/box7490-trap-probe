"""The long-running receiver: listeners, timer, history, alerts and configuration reload."""

from __future__ import annotations

import asyncio
import logging
import signal
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .config import Config, ConfigError, Listener, load_config
from .engine import Alert, Engine, Incident, iso
from .notify import Notifier, build_notifiers, deliver, describe
from .stores import SqliteStore, Store, build_stores
from .syslogparse import MAX_FRAME, FramingError, StreamFramer, parse_syslog, split_datagram

log = logging.getLogger("lantrap")

MAX_TCP_CONNECTIONS = 512
MAX_CONNECTIONS_PER_PEER = 16
TCP_IDLE_SECONDS = 1800  # traps send a heartbeat every few minutes
RELOAD_CHECK_SECONDS = 5
STATE_SAVE_SECONDS = 30
PURGE_HOURS = 6
UNKNOWN_WARN_INTERVAL = timedelta(hours=1)
UNKNOWN_SAVE_INTERVAL = timedelta(minutes=1)
ERROR_LOG_INTERVAL = timedelta(minutes=1)
# a channel that failed is tried again after these delays (in memory: a restart forgets them)
REDELIVERY_MINUTES = (1, 5, 15, 30, 60, 120, 240)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _peer_ip(addr) -> str:
    host = addr[0] if isinstance(addr, tuple) else str(addr)
    return host[7:] if host.startswith("::ffff:") and "." in host else host


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: Receiver, listener: Listener) -> None:
        self.receiver = receiver
        self.listener = listener

    def datagram_received(self, data: bytes, addr) -> None:
        peer = _peer_ip(addr)
        if self.listener.allow and not self.listener.allow.match(peer):
            self.receiver.dropped += 1
            return
        for frame in split_datagram(data[:MAX_FRAME]):
            self.receiver.handle_frame(frame, peer)

    def error_received(self, exc: Exception) -> None:
        log.debug("udp error on %s: %s", self.listener.label, exc)


class Receiver:
    def __init__(self, config: Config, notifiers: list[Notifier] | None = None, stores: list[Store] | None = None,
                 now: Callable[[], datetime] = utcnow, tick_seconds: float = 1.0) -> None:
        self.config = config
        self.now = now
        self.tick_seconds = tick_seconds
        self.engine = Engine(config, now())
        self.notifiers = notifiers if notifiers is not None else build_notifiers(config, strict=False)
        self.stores = stores if stores is not None else build_stores(config.stores)
        self.bound: list[tuple[str, str, int]] = []
        self.received = 0
        self.dropped = 0
        self._servers: list = []
        self._transports: list = []
        self._tasks: set[asyncio.Task] = set()
        self._connections = 0
        self._peer_connections: dict[str, int] = {}
        self._redeliveries: list[tuple[datetime, int, Alert, str]] = []
        self._frame_errors = 0
        self._last_error_log: datetime | None = None
        self._config_mtime = self._mtime()
        self._reload_requested = False
        self._last_reload_check = 0.0
        self._last_state_save = now()
        self._last_purge: datetime | None = None
        self._clock_warned: set[str] = set()

    # ------------------------------------------------------------ input

    def handle_frame(self, data: bytes, peer: str) -> None:
        now = self.now()
        self.received += 1
        try:
            self._handle(data, peer, now)
        except Exception:
            # one malformed message must not stop the listener; log at most once a minute
            self._frame_errors += 1
            if self._last_error_log is None or now - self._last_error_log >= ERROR_LOG_INTERVAL:
                self._last_error_log = now
                log.exception("cannot handle a message from %s (%d errors so far)", peer, self._frame_errors)

    def _handle(self, data: bytes, peer: str, now: datetime) -> None:
        text = data.decode("utf-8", "replace")
        msg = parse_syslog(text, now)
        res = self.engine.receive(peer, msg, now)
        if res.status == "unknown" and res.unknown:
            u = res.unknown
            if u.saved_at is None or now - u.saved_at >= UNKNOWN_SAVE_INTERVAL:
                u.saved_at = now
                self._each_store("write_unknown", u.peer, u.hostname, u.first_seen, u.last_seen, u.count)
            if u.warned_at is None or now - u.warned_at >= UNKNOWN_WARN_INTERVAL:
                u.warned_at = now
                log.warning("message from unknown sender %s (hostname %s) dropped: add it as a trap "
                            "or set unknown_sources = \"accept\"", peer, u.hostname or "-")
            return
        if res.hit and (not res.hit.excluded or self.config.store_excluded):
            self._each_store("write_hit", res.hit)
        elif res.status == "other" and self.config.store_other and res.trap:
            self._each_store("write_other", now, res.trap.id, peer, msg.hostname, msg.tag, msg.message)
        if res.trap:
            st = self.engine.state(res.trap.id)
            if st.clock_ok is False and res.trap.id not in self._clock_warned:
                self._clock_warned.add(res.trap.id)
                log.warning("trap %s: clock differs from ours by %.0f s, check NTP on the box", res.trap.id, st.clock_skew or 0)
            elif st.clock_ok:
                self._clock_warned.discard(res.trap.id)
        self._dispatch(res.alerts)

    # ------------------------------------------------------------ stores

    def _each_store(self, method: str, *args) -> None:
        for store in self.stores:
            try:
                getattr(store, method)(*args)
            except Exception as exc:
                log.error("%s store: %s failed: %s", store.kind, method, exc)

    def _save_incident(self, inc: Incident, reason: str) -> None:
        self._each_store("write_incident", self.engine.snapshot(inc), reason)

    def _save_trap_states(self) -> None:
        for trap_id, st in self.engine.trap_states.items():
            trap = self.engine.trap(trap_id)
            state = {
                "last_seen": iso(st.last_seen), "last_peer": st.last_peer, "last_hostname": st.last_hostname,
                "clock_skew": st.clock_skew, "clock_ok": st.clock_ok, "silent": st.silent,
                "messages": st.messages, "hits": st.hits,
            }
            self._each_store("write_trap_state", trap_id, trap.client if trap else "", state)

    # ------------------------------------------------------------ alerts

    def _dispatch(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            if not self.notifiers:
                log.info("alert %s (no alert channel configured)", alert.kind)
                continue
            task = asyncio.get_running_loop().create_task(self._send(alert))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _send(self, alert: Alert, notifiers: list[Notifier] | None = None, attempt: int = 0) -> None:
        records = await asyncio.to_thread(deliver, alert, notifiers or list(self.notifiers), self.config, attempt == 0)
        for record in records:
            self._each_store("write_alert", record)
            if record["status"] == "failed" and attempt < len(REDELIVERY_MINUTES):
                due = self.now() + timedelta(minutes=REDELIVERY_MINUTES[attempt])
                self._redeliveries.append((due, attempt + 1, alert, record["channel"]))

    def _redeliver(self, now: datetime) -> None:
        due = [r for r in self._redeliveries if r[0] <= now]
        if not due:
            return
        self._redeliveries = [r for r in self._redeliveries if r[0] > now]
        by_name = {n.name: n for n in self.notifiers}
        for _, attempt, alert, name in due:
            notifier = by_name.get(name)
            if notifier is None:
                log.warning("alert %s for channel %s dropped: the channel no longer exists", alert.kind, name)
                continue
            task = asyncio.get_running_loop().create_task(self._send(alert, [notifier], attempt))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------ timer

    def tick(self) -> None:
        now = self.now()
        alerts, closed = self.engine.tick(now)
        for inc in closed:
            self._save_incident(inc, "closed")
        for alert in alerts:
            if alert.incident:
                self._each_store("write_incident", alert.incident, "alert")
        for inc in self.engine.take_dirty():
            self._save_incident(inc, "update")
        self._dispatch(alerts)
        self._redeliver(now)
        if now - self._last_state_save >= timedelta(seconds=STATE_SAVE_SECONDS):
            self._last_state_save = now
            self._save_trap_states()
        if self._last_purge is None or now - self._last_purge >= timedelta(hours=PURGE_HOURS):
            self._last_purge = now
            for store in self.stores:
                try:
                    removed = store.purge(now)
                    if removed:
                        log.info("%s store: removed %d old records", store.kind, removed)
                except Exception as exc:
                    log.error("%s store: purge failed: %s", store.kind, exc)
        self._each_store("flush")

    # ------------------------------------------------------------ reload

    def _mtime(self) -> float | None:
        try:
            return self.config.path.stat().st_mtime if self.config.path else None
        except OSError:
            return None

    def request_reload(self) -> None:
        self._reload_requested = True

    def check_reload(self) -> bool:
        mtime = self._mtime()
        if not self._reload_requested and (mtime is None or mtime == self._config_mtime):
            return False
        self._reload_requested = False
        self._config_mtime = mtime
        if not self.config.path:
            return False
        try:
            new = load_config(self.config.path)
            notifiers = build_notifiers(new, strict=False)
        except Exception as exc:
            log.error("configuration not reloaded, keeping the previous one: %s", exc)
            return False
        if new.listeners != self.config.listeners or new.stores != self.config.stores:
            log.warning("listener or storage changes (addresses, ports, allow lists, certificates, paths, "
                        "retention) need a restart; the other changes are applied")
            new.listeners, new.stores = self.config.listeners, self.config.stores
        self.config = new
        self.engine.reload(new, self.now())
        self.notifiers = notifiers
        log.info("configuration reloaded: %d clients, %d traps, %d alert channels",
                 len(new.clients), len(new.traps), len(self.notifiers))
        return True

    # ------------------------------------------------------------ network

    def _tls_context(self, listener: Listener) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(listener.certfile), str(listener.keyfile))
        if listener.cafile:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(str(listener.cafile))
        return ctx

    async def _handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, listener: Listener) -> None:
        peer = _peer_ip(writer.get_extra_info("peername") or ("?",))
        if ((listener.allow and not listener.allow.match(peer)) or self._connections >= MAX_TCP_CONNECTIONS
                or self._peer_connections.get(peer, 0) >= MAX_CONNECTIONS_PER_PEER):
            self.dropped += 1
            writer.close()
            return
        self._connections += 1
        self._peer_connections[peer] = self._peer_connections.get(peer, 0) + 1
        framer = StreamFramer()
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), timeout=TCP_IDLE_SECONDS)
                if not data:
                    break
                for frame in framer.feed(data):
                    self.handle_frame(frame, peer)
        except TimeoutError:
            log.debug("%s from %s: idle for %d s, connection closed", listener.label, peer, TCP_IDLE_SECONDS)
        except FramingError as exc:
            log.warning("%s from %s: %s, connection closed", listener.label, peer, exc)
        except (ConnectionError, ssl.SSLError, OSError) as exc:
            log.debug("%s from %s: %s", listener.label, peer, exc)
        finally:
            self._connections -= 1
            left = self._peer_connections.get(peer, 1) - 1
            if left > 0:
                self._peer_connections[peer] = left
            else:
                self._peer_connections.pop(peer, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        if not self.config.listeners:
            raise ConfigError("no listener configured")
        for store in self.stores:
            if isinstance(store, SqliteStore):
                stale = store.close_stale_incidents()
                if stale:
                    log.info("closed %d incidents left open by the previous run", stale)
        for listener in self.config.listeners:
            if listener.protocol == "udp":
                transport, _ = await loop.create_datagram_endpoint(
                    lambda lst=listener: _UdpProtocol(self, lst), local_addr=(listener.address, listener.port))
                self._transports.append(transport)
                port = transport.get_extra_info("sockname")[1]
            else:
                ctx = self._tls_context(listener) if listener.protocol == "tls" else None
                server = await asyncio.start_server(
                    lambda r, w, lst=listener: self._handle_stream(r, w, lst), listener.address, listener.port,
                    ssl=ctx, limit=MAX_FRAME * 2)
                self._servers.append(server)
                port = server.sockets[0].getsockname()[1]
            self.bound.append((listener.protocol, listener.address, port))
            log.info("listening on %s://%s:%d", listener.protocol, listener.address, port)
        for store in self.stores:
            log.info("history: %s at %s", store.kind, store.conf.path)
        for n in self.notifiers:
            log.info("alert channel %s: %s", n.name, describe(n))
        if not self.notifiers:
            log.warning("no alert channel configured: incidents are only recorded")
        log.info("%d clients, %d traps configured", len(self.config.clients), len(self.config.traps))

    async def serve(self, stop: asyncio.Event) -> None:
        loop = asyncio.get_running_loop()
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.tick_seconds)
            except TimeoutError:
                pass
            try:
                if loop.time() - self._last_reload_check >= RELOAD_CHECK_SECONDS or self._reload_requested:
                    self._last_reload_check = loop.time()
                    self.check_reload()
                self.tick()
            except Exception:
                log.exception("error in the receiver loop, continuing")

    async def close(self, timeout: float = 30) -> None:
        for transport in self._transports:
            transport.close()
        for server in self._servers:
            server.close()
        for server in self._servers:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=2)
            except (TimeoutError, Exception):
                pass
        self.tick()
        # incidents still in their collection window (or waiting for the hourly limit) are not lost
        pending = self.engine.pending_alerts(self.now())
        for alert in pending:
            self._each_store("write_incident", alert.incident, "alert")
        self._dispatch(pending)
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=timeout)
        if self._redeliveries:
            log.warning("%d alert deliveries still to retry are dropped at shutdown", len(self._redeliveries))
        for inc in self.engine.close_all():
            self._save_incident(inc, "update")
        self._save_trap_states()
        for store in self.stores:
            try:
                store.close()
            except Exception as exc:
                log.error("%s store: close failed: %s", store.kind, exc)


async def run_receiver(config: Config, stop: asyncio.Event | None = None) -> None:
    stop = stop or asyncio.Event()
    receiver = Receiver(config)
    loop = asyncio.get_running_loop()
    for sig, handler in ((getattr(signal, "SIGTERM", None), stop.set), (getattr(signal, "SIGINT", None), stop.set),
                         (getattr(signal, "SIGHUP", None), receiver.request_reload)):
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, handler)
        except (NotImplementedError, RuntimeError):
            pass  # Windows: Ctrl+C arrives as KeyboardInterrupt
    await receiver.start()
    try:
        await receiver.serve(stop)
    finally:
        await receiver.close()
        log.info("receiver stopped (%d messages received)", receiver.received)


def run(config_path: Path) -> int:
    config = load_config(config_path)
    try:
        asyncio.run(run_receiver(config))
    except KeyboardInterrupt:
        pass
    return 0
