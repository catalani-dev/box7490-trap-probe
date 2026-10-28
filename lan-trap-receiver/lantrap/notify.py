"""Alert text, JSON payload and delivery channels (SMTP, Google Chat, webhook, command)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import smtplib
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import __version__
from .config import Config, ConfigError, NotifierConf, resolve_secret, resolve_path
from .engine import Alert, iso
from .i18n import t

log = logging.getLogger("lantrap.notify")

SCHEMA = "lantrap.alert/1"
RETRY_DELAYS = (2.0, 10.0)
MAX_PORTS_IN_TEXT = 30
MAX_CHAT_TEXT = 3800  # Google Chat rejects longer text messages
USER_AGENT = f"lan-trap-receiver/{__version__}"


# ---------------------------------------------------------------- text

def _local(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def _ports_text(ports: list, untracked: int, lang: str) -> str:
    items = []
    for p in ports[:MAX_PORTS_IN_TEXT]:
        label = f"{p['port']}/{p['proto']}" if p.get("port") is not None else p["proto"]
        if p.get("service"):
            label += f" {p['service']}"
        if p.get("attempts", 1) > 1:
            label += f" x{p['attempts']}"
        items.append(label)
    more = len(ports) - MAX_PORTS_IN_TEXT
    if more > 0:
        items.append(f"+{more}")
    if untracked:
        items.append(t(lang, "v.untracked", n=untracked))
    return ", ".join(items) or "-"


def _what(inc: dict, lang: str) -> str:
    key = "title.port_scan" if inc["classification"] == "port_scan" else "title.connection_attempt"
    return t(lang, key, src=inc["source_ip"])


def render(alert: Alert, lang: str) -> tuple[str, str]:
    """Title and plain-text body."""
    client = alert.client.name if alert.client else None
    trap = alert.trap.name if alert.trap else None
    lines: list[tuple[str, str]] = []
    if alert.kind in ("incident", "incident_update", "incident_closed") and alert.incident:
        inc = alert.incident
        what = _what(inc, lang)
        title = {"incident": what, "incident_update": t(lang, "title.update", what=what),
                 "incident_closed": t(lang, "title.closed", what=what)}[alert.kind]
        source = inc["source_ip"]
        if inc.get("source_macs"):
            source += f" (MAC {', '.join(inc['source_macs'])})"
        kind_text = (t(lang, "v.port_scan", n=len(inc["ports"])) if inc["classification"] == "port_scan"
                     else t(lang, "v.connection_attempt"))
        lines = [
            (t(lang, "f.client"), inc["client_name"]),
            (t(lang, "f.trap"), f"{inc['trap_name']} ({inc['trap_id']})"),
            (t(lang, "f.source"), source),
            (t(lang, "f.target"), ", ".join(inc["destinations"][:10]) + (" ..." if len(inc["destinations"]) > 10 else "") or "-"),
            (t(lang, "f.type"), kind_text),
            (t(lang, "f.ports"), _ports_text(inc["ports"], inc.get("ports_untracked", 0), lang)),
            (t(lang, "f.attempts"), t(lang, "v.attempts", attempts=inc["attempts"], lines=inc["lines"])),
            (t(lang, "f.first"), _local(inc["first_seen"])),
            (t(lang, "f.last"), _local(inc["last_seen"])),
            (t(lang, "f.status"), t(lang, "v.open" if inc["status"] == "open" else "v.closed")),
            (t(lang, "f.incident"), inc["id"]),
        ]
    elif alert.kind == "trap_silent":
        title = t(lang, "title.trap_silent", trap=trap)
        last = alert.details.get("last_seen")
        lines = [
            (t(lang, "f.client"), client or "-"),
            (t(lang, "f.trap"), f"{trap} ({alert.trap.id})" if alert.trap else "-"),
            (t(lang, "f.last_message"), _local(last) if last else t(lang, "v.never")),
            (t(lang, "f.threshold"), t(lang, "v.minutes", n=alert.details.get("missing_minutes"))),
        ]
    elif alert.kind == "trap_back":
        title = t(lang, "title.trap_back", trap=trap)
        lines = [
            (t(lang, "f.client"), client or "-"),
            (t(lang, "f.trap"), f"{trap} ({alert.trap.id})" if alert.trap else "-"),
            (t(lang, "f.silent_since"), _local(alert.details.get("silent_since"))),
        ]
    else:
        title = t(lang, "title.test")
        return title, t(lang, "test.body", host=socket.gethostname())
    if alert.waiting:
        lines.append((t(lang, "f.waiting"), str(alert.waiting)))
    if client and alert.kind.startswith("incident"):
        title = f"[{client}] {title}"
    width = max(len(k) for k, _ in lines)
    body = "\n".join(f"{k + ':':<{width + 1}} {v}" for k, v in lines)
    return title, body


def payload(alert: Alert, lang: str) -> dict:
    title, text = render(alert, lang)
    return {
        "schema": SCHEMA,
        "id": alert.id,
        "kind": alert.kind,
        "created_at": iso(alert.created_at),
        "language": lang,
        "title": title,
        "text": text,
        "client": {"id": alert.client.id, "name": alert.client.name} if alert.client else None,
        "trap": {"id": alert.trap.id, "name": alert.trap.name} if alert.trap else None,
        "incident": alert.incident,
        "details": alert.details,
        "waiting_alerts": alert.waiting,
        "receiver": {"host": socket.gethostname(), "version": __version__},
    }


# ---------------------------------------------------------------- channels

class DeliveryError(RuntimeError):
    pass


class Notifier:
    def __init__(self, conf: NotifierConf) -> None:
        self.conf = conf
        self.name = conf.name
        self.timeout = int(conf.options.get("timeout", 20))

    def send(self, data: dict) -> None:
        raise NotImplementedError


def _http_post(url: str, body: bytes, headers: dict, timeout: int, context: ssl.SSLContext | None) -> None:
    request = urllib.request.Request(url, data=body, method="POST", headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            response.read(4096)
    except urllib.error.HTTPError as exc:
        with exc:
            detail = exc.read(300).decode("utf-8", "replace").strip()
        raise DeliveryError(f"HTTP {exc.code} {exc.reason}: {detail}") from None
    except urllib.error.URLError as exc:
        raise DeliveryError(f"cannot reach the server: {exc.reason}") from None
    except TimeoutError:
        raise DeliveryError("timed out") from None


def _redact(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.hostname or ''}{'/...' if parts.path not in ('', '/') else ''}"


class SmtpNotifier(Notifier):
    def __init__(self, conf: NotifierConf) -> None:
        super().__init__(conf)
        o = conf.options
        self.host = o["host"]
        self.security = o.get("security", "starttls")
        self.port = int(o.get("port") or {"ssl": 465, "starttls": 587, "none": 25}[self.security])
        self.username = o.get("username") or None
        self.password = resolve_secret(o, "password", conf.base_dir, required=bool(self.username))
        self.sender = o["from"]
        self.to = [o["to"]] if isinstance(o["to"], str) else list(o["to"])
        self.subject_prefix = o.get("subject_prefix", "[LAN Trap]")

    def send(self, data: dict) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"{self.subject_prefix} {data['title']}".strip()
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.to)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=self.sender.split("@")[-1])
        msg["X-Lantrap-Kind"] = data["kind"]
        msg.set_content(data["text"] + "\n")
        context = ssl.create_default_context()
        try:
            if self.security == "ssl":
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            with server:
                if self.security == "starttls":
                    server.starttls(context=context)
                if self.username:
                    server.login(self.username, self.password or "")
                server.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError(f"SMTP {self.host}:{self.port}: {exc}") from None


class GoogleChatNotifier(Notifier):
    def __init__(self, conf: NotifierConf) -> None:
        super().__init__(conf)
        self.url = resolve_secret(conf.options, "url", conf.base_dir)
        self.thread_by_incident = bool(conf.options.get("thread_by_incident", True))

    def send(self, data: dict) -> None:
        url = self.url or ""
        incident = data.get("incident")
        if self.thread_by_incident and incident:
            # updates about the same incident land in the same thread
            sep = "&" if urllib.parse.urlsplit(url).query else "?"
            url += sep + urllib.parse.urlencode({
                "threadKey": f"lantrap-{incident['id']}",
                "messageReplyOption": "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
            })
        text = data["text"] if len(data["text"]) <= MAX_CHAT_TEXT else data["text"][:MAX_CHAT_TEXT] + "\n..."
        body = json.dumps({"text": f"*{data['title']}*\n```\n{text}\n```"}, ensure_ascii=False).encode("utf-8")
        _http_post(url, body, {"Content-Type": "application/json; charset=UTF-8"}, self.timeout, None)


class WebhookNotifier(Notifier):
    def __init__(self, conf: NotifierConf) -> None:
        super().__init__(conf)
        o = conf.options
        self.url = resolve_secret(o, "url", conf.base_dir)
        self.headers = dict(o.get("headers") or {})
        for header, env in (o.get("headers_env") or {}).items():
            value = os.environ.get(env)
            if not value:
                raise ConfigError(f"notify {conf.name}: environment variable {env} for header {header} is not set")
            self.headers[header] = value
        self.secret = resolve_secret(o, "secret", conf.base_dir, required=False)
        cafile = resolve_path(o.get("cafile"), conf.base_dir)
        self.context = ssl.create_default_context(cafile=str(cafile)) if cafile else None

    def send(self, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=UTF-8", "X-Lantrap-Event": data["kind"], **self.headers}
        if self.secret:
            digest = hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Lantrap-Signature"] = f"sha256={digest}"
        _http_post(self.url or "", body, headers, self.timeout, self.context)


class CommandNotifier(Notifier):
    def __init__(self, conf: NotifierConf) -> None:
        super().__init__(conf)
        self.argv = list(conf.options["argv"])
        self.timeout = int(conf.options.get("timeout", 30))

    def send(self, data: dict) -> None:
        env = dict(os.environ, LANTRAP_EVENT=data["kind"], LANTRAP_ALERT_ID=data["id"])
        try:
            proc = subprocess.run(self.argv, input=json.dumps(data, ensure_ascii=False).encode("utf-8"),
                                  capture_output=True, timeout=self.timeout, env=env, check=False)
        except FileNotFoundError:
            raise DeliveryError(f"command not found: {self.argv[0]}") from None
        except subprocess.TimeoutExpired:
            raise DeliveryError(f"command timed out after {self.timeout} s") from None
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()[-300:]
            raise DeliveryError(f"exit code {proc.returncode}: {err}")


KINDS = {"smtp": SmtpNotifier, "google_chat": GoogleChatNotifier, "webhook": WebhookNotifier, "command": CommandNotifier}


def build_notifiers(config: Config, strict: bool = True) -> list[Notifier]:
    """Create the channels; with strict=False a channel with a missing secret is skipped and logged."""
    out = []
    for conf in config.notifiers:
        try:
            out.append(KINDS[conf.type](conf))
        except Exception as exc:  # missing secret, unreadable file, bad certificate...
            if strict:
                raise ConfigError(f"notify {conf.name}: {exc}") from None
            log.error("alert channel %s disabled: %s", conf.name, exc)
    if config.notifiers and not out:
        log.error("none of the %d configured alert channels could be started: incidents are only recorded",
                  len(config.notifiers))
    return out


def describe(notifier: Notifier) -> str:
    if isinstance(notifier, SmtpNotifier):
        return f"smtp {notifier.host}:{notifier.port} -> {', '.join(notifier.to)}"
    if isinstance(notifier, (GoogleChatNotifier, WebhookNotifier)):
        return f"{notifier.conf.type} {_redact(notifier.url or '')}"
    if isinstance(notifier, CommandNotifier):
        return f"command {notifier.argv[0]}"
    return notifier.conf.type


def deliver(alert: Alert, notifiers: list[Notifier], config: Config, retry: bool = True) -> list[dict]:
    """Send to every channel that wants this alert; one record per channel."""
    records = []
    client_id = alert.client.id if alert.client else None
    for n in notifiers:
        if not n.conf.wants(alert.kind, client_id):
            continue
        lang = n.conf.language or config.language
        data = payload(alert, lang)
        error = None
        delays = RETRY_DELAYS if retry else ()
        for attempt in range(len(delays) + 1):
            try:
                n.send(data)
                error = None
                break
            except DeliveryError as exc:
                error = str(exc)
            except Exception as exc:  # a broken channel must not stop the others
                error = f"{type(exc).__name__}: {exc}"
            if attempt < len(delays):
                time.sleep(delays[attempt])
        if error:
            log.error("alert %s via %s failed: %s", alert.kind, n.name, error)
        else:
            log.info("alert %s sent via %s", alert.kind, n.name)
        records.append({
            "id": alert.id, "created_at": iso(alert.created_at), "kind": alert.kind,
            "trap_id": alert.trap.id if alert.trap else None, "client_id": client_id,
            "incident_id": alert.incident["id"] if alert.incident else None,
            "channel": n.name, "status": "failed" if error else "sent", "error": error, "payload": data,
        })
    return records
