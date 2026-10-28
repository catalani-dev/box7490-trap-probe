"""Every setting of the configuration file, described for the menu: label, help, type, limits, default.

The menu builds its forms from these tables, so any setting the parser accepts can be changed
without editing the file by hand. A setting that is not set keeps its default.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any, Callable

from .config import ALERT_KINDS, DEFAULT_PREFIX, DEFAULT_TRAP_PORTS, LANGUAGES, SMTP_SECURITY

Text = tuple[str, str]  # (English, Italian)


def tx(text: Text, lang: str) -> str:
    return text[1] if lang == "it" and text[1] else text[0]


@dataclass(frozen=True)
class Field:
    key: str
    label: Text
    help: Text = ("", "")
    kind: str = "text"  # text int bool choice list intlist multi secret argv headers tristate
    default: Any = None
    choices: tuple | str = ()  # choice / multi; "clients" = the configured client ids
    minimum: int | None = None
    maximum: int | None = None
    optional_choice: bool = False  # choice: offer "default" to remove the setting
    fixed_after_create: bool = False  # ids that other entries refer to
    show: Callable[[dict], bool] | None = None


def _tls(entry: dict) -> bool:
    return entry.get("protocol") == "tls"


# ---------------------------------------------------------------- sections

GENERAL = [
    Field("language", ("Language", "Lingua"), ("Menus and alerts.", "Menu e avvisi."), "choice", "en", LANGUAGES),
    Field("prefixes", ("Accepted log prefixes", "Prefissi di log accettati"),
          ("Log prefixes of the trap rule on the boxes, for example LANTRAP: or TRAPPOLA:. Type * for any netfilter LOG line.",
           "Prefissi della regola trappola sui box, per esempio LANTRAP: o TRAPPOLA:. Scrivi * per qualsiasi riga LOG di netfilter."),
          "list", [DEFAULT_PREFIX]),
    Field("unknown_sources", ("Unknown senders", "Mittenti sconosciuti"),
          ("drop: ignore and list them, so you can add them as traps. accept: treat each new address as a trap.",
           "drop: scartali ed elencali, per aggiungerli come trappole. accept: ogni nuovo indirizzo diventa una trappola."),
          "choice", "drop", ("drop", "accept")),
    Field("store_excluded", ("Keep excluded hits in the history", "Tieni nello storico i colpi esclusi"),
          ("They never raise alerts.", "Non generano mai avvisi."), "bool", True),
    Field("store_other", ("Keep the other messages of the traps", "Tieni gli altri messaggi delle trappole"),
          ("Heartbeat and system log of the boxes (needs more space).", "Segnale di vita e log di sistema dei box (occupa più spazio)."),
          "bool", False),
]

GLOBAL_EXCLUDE = [
    Field("exclude", ("Exclusions for every client", "Eccezioni per tutti i clienti"),
          ("IP addresses, networks or MAC addresses allowed to scan everywhere (no alert).",
           "Indirizzi IP, reti o MAC autorizzati a scansionare ovunque (nessun avviso)."), "list", []),
]

GROUPING = [
    Field("collect_seconds", ("Seconds to collect before the first alert", "Secondi di raccolta prima del primo avviso"),
          ("A fast scan then arrives complete in one alert.", "Così una scansione veloce arriva completa in un solo avviso."),
          "int", 60, minimum=0, maximum=3600),
    Field("quiet_minutes", ("Minutes of silence that end an incident", "Minuti di silenzio che chiudono un incidente"),
          kind="int", default=15, minimum=1, maximum=1440),
    Field("retry_seconds", ("Seconds that make repeated lines one attempt", "Secondi per cui righe ripetute sono un tentativo"),
          ("Windows retries a refused connection several times: those lines count as one attempt.",
           "Windows ritenta più volte una connessione rifiutata: quelle righe contano come un tentativo."),
          "int", 5, minimum=0, maximum=600),
    Field("reminder_minutes", ("Minutes between reminders", "Minuti tra i promemoria"),
          ("While an incident goes on with new activity. 0 = no reminders.", "Se l'incidente continua con attività nuova. 0 = nessun promemoria."),
          "int", 60, minimum=0, maximum=10080),
    Field("scan_ports", ("Ports that make a port scan", "Porte che fanno una scansione"),
          ("Fewer distinct ports = connection attempt.", "Meno porte diverse = tentativo di connessione."), "int", 3, minimum=2, maximum=65535),
    Field("notify_on_close", ("Alert when an incident ends", "Avvisa quando un incidente finisce"), kind="bool", default=False),
    Field("max_alerts_per_hour", ("Incident alerts per hour and client", "Avvisi di incidente all'ora per cliente"),
          ("The rest wait for a free slot, they are not lost. 0 = no limit.", "Gli altri aspettano un posto libero, non si perdono. 0 = senza limite."),
          "int", 30, minimum=0),
]

HEARTBEAT = [
    Field("enabled", ("Alert when a trap goes silent", "Avvisa quando una trappola tace"), kind="bool", default=True),
    Field("missing_minutes", ("Minutes without logs before the alert", "Minuti senza log prima dell'avviso"),
          ("The setup script makes each box send a heartbeat every 10 minutes.", "Lo script del box manda un segnale di vita ogni 10 minuti."),
          "int", 30, minimum=1, maximum=10080),
]

LISTEN = [
    Field("protocol", ("Protocol", "Protocollo"), ("udp: OpenWrt default. tcp: no loss. tls: encrypted.",
                                                  "udp: predefinito di OpenWrt. tcp: niente perdite. tls: cifrato."),
          "choice", "udp", ("udp", "tcp", "tls")),
    Field("address", ("Listen address", "Indirizzo di ascolto"),
          ("0.0.0.0 = every interface; better the address on the tunnel.", "0.0.0.0 = tutte le interfacce; meglio l'indirizzo sul tunnel."),
          "text", "0.0.0.0"),
    Field("port", ("Port", "Porta"), ("Below 1024 needs extra privileges.", "Sotto 1024 servono privilegi in più."),
          "int", 5514, minimum=1, maximum=65535),
    Field("allow", ("Allowed senders", "Mittenti ammessi"), ("Addresses or networks; empty = anyone.", "Indirizzi o reti; vuoto = tutti."), "list", []),
    Field("certfile", ("Certificate file (PEM)", "File del certificato (PEM)"), show=_tls),
    Field("keyfile", ("Private key file (PEM)", "File della chiave privata (PEM)"), show=_tls),
    Field("cafile", ("CA for client certificates", "CA per i certificati client"),
          ("Set it to require a certificate from every sender.", "Impostala per richiedere un certificato a ogni mittente."), show=_tls),
]

STORE = [
    Field("type", ("Format", "Formato"), ("sqlite is needed for status and reports.", "sqlite serve per stato e rapporti."),
          "choice", "sqlite", ("sqlite", "jsonl", "csv")),
    Field("path", ("Database file", "File del database"), kind="text", default="data/lantrap.sqlite3",
          show=lambda e: e.get("type", "sqlite") == "sqlite"),
    Field("directory", ("Directory (one file per day)", "Cartella (un file al giorno)"), kind="text",
          show=lambda e: e.get("type") in ("jsonl", "csv")),
    Field("retention_days", ("Keep history for days", "Giorni di storico"), ("0 = forever.", "0 = per sempre."),
          "int", 365, minimum=0),
]

NOTIFY_COMMON = [
    Field("name", ("Name", "Nome"), ("Shown in the logs and in the test menu.", "Compare nei log e nel menu di prova."), "text"),
    Field("enabled", ("Enabled", "Attivo"), kind="bool", default=True),
    Field("events", ("Events", "Eventi"), ("Nothing ticked = all.", "Nessuno spuntato = tutti."), "multi", None,
          tuple(k for k in ALERT_KINDS if k != "test")),
    Field("clients", ("Only these clients", "Solo questi clienti"), ("Nothing ticked = all.", "Nessuno spuntato = tutti."),
          "multi", None, "clients"),
    Field("language", ("Language of this channel", "Lingua di questo canale"), ("Default = the general setting.", "Predefinita = quella generale."),
          "choice", None, LANGUAGES, optional_choice=True),
    Field("timeout", ("Timeout (seconds)", "Tempo massimo (secondi)"), kind="int", default=20, minimum=1, maximum=600),
]

NOTIFY_BY_TYPE = {
    "smtp": [
        Field("host", ("SMTP server", "Server SMTP")),
        Field("security", ("Security", "Sicurezza"), kind="choice", default="starttls", choices=SMTP_SECURITY),
        Field("port", ("Port", "Porta"), ("Default: 587 starttls, 465 ssl, 25 none.", "Predefinita: 587 starttls, 465 ssl, 25 none."),
              "int", None, minimum=1, maximum=65535),
        Field("username", ("User", "Utente"), ("Empty = no login.", "Vuoto = senza login.")),
        Field("password", ("Password", "Password"), kind="secret"),
        Field("from", ("Sender address", "Indirizzo del mittente")),
        Field("to", ("Recipients", "Destinatari"), kind="list", default=[]),
        Field("subject_prefix", ("Subject prefix", "Prefisso dell'oggetto"), default="[LAN Trap]"),
    ],
    "google_chat": [
        Field("url", ("Webhook URL of the space", "URL del webhook dello spazio"),
              ("It contains a key: an environment variable or a file keeps it out of the configuration.",
               "Contiene una chiave: una variabile d'ambiente o un file la tengono fuori dalla configurazione."), "secret"),
        Field("thread_by_incident", ("One thread per incident", "Un thread per incidente"), kind="bool", default=True),
    ],
    "webhook": [
        Field("url", ("URL", "URL"), kind="secret"),
        Field("secret", ("HMAC secret for the signature", "Segreto HMAC per la firma"),
              ("Adds X-Lantrap-Signature: sha256=... to every request.", "Aggiunge X-Lantrap-Signature: sha256=... a ogni richiesta."), "secret"),
        Field("headers", ("Extra headers", "Intestazioni aggiuntive"), ("Name: value; Name: value", "Nome: valore; Nome: valore"), "headers"),
        Field("headers_env", ("Headers from environment variables", "Intestazioni da variabili d'ambiente"),
              ("Name: VARIABLE; Name: VARIABLE", "Nome: VARIABILE; Nome: VARIABILE"), "headers"),
        Field("cafile", ("CA file for the server certificate", "File della CA del certificato del server"), ("Empty = system CAs.", "Vuoto = CA di sistema.")),
    ],
    "command": [
        Field("argv", ("Command and arguments", "Comando e argomenti"),
              ("The alert arrives as JSON on standard input.", "L'avviso arriva in JSON sullo standard input."), "argv"),
    ],
}

CLIENT = [
    Field("id", ("Id", "Id"), ("Letters, digits, - _ . (it cannot change later).", "Lettere, cifre, - _ . (poi non si cambia)."),
          fixed_after_create=True),
    Field("name", ("Name", "Nome")),
    Field("exclude", ("Exclusions of this client", "Eccezioni di questo cliente"),
          ("Addresses, networks or MACs allowed to scan (for example the IT scanners).",
           "Indirizzi, reti o MAC autorizzati a scansionare (per esempio gli scanner dei tecnici)."), "list", []),
]

TRAP = [
    Field("id", ("Id", "Id"), ("Letters, digits, - _ . (it cannot change later).", "Lettere, cifre, - _ . (poi non si cambia)."),
          fixed_after_create=True),
    Field("name", ("Name", "Nome")),
    Field("client", ("Client", "Cliente"), kind="choice", choices="clients"),
    Field("source", ("Sender addresses", "Indirizzi del mittente"),
          ("Where its logs come from, for example its WireGuard address.", "Da dove arrivano i suoi log, per esempio l'indirizzo WireGuard."),
          "list", []),
    Field("hostname", ("Hostname to check", "Hostname da controllare"), ("log_hostname of the box; empty = not checked.",
                                                                        "log_hostname del box; vuoto = non controllato.")),
    Field("tunnel_ip", ("WireGuard address of the box", "Indirizzo WireGuard del box"), ("Used by the box setup script.", "Usato dallo script del box.")),
    Field("heartbeat", ("Heartbeat alert", "Avviso di segnale di vita"), kind="tristate"),
    Field("exclude", ("Exclusions of this trap", "Eccezioni di questa trappola"), kind="list", default=[]),
]

OPENWRT = [
    Field("receiver", ("Address the boxes send logs to", "Indirizzo a cui i box mandano i log"),
          ("Usually the receiver address on the tunnel.", "Di solito l'indirizzo del ricevitore sul tunnel.")),
    Field("log_port", ("Port", "Porta"), kind="int", default=5514, minimum=1, maximum=65535),
    Field("log_proto", ("Protocol", "Protocollo"), kind="choice", default="udp", choices=("udp", "tcp")),
    Field("ports", ("Trap ports", "Porte della trappola"), kind="intlist", default=list(DEFAULT_TRAP_PORTS)),
    Field("interface", ("LAN interface", "Interfaccia LAN"), default="br-lan"),
    Field("set_name", ("Name of the exclusion set", "Nome del set delle eccezioni"), default="lantrap_exclude"),
    Field("rate_per_minute", ("Log lines per minute (box limit)", "Righe di log al minuto (limite del box)"),
          kind="int", default=60, minimum=1, maximum=10000),
    Field("heartbeat_minutes", ("Heartbeat every minutes", "Segnale di vita ogni minuti"), ("0 = none.", "0 = nessuno."),
          "int", 10, minimum=0, maximum=59),
    Field("ntp_servers", ("NTP servers", "Server NTP"), ("Empty = keep those of the box.", "Vuoto = tieni quelli del box."), "list", []),
    Field("ipv6", ("Also log IPv6", "Registra anche IPv6"), kind="bool", default=False),
]

WIREGUARD = [
    Field("endpoint", ("Receiver endpoint", "Endpoint del ricevitore"), ("host:port reachable from the client sites.",
                                                                        "host:porta raggiungibile dalle sedi dei clienti.")),
    Field("public_key", ("Receiver public key", "Chiave pubblica del ricevitore")),
    Field("receiver_ip", ("Receiver address in the tunnel", "Indirizzo del ricevitore nel tunnel")),
    Field("network", ("Tunnel network", "Rete del tunnel")),
    Field("keepalive", ("Keepalive (seconds)", "Keepalive (secondi)"), kind="int", default=25, minimum=0, maximum=3600),
]

NEW_NOTIFIER_DEFAULTS = {
    "smtp": {"security": "starttls", "to": []},
    "google_chat": {},
    "webhook": {},
    "command": {"argv": []},
}


def notify_fields(entry: dict) -> list[Field]:
    return NOTIFY_COMMON + NOTIFY_BY_TYPE.get(entry.get("type", ""), [])


def visible(fields: list[Field], entry: dict) -> list[Field]:
    return [f for f in fields if f.show is None or f.show(entry)]


# ---------------------------------------------------------------- values

SECRET_SUFFIXES = ("", "_env", "_file")


def secret_mode(entry: dict, key: str) -> tuple[str | None, str | None]:
    """('inline'|'env'|'file'|None, value)."""
    for mode, suffix in (("env", "_env"), ("file", "_file"), ("inline", "")):
        if entry.get(key + suffix):
            return mode, entry[key + suffix]
    return None, None


def set_secret(entry: dict, key: str, mode: str | None, value: str | None) -> None:
    for suffix in SECRET_SUFFIXES:
        entry.pop(key + suffix, None)
    if mode and value:
        entry[key + {"inline": "", "env": "_env", "file": "_file"}[mode]] = value


def is_set(field: Field, entry: dict) -> bool:
    if field.kind == "secret":
        return secret_mode(entry, field.key)[0] is not None
    return entry.get(field.key) is not None


def display(field: Field, entry: dict, lang: str) -> str:
    """Current value as shown in a form."""
    default_word = "default" if lang != "it" else "predefinito"
    if field.kind == "secret":
        mode, value = secret_mode(entry, field.key)
        if mode == "env":
            return f"env {value}"
        if mode == "file":
            return f"file {value}"
        if mode == "inline":
            return "******" if field.key != "url" else _short(str(value))
        return "-"
    value = entry.get(field.key)
    if value is None:
        if field.kind == "tristate" or field.optional_choice:
            return default_word
        if field.default in (None, [], ""):
            if field.kind == "multi":
                return "all" if lang != "it" else "tutti"
            return "-"
        shown = ", ".join(str(v) for v in field.default) if isinstance(field.default, list) else _scalar(field.default, lang)
        return f"{shown}  ({default_word})"
    if field.kind == "headers":
        return "; ".join(f"{k}: {v}" for k, v in value.items()) or "-"
    if field.kind == "argv":
        return " ".join(shlex.quote(a) for a in value) or "-"
    if field.kind == "tristate":
        return ("on" if value else "off") if lang != "it" else ("attivo" if value else "spento")
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) or "-"
    return _scalar(value, lang)


def _scalar(value: Any, lang: str) -> str:
    if isinstance(value, bool):
        return ("yes" if value else "no") if lang != "it" else ("sì" if value else "no")
    return str(value)


def _short(text: str, size: int = 40) -> str:
    return text if len(text) <= size else text[:size - 3] + "..."


def parse_text(field: Field, text: str) -> Any:
    """Typed value from what the user typed; ValueError with a short reason."""
    text = text.strip()
    if field.kind == "int":
        if not text.lstrip("-").isdigit():
            raise ValueError("a whole number is needed")
        value = int(text)
        if field.minimum is not None and value < field.minimum or field.maximum is not None and value > field.maximum:
            hi = field.maximum if field.maximum is not None else "..."
            raise ValueError(f"{field.minimum}-{hi}")
        return value
    if field.kind == "list":
        return [] if text == "*" else [v.strip() for v in text.split(",") if v.strip()]
    if field.kind == "intlist":
        values = [v.strip() for v in text.split(",") if v.strip()]
        if not values or not all(v.isdigit() and 1 <= int(v) <= 65535 for v in values):
            raise ValueError("ports 1-65535, comma separated")
        return [int(v) for v in values]
    if field.kind == "headers":
        out = {}
        for part in text.split(";"):
            if not part.strip():
                continue
            if ":" not in part:
                raise ValueError("Name: value; Name: value")
            name, value = part.split(":", 1)
            out[name.strip()] = value.strip()
        return out
    if field.kind == "argv":
        return shlex.split(text, posix=True)
    return text


def apply(entry: dict, field: Field, value: Any) -> None:
    """Set a value; None, empty text or an empty list/table removes the setting (back to its default)."""
    if value is None or value == "" or value == {} or (value == [] and field.kind not in ("list", "intlist")):
        entry.pop(field.key, None)
    else:
        entry[field.key] = value


def summary(section: str, entry: dict, lang: str) -> str:
    """One line describing an entry of a list section."""
    if section == "listen":
        return f"{entry.get('protocol', 'udp')}://{entry.get('address', '0.0.0.0')}:{entry.get('port', 6514 if entry.get('protocol') == 'tls' else 5514)}"
    if section == "store":
        kind = entry.get("type", "sqlite")
        where = entry.get("path", "data/lantrap.sqlite3") if kind == "sqlite" else entry.get("directory", f"data/{kind}")
        return f"{kind}  {where}"
    if section == "notify":
        state = "" if entry.get("enabled", True) else ("  (disabled)" if lang != "it" else "  (spento)")
        target = ""
        if entry.get("type") == "smtp":
            target = ", ".join(entry.get("to") or [])
        elif entry.get("type") == "command":
            target = (entry.get("argv") or [""])[0]
        elif entry.get("type") in ("google_chat", "webhook"):
            mode, value = secret_mode(entry, "url")
            target = f"{mode} {value}" if mode in ("env", "file") else ("URL" if mode else "-")
        return f"{entry.get('name', '?')}  [{entry.get('type')}]  {target}{state}"
    if section == "client":
        return f"{entry.get('id')}  {entry.get('name', '')}"
    if section == "trap":
        src = entry.get("source") or []
        src = [src] if isinstance(src, str) else src
        return f"{entry.get('id')}  {entry.get('name', '')}  {', '.join(src) or entry.get('hostname') or ''}"
    return str(entry)
