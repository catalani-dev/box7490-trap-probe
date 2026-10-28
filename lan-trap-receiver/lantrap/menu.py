"""Interactive console menu: arrow or number keys to move, Enter to confirm, Esc to go back.

Settings are edited in forms built from lantrap.forms: every setting is listed with its current
value, the user changes only what they want, and the rest keeps its default.
"""

from __future__ import annotations

import copy
import os
import shutil
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import forms, openwrt, simulate, stores
from .config import Config, ConfigError, default_raw, load_raw, parse_config, save_raw
from .engine import Alert
from .forms import Field, tx
from .i18n import t
from .notify import build_notifiers, deliver

# ---------------------------------------------------------------- terminal

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
RESET, CYAN, WHITE, GREY, YELLOW, RED, GREEN, SELECTED = (
    ("\x1b[0m", "\x1b[36m", "\x1b[97m", "\x1b[90m", "\x1b[33m", "\x1b[31m", "\x1b[32m", "\x1b[30;46m")
    if COLOR else ("",) * 8
)


def _enable_vt() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def read_key() -> str:
    """'up', 'down', 'enter', 'esc', 'space', a digit, or another character."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(msvcrt.getwch(), "")
    else:
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1).decode("utf-8", "ignore")
            if ch == "\x1b" and select.select([fd], [], [], 0.05)[0]:
                seq = os.read(fd, 2).decode("utf-8", "ignore")
                return {"[A": "up", "[B": "down", "[C": "right", "[D": "left"}.get(seq, "")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if ch == "\x03":
        raise KeyboardInterrupt
    return {"\r": "enter", "\n": "enter", "\x1b": "esc", " ": "space"}.get(ch, ch)


def clear() -> None:
    sys.stdout.write("\x1b[H\x1b[2J" if COLOR else "\n" * 2)
    sys.stdout.flush()


def width() -> int:
    return min(76, max(50, shutil.get_terminal_size((80, 24)).columns - 6))


def rows() -> int:
    return shutil.get_terminal_size((80, 24)).lines


# ---------------------------------------------------------------- pure menu logic

@dataclass
class Item:
    key: str
    label: str
    desc: str = ""
    info: str = ""
    warn: bool = False


def menu_step(sel: int, count: int, key: str) -> tuple[int, str | None]:
    """New selection and, when the menu ends, 'enter' or 'esc'."""
    if key == "up":
        return (sel - 1) % count, None
    if key == "down":
        return (sel + 1) % count, None
    if key.isdigit() and 1 <= int(key) <= min(9, count):
        return int(key) - 1, None
    if key in ("enter", "esc"):
        return sel, key
    return sel, None


def check_step(sel: int, states: list[bool], key: str) -> tuple[int, str | None]:
    if key == "space":
        states[sel] = not states[sel]
        return sel, None
    return menu_step(sel, len(states), key)


def window(sel: int, count: int, size: int) -> tuple[int, int]:
    """First and last index of the items to draw, so that long lists scroll with the selection."""
    if count <= size:
        return 0, count
    start = min(max(0, sel - size // 2), count - size)
    return start, start + size


def render(header: list[str], title: str, items: list[Item], sel: int, help_text: str,
           states: list[bool] | None = None, notice: str = "", height: int | None = None) -> str:
    w = width()
    sep = "  " + CYAN + "-" * w + RESET
    out = list(header)
    if notice:
        out.append("  " + notice + RESET)
    out += ["  " + WHITE + title + RESET, ""]
    size = max(5, (height or rows()) - len(out) - 10)
    first, last = window(sel, len(items), size)
    if first > 0:
        out.append("      ...")
    for i in range(first, last):
        it = items[i]
        mark = ("[x] " if states[i] else "[ ] ") if states is not None else ""
        number = f"{i + 1})" if i < 9 else "  "
        label = f"{number}  {mark}{it.label}"[: w - 4]
        if i == sel:
            out.append("   " + SELECTED + " > " + label.ljust(min(w - 6, max(30, len(label) + 2))) + RESET)
        else:
            out.append("      " + label)
    if last < len(items):
        out.append("      ...")
    it = items[sel]
    desc = textwrap.wrap(it.desc, w - 4)[:3]
    color = YELLOW if it.warn else WHITE
    out += ["", sep] + ["   " + color + line + RESET for line in desc] + [""] * (3 - len(desc))
    out += ["   " + GREY + it.info[: w - 4] + RESET, sep, "   " + GREY + help_text + RESET]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- application

LIST_FIELDS: dict[str, Callable[[dict], list[Field]]] = {
    "listen": lambda e: forms.LISTEN,
    "store": lambda e: forms.STORE,
    "notify": forms.notify_fields,
    "client": lambda e: forms.CLIENT,
    "trap": lambda e: forms.TRAP,
}
TABLE_FIELDS = {"grouping": forms.GROUPING, "heartbeat": forms.HEARTBEAT, "openwrt": forms.OPENWRT, "wireguard": forms.WIREGUARD}


class App:
    def __init__(self, path: Path, lang: str | None = None) -> None:
        self.path = Path(path).resolve()
        self.raw: dict = {}
        self.cfg: Config | None = None
        self.lang = lang or "en"
        self.lang_forced = lang is not None
        self.notice = ""

    # --- text helpers

    def tr(self, key: str, **kw) -> str:
        return t(self.lang, key, **kw)

    def header(self) -> list[str]:
        w = width()
        title = "LAN TRAP RECEIVER"
        sub = self.tr("app.subtitle")
        path = str(self.path)
        room = w - len(self.tr("menu.config", path=""))
        if len(path) > room:
            path = "..." + path[-(room - 3):]  # keep the file name, drop the start of the folder
        return [
            "", "  " + CYAN + "=" * w + RESET,
            "  " + " " * max(0, (w - len(title)) // 2) + WHITE + title + RESET,
            "  " + " " * max(0, (w - len(sub)) // 2) + GREY + sub + RESET,
            "  " + CYAN + "=" * w + RESET,
            "  " + GREY + self.tr("menu.config", path=path) + RESET, "",
        ]

    def choose(self, title: str, items: list[Item], start: int = 0, help_key: str = "menu.help") -> str:
        sel = min(start, len(items) - 1)
        notice, self.notice = self.notice, ""
        while True:
            clear()
            sys.stdout.write(render(self.header(), title, items, sel, self.tr(help_key, n=min(9, len(items))), notice=notice))
            sys.stdout.flush()
            sel, done = menu_step(sel, len(items), read_key())
            if done == "enter":
                return items[sel].key
            if done == "esc":
                return "back"

    def checklist(self, title: str, items: list[Item], states: list[bool]) -> list[bool] | None:
        states = list(states)
        sel = 0
        while True:
            clear()
            sys.stdout.write(render(self.header(), title, items, sel, self.tr("menu.help_check"), states))
            sys.stdout.flush()
            sel, done = check_step(sel, states, read_key())
            if done == "enter":
                return states
            if done == "esc":
                return None

    def confirm(self, question: str) -> bool:
        items = [Item("no", self.tr("list.no")), Item("yes", self.tr("list.yes"), warn=True)]
        return self.choose(question, items) == "yes"

    def ask(self, key: str, default: str | None = None, **kw) -> str:
        suffix = f" [{default}]" if default not in (None, "") else ""
        try:
            value = input(f"  {self.tr(key, **kw)}{suffix}: ").strip()
        except EOFError:
            value = ""
        if value == "-":
            return ""
        return value or (default or "")

    def ask_int(self, key: str, default: int, minimum: int = 0, maximum: int = 10**9) -> int:
        while True:
            value = self.ask(key, str(default))
            if value.isdigit() and minimum <= int(value) <= maximum:
                return int(value)
            print(f"  {RED}{minimum}-{maximum}{RESET}")

    def ask_list(self, key: str, default: list | tuple = ()) -> list[str]:
        value = self.ask(key, ", ".join(default))
        return [v.strip() for v in value.split(",") if v.strip()]

    def pause(self) -> None:
        print()
        print("  " + GREY + self.tr("msg.press_key") + RESET)
        try:
            read_key()
        except KeyboardInterrupt:
            pass

    def say(self, text: str, color: str = "") -> None:
        print("  " + color + text + (RESET if color else ""))

    # --- configuration

    def load(self) -> bool:
        created = False
        if not self.path.exists():
            yes = input("  " + self.tr("ask.new_config", path=self.path) + " ").strip().lower()
            if yes not in ("", "y", "yes", "s", "si", "sì"):
                return False
            save_raw(default_raw(), self.path)
            created = True
        try:
            self.raw, fmt = load_raw(self.path)
            self.cfg = parse_config(self.raw, self.path, fmt)
        except (ConfigError, OSError) as exc:
            print(f"  {RED}{exc}{RESET}")
            return False
        if not self.lang_forced:
            self.lang = self.cfg.language
            if created:
                self.choose_language()  # first start: English is preselected, Italian one key away
        return True

    def save(self, raw: dict) -> str | None:
        """Validate and write; None when saved, otherwise the reason."""
        try:
            self.cfg = save_raw(raw, self.path, self.cfg.format if self.cfg else None)
        except ConfigError as exc:
            return str(exc)
        except OSError as exc:
            return f"{exc.filename}: {exc.strerror}"
        self.raw = raw
        self.notice = GREEN + self.tr("msg.saved")
        return None

    def copy(self) -> dict:
        return copy.deepcopy(self.raw)

    # --- main

    def main(self) -> int:
        _enable_vt()
        if not self.load():
            return 2
        actions = {
            "run": self.run_receiver, "status": self.status, "traps": self.clients_menu, "settings": self.settings_menu,
            "test": self.test_alert, "simulate": self.simulate, "openwrt": self.openwrt_script,
            "language": self.choose_language,
        }
        sel = 0
        while True:
            info = {"traps": self._clients_summary(), "settings": self._settings_summary()}
            items = [Item(k, self.tr(f"main.{k}"), self.tr(f"main.{k}.d"), info.get(k, "")) for k in
                     ("run", "status", "traps", "settings", "test", "simulate", "openwrt", "language", "exit")]
            choice = self.choose(self.tr("menu.main"), items, sel)
            if choice in ("exit", "back"):
                clear()
                return 0
            sel = [i.key for i in items].index(choice)
            clear()
            try:
                actions[choice]()
            except KeyboardInterrupt:
                print()
                self.notice = YELLOW + self.tr("msg.cancelled")

    def _clients_summary(self) -> str:
        return self.tr("summary.clients", c=len(self.raw.get("client", [])), t=len(self.raw.get("trap", [])))

    def _settings_summary(self) -> str:
        listen = ", ".join(forms.summary("listen", e, self.lang) for e in self.raw.get("listen", [])) or "-"
        channels = ", ".join(e.get("name", e.get("type", "?")) for e in self.raw.get("notify", [])) or "-"
        history = ", ".join(e.get("type", "?") for e in self.raw.get("store", [])) or "-"
        return f"{listen}  |  {channels}  |  {history}"

    def choose_language(self) -> None:
        """English by default, Italian on request; the choice is saved in the configuration."""
        options = ("en", "it")
        items = [Item(code, self.tr(f"lang.{code}"), self.tr("lang.d")) for code in options]
        picked = self.choose(self.tr("lang.title"), items, options.index(self.lang) if self.lang in options else 0)
        if picked == "back" or (picked == self.raw.get("language", "en") and "language" in self.raw):
            return
        raw = self.copy()
        raw["language"] = picked
        if self.save(raw) is None:
            self.lang = picked

    def run_receiver(self) -> None:
        from .server import run
        self.say(self.tr("msg.running"), GREEN)
        try:
            run(self.path)
        except (ConfigError, OSError) as exc:
            self.say(str(exc), RED)
        self.pause()

    # --- forms

    def _choices(self, field: Field) -> tuple:
        if field.choices == "clients":
            return tuple(c.get("id") for c in self.raw.get("client", []) if c.get("id"))
        return tuple(field.choices)

    def _choice_label(self, field: Field, value: str) -> str:
        label = self.tr(f"ch.{value}")
        return value if label == f"ch.{value}" else f"{value}  -  {label}"

    def edit_form(self, title: str, fields_fn: Callable[[dict], list[Field]], entry: dict, is_new: bool,
                  commit: Callable[[dict], str | None]) -> bool:
        """Show every setting with its value; Enter changes one, Save validates and writes."""
        entry = copy.deepcopy(entry)
        sel = 0
        while True:
            fields = forms.visible(fields_fn(entry), entry)
            col = min(38, max(len(tx(f.label, self.lang)) for f in fields) + 2) if fields else 20
            items = []
            for f in fields:
                fixed = f.fixed_after_create and not is_new
                value = forms.display(f, entry, self.lang)
                hint = self.tr("form.fixed") if fixed else ""
                items.append(Item(f"f:{f.key}", f"{tx(f.label, self.lang):<{col}} {value}", tx(f.help, self.lang), hint))
            items.append(Item("save", self.tr("form.save"), self.tr("form.save.d")))
            items.append(Item("cancel", self.tr("form.cancel"), self.tr("form.cancel.d")))
            choice = self.choose(title, items, sel, "form.help")
            if choice in ("cancel", "back"):
                self.notice = YELLOW + self.tr("msg.cancelled")
                return False
            sel = [i.key for i in items].index(choice)
            if choice == "save":
                error = commit(entry)
                if error is None:
                    return True
                self.notice = RED + self.tr("msg.invalid", error=error)
                continue
            field = next(f for f in fields if f"f:{f.key}" == choice)
            if field.fixed_after_create and not is_new:
                self.notice = YELLOW + self.tr("form.fixed")
                continue
            self.edit_field(title, field, entry)

    def edit_field(self, title: str, field: Field, entry: dict) -> None:
        kind = field.kind
        if kind == "bool":
            current = entry.get(field.key, field.default)
            entry[field.key] = not bool(current)
            return
        if kind in ("choice", "tristate"):
            if kind == "tristate":
                options = [("default", None), ("on", True), ("off", False)]
                items = [Item(k, self.tr(f"form.{k}")) for k, _ in options]
            else:
                options = [(c, c) for c in self._choices(field)]
                if field.optional_choice or not options:
                    options.insert(0, ("default", None))
                items = [Item(k, self.tr("form.default") if k == "default" and v is None else self._choice_label(field, k))
                         for k, v in options]
            if not items:
                self.notice = YELLOW + self.tr("list.need_client")
                return
            picked = self.choose(f"{title} > {tx(field.label, self.lang)}", items)
            if picked != "back":
                forms.apply(entry, field, dict(options)[picked])
            return
        if kind == "multi":
            choices = self._choices(field)
            if not choices:
                self.notice = YELLOW + self.tr("list.need_client")
                return
            current = entry.get(field.key) or []
            states = self.checklist(f"{title} > {tx(field.label, self.lang)}",
                                    [Item(c, self._choice_label(field, c)) for c in choices], [c in current for c in choices])
            if states is not None:
                selected = [c for c, on in zip(choices, states, strict=True) if on]
                forms.apply(entry, field, selected or None)
            return
        if kind == "secret":
            mode, value = forms.secret_mode(entry, field.key)
            items = [Item(m, self.tr(f"form.secret.{m}"), self.tr(f"form.secret.{m}.d")) for m in ("env", "file", "inline", "none")]
            picked = self.choose(f"{title} > {tx(field.label, self.lang)}", items, ["env", "file", "inline", "none"].index(mode or "env"))
            if picked == "back":
                return
            if picked == "none":
                forms.set_secret(entry, field.key, None, None)
                return
            text = self.prompt(title, field, self.tr(f"form.secret.ask_{picked}"), value if mode == picked and picked != "inline" else "")
            if text:
                forms.set_secret(entry, field.key, picked, text)
            return
        current = forms.display(field, entry, self.lang)
        text = self.prompt(title, field, self.tr("form.prompt"), current)
        if text == "":
            return
        if text == "-":
            forms.apply(entry, field, None)
            return
        try:
            forms.apply(entry, field, forms.parse_text(field, text))
        except ValueError as exc:
            self.notice = RED + self.tr("msg.invalid", error=exc)

    def prompt(self, title: str, field: Field, question: str, current: str) -> str:
        clear()
        for line in self.header():
            print(line)
        self.say(WHITE + f"{title} > {tx(field.label, self.lang)}" + RESET)
        for line in textwrap.wrap(tx(field.help, self.lang), width() - 4):
            self.say(GREY + line + RESET)
        print()
        self.say(f"{self.tr('form.current')}: {current or '-'}")
        try:
            return input(f"  {question}: ").strip()
        except EOFError:
            return ""

    # --- sections stored as one table, or at the top level

    def table_form(self, section: str, title: str) -> None:
        entry = dict(self.raw.get(section) or {})

        def commit(e: dict) -> str | None:
            raw = self.copy()
            if e:
                raw[section] = e
            else:
                raw.pop(section, None)
            return self.save(raw)

        self.edit_form(title, lambda e: TABLE_FIELDS[section], entry, False, commit)

    def top_form(self, fields: list[Field], title: str) -> None:
        keys = [f.key for f in fields]
        entry = {k: self.raw[k] for k in keys if k in self.raw}

        def commit(e: dict) -> str | None:
            raw = self.copy()
            for k in keys:
                if k in e:
                    raw[k] = e[k]
                else:
                    raw.pop(k, None)
            error = self.save(raw)
            if error is None and "language" in keys and not self.lang_forced:
                self.lang = raw.get("language", "en")
            return error

        self.edit_form(title, lambda e: fields, entry, False, commit)

    # --- sections stored as lists of entries

    def _commit_entry(self, section: str, index: int | None) -> Callable[[dict], str | None]:
        def commit(entry: dict) -> str | None:
            raw = self.copy()
            entries = raw.setdefault(section, [])
            if index is None:
                entries.append(entry)
            else:
                entries[index] = entry
            return self.save(raw)
        return commit

    def list_menu(self, section: str, title: str, new_entry: Callable[[], dict | None],
                  only: Callable[[dict], bool] | None = None, extra: list[Item] | None = None,
                  extra_actions: dict[str, Callable[[], None]] | None = None) -> None:
        sel = 0
        while True:
            entries = [(i, e) for i, e in enumerate(self.raw.get(section, [])) if only is None or only(e)]
            items = [Item(f"e:{i}", forms.summary(section, e, self.lang), self.tr("list.entry.d")) for i, e in entries]
            items.append(Item("add", self.tr("list.add"), self.tr(f"list.add.{section}")))
            items += extra or []
            items.append(Item("back", self.tr("settings.back"), self.tr("settings.back.d")))
            choice = self.choose(title, items, sel)
            if choice == "back":
                return
            sel = [i.key for i in items].index(choice)
            if choice == "add":
                entry = new_entry()
                if entry is not None:
                    self.edit_form(f"{title} > {self.tr('list.add')}", LIST_FIELDS[section], entry, True,
                                   self._commit_entry(section, None))
            elif extra_actions and choice in extra_actions:
                extra_actions[choice]()
            else:
                self.entry_menu(section, int(choice[2:]), title)

    def entry_menu(self, section: str, index: int, title: str) -> None:
        while True:
            entries = self.raw.get(section, [])
            if index >= len(entries):
                return
            entry = entries[index]
            name = forms.summary(section, entry, self.lang)
            items = [Item("edit", self.tr("list.edit"), self.tr("list.edit.d"))]
            if section == "notify":
                items.append(Item("test", self.tr("list.test"), self.tr("main.test.d")))
            if section == "client":
                items.append(Item("traps", self.tr("list.traps"), self.tr("list.traps.d")))
            items.append(Item("remove", self.tr("list.remove"), self.tr(f"list.remove.{section}"), warn=True))
            items.append(Item("back", self.tr("settings.back"), self.tr("settings.back.d")))
            choice = self.choose(f"{title} > {name}", items)
            if choice == "back":
                return
            if choice == "edit":
                self.edit_form(f"{title} > {name}", LIST_FIELDS[section], entry, False, self._commit_entry(section, index))
            elif choice == "test":
                clear()
                for _, line in send_test(self.cfg, [entry.get("name")]) if self.cfg else []:
                    self.say(line)
                self.pause()
            elif choice == "traps":
                client_id = entry.get("id")
                self.list_menu("trap", f"{title} > {name}", lambda cid=client_id: {"client": cid},
                               only=lambda e, cid=client_id: e.get("client") == cid)
            elif choice == "remove":
                if self.remove_entry(section, index, name):
                    return

    def remove_entry(self, section: str, index: int, name: str) -> bool:
        raw = self.copy()
        entry = raw[section][index]
        linked = []
        if section == "client":
            linked = [x.get("id") for x in raw.get("trap", []) if x.get("client") == entry.get("id")]
        what = ", ".join([name] + linked)
        if not self.confirm(self.tr("list.confirm", what=what)):
            return False
        del raw[section][index]
        if linked:
            raw["trap"] = [x for x in raw.get("trap", []) if x.get("client") != entry.get("id")]
        error = self.save(raw)
        if error:
            self.notice = RED + self.tr("msg.invalid", error=error)
            return False
        return True

    def _pick(self, title_key: str, kinds: tuple) -> str | None:
        choice = self.choose(self.tr(title_key), [Item(k, self.tr(f"ch.{k}")) for k in kinds])
        return None if choice == "back" else choice

    def _new_listener(self) -> dict | None:
        proto = self._pick("list.choose_type", ("udp", "tcp", "tls"))
        return None if proto is None else {"protocol": proto, "address": "0.0.0.0", "port": 6514 if proto == "tls" else 5514}

    def _new_store(self) -> dict | None:
        kind = self._pick("list.choose_type", ("sqlite", "jsonl", "csv"))
        if kind is None:
            return None
        where = {"path": "data/lantrap.sqlite3"} if kind == "sqlite" else {"directory": f"data/{kind}"}
        return {"type": kind, **where}

    def _new_notifier(self) -> dict | None:
        kind = self._pick("list.choose_type", ("smtp", "google_chat", "webhook", "command"))
        if kind is None:
            return None
        names = {e.get("name") for e in self.raw.get("notify", [])}
        base = kind.replace("_", "-")
        name = next(n for n in [base] + [f"{base}-{i}" for i in range(2, 100)] if n not in names)
        return {"name": name, "type": kind, **copy.deepcopy(forms.NEW_NOTIFIER_DEFAULTS[kind])}

    def _new_trap(self) -> dict | None:
        clients = [c.get("id") for c in self.raw.get("client", [])]
        if not clients:
            self.notice = YELLOW + self.tr("list.need_client")
            return None
        return {"client": clients[0]}

    # --- menus

    def settings_menu(self) -> None:
        sel = 0
        sections = ("general", "listen", "notify", "store", "grouping", "heartbeat", "openwrt", "wireguard")
        while True:
            info = {
                "listen": ", ".join(forms.summary("listen", e, self.lang) for e in self.raw.get("listen", [])),
                "notify": ", ".join(e.get("name", "?") for e in self.raw.get("notify", [])),
                "store": ", ".join(e.get("type", "?") for e in self.raw.get("store", [])),
                "general": f"{self.raw.get('language', 'en')}, {', '.join(self.raw.get('prefixes', ['LANTRAP:'])) or '*'}, "
                           f"{self.raw.get('unknown_sources', 'drop')}",
            }
            items = [Item(k, self.tr(f"settings.{k}"), self.tr(f"settings.{k}.d"), info.get(k, "")) for k in sections]
            items.append(Item("back", self.tr("settings.back"), self.tr("settings.back.d")))
            choice = self.choose(self.tr("settings.title"), items, sel)
            if choice == "back":
                return
            sel = [i.key for i in items].index(choice)
            title = self.tr(f"settings.{choice}")
            if choice == "general":
                self.top_form(forms.GENERAL, title)
            elif choice == "listen":
                self.list_menu("listen", title, self._new_listener)
            elif choice == "notify":
                self.list_menu("notify", title, self._new_notifier)
            elif choice == "store":
                self.list_menu("store", title, self._new_store)
            else:
                self.table_form(choice, title)

    def clients_menu(self) -> None:
        title = self.tr("traps.title")
        extra = [
            Item("all_traps", self.tr("traps.all"), self.tr("traps.all.d")),
            Item("global", self.tr("traps.global"), self.tr("traps.global.d"), ", ".join(self.raw.get("exclude", []))),
            Item("from_unknown", self.tr("traps.from_unknown"), self.tr("traps.from_unknown.d")),
        ]
        actions = {
            "all_traps": lambda: self.list_menu("trap", self.tr("traps.all"), self._new_trap),
            "global": lambda: self.top_form(forms.GLOBAL_EXCLUDE, self.tr("traps.global")),
            "from_unknown": self.trap_from_unknown,
        }
        self.list_menu("client", title, lambda: {}, extra=extra, extra_actions=actions)

    def trap_from_unknown(self) -> None:
        db = self.cfg.sqlite_path() if self.cfg else None
        rows_ = stores.unknown_rows(db) if db and db.exists() else []
        if not rows_:
            self.notice = YELLOW + self.tr("msg.no_unknown")
            return
        items = [Item(str(i), f"{r['peer']}  {r['hostname'] or '-'}", f"{r['count']} messages, last {r['last_seen']}")
                 for i, r in enumerate(rows_[:50])]
        choice = self.choose(self.tr("traps.from_unknown"), items)
        if choice == "back":
            return
        entry = self._new_trap()
        if entry is None:
            return
        row = rows_[int(choice)]
        entry["source"] = [row["peer"]]
        if row["hostname"]:
            entry["hostname"] = row["hostname"]
            entry["id"] = row["hostname"]
        self.edit_form(self.tr("traps.from_unknown"), LIST_FIELDS["trap"], entry, True, self._commit_entry("trap", None))

    # --- status and tools

    def status(self) -> None:
        cfg = self.cfg
        db = cfg.sqlite_path() if cfg else None
        if not cfg or not db:
            self.say(self.tr("msg.no_sqlite"), YELLOW)
            return self.pause()
        if not db.exists():
            self.say(self.tr("msg.no_db"), YELLOW)
            return self.pause()
        for line in status_lines(cfg, self.lang):
            print("  " + line)
        self.pause()

    def test_alert(self) -> None:
        cfg = self.cfg
        if not cfg or not cfg.notifiers:
            self.say(self.tr("msg.no_notifiers"), YELLOW)
            return self.pause()
        items = [Item(n.name, f"{n.name} ({n.type})") for n in cfg.notifiers]
        chosen = self.checklist(self.tr("ask.test_channels"), items, [True] * len(items))
        if chosen is None:
            return
        clear()
        for _, line in send_test(cfg, [i.key for i, on in zip(items, chosen, strict=True) if on]):
            self.say(line)
        self.pause()

    def simulate(self) -> None:
        cfg = self.cfg
        lst = cfg.listeners[0] if cfg and cfg.listeners else None
        default_host = "127.0.0.1" if not lst or lst.address in ("0.0.0.0", "::") else lst.address
        host = self.ask("ask.sim_host", default_host)
        port = self.ask_int("ask.sim_port", lst.port if lst else 5514, 1, 65535)
        proto = self.ask("ask.sim_proto", lst.protocol if lst and lst.protocol != "tls" else "udp").lower()
        src = self.ask("ask.sim_src", "192.168.1.2")
        ports = [int(p) for p in self.ask_list("ask.sim_ports", ["21", "23", "445", "3389", "8080"]) if p.isdigit()]
        first_trap = next(iter(cfg.traps.values()), None) if cfg else None
        hostname = self.ask("ask.sim_hostname", (first_trap.hostname or first_trap.id) if first_trap else "OpenWrt")
        prefix = cfg.prefixes[0] if cfg and cfg.prefixes else "LANTRAP:"
        lines = simulate.scan_lines(ports, src=src, prefix=prefix, hostname=hostname)
        try:
            simulate.send(lines, host, port, "tcp" if proto == "tcp" else "udp")
            self.say(self.tr("msg.sim_done", n=len(lines), target=f"{proto}://{host}:{port}"), GREEN)
        except OSError as exc:
            self.say(str(exc), RED)
        self.pause()

    def openwrt_script(self) -> None:
        cfg = self.cfg
        if not cfg or not cfg.traps:
            self.say(self.tr("msg.no_traps"), YELLOW)
            return self.pause()
        items = [Item(tr.id, f"{tr.id}  ({tr.name})", cfg.clients[tr.client].name) for tr in cfg.traps.values()]
        choice = self.choose(self.tr("ask.openwrt_trap"), items)
        if choice == "back":
            return
        clear()
        try:
            script = openwrt.box_script(cfg, cfg.traps[choice])
        except ConfigError as exc:
            self.say(str(exc), RED)
            return self.pause()
        out = self.path.with_name(f"lantrap-{choice}.sh")
        out.write_text(script, encoding="utf-8", newline="\n")
        print(script)
        self.say(str(out), GREEN)
        self.pause()


# ---------------------------------------------------------------- shared with the CLI

def _local(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def status_lines(cfg: Config, lang: str) -> list[str]:
    db = cfg.sqlite_path()
    lines = [WHITE + t(lang, "msg.status_traps") + RESET]
    trap_rows = {r["trap_id"]: r for r in stores.trap_rows(db)} if db else {}
    for trap in cfg.traps.values():
        r = trap_rows.get(trap.id, {})
        flags = []
        if r.get("silent"):
            flags.append(RED + t(lang, "msg.silent") + RESET)
        if r.get("clock_ok") == 0:
            flags.append(YELLOW + t(lang, "msg.clock_bad") + RESET)
        last = _local(r.get("last_seen")) if r.get("last_seen") else t(lang, "msg.never")
        lines.append(f"  {trap.id:<20} {cfg.clients[trap.client].name:<24} {last:<20} {' '.join(flags)}")
    if not cfg.traps:
        lines.append("  " + t(lang, "msg.no_traps"))
    unknown = stores.unknown_rows(db) if db else []
    if unknown:
        lines += ["", WHITE + t(lang, "msg.status_unknown") + RESET]
        lines += [f"  {u['peer']:<20} {u['hostname'] or '-':<24} {_local(u['last_seen']):<20} {u['count']}" for u in unknown[:10]]
    lines += ["", WHITE + t(lang, "msg.status_incidents") + RESET]
    for inc in stores.recent_incidents(db, 10) if db else []:
        ports = ",".join(str(p["port"]) for p in inc["ports"][:8]) + ("..." if len(inc["ports"]) > 8 else "")
        lines.append(f"  {_local(inc['last_seen']):<20} {inc['client_name'][:18]:<18} {inc['source_ip']:<16} "
                     f"{inc['attempts']:>4}x  {ports}  {inc['status']}")
    return lines


def send_test(cfg: Config, names: list[str] | None = None) -> list[tuple[bool, str]]:
    """Send a test alert to the named channels (all when None); (sent, text) per channel."""
    selected = [n for n in cfg.notifiers if names is None or n.name in names]
    trial = Config(**{**cfg.__dict__, "notifiers": selected})
    try:
        notifiers = build_notifiers(trial, strict=True)
    except ConfigError as exc:
        return [(False, RED + str(exc) + RESET)]
    if not notifiers:
        return [(False, YELLOW + t(cfg.language, "msg.no_notifiers") + RESET)]
    alert = Alert("test", datetime.now(timezone.utc), None, None)
    results = []
    for record in deliver(alert, notifiers, cfg, retry=False):
        if record["status"] == "sent":
            results.append((True, GREEN + t(cfg.language, "msg.sent", name=record["channel"]) + RESET))
        else:
            results.append((False, RED + t(cfg.language, "msg.failed", name=record["channel"], error=record["error"]) + RESET))
    return results
