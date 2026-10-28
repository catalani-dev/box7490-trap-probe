"""Minimal TOML writer for the configuration file (the standard library only reads TOML)."""

from __future__ import annotations

import math
import re
from typing import Any

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _key(key: str) -> str:
    return key if _BARE_KEY.match(key) else _string(key)


def _string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN and infinity are not supported")
        return repr(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_key(k)} = {_value(v)}" for k, v in value.items()) + "}"
    raise TypeError(f"cannot write {type(value).__name__} as TOML")


def _is_table_array(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, dict) for v in value)


def _write_table(lines: list[str], data: dict, prefix: str) -> None:
    # scalars, inline arrays and inline tables of scalars stay in this table
    nested: list[tuple[str, Any]] = []
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, dict) and any(isinstance(v, (dict, list)) for v in value.values()):
            nested.append((key, value))
        elif isinstance(value, dict) and prefix == "" and value:
            nested.append((key, value))
        elif _is_table_array(value):
            nested.append((key, value))
        else:
            lines.append(f"{_key(key)} = {_value(value)}")
    for key, value in nested:
        name = f"{prefix}.{_key(key)}" if prefix else _key(key)
        if isinstance(value, dict):
            lines.append("")
            lines.append(f"[{name}]")
            _write_table(lines, value, name)
        else:
            for item in value:
                lines.append("")
                lines.append(f"[[{name}]]")
                _write_table(lines, item, name)


def dumps(data: dict, header: str = "") -> str:
    lines: list[str] = []
    if header:
        lines.extend(f"# {line}".rstrip() for line in header.splitlines())
        lines.append("")
    _write_table(lines, data, "")
    return "\n".join(lines).strip("\n") + "\n"
