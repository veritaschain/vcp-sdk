"""Strict JSON loading for verification input.

Python's ``json`` module silently keeps the last of two duplicate keys, accepts
``NaN``/``Infinity`` and turns ``1e400`` into infinity. Two parsers can then
disagree about what an event contains, so the verifier loads input with this
module. Its limits match the TypeScript parser: nesting depth 128, integer
literals of at most 4300 digits.

JSON Lines are split on ``\\n`` only (a trailing ``\\r`` is removed). Other
Unicode line separators such as U+2028 are ordinary characters inside a line.
"""

from __future__ import annotations

import json
import math
from typing import Any

from .jcs import MAX_DEPTH

__all__ = ["StrictJSONError", "loads", "load_jsonl", "MAX_INT_DIGITS"]

MAX_INT_DIGITS = 4300


class StrictJSONError(ValueError):
    """The text is not acceptable JSON for verification."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJSONError(f"duplicate key: {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise StrictJSONError(f"non-JSON constant: {name}")


def _parse_float(text: str) -> float:
    x = float(text)
    if not math.isfinite(x):
        raise StrictJSONError(f"number out of binary64 range: {text[:40]}")
    return x


def _parse_int(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise StrictJSONError(f"integer literal longer than {MAX_INT_DIGITS} digits")
    return int(text)


def _check_depth(value: Any) -> None:
    stack = [(value, 0)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, (dict, list)):
            if d >= MAX_DEPTH:
                raise StrictJSONError(f"nesting deeper than {MAX_DEPTH} levels")
            children = v.values() if isinstance(v, dict) else v
            stack.extend((c, d + 1) for c in children)


def loads(text: str | bytes) -> Any:
    """Parse JSON strictly. Raises :class:`StrictJSONError` for anything rejected."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("input is not valid UTF-8") from exc
    if text.startswith("﻿"):
        raise StrictJSONError("input starts with a byte-order mark")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
        )
    except StrictJSONError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise StrictJSONError(f"{type(exc).__name__}: {exc}") from exc
    _check_depth(value)
    return value


def load_jsonl(text: str | bytes) -> list[Any]:
    """Parse one JSON value per non-empty line (lines end with \\n)."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("input is not valid UTF-8") from exc
    out = []
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        if line.strip(" \t"):
            out.append(loads(line))
    return out
