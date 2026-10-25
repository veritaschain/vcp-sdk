"""Canonical JSON for EventHash: RFC 8785 (JCS) with one rule for integers.

Strings, literals, arrays, objects and key order follow RFC 8785 exactly.

Numbers (INTERPRETATIONS.md, I-4). VCP v1.2 carries ``TimestampInt`` as a JSON
integer of nanoseconds and says its 64-bit precision must be preserved, while
RFC 8785 treats every number as an IEEE 754 binary64 value. Applying RFC 8785
literally would round most nanosecond timestamps, and for some exactly
representable values it would print a different digit string (2**60 becomes
``1152921504606847000``). So, by default:

* an integer (Python ``int``) is written as its exact decimal digits;
* a float is written as RFC 8785 writes it (ECMAScript ``Number#toString``),
  except that a float with an integral value of magnitude in [2**53, 10**21) is
  rejected: its RFC 8785 form is a plain digit string that could equal the
  digits of a different integer, so accepting it would let two different
  values share one hash.

With these rules different numeric values never share a canonical form.
``strict=True`` applies RFC 8785 to integers as well: an integer is converted to
binary64 (and rejected if that would change it) and written in RFC 8785 form.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

__all__ = [
    "CanonicalizationError",
    "MAX_DEPTH",
    "canonicalize",
    "canonicalize_str",
    "format_number",
    "differs_from_rfc8785",
]

MAX_DEPTH = 128
_TWO53 = 2**53


class CanonicalizationError(ValueError):
    """The value cannot be canonicalised without changing or confusing it."""


_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _serialize_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise CanonicalizationError("string contains a lone surrogate")
        esc = _SHORT_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es_format_double(x: float) -> str:
    """ECMAScript Number::toString for a finite binary64 value."""
    if x == 0:
        return "0"  # also covers -0
    if x < 0:
        return "-" + _es_format_double(-x)
    # repr() gives the shortest digit string that round-trips, nearest to x.
    _sign, digits_t, exponent = Decimal(repr(x)).as_tuple()
    digits = list(digits_t)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    while len(digits) > 1 and digits[0] == 0:
        digits.pop(0)
    ds = "".join(str(d) for d in digits)
    k = len(ds)
    n = exponent + k
    if k <= n <= 21:
        return ds + "0" * (n - k)
    if 0 < n <= 21:
        return ds[:n] + "." + ds[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + ds
    e = n - 1
    exp = ("+" if e > 0 else "-") + str(abs(e))
    if k == 1:
        return ds + "e" + exp
    return ds[0] + "." + ds[1:] + "e" + exp


def _int_digits(value: int) -> str:
    try:
        return int.__repr__(value)  # not str(): an IntEnum would print its name on Python 3.10
    except ValueError as exc:  # interpreter digit limit
        raise CanonicalizationError("integer has too many digits") from exc


def format_number(value: int | float, strict: bool = False) -> str:
    """Serialise a JSON number under the rules in the module docstring."""
    if isinstance(value, bool):
        raise TypeError("bool is not a number")
    if isinstance(value, int):
        if not strict:
            return _int_digits(value)
        try:
            f = float(value)
            exact = int(f) == value
        except OverflowError:
            exact = False
        if not exact:
            raise CanonicalizationError(
                f"integer {_int_digits(value)} is not exactly representable as binary64; "
                "RFC 8785 processing would change the value"
            )
        return _es_format_double(f)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("NaN and Infinity are not valid JSON numbers")
        if not strict and value.is_integer() and _TWO53 <= abs(value) < 1e21:
            raise CanonicalizationError(
                "a floating-point number with an integral value of 2**53 or more is ambiguous; "
                "write it as an integer or a decimal string"
            )
        return _es_format_double(value)
    raise TypeError(f"not a number: {type(value).__name__}")


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _serialize(value: Any, out: list[str], strict: bool, depth: int) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_serialize_string(value))
    elif isinstance(value, (int, float)):
        out.append(format_number(value, strict))
    elif isinstance(value, (dict, list, tuple)):
        if depth >= MAX_DEPTH:
            raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH} levels")
        if isinstance(value, dict):
            for key in value:
                if not isinstance(key, str):
                    raise CanonicalizationError("object keys must be strings")
            out.append("{")
            for i, key in enumerate(sorted(value, key=_utf16_key)):
                if i:
                    out.append(",")
                out.append(_serialize_string(key))
                out.append(":")
                _serialize(value[key], out, strict, depth + 1)
            out.append("}")
        else:
            out.append("[")
            for i, item in enumerate(value):
                if i:
                    out.append(",")
                _serialize(item, out, strict, depth + 1)
            out.append("]")
    else:
        raise CanonicalizationError(f"unsupported type: {type(value).__name__}")


def canonicalize_str(value: Any, strict: bool = False) -> str:
    """Return the canonical form as a ``str``."""
    out: list[str] = []
    _serialize(value, out, strict, 0)
    return "".join(out)


def canonicalize(value: Any, strict: bool = False) -> bytes:
    """Return the canonical form as UTF-8 bytes."""
    return canonicalize_str(value, strict).encode("utf-8")


def differs_from_rfc8785(value: Any) -> bool:
    """True if ``value`` holds an integer whose form here differs from strict RFC 8785.

    That is any integer of magnitude above 2**53 except those whose RFC 8785
    form happens to equal their digits. Iterative, so depth is not a concern.
    """
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, bool) or v is None or isinstance(v, (str, float)):
            continue
        if isinstance(v, int):
            if abs(v) > _TWO53:
                try:
                    if format_number(v, strict=True) != _int_digits(v):
                        return True
                except CanonicalizationError:
                    return True
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return False
