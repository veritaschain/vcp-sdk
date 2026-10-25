"""UUIDv7 event identifiers and VCP's dual-format timestamps.

``TimestampInt`` is nanoseconds since the Unix epoch (UTC), as the v1.2 event
schema describes. ``TimestampISO`` is RFC 3339 in UTC with a ``Z`` suffix and
3, 6 or 9 fractional digits for MILLISECOND, MICROSECOND or NANOSECOND
precision (section 1.5.4).
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timedelta, timezone

__all__ = [
    "uuid7",
    "now_ns",
    "iso_from_ns",
    "ns_from_iso",
    "iso_matches_ns",
    "PRECISION_DIGITS",
]

PRECISION_DIGITS = {"MILLISECOND": 3, "MICROSECOND": 6, "NANOSECOND": 9}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ISO = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})",
    re.ASCII,
)


def uuid7(unix_ms: int | None = None, rand: bytes | None = None) -> str:
    """Return an RFC 9562 version 7 UUID string."""
    ms = int(time.time() * 1000) if unix_ms is None else unix_ms
    if not 0 <= ms < 1 << 48:
        raise ValueError("unix_ms out of range")
    r = os.urandom(10) if rand is None else rand
    if len(r) != 10:
        raise ValueError("rand must be 10 bytes")
    b = bytearray(ms.to_bytes(6, "big") + r)
    b[6] = 0x70 | (b[6] & 0x0F)
    b[8] = 0x80 | (b[8] & 0x3F)
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def now_ns() -> int:
    return time.time_ns()


def iso_from_ns(ns: int, precision: str = "MILLISECOND") -> str:
    """Format nanoseconds since the epoch as ``YYYY-MM-DDTHH:MM:SS.fffZ``."""
    digits = PRECISION_DIGITS.get(precision)
    if digits is None:
        raise ValueError(f"unknown precision {precision!r}")
    if ns < 0:
        raise ValueError("negative timestamp")
    seconds, frac = divmod(ns, 1_000_000_000)
    dt = _EPOCH + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "." + f"{frac:09d}"[:digits] + "Z"


def ns_from_iso(value: str) -> tuple[int, int]:
    """Parse an RFC 3339 timestamp. Returns (nanoseconds, fractional digits given)."""
    m = _ISO.fullmatch(value) if isinstance(value, str) else None
    if not m:
        raise ValueError(f"not an RFC 3339 timestamp: {value!r}")
    y, mo, d, hh, mm, ss, frac, tz = m.groups()
    dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    if tz != "Z":
        oh, om = int(tz[1:3]), int(tz[4:6])
        if oh > 23 or om > 59:
            raise ValueError(f"invalid UTC offset: {tz}")
        sign = 1 if tz[0] == "+" else -1
        dt = dt - sign * timedelta(hours=oh, minutes=om)
    delta = dt - _EPOCH
    seconds = delta.days * 86400 + delta.seconds
    frac = frac or ""
    ns = seconds * 1_000_000_000 + (int(frac.ljust(9, "0")) if frac else 0)
    return ns, len(frac)


def iso_matches_ns(iso: str, ns: int) -> bool:
    """True if ``TimestampISO`` and ``TimestampInt`` agree at the ISO value's precision."""
    iso_ns, digits = ns_from_iso(iso)
    unit = 10 ** (9 - digits)
    return ns // unit == iso_ns // unit
