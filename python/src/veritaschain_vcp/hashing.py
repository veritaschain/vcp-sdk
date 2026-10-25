"""EventHash calculation (VCP v1.2 section 6.1).

``EventHash = H( JCS(Header) || JCS(Payload) [|| PrevHash-hex] )`` where ``||``
is string concatenation and the result is UTF-8 encoded before hashing
(section 6.1.1; the PrevHash form is section 6.1.2).

Representation choices this SDK makes where the specification leaves room
(INTERPRETATIONS.md, I-2 and I-3):

* :func:`compute_event_hash` returns the bare lowercase hex digest, as the
  section 6.1.1 example does.
* ``Security.EventHash`` is written in the ``sha256:<hex>`` form that the v1.2
  event schema describes for production values. Parsing accepts either form.
* When a PrevHash is used, the bare lowercase hex of the previous EventHash is
  appended, whatever form ``Security.PrevHash`` is written in.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from .jcs import canonicalize_str

__all__ = [
    "SUPPORTED_HASH_ALGOS",
    "UnsupportedAlgorithm",
    "compute_event_hash",
    "format_event_hash",
    "parse_hash",
    "ZERO_HASH",
]

ZERO_HASH = "0" * 64
_HEX64 = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)
_PREFIX = {"SHA256": "sha256:"}


class UnsupportedAlgorithm(ValueError):
    """The named algorithm is not implemented by this SDK."""


def _blake3(data: bytes) -> str:
    try:
        import blake3  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise UnsupportedAlgorithm("BLAKE3 needs the optional 'blake3' package") from exc
    return blake3.blake3(data).hexdigest()


_HASHERS = {
    "SHA256": lambda b: hashlib.sha256(b).hexdigest(),
    "SHA3_256": lambda b: hashlib.sha3_256(b).hexdigest(),
    "BLAKE3": _blake3,
}

SUPPORTED_HASH_ALGOS = frozenset(_HASHERS)


def parse_hash(value: str) -> str:
    """Return the bare lowercase hex digest from ``<hex>`` or ``sha256:<hex>``."""
    if not isinstance(value, str):
        raise ValueError("hash must be a string")
    body = value[7:] if value.startswith("sha256:") else value
    if not _HEX64.fullmatch(body):
        raise ValueError(f"not a 32-byte hex digest: {value!r}")
    return body.lower()


def format_event_hash(hex_digest: str, algo: str = "SHA256") -> str:
    """Return the value to store in ``Security.EventHash``."""
    return _PREFIX.get(algo, "") + parse_hash(hex_digest)


def compute_event_hash(
    header: Mapping[str, Any],
    payload: Mapping[str, Any],
    prev_hash: str | None = None,
    algo: str = "SHA256",
    strict_integers: bool = False,
) -> str:
    """Compute the EventHash of an event and return the bare lowercase hex digest.

    ``strict_integers=True`` applies RFC 8785 to integers too (see :mod:`.jcs`):
    an integer binary64 cannot represent exactly is rejected, and others are
    written in RFC 8785 form, so the hash differs from the default for many
    integers above 2**53.
    """
    hasher = _HASHERS.get(algo) if isinstance(algo, str) else None
    if hasher is None:
        raise UnsupportedAlgorithm(f"hash algorithm not supported: {algo!r}")
    hash_input = canonicalize_str(dict(header), strict_integers) + canonicalize_str(dict(payload), strict_integers)
    if prev_hash is not None:
        prev = parse_hash(prev_hash)
        if prev != ZERO_HASH:
            hash_input += prev
    return hasher(hash_input.encode("utf-8"))
