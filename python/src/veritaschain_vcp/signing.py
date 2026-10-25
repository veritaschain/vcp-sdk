"""Ed25519 signatures (RFC 8032) for events and Merkle roots.

Which bytes are signed (INTERPRETATIONS.md, I-5):

* Event signature: the ASCII bytes of the bare lowercase hex EventHash, as in
  VCP v1.0 section 6.2.2 (``event_hash.encode()``). VCP v1.2 requires every
  event to be signed (section 6.3.1) but does not restate this.
* Merkle root signature: the 32 decoded root bytes, as in VCP v1.2
  section 6.3.1 (``bytes.fromhex(merkle_root)``). This signature covers the
  root only; it does not cover the other AnchorRecord fields.

Verification rule, identical in the Python and TypeScript packages:

* the public key must be a canonical encoding of a point on the curve that is
  not of small order (this rejects, among others, the identity point, for which
  ``R = identity, S = 0`` would "verify" any message);
* ``S`` must be below the group order L;
* the check is cofactorless: ``encode([S]B - [k]A)`` must equal the R bytes.

Signatures are standard base64 with padding, canonical spelling only. Only
ED25519 is implemented; other SignAlgo values are reported by the verifier as
unsupported, not as failures.
"""

from __future__ import annotations

import base64
import binascii
import os
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .hashing import parse_hash

__all__ = [
    "SigningKey",
    "VerifyKey",
    "generate_key",
    "sign_event_hash",
    "verify_event_signature",
    "sign_merkle_root",
    "verify_root_signature",
    "decode_key",
    "KeyRejected",
]

_HEX64 = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)

# --- point validation (edwards25519, RFC 8032 section 5.1.3) -------------------
_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(b: bytes) -> tuple[int, int] | None:
    """Strict RFC 8032 decoding; None for a non-canonical or off-curve encoding."""
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        return (0, y)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y)


_L = 2**252 + 27742317777372353535851937790883648493


def _ext_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Point addition in extended coordinates (RFC 8032 section 5.1.4)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ext_mul(k: int, pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)
    while k > 0:
        if k & 1:
            q = _ext_add(q, pt)
        pt = _ext_add(pt, pt)
        k >>= 1
    return q


def _is_identity(pt: tuple[int, int, int, int]) -> bool:
    x, y, z, _ = pt
    return x % _P == 0 and (y - z) % _P == 0


def public_key_problem(raw: bytes) -> str | None:
    """Why ``raw`` is not an acceptable Ed25519 public key, or None if it is.

    Accepted keys are canonical encodings of points in the prime-order subgroup
    other than the identity: small-order points and points with a small-order
    (torsion) component are rejected.
    """
    pt = _decode_point(raw)
    if pt is None:
        return "not a canonical encoding of a curve point"
    x, y = pt
    ext = (x, y, 1, x * y % _P)
    if _is_identity(_ext_mul(8, ext)):
        return "small-order point"
    if not _is_identity(_ext_mul(_L, ext)):
        return "point has a small-order (torsion) component"
    return None


class KeyRejected(ValueError):
    """A key could not be accepted."""


def decode_key(value: str | bytes) -> bytes:
    """Decode a 32-byte key given as raw bytes, 64-char hex or canonical base64."""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str) and _HEX64.fullmatch(value):
        raw = bytes.fromhex(value)
    elif isinstance(value, str):
        try:
            raw = base64.b64decode(value, validate=True)
        except binascii.Error as exc:
            raise KeyRejected("key is neither 64-char hex nor base64") from exc
        if base64.b64encode(raw).decode("ascii") != value:
            raise KeyRejected("key base64 is not in canonical form")
    else:
        raise KeyRejected("key must be bytes or str")
    if len(raw) != 32:
        raise KeyRejected(f"Ed25519 keys are 32 bytes, got {len(raw)}")
    return raw


class VerifyKey:
    """An Ed25519 public key. Rejects non-canonical, small-order and torsion-component points."""

    def __init__(self, public_key: str | bytes) -> None:
        self.raw = decode_key(public_key)
        problem = public_key_problem(self.raw)
        if problem:
            raise KeyRejected(f"public key rejected: {problem}")
        self._key = Ed25519PublicKey.from_public_bytes(self.raw)

    def verify(self, signature: bytes, message: bytes) -> bool:
        # OpenSSL: S < L check and cofactorless comparison of encoded R.
        try:
            self._key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def to_base64(self) -> str:
        return base64.b64encode(self.raw).decode("ascii")

    def __repr__(self) -> str:
        return f"VerifyKey({self.to_base64()})"


class SigningKey:
    """An Ed25519 private key (32-byte seed)."""

    def __init__(self, seed: str | bytes) -> None:
        self._seed = decode_key(seed)
        self._key = Ed25519PrivateKey.from_private_bytes(self._seed)
        self.verify_key = VerifyKey(self._key.public_key().public_bytes_raw())

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def seed_base64(self) -> str:
        return base64.b64encode(self._seed).decode("ascii")

    def __repr__(self) -> str:
        return f"SigningKey(public={self.verify_key.to_base64()})"


def generate_key() -> SigningKey:
    return SigningKey(os.urandom(32))


def _b64decode_signature(signature_b64: object) -> bytes | None:
    if not isinstance(signature_b64, str):
        return None
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(sig) != 64 or base64.b64encode(sig).decode("ascii") != signature_b64:
        return None
    return sig


def sign_event_hash(event_hash: str, key: SigningKey) -> str:
    message = parse_hash(event_hash).encode("ascii")
    return base64.b64encode(key.sign(message)).decode("ascii")


def verify_event_signature(event_hash: str, signature_b64: str, key: VerifyKey) -> bool:
    sig = _b64decode_signature(signature_b64)
    if sig is None:
        return False
    return key.verify(sig, parse_hash(event_hash).encode("ascii"))


def sign_merkle_root(merkle_root: str, key: SigningKey) -> str:
    return base64.b64encode(key.sign(bytes.fromhex(parse_hash(merkle_root)))).decode("ascii")


def verify_root_signature(merkle_root: str, signature_b64: str, key: VerifyKey) -> bool:
    sig = _b64decode_signature(signature_b64)
    if sig is None:
        return False
    return key.verify(sig, bytes.fromhex(parse_hash(merkle_root)))
