"""Edge-case Ed25519 material built with RFC 8032 reference arithmetic.

Used by generate_vectors.py. Produces: the 8 small-order point encodings,
non-canonical encodings, the identity-key "signature" that verifies any message
under a cofactorless check, a mixed-order-R signature from a real key (rejected
by a cofactorless check, accepted by some cofactored ones), and an S >= L
variant of a valid signature.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENT = (0, 1, 1, 0)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(s: int, pt):
    q = IDENT
    while s > 0:
        if s & 1:
            q = add(q, pt)
        pt = add(pt, pt)
        s >>= 1
    return q


def enc(pt) -> bytes:
    x, y, z, _ = pt
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def recover_x(y: int, sign: int):
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return 0 if not sign else None
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


GY = 4 * _inv(5) % P
GX = recover_x(GY, 0)
B = (GX, GY, 1, GX * GY % P)


def _torsion8():
    for y in range(2, 500):
        x = recover_x(y, 0)
        if x is None:
            continue
        t = mul(L, (x, y, 1, x * y % P))
        if enc(mul(4, t)) != enc(IDENT):
            return t
    raise RuntimeError("no order-8 point found")


T8 = _torsion8()


def small_order_encodings() -> list[str]:
    return sorted({enc(mul(k, T8)).hex() for k in range(8)})


def non_canonical_encodings() -> list[str]:
    out = []
    for y in (P, P + 1):  # aliases of y = 0 and y = 1
        for sign in (0, 1):
            out.append((y | (sign << 255)).to_bytes(32, "little").hex())
    out.append((1 | (1 << 255)).to_bytes(32, "little").hex())  # identity with sign bit set (x = 0)
    return out


def torsion_component_encodings(seed: bytes) -> list[str]:
    """A + T for the seed's public key A and small-order T of order 2, 4 and 8.

    Canonical encodings of points that are neither small-order nor in the
    prime-order subgroup.
    """
    _a, a_bytes = _secret(seed)
    a_pt = mul(_secret(seed)[0], B)
    return [enc(add(a_pt, mul(k, T8))).hex() for k in (4, 2, 1)]


def _secret(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, enc(mul(a, B))


def _k(r_bytes: bytes, a_bytes: bytes, msg: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r_bytes + a_bytes + msg).digest(), "little") % L


def mixed_order_signature(seed: bytes, msg: bytes, r: int = 12345678901234567890) -> bytes:
    a, a_bytes = _secret(seed)
    r_bytes = enc(add(mul(r, B), T8))
    s = (r + _k(r_bytes, a_bytes, msg) * a) % L
    return r_bytes + s.to_bytes(32, "little")


def identity_forgery() -> tuple[str, str]:
    """(public key, signature): identity point and (R = identity, S = 0)."""
    ident = enc(IDENT)
    return ident.hex(), (ident + bytes(32)).hex()


def s_plus_l(signature: bytes) -> bytes:
    s = int.from_bytes(signature[32:], "little") + L
    return signature[:32] + s.to_bytes(32, "little")
