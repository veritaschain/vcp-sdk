#!/usr/bin/env python3
"""Generate test-vectors/vectors.json and test-vectors/hostile.json.

vectors.json holds known-good material produced by the Python implementation
(canonical bytes, hashes, signatures, Merkle roots and proofs), which the
TypeScript and MQL5 code must reproduce. Merkle values are also checked against
transparency-dev/merkle (tools/merkle-crosscheck-go) and JCS against the
rfc8785 package, so the file is not only self-referential.

hostile.json holds malformed and adversarial inputs. Each case's expected
status is written by hand in this file, not computed by the verifier, and both
test suites must produce it.

Usage:  python tools/generate_vectors.py [OUTPUT_DIR]   (default: test-vectors/)
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ed25519_edge as edge  # noqa: E402

import veritaschain_vcp as vcp  # noqa: E402
from veritaschain_vcp import merkle  # noqa: E402
from veritaschain_vcp.jcs import CanonicalizationError, canonicalize_str, format_number  # noqa: E402
from veritaschain_vcp.producer import build_batch, seal_event  # noqa: E402
from veritaschain_vcp.verify import verify_batch, verify_chain, verify_event, verify_inclusion_proof  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SEED1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"

# RFC 8032 section 7.1 TEST 1, 2 and 3
RFC8032 = [
    {"seed": SEED1, "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "message": "",
     "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
    {"seed": SEED2, "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "message": "72",
     "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
    {"seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "message": "af82",
     "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
]

JCS_INPUTS = [
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], '
    '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", "literals": [null, true, false]}',
    '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", "\\ufb33": "Hebrew Letter Dalet With Dagesh", '
    '"1": "One", "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control", '
    '"\\u00f6": "Latin Small Letter O With Diaeresis"}',
    '{"TimestampInt": 1791504000123456789, "SequenceNum": 0, "Big": 9007199254740993, "Neg": -9007199254740993}',
    '{"a": [1, 2.5, -0.0, 1e21, 1e-7, 123456789012345680000], "b": {"z": "\\u001f\\u007f", "y": "日本語"}}',
    '{"P60": 1152921504606846976, "Collide": 1791504000123456768, "Other": 1791504000123456800, "Min": -9223372036854775808, "Max": 9223372036854775807}',
    '-0',
    '[]',
    '{}',
    '"\\u2028\\u2029"',
]

INTEGERS = [0, -1, 2**53, 2**53 + 1, 2**60, 1791504000000000000, 1791504000123456768, 1791504000123456800,
            1791504000123456789, -(2**63), 2**63 - 1, 10**21, 10**21 + 1, 10**30]


def number_vectors() -> list[dict[str, str]]:
    rng = random.Random(20261025)
    specials = [
        "0000000000000000", "8000000000000000", "0000000000000001", "7fefffffffffffff",
        "4340000000000000", "4430000000000000", "44b52d02c7e14af6", "444b1ae4d6e2ef50",
        "3eb0c6f7a0b5ed8d", "41b3de4355555554", "becbf647612f3696", "43143ff3c1cb0959",
    ]
    bits = specials + [rng.getrandbits(64).to_bytes(8, "big").hex() for _ in range(3000)]
    bits += [struct.pack(">d", rng.uniform(-1e6, 1e6)).hex() for _ in range(1000)]
    bits += [struct.pack(">d", float(rng.randrange(-(2**53), 2**53))).hex() for _ in range(500)]
    out = []
    for b in bits:
        x = struct.unpack(">d", bytes.fromhex(b))[0]
        if x != x or x in (float("inf"), float("-inf")):
            continue
        out.append({"bits": b, "es": format_number(x, strict=True)})
    return out


def integer_vectors() -> list[dict]:
    out = []
    for n in INTEGERS:
        try:
            strict = format_number(n, strict=True)
        except CanonicalizationError:
            strict = None
        out.append({"value": str(n), "default": format_number(n), "strict": strict})
    return out


def merkle_vectors() -> dict:
    leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(24)]
    roots, legacy, inclusion, consistency = {}, {}, {}, {}
    for n in range(0, 25):
        roots[str(n)] = merkle.root(leaves[:n]).hex()
    for n in range(1, 25):
        t = merkle.MerkleTree(leaves[:n])
        legacy[str(n)] = merkle.legacy_example_root(leaves[:n]).hex()
        inclusion[str(n)] = {str(i): [h.hex() for h in t.inclusion_proof(i)] for i in range(n)}
        consistency[str(n)] = {str(m): [h.hex() for h in t.consistency_proof(m)] for m in range(1, n)}
    return {"leaf_data": "sha256(decimal string of i), i = 0..23", "leaves": [x.hex() for x in leaves],
            "roots": roots, "legacy_example_roots": legacy, "inclusion": inclusion, "consistency": consistency}


PAYLOADS = [
    ("INIT", {"VCP-GOV": {"AlgoID": "example-ea", "AlgoVersion": "1.0.0"}}),
    ("SIG", {"VCP-TRADE": {"Symbol": "USDJPY", "Side": "BUY", "Price": "151.234", "Quantity": "100000"}}),
    ("ORD", {"VCP-TRADE": {"Symbol": "USDJPY", "Side": "BUY", "OrderType": "LIMIT", "Price": "151.230", "Quantity": "100000",
                           "Note": "注文 € \u001f  "}}),
    ("ERR_REJECT", {"VCP-TRADE": {"Symbol": "USDJPY", "RejectReason": "price out of band"}}),
    ("CXL", {"VCP-TRADE": {"Symbol": "USDJPY", "Tags": ["a", "b", 3, True, None]}, "VCP-RISK": {"Limit": "5"}}),
]


def good_batch(n: int = 5, precision: str = "NANOSECOND", base: int = 1791504000123456789):
    key = vcp.SigningKey(SEED1)
    producer = vcp.Producer(key, actor_id="actor-example", chain_id="chain-001",
                            policy_id="org.veritaschain.sdk:test-vectors", precision=precision, use_prev_hash=True)
    for i, (et, pl) in enumerate(PAYLOADS[:n]):
        ts = base + i * 1_000_123
        producer.create(et, pl, timestamp_ns=ts, event_id=vcp.uuid7(ts // 1_000_000, rand=bytes([i]) * 10))
    target = {"Type": "PUBLIC_SERVICE", "Identifier": "example.invalid", "Proof": "synthetic-proof-not-a-real-anchor"}
    batch, record = producer.close_batch(anchor_target=target, timestamp_ns=base + 10_000_000_000)
    return key, batch, record


def reseal(ev: dict, key: vcp.SigningKey) -> dict:
    """Re-sign an event after its Header/Payload was changed (keeps PrevHash)."""
    out = seal_event(ev["Header"], ev["Payload"], key, prev_hash=ev["Security"].get("PrevHash"))
    for k in ("MerkleRoot", "MerkleIndex", "AnchorReference"):
        if k in ev["Security"]:
            out["Security"][k] = ev["Security"][k]
    return out


def events_and_batch():
    key, batch, record = good_batch()
    rows = []
    for ev in batch.events:
        rows.append({
            "event": ev,
            "canonical_header": canonicalize_str(ev["Header"]),
            "canonical_payload": canonicalize_str(ev["Payload"]),
            "event_hash": vcp.parse_hash(ev["Security"]["EventHash"]),
        })
    proofs = {str(i): batch.inclusion_proof(i) for i in range(len(batch.events))}
    return key, rows, batch, record, proofs


def cases(key, rows, record):
    events = [r["event"] for r in rows]
    pub = key.verify_key.to_base64()
    other = vcp.SigningKey(SEED2).verify_key.to_base64()
    out = []

    def add(name, evs, rec, pubkey, ext, chain=False):
        if chain:
            rep = verify_chain(evs, prior_hash=None)
        else:
            rep = verify_batch(evs, rec, pubkey, external_anchor_verifier=(lambda r: ext) if ext is not None else None)
        out.append({
            "name": name, "kind": "chain" if chain else "batch", "events": evs, "anchor_record": rec,
            "public_key": pubkey, "external_anchor_result": ext, "expected_status": rep.status,
            "expected_non_valid": sorted({(c.name, c.status, c.reason or "") for c in rep.checks if c.status != "VALID"}),
            "expected_checks": [[c.name, c.status, c.reason or "", c.subject or ""] for c in rep.checks],
        })

    add("intact batch, external anchor verified by caller", events, record, pub, True)
    add("intact batch, no external anchor verifier", events, record, pub, None)
    add("intact batch, no key", events, record, None, True)
    add("wrong key", events, record, other, True)
    t = copy.deepcopy(events)
    t[2]["Payload"]["VCP-TRADE"]["Price"] = "151.231"
    add("payload altered after hashing", t, record, pub, True)
    add("event omitted", events[:2] + events[3:], record, pub, True)
    t = copy.deepcopy(events)
    t[1], t[2] = t[2], t[1]
    add("events reordered", t, record, pub, True)
    r2 = copy.deepcopy(record)
    r2["EventCount"] = 4
    add("EventCount altered (not covered by the root signature)", events, r2, pub, True)
    t = copy.deepcopy(events)
    t[0]["Header"]["TimestampISO"] = "2026-10-09T00:00:01.000000000Z"
    add("TimestampISO disagrees with TimestampInt", t, record, pub, True)
    add("external anchor reported as not matching", events, record, pub, False)
    add("chain intact", events, None, None, None, chain=True)
    t = copy.deepcopy(events)
    del t[2]
    add("chain with a missing event", t, None, None, None, chain=True)
    return out


def ed25519_edges(rows) -> dict:
    ident_pub, weak_sig = edge.identity_forgery()
    ev0 = rows[0]["event"]
    msg = rows[0]["event_hash"].encode("ascii")
    mixed = edge.mixed_order_signature(bytes.fromhex(SEED1), msg)
    good = base64.b64decode(ev0["Security"]["Signature"])
    return {
        "small_order_public_keys": edge.small_order_encodings(),
        "non_canonical_public_keys": edge.non_canonical_encodings(),
        "torsion_component_public_keys": edge.torsion_component_encodings(bytes.fromhex(SEED1)),
        "identity_forgery": {"public": ident_pub, "signature": weak_sig},
        "event0_mixed_order_signature": base64.b64encode(mixed).decode(),
        "event0_s_plus_l_signature": base64.b64encode(edge.s_plus_l(good)).decode(),
    }


def hostile(key, rows, record, edges) -> list[dict]:
    """Adversarial cases. Expected statuses are written by hand."""
    pub = key.verify_key.to_base64()
    events = [r["event"] for r in rows]
    ev0 = events[0]
    out: list[dict] = []

    def ev_case(name, event, expected, reason=None, public_key=pub, require=None):
        out.append({"name": name, "kind": "event", "event": event, "public_key": public_key,
                    "require_sign_algo": require, "expected": expected, "reason": reason})

    def mut(fn, ev=ev0, resign=False):
        e = copy.deepcopy(ev)
        fn(e)
        return reseal(e, key) if resign else e

    def bare(e):
        e["Security"]["EventHash"] = vcp.parse_hash(e["Security"]["EventHash"])

    ev_case("HashAlgo is a list", mut(lambda e: (bare(e), e["Security"].__setitem__("HashAlgo", ["SHA256"]))), "INVALID", "BAD_FORMAT")
    ev_case("HashAlgo is an object", mut(lambda e: (bare(e), e["Security"].__setitem__("HashAlgo", {}))), "INVALID", "BAD_FORMAT")
    ev_case("HashAlgo is null", mut(lambda e: e["Security"].__setitem__("HashAlgo", None)), "INVALID", "BAD_FORMAT")
    for name in ("toString", "constructor", "__proto__", "valueOf", "hasOwnProperty"):
        ev_case(f"HashAlgo named {name}", mut(lambda e, n=name: (bare(e), e["Security"].__setitem__("HashAlgo", n))),
                "INDETERMINATE", "ALGORITHM_UNSUPPORTED")
    ev_case("TimestampISO with trailing newline", mut(lambda e: e["Header"].__setitem__("TimestampISO", e["Header"]["TimestampISO"] + "\n"), resign=True), "INVALID", "BAD_FORMAT")
    ev_case("TimestampISO with full-width digits", mut(lambda e: e["Header"].__setitem__("TimestampISO", "２０２６" + e["Header"]["TimestampISO"][4:]), resign=True), "INVALID", "BAD_FORMAT")
    ev_case("TimestampISO with second 60", mut(lambda e: e["Header"].__setitem__("TimestampISO", "2026-10-09T00:00:60.123456789Z"), resign=True), "INVALID", "BAD_FORMAT")
    ev_case("TimestampISO year 0070 with TimestampInt 0",
            mut(lambda e: (e["Header"].__setitem__("TimestampISO", "0070-01-01T00:00:00.000000000Z"), e["Header"].__setitem__("TimestampInt", 0)), resign=True),
            "INVALID", "TIMESTAMP_MISMATCH")
    ev_case("TimestampISO with +09:00 offset", mut(lambda e: e["Header"].__setitem__("TimestampISO", "2026-10-09T09:00:00.123456789+09:00"), resign=True), "VALID")
    ev_case("TimestampISO in 1969 within one unit of the epoch",
            mut(lambda e: (e["Header"].__setitem__("TimestampISO", "1969-12-31T23:59:59.9995Z"), e["Header"].__setitem__("TimestampInt", 0)), resign=True),
            "INVALID", "TIMESTAMP_MISMATCH")
    ev_case("TimestampInt written as a float", mut(lambda e: e["Header"].__setitem__("TimestampInt", 1.791504000123e18)), "INVALID", "CANONICALIZATION_UNSUPPORTED")
    ev_case("SequenceNum written as 0.0", mut(lambda e: e["Header"].__setitem__("SequenceNum", 0.0)), "VALID")
    ev_case("EventID with trailing newline", mut(lambda e: e["Header"].__setitem__("EventID", e["Header"]["EventID"] + "\n")), "INVALID", "BAD_FORMAT")
    ev_case("ActorID is a big integer", mut(lambda e: e["Header"].__setitem__("ActorID", 12345678901234567890123)), "INVALID", "MISSING_FIELD")
    ev_case("Header is an array", mut(lambda e: e.__setitem__("Header", [1, 2])), "INVALID", "MISSING_FIELD")
    ev_case("event is an array", [ev0], "INVALID", "NOT_AN_OBJECT")
    ev_case("PolicyIdentification is a string", mut(lambda e: e.__setitem__("PolicyIdentification", "x")), "INVALID", "BAD_FORMAT")
    ev_case("PrevHash is garbage", mut(lambda e: e["Security"].__setitem__("PrevHash", "garbage"), ev=events[1]), "INVALID", "BAD_FORMAT")
    ev_case("Signature is a number", mut(lambda e: e["Security"].__setitem__("Signature", 123)), "INVALID", "BAD_FORMAT")
    ev_case("SignAlgo DILITHIUM2, no algorithm required", mut(lambda e: e["Security"].__setitem__("SignAlgo", "DILITHIUM2")), "INDETERMINATE", "ALGORITHM_UNSUPPORTED")
    ev_case("SignAlgo DILITHIUM2, ED25519 required", mut(lambda e: e["Security"].__setitem__("SignAlgo", "DILITHIUM2")), "INVALID", "ALGORITHM_MISMATCH", require="ED25519")
    ev_case("identity public key with (R=identity, S=0)",
            mut(lambda e: e["Security"].__setitem__("Signature", base64.b64encode(bytes.fromhex(edges["identity_forgery"]["signature"])).decode())),
            "INDETERMINATE", "KEY_NOT_ESTABLISHED", public_key={"actor-example": base64.b64encode(bytes.fromhex(edges["identity_forgery"]["public"])).decode()})
    ev_case("mixed-order R signature from the real key", mut(lambda e: e["Security"].__setitem__("Signature", edges["event0_mixed_order_signature"])), "INVALID", "SIGNATURE_MISMATCH")
    ev_case("S + L signature", mut(lambda e: e["Security"].__setitem__("Signature", edges["event0_s_plus_l_signature"])), "INVALID", "SIGNATURE_MISMATCH")
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    noncanon = pub[:-2] + b64[b64.index(pub[-2]) | 1] + "="
    assert noncanon != pub
    ev_case("public key base64 with non-zero padding bits", ev0, "INDETERMINATE", "KEY_NOT_ESTABLISHED", public_key=noncanon)
    for i, enc in enumerate(edges["small_order_public_keys"]):
        ev_case(f"small-order public key {i}", ev0, "INDETERMINATE", "KEY_NOT_ESTABLISHED", public_key=enc)
    for i, enc in enumerate(edges["non_canonical_public_keys"]):
        ev_case(f"non-canonical public key {i}", ev0, "INDETERMINATE", "KEY_NOT_ESTABLISHED", public_key=enc)
    for i, enc in enumerate(edges["torsion_component_public_keys"]):
        ev_case(f"public key with a torsion component {i}", ev0, "INDETERMINATE", "KEY_NOT_ESTABLISHED", public_key=enc)

    # integer collision: sealed with ...768, presented with ...800
    k2, b2, _ = good_batch(1, precision="MILLISECOND", base=1791504000123456768)
    collide = copy.deepcopy(b2.events[0])
    collide["Header"]["TimestampInt"] = 1791504000123456800
    ev_case("TimestampInt 1791504000123456768 replaced by 1791504000123456800", collide, "INVALID", "HASH_MISMATCH")
    ev_case("TimestampInt 1791504000123456768 untouched", b2.events[0], "VALID")

    def b_case(name, evs, rec, expected, reason=None, ext=True, require=None):
        out.append({"name": name, "kind": "batch", "events": evs, "anchor_record": rec, "public_key": pub,
                    "external_anchor_result": ext, "require_sign_algo": require, "expected": expected, "reason": reason})

    def rec_mut(fn):
        r = copy.deepcopy(record)
        fn(r)
        return r

    b_case("AnchorRecord is an array", events, [record], "INVALID", "BAD_FORMAT")
    b_case("events is an object", {"a": events[0]}, record, "INVALID", "BAD_FORMAT")
    t = copy.deepcopy(events)
    t[1]["Security"]["MerkleIndex"] = True
    b_case("MerkleIndex true", t, record, "INVALID", "BAD_FORMAT")
    b_case("EventCount true", events, rec_mut(lambda r: r.__setitem__("EventCount", True)), "INVALID", "BINDING_MISMATCH")
    b_case("AnchorTarget Type unknown, Proof object", events, rec_mut(lambda r: r.__setitem__("AnchorTarget", {"Type": "NOT_A_TYPE", "Proof": {}})), "INVALID", "BAD_FORMAT")
    b_case("AnchorTarget Proof object", events, rec_mut(lambda r: r.__setitem__("AnchorTarget", {"Type": "TSA", "Proof": {}})), "INVALID", "BAD_FORMAT")
    b_case("AnchorTarget Proof empty", events, rec_mut(lambda r: r.__setitem__("AnchorTarget", {"Type": "TSA", "Proof": ""})), "INDETERMINATE", "MISSING_ANCHOR_PROOF")
    b_case("AnchorTarget is a string", events, rec_mut(lambda r: r.__setitem__("AnchorTarget", "x")), "INVALID", "BAD_FORMAT")
    b_case("AnchorRecord Timestamp -5", events, rec_mut(lambda r: r.__setitem__("Timestamp", -5)), "INVALID", "BAD_FORMAT")
    b_case("AnchorRecord Timestamp is a string", events, rec_mut(lambda r: r.__setitem__("Timestamp", "yesterday")), "INVALID", "BAD_FORMAT")
    t = copy.deepcopy(events)
    for e in t:
        e["Security"]["AnchorReference"] = "totally-different-anchor"
    b_case("AnchorReference altered (not checked; see notes)", t, record, "VALID")
    t = copy.deepcopy(events)
    for e in t:
        del e["Security"]["MerkleRoot"]
        del e["Security"]["MerkleIndex"]
    b_case("events lack MerkleRoot and MerkleIndex", t, record, "INDETERMINATE", "MISSING_FIELD")
    t = copy.deepcopy(events)
    t[0]["Security"]["HashAlgo"] = "toString"
    t[0]["Security"]["EventHash"] = vcp.parse_hash(t[0]["Security"]["EventHash"])
    b_case("HashAlgo toString inside a batch", t, record, "INDETERMINATE", "ALGORITHM_UNSUPPORTED")
    # a batch built the section 6.2.1 example way
    leaves = [bytes.fromhex(vcp.parse_hash(e["Security"]["EventHash"])) for e in events[:3]]
    legacy = merkle.legacy_example_root(leaves).hex()
    lev = copy.deepcopy(events[:3])
    for e in lev:
        e["Security"]["MerkleRoot"] = legacy
        e["Security"]["AnchorReference"] = legacy
    lrec = copy.deepcopy(record)
    lrec.update({"MerkleRoot": legacy, "Signature": vcp.sign_merkle_root(legacy, key), "EventCount": 3, "LastEventID": lev[-1]["Header"]["EventID"]})
    b_case("batch built with the section 6.2.1 example construction", lev, lrec, "INDETERMINATE", "LEGACY_MERKLE_CONSTRUCTION")

    # A tampered event must stay INVALID whatever is wrong with the (unsigned)
    # AnchorRecord fields next to it: no malformed field may turn the report
    # into INDETERMINATE.
    tampered = copy.deepcopy(events)
    tampered[2]["Payload"]["VCP-TRADE"]["Price"] = "999"
    big = 12345678901234567890123
    combos = [
        ("AnchorTarget.Type is a list", lambda r: r["AnchorTarget"].__setitem__("Type", ["TSA"]), None),
        ("AnchorTarget.Type is an object", lambda r: r["AnchorTarget"].__setitem__("Type", {}), None),
        ("AnchorTarget.Type is a big integer", lambda r: r["AnchorTarget"].__setitem__("Type", big), None),
        ("SignAlgo is a big integer, ED25519 required", lambda r: r.__setitem__("SignAlgo", big), "ED25519"),
        ("SignAlgo is a list, ED25519 required", lambda r: r.__setitem__("SignAlgo", ["ED25519"]), "ED25519"),
        ("AnchorTarget.Proof is an object", lambda r: r["AnchorTarget"].__setitem__("Proof", {}), None),
        ("Timestamp is a string", lambda r: r.__setitem__("Timestamp", "yesterday"), None),
        ("EventCount is an object", lambda r: r.__setitem__("EventCount", {}), None),
        ("FirstEventID is an object", lambda r: r.__setitem__("FirstEventID", {}), None),
        ("PolicyID is a list", lambda r: r.__setitem__("PolicyID", ["x"]), None),
        ("MerkleRoot is a list", lambda r: r.__setitem__("MerkleRoot", [record["MerkleRoot"]]), None),
        ("Signature is a list", lambda r: r.__setitem__("Signature", [record["Signature"]]), None),
        ("AnchorTarget is a list", lambda r: r.__setitem__("AnchorTarget", [record["AnchorTarget"]]), None),
    ]
    for label, fn, req in combos:
        b_case(f"tampered event and {label}", tampered, rec_mut(fn), "INVALID", "HASH_MISMATCH", require=req)
    b_case("tampered event, external verifier absent", tampered, record, "INVALID", "HASH_MISMATCH", ext=None)
    t = copy.deepcopy(events)
    t[-1]["Header"]["EventID"] = None
    b_case("last EventID null and LastEventID absent", t, rec_mut(lambda r: r.pop("LastEventID")), "INVALID", "BINDING_MISMATCH")
    t = copy.deepcopy(events)
    t[0]["Header"]["EventID"] = None
    b_case("first EventID null and FirstEventID null", t, rec_mut(lambda r: r.__setitem__("FirstEventID", None)), "INVALID", "BINDING_MISMATCH")

    def c_case(name, evs, expected, reason=None, prior=None):
        out.append({"name": name, "kind": "chain", "events": evs, "prior_hash": prior, "expected": expected, "reason": reason})

    t = copy.deepcopy(events)
    t[0]["Header"]["ActorID"] = 12345678901234567890123
    c_case("chain: first ActorID is a big integer", t, "INVALID", "MISSING_FIELD")
    t = copy.deepcopy(events)
    t[2]["Security"]["PrevHash"] = "garbage"
    c_case("chain: PrevHash garbage", t, "INVALID", "BAD_FORMAT")
    c_case("chain: prior_hash malformed", events[1:], "INDETERMINATE", "PRIOR_HASH_MALFORMED", prior="nothex")
    c_case("chain: prior_hash malformed and an event missing", [events[1]] + events[3:], "INVALID", "SEQUENCE_GAP", prior="nothex")
    c_case("chain: prior_hash given, first event INIT without PrevHash", events, "INDETERMINATE", "CHAIN_NOT_USED", prior="ab" * 32)
    c_case("chain: continues from the given prior hash", events[1:], "VALID", prior=rows[0]["event_hash"])

    h0 = rows[0]["event_hash"]
    proofs = dict(enumerate(proofs_for(events)))

    def i_case(name, args, expected, reason=None):
        out.append({"name": name, "kind": "inclusion", "args": args, "expected": expected, "reason": reason})

    i_case("inclusion: hash with trailing newline", [h0 + "\n", 0, 5, proofs[0], record["MerkleRoot"], True], "INVALID", "BAD_FORMAT")
    i_case("inclusion: tree_size is a string", [h0, 0, "5", proofs[0], record["MerkleRoot"], True], "INVALID", "BAD_FORMAT")
    i_case("inclusion: index is true", [h0, True, 5, proofs[0], record["MerkleRoot"], True], "INVALID", "BAD_FORMAT")
    i_case("inclusion: valid, root asserted by caller", [h0, 0, 5, proofs[0], record["MerkleRoot"], True], "VALID")
    i_case("inclusion: valid, root not authenticated", [h0, 0, 5, proofs[0], record["MerkleRoot"], False], "INDETERMINATE", "ROOT_NOT_AUTHENTICATED")
    i_case("inclusion: root_authenticated is the string \"false\"", [h0, 0, 5, proofs[0], record["MerkleRoot"], "false"], "INDETERMINATE", "ROOT_NOT_AUTHENTICATED")
    i_case("inclusion: root_authenticated is 1", [h0, 0, 5, proofs[0], record["MerkleRoot"], 1], "INDETERMINATE", "ROOT_NOT_AUTHENTICATED")
    i_case("inclusion: wrong index", [h0, 1, 5, proofs[0], record["MerkleRoot"], True], "INVALID", "PROOF_MISMATCH")
    # index 2**60 in a tree of 2**60 + 1 leaves: the proof is the root of the left 2**60 subtree
    left = bytes.fromhex("cd" * 32)
    big_root = merkle.node_hash(left, merkle.leaf_hash(bytes.fromhex(h0))).hex()
    i_case("inclusion: index 2**60 in a tree of 2**60 + 1 leaves", [h0, 2**60, 2**60 + 1, [left.hex()], big_root, True], "VALID")
    i_case("inclusion: index 2**60, wrong root", [h0, 2**60, 2**60 + 1, [left.hex()], record["MerkleRoot"], True], "INVALID", "PROOF_MISMATCH")

    def p_case(name, text, ok, canonical=None):
        out.append({"name": name, "kind": "parse", "text": text, "ok": ok, "canonical": canonical})

    p_case("nesting 200 deep", "[" * 200 + "]" * 200, False)
    p_case("nesting 129 deep", "[" * 129 + "]" * 129, False)
    p_case("nesting 128 deep", "[" * 128 + "]" * 128, True, "[" * 128 + "]" * 128)
    p_case("duplicate keys", '{"a":1,"a":2}', False)
    p_case("1e400", '{"a":1e400}', False)
    p_case("NaN", '{"a":NaN}', False)
    p_case("integer of 4301 digits", "1" * 4301, False)
    p_case("integer of 4300 digits", "1" * 4300, True, "1" * 4300)
    p_case("byte-order mark", "﻿{}", False)
    p_case("raw U+2028 in a string", '{"a":"x y"}', True, '{"a":"x y"}')
    p_case("-0", "-0", True, "0")
    p_case("float 1.8e18 (integral, at least 2**53)", "1.8e18", True, None)  # parses; canonicalising it is rejected
    p_case("lone surrogate escape", '"\\ud800"', True, None)  # parses; canonicalising it is rejected
    p_case("trailing comma", "[1,]", False)
    p_case("leading zero", "01", False)

    def l_case(name, text, count):
        out.append({"name": name, "kind": "jsonl", "text": text, "count": count})

    l_case("two objects joined by U+2028", '{"a":1} {"b":2}\n', None)
    l_case("two objects joined by form feed", '{"a":1}\x0c{"b":2}\n', None)
    l_case("two objects joined by U+0085", '{"a":1}\u0085{"b":2}\n', None)
    l_case("raw U+2028 inside a string", '{"a":"x y"}\n', 1)
    l_case("CRLF line endings", '{"a":1}\r\n{"b":2}\r\n', 2)
    l_case("blank lines", '\n{"a":1}\n\n  \n{"b":2}', 2)

    # The full check list the Python verifier produces, in order; the
    # TypeScript suite must produce the same list (details may differ).
    for c in out:
        if c["kind"] in ("event", "batch", "chain", "inclusion"):
            c["python_checks"] = [[x.name, x.status, x.reason or "", x.subject or ""] for x in run_case(c).checks]
    return out


def run_case(c):
    if c["kind"] == "event":
        return verify_event(c["event"], c["public_key"], c["require_sign_algo"])
    if c["kind"] == "batch":
        ext = c["external_anchor_result"]
        return verify_batch(c["events"], c["anchor_record"], c["public_key"],
                            external_anchor_verifier=(lambda r: ext) if ext is not None else None,
                            require_sign_algo=c["require_sign_algo"])
    if c["kind"] == "chain":
        return verify_chain(c["events"], prior_hash=c["prior_hash"])
    return verify_inclusion_proof(*c["args"])


def proofs_for(events):
    leaves = [bytes.fromhex(vcp.parse_hash(e["Security"]["EventHash"])) for e in events]
    t = merkle.MerkleTree(leaves)
    return [[h.hex() for h in t.inclusion_proof(i)] for i in range(len(events))]


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "test-vectors"
    out_dir.mkdir(parents=True, exist_ok=True)
    key, rows, batch, record, proofs = events_and_batch()
    jcs = []
    for text in JCS_INPUTS:
        jcs.append({"input": text, "canonical": canonicalize_str(json.loads(text))})
    edges = ed25519_edges(rows)
    doc = {
        "description": "Test vectors for veritaschain/vcp-sdk. Generated by tools/generate_vectors.py from the Python implementation. Synthetic data; the anchor proof is not a real external anchor.",
        "sdk_version": vcp.__version__,
        "vcp_spec": {"version": vcp.VCP_SPEC_VERSION, "commit": vcp.VCP_SPEC_COMMIT},
        "interpretations": "INTERPRETATIONS.md",
        "jcs": jcs,
        "integers": integer_vectors(),
        "numbers": number_vectors(),
        "merkle": merkle_vectors(),
        "ed25519_rfc8032": RFC8032,
        "ed25519_edges": edges,
        "signing_key_seed_hex": SEED1,
        "public_key_base64": key.verify_key.to_base64(),
        "events": rows,
        "batch": {"merkle_root": batch.merkle_root, "inclusion_proofs": proofs, "anchor_record": record},
        "single_event_status": verify_event(rows[0]["event"], key.verify_key).status,
        "cases": cases(key, rows, record),
    }
    (out_dir / "vectors.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    hz = {"description": "Hostile and malformed inputs for veritaschain/vcp-sdk. Expected results are written by hand in tools/generate_vectors.py; both test suites must produce them. Every verifier call must return a report, never raise.",
          "public_key_base64": key.verify_key.to_base64(),
          "cases": hostile(key, rows, record, edges)}
    (out_dir / "hostile.json").write_text(json.dumps(hz, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out_dir}/vectors.json ({len(doc['cases'])} cases) and hostile.json ({len(hz['cases'])} cases)")


if __name__ == "__main__":
    main()
