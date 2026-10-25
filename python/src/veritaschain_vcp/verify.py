"""Offline verification with three-valued results.

Every check returns ``VALID``, ``INVALID`` or ``INDETERMINATE``:

* ``VALID`` - the check was performed and matched.
* ``INVALID`` - the check was performed and a mismatch, or a malformed field,
  was shown.
* ``INDETERMINATE`` - the check could not be performed with the material and
  trust information supplied (missing proof or field, key not established,
  unsupported algorithm, value that cannot be canonicalised, and so on).

Precedence when combining: ``INVALID`` > ``INDETERMINATE`` > ``VALID``.
``INDETERMINATE`` is not a pass. The values follow the unadopted VSO discussion
draft ``vap-spec/proposals/three-valued-verification`` (revision 0.1); the
reason codes are this SDK's and are not registered identifiers.

A check that this module does not perform is not reported as VALID: either it is
reported INDETERMINATE, or the report says in a note that it is not checked.
An unexpected exception inside a verifier gives an INDETERMINATE report with
reason ``VERIFIER_ERROR`` rather than escaping.

What a ``VALID`` result does not show: that the events are true, that every
event that should have been recorded was recorded, that a key belongs to the
party named in the event (the caller supplies keys it trusts), or that the
system producing the events is conformant or certified.
"""

from __future__ import annotations

import functools
import inspect
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence, Union

from . import merkle
from .hashing import ZERO_HASH, UnsupportedAlgorithm, compute_event_hash, parse_hash
from .jcs import CanonicalizationError, differs_from_rfc8785
from .signing import VerifyKey, verify_event_signature, verify_root_signature
from .timeutil import iso_matches_ns

__all__ = [
    "VALID",
    "INVALID",
    "INDETERMINATE",
    "Check",
    "Report",
    "combine",
    "verify_event",
    "verify_batch",
    "verify_inclusion_proof",
    "verify_chain",
    "EVENT_TYPES",
]

VALID = "VALID"
INVALID = "INVALID"
INDETERMINATE = "INDETERMINATE"
_RANK = {VALID: 0, INDETERMINATE: 1, INVALID: 2}

EVENT_TYPES = frozenset(
    "INIT SIG ORD ACK EXE CXL MOD RSK ERR HBT CLS ANC "
    "ERR_CONN ERR_AUTH ERR_TIMEOUT ERR_REJECT ERR_PARSE ERR_SYNC ERR_RISK ERR_SYSTEM ERR_RECOVER "
    "ERASURE SYS_RECOVERY_ANNOUNCE SYS_CHECKPOINT SYS_AUDIT SYS_ANCHOR_MIGRATION SYS_ANCHOR_FAILOVER".split()
)
_ANCHOR_TYPES = frozenset({"BLOCKCHAIN", "TSA", "DATABASE", "PUBLIC_SERVICE"})
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.ASCII)
_HEADER_STR = ("EventID", "TimestampISO", "EventType", "ActorID", "ChainID", "PolicyID")
_HEADER_INT = ("TimestampInt", "SequenceNum")
_SEC_STR_OPTIONAL = ("Version", "HashAlgo", "PrevHash", "Signature", "MerkleRoot", "AnchorReference", "AnchorRef",
                     "PQCSignature", "PQCSignAlgo")

KeyInput = Union[VerifyKey, str, bytes, Mapping[str, Union[VerifyKey, str, bytes]], None]
ExternalVerifier = Callable[[Mapping[str, Any]], Optional[bool]]


@dataclass
class Check:
    name: str
    status: str
    reason: str | None = None
    detail: str | None = None
    subject: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "status": self.status}
        for k in ("reason", "detail", "subject"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


@dataclass
class Report:
    status: str
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from . import __version__

        return {
            "status": self.status,
            "checks": [c.to_dict() for c in self.checks],
            "notes": list(dict.fromkeys(self.notes)),
            "verifier": {
                "name": "veritaschain-vcp (Python)",
                "version": __version__,
                "vcp_version": "1.2.0",
                "result_values": "three-valued (VSO discussion draft, unadopted)",
            },
        }

    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.status != VALID]


def combine(statuses: Sequence[str]) -> str:
    """INVALID over INDETERMINATE over VALID. An empty list is INDETERMINATE."""
    if not statuses:
        return INDETERMINATE
    return max(statuses, key=lambda s: _RANK[s])


def _report(checks: list[Check], notes: list[str]) -> Report:
    return Report(combine([c.status for c in checks]), checks, list(dict.fromkeys(notes)))


@dataclass
class _Ctx:
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _guarded(fn: Callable[..., Report]) -> Callable[..., Report]:
    """Run a verifier so that an unexpected exception cannot hide results.

    Checks completed before the exception are kept (an INVALID among them still
    makes the report INVALID), and a VERIFIER_ERROR check is added.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Report:
        ctx = _Ctx()
        try:
            return fn(*args, _ctx=ctx, **kwargs)
        except Exception as exc:  # noqa: BLE001 - a verifier must not raise on hostile input
            checks = list(ctx.checks) + [Check("verifier", INDETERMINATE, "VERIFIER_ERROR", f"{type(exc).__name__}: {exc}")]
            return _report(checks, ctx.notes)

    sig = inspect.signature(fn)
    wrapper.__signature__ = sig.replace(parameters=[p for p in sig.parameters.values() if p.name != "_ctx"])  # type: ignore[attr-defined]
    return wrapper


def _is_obj(v: Any) -> bool:
    return isinstance(v, Mapping)


def _hdr(e: Any) -> Mapping[str, Any]:
    h = e.get("Header") if _is_obj(e) else None
    return h if _is_obj(h) else {}


def _sec(e: Any) -> Mapping[str, Any]:
    s = e.get("Security") if _is_obj(e) else None
    return s if _is_obj(s) else {}


def _is_int(v: Any) -> bool:
    """A JSON integer: an int, or a float with an integral value (JSON Schema semantics)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and math.isfinite(v) and v.is_integer()


def _safe_hex(v: Any) -> str | None:
    try:
        return parse_hash(v)
    except (ValueError, TypeError):
        return None


@functools.lru_cache(maxsize=256)
def _cached_key(value: str | bytes) -> VerifyKey:
    return VerifyKey(value)


def _key_for(keys: KeyInput, actor_id: Any) -> tuple[VerifyKey | None, str | None]:
    """Return (key, problem). ``problem`` is set when a supplied key was rejected."""
    if keys is None:
        return None, None
    try:
        if isinstance(keys, VerifyKey):
            return keys, None
        if isinstance(keys, (str, bytes)):
            return _cached_key(keys), None
        if not isinstance(actor_id, str) or not isinstance(keys, Mapping):
            return None, None
        k = keys.get(actor_id)
        if k is None:
            return None, None
        if isinstance(k, VerifyKey):
            return k, None
        if isinstance(k, (str, bytes)):
            return _cached_key(k), None
        return None, "key must be a string or bytes"
    except ValueError as exc:
        return None, str(exc)


def _structure(event: Any, subject: str | None) -> Check:
    def bad(reason: str, detail: str) -> Check:
        return Check("structure", INVALID, reason, detail, subject)

    if not _is_obj(event):
        return bad("NOT_AN_OBJECT", "event is not a JSON object")
    for part in ("Header", "Payload", "Security"):
        if not _is_obj(event.get(part)):
            return bad("MISSING_FIELD", f"{part} object missing")
    h, s = event["Header"], event["Security"]
    for f in _HEADER_STR:
        if not isinstance(h.get(f), str) or not h.get(f):
            return bad("MISSING_FIELD", f"Header.{f} missing or not a string")
    for f in _HEADER_INT:
        if not _is_int(h.get(f)) or h[f] < 0:
            return bad("MISSING_FIELD", f"Header.{f} missing or not a non-negative integer")
    if not _UUID.fullmatch(h["EventID"]):
        return bad("BAD_FORMAT", "Header.EventID is not a UUID")
    if "TraceID" in h and not (isinstance(h["TraceID"], str) and _UUID.fullmatch(h["TraceID"])):
        return bad("BAD_FORMAT", "Header.TraceID is not a UUID")
    if h["EventType"] not in EVENT_TYPES:
        return bad("UNKNOWN_EVENT_TYPE", f"EventType {h['EventType']!r} is not in the v1.2 registry")
    for f in ("EventHash", "SignAlgo"):
        if not isinstance(s.get(f), str) or not s.get(f):
            return bad("MISSING_FIELD", f"Security.{f} missing or not a string")
    for f in _SEC_STR_OPTIONAL:
        if f in s and not isinstance(s[f], str):
            return bad("BAD_FORMAT", f"Security.{f} is not a string")
    if "PrevHash" in s and _safe_hex(s["PrevHash"]) is None:
        return bad("BAD_FORMAT", "Security.PrevHash is not a 32-byte hex digest")
    if "MerkleRoot" in s and _safe_hex(s["MerkleRoot"]) is None:
        return bad("BAD_FORMAT", "Security.MerkleRoot is not a 32-byte hex digest")
    if "MerkleIndex" in s and not (_is_int(s["MerkleIndex"]) and s["MerkleIndex"] >= 0):
        return bad("BAD_FORMAT", "Security.MerkleIndex is not a non-negative integer")
    pid = event.get("PolicyIdentification")
    if "PolicyIdentification" in event and not _is_obj(pid):
        return bad("BAD_FORMAT", "PolicyIdentification is not an object")
    return Check("structure", VALID, subject=subject)


def _event_checks(
    event: Any, keys: KeyInput, notes: list[str], require_sign_algo: str | None, checks: list[Check]
) -> str | None:
    """Append the checks for one event to ``checks``. Returns the confirmed bare hex EventHash or None."""
    sid = _hdr(event).get("EventID")
    subject = sid if isinstance(sid, str) else None
    st = _structure(event, subject)
    checks.append(st)
    if st.status != VALID:
        return None
    h, p, s = event["Header"], event["Payload"], event["Security"]

    try:
        ok = iso_matches_ns(h["TimestampISO"], int(h["TimestampInt"]))
        checks.append(Check("timestamp", VALID if ok else INVALID, None if ok else "TIMESTAMP_MISMATCH",
                            None if ok else "TimestampISO and TimestampInt disagree", subject))
    except (ValueError, OverflowError) as exc:
        checks.append(Check("timestamp", INVALID, "BAD_FORMAT", str(exc), subject))

    if differs_from_rfc8785(h) or differs_from_rfc8785(p):
        notes.append(
            "Some events contain integers above 2**53 (typically TimestampInt). They were hashed as their "
            "exact decimal digits (INTERPRETATIONS.md I-4); an implementation that applies RFC 8785 to "
            "integers would round, reject or reformat them and compute a different EventHash."
        )

    if "PolicyIdentification" in event:
        notes.append("PolicyIdentification is outside EventHash (VCP v1.2 section 6.1.1); its contents are not integrity-checked.")
        if event["PolicyIdentification"].get("PolicyID") != h["PolicyID"]:
            checks.append(Check("policy_id", INVALID, "POLICY_MISMATCH",
                                "PolicyIdentification.PolicyID differs from Header.PolicyID", subject))

    if "HashAlgo" in s:
        algo = s["HashAlgo"]
    else:
        algo = "SHA256"
        notes.append("Security.HashAlgo absent; SHA256 (the section 1.5.2 default) was assumed.")
    recomputed: str | None = None
    claimed = s["EventHash"]
    claimed_hex = _safe_hex(claimed)
    if claimed.startswith("sha256:") and algo != "SHA256":
        checks.append(Check("event_hash", INVALID, "HASH_FORMAT_MISMATCH", f"sha256: prefix with HashAlgo {algo}", subject))
    elif claimed_hex is None:
        checks.append(Check("event_hash", INVALID, "BAD_FORMAT", "Security.EventHash is not a 32-byte hex digest", subject))
    else:
        try:
            recomputed = compute_event_hash(h, p, prev_hash=s.get("PrevHash"), algo=algo)
            ok = recomputed == claimed_hex
            checks.append(Check("event_hash", VALID if ok else INVALID, None if ok else "HASH_MISMATCH",
                                None if ok else "recomputed EventHash differs from Security.EventHash", subject))
        except UnsupportedAlgorithm as exc:
            checks.append(Check("event_hash", INDETERMINATE, "ALGORITHM_UNSUPPORTED", str(exc), subject))
        except CanonicalizationError as exc:
            checks.append(Check("event_hash", INDETERMINATE, "CANONICALIZATION_UNSUPPORTED", str(exc), subject))

    sig = s.get("Signature")
    sign_algo = s["SignAlgo"]
    if require_sign_algo is not None and sign_algo != require_sign_algo:
        checks.append(Check("signature", INVALID, "ALGORITHM_MISMATCH",
                            f"SignAlgo {sign_algo} but {require_sign_algo} is required by the caller", subject))
    elif sig is None:
        checks.append(Check("signature", INDETERMINATE, "MISSING_SIGNATURE",
                            "no Security.Signature (it may be carried by a COSE envelope, which this SDK does not read)", subject))
    elif sign_algo != "ED25519":
        checks.append(Check("signature", INDETERMINATE, "ALGORITHM_UNSUPPORTED", f"SignAlgo {sign_algo}", subject))
    else:
        key, problem = _key_for(keys, h["ActorID"])
        if key is None:
            detail = problem or f"no trusted public key supplied for ActorID {h['ActorID']!r}"
            checks.append(Check("signature", INDETERMINATE, "KEY_NOT_ESTABLISHED", detail, subject))
        elif recomputed is None:
            checks.append(Check("signature", INDETERMINATE, "HASH_NOT_RECOMPUTED",
                                "the signature is checked against the recomputed EventHash, which is unavailable", subject))
        else:
            ok = verify_event_signature(recomputed, sig, key)
            checks.append(Check("signature", VALID if ok else INVALID, None if ok else "SIGNATURE_MISMATCH", None, subject))
    if "PQCSignature" in s:
        notes.append("PQCSignature present; post-quantum signatures are not verified by this SDK.")
    return recomputed if recomputed is not None and recomputed == claimed_hex else None


@_guarded
def verify_event(event: Any, public_key: KeyInput = None, require_sign_algo: str | None = None, *, _ctx: _Ctx) -> Report:
    """Verify one event: structure, timestamp agreement, EventHash, signature.

    ``require_sign_algo`` (for example ``"ED25519"``) makes a different SignAlgo
    INVALID instead of INDETERMINATE, so an event cannot avoid signature
    checking by naming an algorithm this SDK does not implement.
    """
    _event_checks(event, public_key, _ctx.notes, require_sign_algo, _ctx.checks)
    return _report(_ctx.checks, _ctx.notes)


@_guarded
def verify_inclusion_proof(
    event_hash: str,
    index: int,
    tree_size: int,
    proof: Sequence[str],
    merkle_root: str,
    root_authenticated: bool = False,
    *,
    _ctx: _Ctx,
) -> Report:
    """Verify an RFC 6962 inclusion proof for one EventHash against a root.

    This shows inclusion under ``merkle_root`` for a tree of ``tree_size``
    leaves. It does not authenticate the root or the size; with VCP v1.2 the
    size is not covered by the root signature. Unless the caller says it has
    authenticated both (``root_authenticated=True``), the report carries an
    INDETERMINATE ``root_authenticity`` check. When the caller says so, that
    check is omitted and a note records that the SDK did not perform it.
    """
    notes: list[str] = []
    if isinstance(index, bool) or not isinstance(index, int) or isinstance(tree_size, bool) or not isinstance(tree_size, int):
        return _report([Check("inclusion", INVALID, "BAD_FORMAT", "index and tree_size must be integers")], notes)
    if isinstance(proof, (str, bytes)) or not isinstance(proof, Sequence) or not all(isinstance(x, str) for x in proof):
        return _report([Check("inclusion", INVALID, "BAD_FORMAT", "proof must be a list of hex strings")], notes)
    leaf_hex, root_hex = _safe_hex(event_hash), _safe_hex(merkle_root)
    path_hex = [_safe_hex(x) for x in proof]
    if leaf_hex is None or root_hex is None or any(x is None for x in path_hex):
        return _report([Check("inclusion", INVALID, "BAD_FORMAT", "a hash is not a 32-byte hex digest")], notes)
    ok = merkle.verify_inclusion(bytes.fromhex(leaf_hex), index, tree_size,
                                 [bytes.fromhex(x) for x in path_hex], bytes.fromhex(root_hex))  # type: ignore[arg-type]
    checks = [Check("inclusion", VALID if ok else INVALID, None if ok else "PROOF_MISMATCH")]
    if root_authenticated is True:
        notes.append("The caller stated that the Merkle root and tree size were authenticated; this SDK did not check that.")
    else:
        checks.append(Check("root_authenticity", INDETERMINATE, "ROOT_NOT_AUTHENTICATED",
                            "the Merkle root and tree size were not authenticated by a verified anchor"))
    return _report(checks, notes)


@_guarded
def verify_batch(
    events: Sequence[Any],
    anchor_record: Mapping[str, Any] | None = None,
    public_key: KeyInput = None,
    anchor_public_key: VerifyKey | str | bytes | None = None,
    external_anchor_verifier: ExternalVerifier | None = None,
    require_sign_algo: str | None = None,
    *,
    _ctx: _Ctx,
) -> Report:
    """Verify a complete batch against its AnchorRecord.

    ``events`` must be the whole batch in Merkle order. ``anchor_public_key``
    defaults to ``public_key`` when that is a single key.
    ``external_anchor_verifier(record)`` may return True, False or None (could
    not determine); without it the external anchor is INDETERMINATE.
    """
    notes = _ctx.notes
    notes.extend([
        "Completeness is shown only relative to the anchored root, at anchor granularity: "
        "an event that was never included in the batch is not detectable here.",
        "Security.AnchorReference is not checked by this SDK.",
    ])
    checks = _ctx.checks
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        return _report([Check("batch", INVALID, "BAD_FORMAT", "events must be a list")], notes)
    if not events:
        return _report([Check("batch", INVALID, "EMPTY_BATCH", "no events supplied")], notes)
    hashes: list[str | None] = []
    for e in events:
        hashes.append(_event_checks(e, public_key, notes, require_sign_algo, checks))

    tree_root: str | None = None
    legacy_root: str | None = None
    if any(h is None for h in hashes):
        checks.append(Check("merkle_root", INDETERMINATE, "HASH_NOT_RECOMPUTED",
                            "the tree cannot be rebuilt because some EventHash values could not be confirmed"))
    else:
        leaves = [bytes.fromhex(h) for h in hashes]  # type: ignore[arg-type]
        tree_root = merkle.root(leaves).hex()
        legacy_root = merkle.legacy_example_root(leaves).hex()
        missing = 0
        for i, e in enumerate(events):
            sec = _sec(e)
            sid = _hdr(e).get("EventID")
            if "MerkleRoot" not in sec or "MerkleIndex" not in sec:
                missing += 1
            if "MerkleRoot" in sec:
                er = _safe_hex(sec["MerkleRoot"])
                if er == legacy_root and er != tree_root:
                    checks.append(Check("event_merkle_root", INDETERMINATE, "LEGACY_MERKLE_CONSTRUCTION",
                                        "Security.MerkleRoot matches the section 6.2.1 example construction, not RFC 6962", sid))
                elif er != tree_root:
                    checks.append(Check("event_merkle_root", INVALID, "MERKLE_FIELD_MISMATCH",
                                        "Security.MerkleRoot differs from the batch root", sid))
            if "MerkleIndex" in sec and int(sec["MerkleIndex"]) != i:
                checks.append(Check("event_merkle_index", INVALID, "MERKLE_FIELD_MISMATCH",
                                    f"Security.MerkleIndex {sec['MerkleIndex']!r} but position {i}", sid))
        if missing:
            checks.append(Check("event_merkle_fields", INDETERMINATE, "MISSING_FIELD",
                                f"{missing} event(s) lack Security.MerkleRoot or MerkleIndex (REQUIRED from v1.1, section 6.4.1); "
                                "their placement in the batch was not checked"))

    if anchor_record is None:
        checks.append(Check("anchor_record", INDETERMINATE, "MISSING_ANCHOR_RECORD"))
        return _report(checks, notes)
    if not _is_obj(anchor_record):
        checks.append(Check("anchor_record", INVALID, "BAD_FORMAT", "AnchorRecord is not a JSON object"))
        return _report(checks, notes)

    rec_root = _safe_hex(anchor_record.get("MerkleRoot"))
    if rec_root is None:
        checks.append(Check("merkle_root", INVALID, "BAD_FORMAT", "AnchorRecord.MerkleRoot is not a 32-byte hex digest"))
    elif tree_root is not None:
        if tree_root == rec_root:
            checks.append(Check("merkle_root", VALID))
        elif legacy_root == rec_root:
            checks.append(Check("merkle_root", INDETERMINATE, "LEGACY_MERKLE_CONSTRUCTION",
                                "the root matches the VCP v1.2 section 6.2.1 example construction "
                                "(odd node duplicated), not RFC 6962; this SDK does not verify that construction"))
        else:
            checks.append(Check("merkle_root", INVALID, "ROOT_MISMATCH",
                                "the supplied events do not reproduce AnchorRecord.MerkleRoot"))

    sig = anchor_record.get("Signature")
    sign_algo = anchor_record.get("SignAlgo")
    defaulted_key = False
    if anchor_public_key is None and isinstance(public_key, (VerifyKey, str, bytes)):
        anchor_public_key = public_key
        defaulted_key = True
    if require_sign_algo is not None and sign_algo != require_sign_algo:
        checks.append(Check("root_signature", INVALID, "ALGORITHM_MISMATCH", f"SignAlgo {sign_algo!r} but {require_sign_algo} is required"))
    elif sig is None:
        checks.append(Check("root_signature", INDETERMINATE, "MISSING_SIGNATURE"))
    elif not isinstance(sig, str) or not isinstance(sign_algo, str):
        checks.append(Check("root_signature", INVALID, "BAD_FORMAT", "Signature and SignAlgo must be strings"))
    elif sign_algo != "ED25519":
        checks.append(Check("root_signature", INDETERMINATE, "ALGORITHM_UNSUPPORTED", f"SignAlgo {sign_algo}"))
    elif anchor_public_key is None:
        checks.append(Check("root_signature", INDETERMINATE, "KEY_NOT_ESTABLISHED", "no trusted key supplied for the AnchorRecord"))
    elif rec_root is None:
        checks.append(Check("root_signature", INDETERMINATE, "BAD_FORMAT", "no valid MerkleRoot to check the signature against"))
    else:
        k, problem = _key_for(anchor_public_key, None)
        if k is None:
            checks.append(Check("root_signature", INDETERMINATE, "KEY_NOT_ESTABLISHED", problem or "key rejected"))
        else:
            ok = verify_root_signature(rec_root, sig, k)
            checks.append(Check("root_signature", VALID if ok else INVALID, None if ok else "SIGNATURE_MISMATCH"))
            if defaulted_key:
                notes.append("The AnchorRecord signature was verified against the same key as the events (no separate anchor key was supplied).")

    notes.append("The AnchorRecord signature covers the Merkle root only (VCP v1.2 section 6.3.1); "
                 "EventCount, FirstEventID, LastEventID and PolicyID are checked against the supplied events, "
                 "and Timestamp for format only, not against a signature.")
    problems = []
    count = anchor_record.get("EventCount")
    if not _is_int(count) or int(count) != len(events):
        problems.append(f"EventCount {count!r} but {len(events)} events supplied")
    for key, ev, label in (("FirstEventID", events[0], "first"), ("LastEventID", events[-1], "last")):
        rec_id, ev_id = anchor_record.get(key), _hdr(ev).get("EventID")
        if not isinstance(rec_id, str) or not isinstance(ev_id, str) or rec_id != ev_id:
            problems.append(f"{key} differs from the {label} event")
    rec_pid = anchor_record.get("PolicyID")
    if not isinstance(rec_pid, str) or any(_hdr(e).get("PolicyID") != rec_pid for e in events):
        problems.append("PolicyID differs from the events' Header.PolicyID")
    checks.append(Check("anchor_binding", INVALID if problems else VALID,
                        "BINDING_MISMATCH" if problems else None, "; ".join(problems) or None))

    ts = anchor_record.get("Timestamp")
    if _is_int(ts) and ts >= 0:
        checks.append(Check("anchor_timestamp_format", VALID, detail="non-negative integer; the value is not checked and not covered by the signature"))
    else:
        checks.append(Check("anchor_timestamp_format", INVALID, "BAD_FORMAT", f"Timestamp {ts!r} is not a non-negative integer"))

    if "AnchorTarget" not in anchor_record:
        checks.append(Check("external_anchor", INDETERMINATE, "MISSING_ANCHOR_PROOF",
                            "no AnchorTarget; VCP v1.2 section 6.3.3 requires external anchoring"))
    else:
        target = anchor_record["AnchorTarget"]
        proof = target.get("Proof") if _is_obj(target) else None
        if not _is_obj(target):
            checks.append(Check("external_anchor", INVALID, "BAD_FORMAT", "AnchorTarget is not an object"))
        elif not isinstance(target.get("Type"), str) or target.get("Type") not in _ANCHOR_TYPES:
            checks.append(Check("external_anchor", INVALID, "BAD_FORMAT", f"AnchorTarget.Type {target.get('Type')!r}"))
        elif proof is not None and not isinstance(proof, str):
            checks.append(Check("external_anchor", INVALID, "BAD_FORMAT", "AnchorTarget.Proof is not a string"))
        elif not proof:
            checks.append(Check("external_anchor", INDETERMINATE, "MISSING_ANCHOR_PROOF", "AnchorTarget.Proof is empty or absent"))
        elif external_anchor_verifier is None:
            checks.append(Check("external_anchor", INDETERMINATE, "EXTERNAL_ANCHOR_NOT_VERIFIED",
                                "this SDK does not contact anchor targets; supply external_anchor_verifier"))
        else:
            try:
                r = external_anchor_verifier(anchor_record)
            except Exception as exc:  # noqa: BLE001
                r = None
                notes.append(f"external_anchor_verifier raised {type(exc).__name__}: {exc}")
            if r is True:
                checks.append(Check("external_anchor", VALID, detail="reported by the supplied external_anchor_verifier"))
            elif r is False:
                checks.append(Check("external_anchor", INVALID, "ANCHOR_MISMATCH", "reported by the supplied external_anchor_verifier"))
            else:
                checks.append(Check("external_anchor", INDETERMINATE, "ANCHOR_PENDING_OR_UNREACHABLE"))
    return _report(checks, notes)


def _link_hash(v: Any) -> str | None:
    """A PrevHash value as bare hex, treating the all-zero sentinel as absent."""
    h = _safe_hex(v)
    return None if h is None or h == ZERO_HASH else h


@_guarded
def verify_chain(events: Sequence[Any], prior_hash: str | None = None, *, _ctx: _Ctx) -> Report:
    """Check SequenceNum continuity and PrevHash links for one ActorID/ChainID, in order.

    PrevHash is OPTIONAL from v1.1. Links without a PrevHash (or with the
    all-zero value) are INDETERMINATE, except an INIT event at the start of the
    supplied sequence when no ``prior_hash`` is given, which is a chain start.
    A gap inside the supplied sequence is INVALID; whether events were withheld
    or never written is not answered here.
    """
    notes, checks = _ctx.notes, _ctx.checks
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        return _report([Check("chain", INVALID, "BAD_FORMAT", "events must be a list")], notes)
    if not events:
        return _report([Check("chain", INVALID, "EMPTY_CHAIN")], notes)
    expected_prior: str | None = None
    prior_malformed = False
    if prior_hash is not None:
        expected_prior = _safe_hex(prior_hash)
        prior_malformed = expected_prior is None
    chain_key: tuple[str, str] | None = None
    prev_hex: str | None = None
    prev_seq: Any = None
    for i, e in enumerate(events):
        st = _structure(e, None)
        if st.status != VALID:
            checks.append(st)
            prev_hex, prev_seq = None, None
            continue
        h, s = e["Header"], e["Security"]
        sid = h["EventID"]
        key = (h["ActorID"], h["ChainID"])
        if chain_key is None:
            chain_key = key
        elif key != chain_key:
            checks.append(Check("chain_identity", INVALID, "MIXED_CHAIN", "ActorID/ChainID differs within the sequence", sid))
        if i > 0:
            if prev_seq is None:
                checks.append(Check("sequence", INDETERMINATE, "PREVIOUS_EVENT_INVALID", "the preceding event could not be read", sid))
            elif int(h["SequenceNum"]) != int(prev_seq) + 1:
                checks.append(Check("sequence", INVALID, "SEQUENCE_GAP", f"SequenceNum {h['SequenceNum']!r} after {prev_seq!r}", sid))
            else:
                checks.append(Check("sequence", VALID, subject=sid))
        this_hex = None
        try:
            this_hex = compute_event_hash(h, e["Payload"], prev_hash=s.get("PrevHash"), algo=s.get("HashAlgo", "SHA256"))
            if this_hex != _safe_hex(s["EventHash"]):
                checks.append(Check("link_source", INVALID, "HASH_MISMATCH", "EventHash does not match the event", sid))
                this_hex = None
        except (UnsupportedAlgorithm, CanonicalizationError) as exc:
            checks.append(Check("link_source", INDETERMINATE, "HASH_NOT_RECOMPUTED", str(exc), sid))
        link = _link_hash(s.get("PrevHash"))
        expected = expected_prior if i == 0 else prev_hex
        if link is None:
            if i == 0 and prior_hash is None and h["EventType"] == "INIT":
                checks.append(Check("prev_hash", VALID, detail="chain start (INIT without PrevHash)", subject=sid))
            else:
                checks.append(Check("prev_hash", INDETERMINATE, "CHAIN_NOT_USED", "no PrevHash on this event", sid))
        elif expected is None:
            if i == 0 and prior_malformed:
                reason, why = "PRIOR_HASH_MALFORMED", "prior_hash is not a 32-byte hex digest"
            else:
                reason = "PRIOR_HASH_MISSING" if i == 0 else "PREVIOUS_HASH_UNAVAILABLE"
                why = "the hash of the preceding event is not available"
            checks.append(Check("prev_hash", INDETERMINATE, reason, why, sid))
        else:
            ok = link == expected
            checks.append(Check("prev_hash", VALID if ok else INVALID, None if ok else "CHAIN_BREAK", None, sid))
        prev_hex = this_hex
        prev_seq = h["SequenceNum"]
    return _report(checks, notes)


def precheck_unsigned(event: Any) -> str | None:
    """Problems that should stop an event from being signed, or None.

    Used by ``vcp seal``: the Header must pass the structure check, TimestampISO
    and TimestampInt must agree, and the Header and Payload must canonicalise.
    """
    if not _is_obj(event) or not _is_obj(event.get("Header")) or not _is_obj(event.get("Payload")):
        return "line is not an object with Header and Payload"
    probe = {"Header": event["Header"], "Payload": event["Payload"],
             "Security": {"EventHash": ZERO_HASH, "SignAlgo": "ED25519"}}
    st = _structure(probe, None)
    if st.status != VALID:
        return st.detail or st.reason
    try:
        if not iso_matches_ns(event["Header"]["TimestampISO"], int(event["Header"]["TimestampInt"])):
            return "TimestampISO and TimestampInt disagree"
    except (ValueError, OverflowError) as exc:
        return str(exc)
    try:
        compute_event_hash(event["Header"], event["Payload"])
    except CanonicalizationError as exc:
        return str(exc)
    return None
