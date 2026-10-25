"""Producing VCP v1.2 events, batches and AnchorRecords.

The producer computes and records; it does not send anything anywhere. External
anchoring (OpenTimestamps, an RFC 3161 TSA, a blockchain, an attested database)
is the caller's job: pass the resulting proof to :func:`anchor_record` or set
``AnchorTarget`` afterwards. VCP v1.2 section 6.3.3 requires external anchoring
at every tier; an AnchorRecord without an external proof does not meet it.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from . import merkle
from .hashing import compute_event_hash, format_event_hash, parse_hash
from .signing import SigningKey, sign_event_hash, sign_merkle_root
from .timeutil import iso_from_ns, now_ns, uuid7

__all__ = ["Producer", "seal_event", "build_batch", "anchor_record", "Batch"]

SECURITY_VERSION = "1.1"  # VCP v1.2 section 6.4 schema example


def seal_event(
    header: Mapping[str, Any],
    payload: Mapping[str, Any],
    key: SigningKey,
    prev_hash: str | None = None,
    hash_algo: str = "SHA256",
) -> dict[str, Any]:
    """Return a complete event with ``Security`` (EventHash, Signature, algorithms).

    MerkleRoot, MerkleIndex and AnchorReference are added by :func:`build_batch`.
    """
    event_hash = compute_event_hash(header, payload, prev_hash=prev_hash, algo=hash_algo)
    security: dict[str, Any] = {
        "Version": SECURITY_VERSION,
        "EventHash": format_event_hash(event_hash, hash_algo),
        "HashAlgo": hash_algo,
        "Signature": sign_event_hash(event_hash, key),
        "SignAlgo": "ED25519",
    }
    if prev_hash is not None:
        security["PrevHash"] = format_event_hash(prev_hash, hash_algo)
    return {"Header": copy.deepcopy(dict(header)), "Payload": copy.deepcopy(dict(payload)), "Security": security}


@dataclass
class Batch:
    """A closed batch: events with Merkle fields set, and the unsigned anchor inputs."""

    events: list[dict[str, Any]]
    merkle_root: str
    tree: merkle.MerkleTree = field(repr=False)

    def inclusion_proof(self, index: int) -> list[str]:
        return [h.hex() for h in self.tree.inclusion_proof(index)]


def build_batch(events: Sequence[Mapping[str, Any]], anchor_reference: str | None = None) -> Batch:
    """Build the RFC 6962 tree over the events' EventHash values, in the given order.

    Sets ``Security.MerkleRoot`` (bare hex), ``Security.MerkleIndex`` and
    ``Security.AnchorReference`` on copies of the events. ``AnchorReference``
    defaults to the Merkle root, which identifies the AnchorRecord that carries it.
    """
    if not events:
        raise ValueError("a batch needs at least one event")
    out = [copy.deepcopy(dict(e)) for e in events]
    leaves = [bytes.fromhex(parse_hash(e["Security"]["EventHash"])) for e in out]
    tree = merkle.MerkleTree(leaves)
    root_hex = tree.root.hex()
    ref = anchor_reference if anchor_reference is not None else root_hex
    for i, e in enumerate(out):
        e["Security"]["MerkleRoot"] = root_hex
        e["Security"]["MerkleIndex"] = i
        e["Security"]["AnchorReference"] = ref
    return Batch(events=out, merkle_root=root_hex, tree=tree)


def anchor_record(
    batch: Batch,
    key: SigningKey,
    policy_id: str,
    anchor_target: Mapping[str, Any] | None = None,
    timestamp_ns: int | None = None,
) -> dict[str, Any]:
    """Return an AnchorRecord (VCP v1.2 section 6.3.3) for a batch.

    The signature covers the Merkle root only (section 6.3.1). EventCount,
    FirstEventID, LastEventID, PolicyID and Timestamp are not covered by it.
    """
    record: dict[str, Any] = {
        "MerkleRoot": batch.merkle_root,
        "Signature": sign_merkle_root(batch.merkle_root, key),
        "SignAlgo": "ED25519",
        "Timestamp": now_ns() if timestamp_ns is None else timestamp_ns,
        "EventCount": len(batch.events),
        "FirstEventID": batch.events[0]["Header"]["EventID"],
        "LastEventID": batch.events[-1]["Header"]["EventID"],
        "PolicyID": policy_id,
    }
    if anchor_target is not None:
        record["AnchorTarget"] = dict(anchor_target)
    return record


class Producer:
    """Creates sealed events for one ActorID/ChainID under one PolicyID.

    ``use_prev_hash`` turns on the OPTIONAL hash chain (section 6.1.2).
    """

    def __init__(
        self,
        key: SigningKey,
        actor_id: str,
        chain_id: str,
        policy_id: str,
        precision: str = "MILLISECOND",
        use_prev_hash: bool = False,
        hash_algo: str = "SHA256",
        start_sequence: int = 0,
        prev_hash: str | None = None,
    ) -> None:
        self.key = key
        self.actor_id = actor_id
        self.chain_id = chain_id
        self.policy_id = policy_id
        self.precision = precision
        self.use_prev_hash = use_prev_hash
        self.hash_algo = hash_algo
        self.sequence = start_sequence
        self.last_hash = prev_hash
        self.pending: list[dict[str, Any]] = []

    def create(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        timestamp_ns: int | None = None,
        event_id: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        ts = now_ns() if timestamp_ns is None else timestamp_ns
        header: dict[str, Any] = {
            "EventID": event_id or uuid7(ts // 1_000_000),
            "TimestampISO": iso_from_ns(ts, self.precision),
            "TimestampInt": ts,
            "EventType": event_type,
            "ActorID": self.actor_id,
            "ChainID": self.chain_id,
            "SequenceNum": self.sequence,
            "PolicyID": self.policy_id,
        }
        if trace_id is not None:
            header["TraceID"] = trace_id
        prev = self.last_hash if self.use_prev_hash else None
        event = seal_event(header, payload, self.key, prev_hash=prev, hash_algo=self.hash_algo)
        self.sequence += 1
        self.last_hash = parse_hash(event["Security"]["EventHash"])
        self.pending.append(event)
        return event

    def close_batch(
        self,
        anchor_target: Mapping[str, Any] | None = None,
        anchor_reference: str | None = None,
        timestamp_ns: int | None = None,
    ) -> tuple[Batch, dict[str, Any]]:
        """Close the pending events into a batch and return (batch, AnchorRecord)."""
        batch = build_batch(self.pending, anchor_reference=anchor_reference)
        record = anchor_record(batch, self.key, self.policy_id, anchor_target, timestamp_ns)
        self.pending = []
        return batch, record
