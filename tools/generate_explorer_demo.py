#!/usr/bin/env python3
"""Generate deterministic evidence for the optional SDK -> API -> GUI demo.

The events are synthetic. Hashes, signatures and Merkle proofs are produced by
the real Python SDK. No external anchor or verification result is fabricated.
The RFC 8032 TEST 1 seed below is public test material, never an operational key.

Run from the repository root:
    PYTHONPATH=python/src python tools/generate_explorer_demo.py [OUTPUT_DIR]
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import veritaschain_vcp as vcp
from veritaschain_vcp.jcs import canonicalize_str

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "examples" / "explorer-demo"

# PUBLIC RFC 8032 section 7.1 TEST 1 key. Anyone can sign with this seed.
# Its signatures demonstrate mechanics, not identity or production authenticity.
PUBLIC_TEST_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
ACTOR_ID = "sdk-demo"
BASE_NS = 1793145600123456789  # 2026-10-28T00:00:00.123456789Z; above 2**53.


def _json_file(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def generate() -> dict[str, str]:
    """Return the exact UTF-8 contents of bundle.json and trust.json."""
    key = vcp.SigningKey(PUBLIC_TEST_SEED)
    producer = vcp.Producer(
        key,
        actor_id=ACTOR_ID,
        chain_id="sdk-explorer-demo-001",
        policy_id="org.veritaschain.sdk:explorer-demo-v1",
        precision="NANOSECOND",
        use_prev_hash=True,
    )
    payloads = [
        ("INIT", {"VCP-GOV": {"AlgoID": "synthetic-demo", "AlgoVersion": "1.0.0"}}),
        ("SIG", {"VCP-TRADE": {"Symbol": "USDJPY", "Side": "BUY", "Price": "151.234", "Quantity": "100000"}}),
        ("ORD", {"VCP-TRADE": {"Symbol": "USDJPY", "Side": "BUY", "OrderType": "LIMIT", "Price": "151.230", "Quantity": "100000"}}),
    ]
    for i, (event_type, payload) in enumerate(payloads):
        timestamp = BASE_NS + i * 1_000_123
        producer.create(
            event_type,
            payload,
            timestamp_ns=timestamp,
            event_id=vcp.uuid7(timestamp // 1_000_000, rand=bytes([i + 1]) * 10),
        )
    # Deliberately omit AnchorTarget. There is no real external anchor in this demo.
    batch, record = producer.close_batch(timestamp_ns=BASE_NS + 10_000_000_000)
    record_text = canonicalize_str(record) + "\n"
    proofs = [
        {
            "event_id": event["Header"]["EventID"],
            "index": i,
            "tree_size": len(batch.events),
            "event_hash": event["Security"]["EventHash"],
            "merkle_root": batch.merkle_root,
            "proof": batch.inclusion_proof(i),
        }
        for i, event in enumerate(batch.events)
    ]

    def case(case_id: str, title: str, description: str, events: list[dict]) -> dict:
        return {
            "id": case_id,
            "title": title,
            "description": description,
            # These strings preserve integers and supplied evidence bytes through
            # a normal JSON transport. Consumers must not JSON.parse the inner
            # evidence with a binary64-only parser before verification.
            "events_jsonl": "".join(canonicalize_str(event) + "\n" for event in events),
            "anchor_record_json": record_text,
            "inclusion_proofs": copy.deepcopy(proofs),
        }

    tampered = copy.deepcopy(batch.events)
    tampered[2]["Payload"]["VCP-TRADE"]["Price"] = "999.000"
    bundle = {
        "format": "vcp-evidence-demo/1",
        "sdk_version": vcp.__version__,
        "spec_version": vcp.VCP_SPEC_VERSION,
        "disclosure": [
            "Synthetic first-party demonstration, not real trading activity or independent validation.",
            "The public RFC 8032 test key demonstrates cryptographic mechanics; it establishes no identity.",
            "No external anchor proof is supplied. The full intact-batch result remains INDETERMINATE.",
            "VALID for local checks is a scoped result, not VCP/VAP conformance or certification.",
            "The SDK's exact-integer and other interpretations remain non-normative implementation choices.",
        ],
        "cases": [
            case("intact", "Intact signed evidence", "The supplied events, signatures, chain and Merkle proofs match under the separate demo trust configuration. External anchoring remains unverified.", batch.events),
            case("tampered", "Payload changed after signing", "The order price changes from 151.230 to 999.000; original hashes, signatures, root and proofs are retained so fresh verification detects the change.", tampered),
            case("missing-key", "Trusted key unavailable", "The evidence bytes are identical to the intact case. The separate trust configuration supplies no trusted event or root key.", batch.events),
        ],
    }
    public_hex = key.verify_key.raw.hex()
    trusted = {"actor_public_keys": {ACTOR_ID: public_hex}, "anchor_public_key": public_hex}
    trust = {
        "format": "vcp-evidence-demo-trust/1",
        "notice": "PUBLIC RFC 8032 TEST 1 key, for this synthetic demo only. Anyone can sign with it. This configuration is explicit caller policy and establishes no real-world identity.",
        "cases": {
            "intact": copy.deepcopy(trusted),
            "tampered": copy.deepcopy(trusted),
            "missing-key": {"actor_public_keys": {}, "anchor_public_key": None},
        },
    }
    return {"bundle.json": _json_file(bundle), "trust.json": _json_file(trust)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, text in generate().items():
        (args.output_dir / name).write_text(text, encoding="utf-8", newline="\n")
        print(args.output_dir / name)


if __name__ == "__main__":
    main()
