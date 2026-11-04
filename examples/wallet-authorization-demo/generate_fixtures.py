#!/usr/bin/env python3
"""Reproduce synthetic, signed records from the pinned companion fixture API."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import demo
from veritaschain_vcp import Producer, SigningKey, uuid7

# PUBLIC, DETERMINISTIC TEST SEED. It is not a secret and must never hold assets.
RECORDER_SEED = hashlib.sha256(b"vcp-sdk wallet-authorization-demo synthetic recorder seed v0").digest()
ACTOR_ID = "wallet-demo:synthetic-recorder"
AUDIT_CHAIN_ID = "wallet-demo:audit-stream"
POLICY_ID = "wallet-demo:research-only-v0"


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def generate(vap_spec: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    _, fixtures, lock = demo.load_fixture_source(vap_spec)
    key = SigningKey(RECORDER_SEED)
    records = {
        "schema": "vcp-wallet-authorization-demo-fixtures/1",
        "provenance": {
            "kind": "synthetic, first-party, deterministic test evidence",
            "generator": "examples/wallet-authorization-demo/generate_fixtures.py",
            "sdk_base_commit": demo.SDK_BASE_COMMIT,
            "companion_result_schema": demo.COMPANION_SCHEMA,
            "companion_source_commit": lock["source_commit"],
            "companion_source_files": lock["files"],
            "private_keys": "Public synthetic seeds in fixture generators; never production keys.",
        },
        "cases": {},
    }
    trust = {
        "schema": "vcp-wallet-authorization-demo-trust/1",
        "sdk_recorder": {"actor_id": ACTOR_ID, "public_key_hex": key.verify_key.raw.hex()},
        "cases": {},
    }
    for case in demo.CASES:
        bundle, trusted_keys, evaluation_time = fixtures.make_fixture(case)
        producer = Producer(key, ACTOR_ID, AUDIT_CHAIN_ID, POLICY_ID)
        event = producer.create(
            "SYS_AUDIT",
            {"ExperimentalWalletEvidence": {"Case": case, "Bundle": bundle}},
            timestamp_ns=evaluation_time * 1_000_000_000,
            event_id=uuid7(evaluation_time * 1000, rand=hashlib.sha256(case.encode("ascii")).digest()[:10]),
        )
        records["cases"][case] = {"evaluation_time": evaluation_time, "recorded_event": event}
        trust["cases"][case] = {
            "companion_keys": {role: {key_id: raw.hex() for key_id, raw in keys.items()}
                               for role, keys in trusted_keys.items()},
        }
    return records, trust


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vap-spec", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="use a temporary directory to compare reproducibility")
    args = parser.parse_args()
    records, trust = generate(args.vap_spec)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "fixtures.json").write_bytes(json_bytes(records))
    (args.output_dir / "trust.json").write_bytes(json_bytes(trust))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
