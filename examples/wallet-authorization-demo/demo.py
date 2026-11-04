#!/usr/bin/env python3
"""Offline, non-normative SDK/companion evidence demonstration.

The SDK checks the saved record. An optional, separately pinned VAP experiment
checks wallet evidence taken from that record's hash-covered Payload. No
transaction, RPC request, download, or live admission control is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent
SDK_ROOT = HERE.parents[1]
sys.path.insert(0, str(SDK_ROOT / "python" / "src"))

from veritaschain_vcp import VALID, loads_strict, verify_event  # noqa: E402

EXPERIMENT = Path("experiments/wallet-authorization-evidence")
CLAIMS = ("integrity", "authorization", "execution_match", "delegation_state")
CASES = ("approval_mismatch", "missing_approval", "stop_with_delegation", "clear_observed")
SDK_BASE_COMMIT = "8979696800835cb239d47502c1e2c6858dd312c8"
COMPANION_SCHEMA = "experimental-wallet-authorization-evidence-v0"


def read_json(path: Path) -> Any:
    return loads_strict(path.read_text(encoding="utf-8"))


def _load_verified_module(name: str, path: Path, verified_source: bytes) -> ModuleType:
    # Execute exactly the bytes checked by _verified_sources. Path-based loaders
    # can read the file again or choose a .pyc; neither is the pinned byte string.
    # An existing sys.modules entry is not evidence that its code was verified.
    previous = sys.modules.get(name)
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(verified_source, str(path), "exec", dont_inherit=True), module.__dict__)
    except Exception:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def _verified_sources(vap_spec: Path) -> tuple[Path, dict[str, bytes], dict[str, Any]]:
    lock = read_json(HERE / "companion-lock.json")
    expected_names = {"wallet_evidence.py", "fixtures.py"}
    if lock.get("schema") != "vcp-wallet-demo-companion-lock/1" or set(lock.get("files", {})) != expected_names:
        raise ValueError("invalid companion source lock")
    source = vap_spec.expanduser().resolve() / EXPERIMENT
    verified = {}
    for name in sorted(expected_names):
        raw = (source / name).read_bytes()
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if actual != lock["files"][name]:
            raise ValueError(f"companion source pin mismatch: {name}")
        verified[name] = raw
    return source, verified, lock


def load_companion(vap_spec: Path) -> tuple[ModuleType, dict[str, Any]]:
    """Load only the explicit local source whose bytes match the checked-in pin.

    A requested but missing/mismatched dependency is an error, never a silent
    fallback to an unverified implementation or to a successful verdict.
    """
    source, verified, lock = _verified_sources(vap_spec)
    module = _load_verified_module("wallet_evidence", source / "wallet_evidence.py", verified["wallet_evidence.py"])
    return module, lock


def load_fixture_source(vap_spec: Path) -> tuple[ModuleType, ModuleType, dict[str, Any]]:
    """Used by the reproducible generator/tests, not by normal demo replay."""
    source, verified, lock = _verified_sources(vap_spec)
    companion = _load_verified_module("wallet_evidence", source / "wallet_evidence.py", verified["wallet_evidence.py"])
    fixtures = _load_verified_module("_vcp_wallet_demo_fixture_source", source / "fixtures.py", verified["fixtures.py"])
    return companion, fixtures, lock


def read_fixtures() -> tuple[dict[str, Any], dict[str, Any]]:
    records = read_json(HERE / "fixtures.json")
    trust = read_json(HERE / "trust.json")
    if records.get("schema") != "vcp-wallet-authorization-demo-fixtures/1":
        raise ValueError("unsupported demo fixture schema")
    if trust.get("schema") != "vcp-wallet-authorization-demo-trust/1":
        raise ValueError("unsupported demo trust schema")
    if set(records.get("cases", {})) != set(CASES) or set(trust.get("cases", {})) != set(CASES):
        raise ValueError("demo case inventory differs from the documented fixture set")
    return records, trust


def decode_companion_keys(role_keys: dict[str, dict[str, str]]) -> dict[str, dict[str, bytes]]:
    # Supplied out of band in trust.json. Never take trust roots from the event.
    return {role: {key_id: bytes.fromhex(value) for key_id, value in keys.items()}
            for role, keys in role_keys.items()}


def _unperformed_companion(reason: str) -> dict[str, Any]:
    return {
        "schema": COMPANION_SCHEMA,
        "synthetic": True,
        "adapter_generated": True,
        "claims": {name: {"verdict": "INDETERMINATE", "evidence_refs": [], "reasons": [reason]}
                   for name in CLAIMS},
        "admission": "DENY",
        "notes": ["The companion checks were not performed. This is an adapter-generated result."],
    }


def verify_record(
    event: dict[str, Any],
    event_public_key: str | bytes | None,
    trusted_keys: dict[str, dict[str, bytes]],
    *,
    companion: ModuleType | None,
    evaluation_time: int,
    max_snapshot_age: int = 300,
    record_ref: str = "input:recorded_event",
    record_trust_ref: str = "input:record_trust",
    companion_trust_ref: str = "input:companion_trust",
) -> dict[str, Any]:
    """Keep cryptographic record checks and companion claims independently visible."""
    record_report = verify_event(event, public_key=event_public_key, require_sign_algo="ED25519").to_dict()
    payload = event.get("Payload", {})
    wrapper = payload.get("ExperimentalWalletEvidence", {}) if isinstance(payload, dict) else {}
    if companion is None:
        wallet_report = _unperformed_companion("COMPANION_NOT_AVAILABLE")
        companion_admission = "DENY"
    elif not isinstance(wrapper, dict) or "Bundle" not in wrapper:
        wallet_report = _unperformed_companion("MISSING_COMPANION_BUNDLE")
        companion_admission = "DENY"
    else:
        wallet_report = companion.verify_bundle(
            wrapper["Bundle"], trusted_keys,
            evaluation_time=evaluation_time, max_snapshot_age=max_snapshot_age,
        )
        companion_admission = companion.admission_decision(wallet_report)

    # This is a local illustration of requiring both sets of evidence, not a
    # change to the SDK verdict or an assertion that an absent approval is denied.
    decision = "ALLOW" if record_report["status"] == VALID and companion_admission == "ALLOW" else "DENY"
    return {
        "schema": "vcp-wallet-authorization-demo-report/1",
        "evaluation_time": evaluation_time,
        "max_snapshot_age": max_snapshot_age,
        "inputs": {
            "record": record_ref,
            "wallet_evidence_base": record_ref + "/Payload/ExperimentalWalletEvidence/Bundle",
            "record_trust": record_trust_ref,
            "wallet_trust": companion_trust_ref,
        },
        "recorded_event_integrity": record_report,
        "wallet_evidence": wallet_report,
        "simulated_admission": {
            "decision": decision,
            "policy": "Require SDK record integrity VALID and companion admission ALLOW.",
            "scope": "Informational local decision only; no live signer, wallet, or gate is controlled.",
        },
        "notes": [
            "SDK verify_event checks structure, timestamp agreement, EventHash, and signature against supplied trust.",
            "The companion result does not change the SDK's VALID meaning or establish VCP/VAP conformance.",
            "Missing approval evidence means authorization is unknown, not proof that approval never existed.",
            "DENY may reflect missing evidence; it is not itself a finding of an authorization violation.",
            "Chain observations are scoped to their identified block and evaluation time; no current or global safety is claimed.",
            "No external anchor, event completeness, human identity, or public-chain state is verified by this demo.",
            "All records and evidence are synthetic, first-party fixtures with publicly reproducible test keys.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vap-spec", type=Path, help="explicit local companion checkout, checked against companion-lock.json")
    parser.add_argument("--case", choices=("all",) + CASES, default="all")
    parser.add_argument("--evaluation-time", type=int, help="Unix seconds; default is each fixture's fixed synthetic time")
    parser.add_argument("--max-snapshot-age", type=int, default=300, help="seconds, default 300")
    args = parser.parse_args(argv)
    if args.max_snapshot_age <= 0 or (args.evaluation_time is not None and args.evaluation_time < 0):
        parser.error("time must be non-negative and maximum snapshot age must be positive")
    try:
        records, trust = read_fixtures()
        companion, lock = load_companion(args.vap_spec) if args.vap_spec else (None, None)
        cases = CASES if args.case == "all" else (args.case,)
        reports = {}
        for case in cases:
            item = records["cases"][case]
            reports[case] = verify_record(
                item["recorded_event"], trust["sdk_recorder"]["public_key_hex"],
                decode_companion_keys(trust["cases"][case]["companion_keys"]),
                companion=companion,
                evaluation_time=item["evaluation_time"] if args.evaluation_time is None else args.evaluation_time,
                max_snapshot_age=args.max_snapshot_age,
                record_ref=f"fixtures.json#/cases/{case}/recorded_event",
                record_trust_ref="trust.json#/sdk_recorder/public_key_hex",
                companion_trust_ref=f"trust.json#/cases/{case}/companion_keys",
            )
        result = {
            "schema": "vcp-wallet-authorization-demo-run/1",
            "provenance": records["provenance"],
            "companion_source_pin": lock,
            "reports": reports,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        parser.exit(2, f"wallet demo: {exc}\n")
    return 0  # Report produced, not an authorization pass; inspect each claim.


if __name__ == "__main__":
    raise SystemExit(main())
