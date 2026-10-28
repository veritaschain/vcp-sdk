"""Verify the actual demo evidence; these expectations are not API responses."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path

import pytest
import veritaschain_vcp as vcp
from veritaschain_vcp.jsonio import load_jsonl
from veritaschain_vcp.verify import combine

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples" / "explorer-demo"
BUNDLE = json.loads((DEMO / "bundle.json").read_text(encoding="utf-8"))
TRUST = json.loads((DEMO / "trust.json").read_text(encoding="utf-8"))
CASES = {case["id"]: case for case in BUNDLE["cases"]}

# Hand-written expectations, not emitted by the generator or consumed by the API.
EXPECTED = {
    "intact": ("VALID", "INDETERMINATE"),
    "tampered": ("INVALID", "INVALID"),
    "missing-key": ("INDETERMINATE", "INDETERMINATE"),
}


def test_generated_evidence_is_reproducible():
    spec = spec_from_file_location("generate_explorer_demo", ROOT / "tools" / "generate_explorer_demo.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    generated = module.generate()
    assert generated == module.generate()
    for name, text in generated.items():
        assert text.encode("utf-8") == (DEMO / name).read_bytes()


@pytest.mark.parametrize("case_id", list(EXPECTED))
def test_fresh_batch_and_chain_verification(case_id):
    case, trust = CASES[case_id], TRUST["cases"][case_id]
    events = load_jsonl(case["events_jsonl"])
    record = vcp.loads_strict(case["anchor_record_json"])
    report = vcp.verify_batch(
        events, record,
        public_key=trust["actor_public_keys"],
        anchor_public_key=trust["anchor_public_key"],
        require_sign_algo="ED25519",
    )
    chain = vcp.verify_chain(events)
    local = combine([c.status for c in report.checks if c.name != "external_anchor"] + [c.status for c in chain.checks])
    assert (local, report.status) == EXPECTED[case_id]
    external = [c for c in report.checks if c.name == "external_anchor"]
    assert len(external) == 1
    assert (external[0].status, external[0].reason) == ("INDETERMINATE", "MISSING_ANCHOR_PROOF")
    assert "AnchorTarget" not in record
    if case_id == "tampered":
        assert {"HASH_MISMATCH", "SIGNATURE_MISMATCH"} <= {c.reason for c in report.checks}
    if case_id == "missing-key":
        assert any(c.name == "signature" and c.reason == "KEY_NOT_ESTABLISHED" for c in report.checks)
        assert any(c.name == "root_signature" and c.reason == "KEY_NOT_ESTABLISHED" for c in report.checks)


@pytest.mark.parametrize("case_id", list(EXPECTED))
def test_paths_are_bound_to_recomputed_event_hashes(case_id):
    case = CASES[case_id]
    events = load_jsonl(case["events_jsonl"])
    for event, proof in zip(events, case["inclusion_proofs"], strict=True):
        assert proof["event_id"] == event["Header"]["EventID"]
        assert proof["event_hash"] == event["Security"]["EventHash"]
        digest = vcp.compute_event_hash(
            event["Header"], event["Payload"],
            prev_hash=event["Security"].get("PrevHash"),
            algo=event["Security"]["HashAlgo"],
        )
        report = vcp.verify_inclusion_proof(
            digest, proof["index"], proof["tree_size"], proof["proof"], proof["merkle_root"],
        )
        expected = "INVALID" if case_id == "tampered" and proof["index"] == 2 else "VALID"
        assert next(c.status for c in report.checks if c.name == "inclusion") == expected
        assert any(c.name == "root_authenticity" and c.status == "INDETERMINATE" for c in report.checks)


def test_raw_evidence_and_trust_are_separate():
    intact, missing, tampered = CASES["intact"], CASES["missing-key"], CASES["tampered"]
    assert intact["events_jsonl"] == missing["events_jsonl"]
    assert intact["anchor_record_json"] == missing["anchor_record_json"]
    assert intact["inclusion_proofs"] == tampered["inclusion_proofs"]
    assert TRUST["cases"]["missing-key"] == {"actor_public_keys": {}, "anchor_public_key": None}
    for case in CASES.values():
        assert set(case) == {"id", "title", "description", "events_jsonl", "anchor_record_json", "inclusion_proofs"}
    # A normal JSON envelope round trip does not parse or round inner timestamps.
    transported = json.loads(json.dumps(BUNDLE))
    assert transported == BUNDLE
    first = load_jsonl(intact["events_jsonl"])[0]
    assert first["Header"]["TimestampInt"] == 1793145600123456789
    assert int(float(first["Header"]["TimestampInt"])) != first["Header"]["TimestampInt"]
