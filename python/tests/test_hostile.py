"""Hostile and malformed inputs (test-vectors/hostile.json, expectations written by hand)."""

import json
from pathlib import Path

import pytest

import veritaschain_vcp as vcp
from veritaschain_vcp import jcs
from veritaschain_vcp.jsonio import StrictJSONError, load_jsonl, loads
from veritaschain_vcp.verify import VALID, verify_batch, verify_chain, verify_event, verify_inclusion_proof

ROOT = Path(__file__).resolve().parents[2]
H = loads((ROOT / "test-vectors" / "hostile.json").read_bytes())
VERIFIER_CASES = [c for c in H["cases"] if c["kind"] in ("event", "batch", "chain", "inclusion")]
PARSE_CASES = [c for c in H["cases"] if c["kind"] == "parse"]
JSONL_CASES = [c for c in H["cases"] if c["kind"] == "jsonl"]


def run(c):
    if c["kind"] == "event":
        return verify_event(c["event"], c["public_key"], require_sign_algo=c["require_sign_algo"])
    if c["kind"] == "batch":
        ext = c["external_anchor_result"]
        return verify_batch(c["events"], c["anchor_record"], c["public_key"],
                            external_anchor_verifier=(lambda r: ext) if ext is not None else None,
                            require_sign_algo=c.get("require_sign_algo"))
    if c["kind"] == "chain":
        return verify_chain(c["events"], prior_hash=c["prior_hash"])
    return verify_inclusion_proof(*c["args"])


@pytest.mark.parametrize("case", VERIFIER_CASES, ids=lambda c: c["name"])
def test_verifier_case(case):
    rep = run(case)
    reasons = {x.reason for x in rep.checks if x.status != VALID}
    assert "VERIFIER_ERROR" not in reasons, rep.to_dict()
    assert rep.status == case["expected"], rep.to_dict()
    if case["reason"]:
        assert case["reason"] in reasons, rep.to_dict()
    assert [[x.name, x.status, x.reason or "", x.subject or ""] for x in rep.checks] == case["python_checks"]


@pytest.mark.parametrize("case", PARSE_CASES, ids=lambda c: c["name"])
def test_parse_case(case):
    if not case["ok"]:
        with pytest.raises(StrictJSONError):
            loads(case["text"])
        return
    v = loads(case["text"])
    if case["canonical"] is None:
        with pytest.raises(jcs.CanonicalizationError):
            jcs.canonicalize_str(v)
    else:
        assert jcs.canonicalize_str(v) == case["canonical"]


@pytest.mark.parametrize("case", JSONL_CASES, ids=lambda c: c["name"])
def test_jsonl_case(case):
    if case["count"] is None:
        with pytest.raises(StrictJSONError):
            load_jsonl(case["text"])
    else:
        assert len(load_jsonl(case["text"])) == case["count"]


def test_external_verifier_that_raises():
    key = vcp.SigningKey("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    p = vcp.Producer(key, "a", "c", "org.example:p")
    p.create("INIT", {"VCP-GOV": {"AlgoID": "x"}}, timestamp_ns=1791504000000000000)
    b, rec = p.close_batch(anchor_target={"Type": "TSA", "Identifier": "t", "Proof": "p"})

    def boom(r):
        raise RuntimeError("network down")

    rep = verify_batch(b.events, rec, key.verify_key, external_anchor_verifier=boom)
    assert rep.status == "INDETERMINATE"
    assert any("network down" in n for n in rep.notes)


def test_small_order_keys_rejected_directly():
    V = json.loads((ROOT / "test-vectors" / "vectors.json").read_text(encoding="utf-8"))
    E = V["ed25519_edges"]
    for enc in E["small_order_public_keys"] + E["non_canonical_public_keys"] + E["torsion_component_public_keys"]:
        with pytest.raises(ValueError):
            vcp.VerifyKey(enc)
