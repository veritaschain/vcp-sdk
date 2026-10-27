"""Non-normative boundary fixtures; not an independent conformance assessment."""
import json
from pathlib import Path
import pytest
from veritaschain_vcp import merkle
from veritaschain_vcp.jcs import canonicalize_str

CASES = json.loads((Path(__file__).resolve().parents[2] / "test-vectors" / "interoperability-boundaries.json").read_text())["cases"]

@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "canonical-json"], ids=lambda c: c["id"])
def test_boundary_canonical_bytes(case):
    parsed = json.loads(case["input"])
    assert canonicalize_str(parsed).encode("utf-8") == case["expectedCanonical"].encode("utf-8")

@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "merkle-root"], ids=lambda c: c["id"])
def test_boundary_merkle_root(case):
    leaves = [bytes.fromhex(x) for x in case["leafHex"]]
    assert merkle.root(leaves).hex() == case["expectedRootHex"]

def test_non_power_of_two_not_equivalent_to_duplicate_leaf():
    roots = {c["id"]: c["expectedRootHex"] for c in CASES if c["kind"] == "merkle-root"}
    assert roots["merkle-3-leaves"] != roots["merkle-4-leaves"]

def test_negative_cases_are_not_misrepresented_as_passing():
    cases = [c for c in CASES if c["kind"].startswith("security-")]
    assert len(cases) == 2
    assert all("expectedRootHex" not in c and "expectedCanonical" not in c for c in cases)
