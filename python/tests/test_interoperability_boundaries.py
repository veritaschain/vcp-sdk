"""Non-normative boundary fixtures; not an independent conformance assessment."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import pytest
from veritaschain_vcp import merkle, signing, verify_batch
from veritaschain_vcp.hashing import compute_event_hash
from veritaschain_vcp.jcs import canonicalize_str

FIXTURES = json.loads((Path(__file__).resolve().parents[2] / "test-vectors" / "interoperability-boundaries.json").read_text())
CASES = FIXTURES["cases"]
ANCHOR = FIXTURES["anchorFixture"]
TEST_KEY = FIXTURES["testKey"]


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


@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "signature-bytes"], ids=lambda c: c["id"])
def test_signature_input_bytes(case):
    event_bytes = bytes.fromhex(case["expectedEventSignedBytesHex"])
    root_bytes = bytes.fromhex(case["expectedRootSignedBytesHex"])
    assert event_bytes == case["digestHex"].encode("ascii")
    assert root_bytes.hex() == case["digestHex"]
    assert event_bytes != root_bytes

    # Check the frozen signatures over literal bytes without the SDK wrappers.
    # This remains a first-party check, not independent implementation evidence.
    raw_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(TEST_KEY["publicKeyHex"]))
    raw_key.verify(base64.b64decode(case["expectedEventSignatureBase64"], validate=True), event_bytes)
    raw_key.verify(base64.b64decode(case["expectedRootSignatureBase64"], validate=True), root_bytes)

    key = signing.SigningKey(TEST_KEY["seedHex"])
    public_key = signing.VerifyKey(TEST_KEY["publicKeyHex"])
    assert key.verify_key.raw.hex() == TEST_KEY["publicKeyHex"]
    assert signing.sign_event_hash(case["digestHex"], key) == case["expectedEventSignatureBase64"]
    assert signing.sign_merkle_root(case["digestHex"], key) == case["expectedRootSignatureBase64"]
    assert signing.verify_event_signature(case["digestHex"], case["expectedEventSignatureBase64"], public_key) is case["expectedEventVerification"]
    assert signing.verify_root_signature(case["digestHex"], case["expectedRootSignatureBase64"], public_key) is case["expectedRootVerification"]
    assert signing.verify_event_signature(case["digestHex"], case["expectedRootSignatureBase64"], public_key) is case["expectedCrossVerification"]
    assert signing.verify_root_signature(case["digestHex"], case["expectedEventSignatureBase64"], public_key) is case["expectedCrossVerification"]


def test_anchor_fixture_literal_bytes():
    event = ANCHOR["event"]
    assert canonicalize_str(event["Header"]) == ANCHOR["expectedHeaderCanonical"]
    assert canonicalize_str(event["Payload"]) == ANCHOR["expectedPayloadCanonical"]
    literal_bytes = (ANCHOR["expectedHeaderCanonical"] + ANCHOR["expectedPayloadCanonical"]).encode("utf-8")
    assert hashlib.sha256(literal_bytes).hexdigest() == ANCHOR["expectedEventHashHex"]
    assert compute_event_hash(event["Header"], event["Payload"]) == ANCHOR["expectedEventHashHex"]
    leaf = bytes.fromhex(ANCHOR["expectedEventHashHex"])
    assert hashlib.sha256(b"\x00" + leaf).hexdigest() == ANCHOR["expectedRootHex"]
    assert merkle.root([leaf]).hex() == ANCHOR["expectedRootHex"]


@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "anchor-record"], ids=lambda c: c["id"])
def test_anchor_record_boundaries(case):
    record = deepcopy(ANCHOR["record"])
    record.update(deepcopy(case["anchorPatch"]))
    # Every metadata/proof case retains the same root and root-only signature.
    assert record["MerkleRoot"] == ANCHOR["record"]["MerkleRoot"]
    assert record["Signature"] == ANCHOR["record"]["Signature"]
    report = verify_batch(
        [deepcopy(ANCHOR["event"])], record,
        public_key=TEST_KEY["publicKeyHex"], anchor_public_key=TEST_KEY["publicKeyHex"],
    )
    expected = {**ANCHOR["expectedChecks"], **case.get("expectedCheckOverrides", {})}
    actual = {}
    for check in report.checks:
        assert check.name not in actual, "single-event fixture should have one check of each kind"
        actual[check.name] = {"status": check.status}
        if check.reason is not None:
            actual[check.name]["reason"] = check.reason
    assert actual == expected
    # A proven binding mismatch is INVALID even with an INDETERMINATE external anchor.
    assert report.status == case["expectedStatus"]
    assert any("signature covers the Merkle root only" in note for note in report.notes)
    timestamp = next(check for check in report.checks if check.name == "anchor_timestamp_format")
    assert "not covered by the signature" in timestamp.detail
