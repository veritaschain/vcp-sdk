import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

import veritaschain_vcp as vcp
from veritaschain_vcp import cli
from veritaschain_vcp.jsonio import StrictJSONError, loads
from veritaschain_vcp.verify import INDETERMINATE, INVALID, VALID, verify_batch, verify_chain, verify_event

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "test-vectors" / "vectors.json").read_text(encoding="utf-8"))
SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"


def test_rfc8032_vectors():
    for v in VECTORS["ed25519_rfc8032"]:
        k = vcp.SigningKey(v["seed"])
        assert k.verify_key.raw.hex() == v["public"]
        assert k.sign(bytes.fromhex(v["message"])).hex() == v["signature"]
        assert k.verify_key.verify(bytes.fromhex(v["signature"]), bytes.fromhex(v["message"]))


def test_vectors_files_are_reproducible(tmp_path):
    gen = ROOT / "tools" / "generate_vectors.py"
    subprocess.run([sys.executable, str(gen), str(tmp_path)], check=True, capture_output=True)
    for name in ("vectors.json", "hostile.json"):
        assert (tmp_path / name).read_bytes() == (ROOT / "test-vectors" / name).read_bytes(), name


def test_vector_events_hash_and_sign():
    key = vcp.SigningKey(SEED)
    for row in VECTORS["events"]:
        ev = row["event"]
        h = vcp.compute_event_hash(ev["Header"], ev["Payload"], prev_hash=ev["Security"].get("PrevHash"))
        assert h == row["event_hash"]
        assert vcp.verify_event_signature(h, ev["Security"]["Signature"], key.verify_key)
        assert vcp.jcs.canonicalize_str(ev["Header"]) == row["canonical_header"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_vector_cases(case):
    if case["kind"] == "chain":
        rep = verify_chain(case["events"])
    else:
        ext = case["external_anchor_result"]
        rep = verify_batch(case["events"], case["anchor_record"], case["public_key"],
                           external_anchor_verifier=(lambda r: ext) if ext is not None else None)
    assert rep.status == case["expected_status"]
    got = sorted({(c.name, c.status, c.reason or "") for c in rep.checks if c.status != VALID})
    assert [list(x) for x in got] == case["expected_non_valid"]


def make_batch(n=4, **kw):
    key = vcp.SigningKey(SEED)
    p = vcp.Producer(key, "actor", "chain", "org.example:p", **kw)
    for i in range(n):
        p.create("ORD" if i else "INIT", {"VCP-TRADE": {"Price": f"1.{i:03d}"}}, timestamp_ns=1_791_504_000_000_000_000 + i * 1_234_567)
    batch, rec = p.close_batch(anchor_target={"Type": "TSA", "Identifier": "tsa.example", "Proof": "x"})
    return key, batch, rec


def test_round_trip_and_three_values():
    key, batch, rec = make_batch()
    ok = verify_batch(batch.events, rec, key.verify_key, external_anchor_verifier=lambda r: True)
    assert ok.status == VALID
    assert verify_batch(batch.events, rec, key.verify_key).status == INDETERMINATE
    assert verify_batch(batch.events, rec, key.verify_key, external_anchor_verifier=lambda r: None).status == INDETERMINATE
    assert verify_batch(batch.events, None, key.verify_key).status == INDETERMINATE
    no_target = dict(rec)
    del no_target["AnchorTarget"]
    r = verify_batch(batch.events, no_target, key.verify_key, external_anchor_verifier=lambda r: True)
    assert ("external_anchor", "MISSING_ANCHOR_PROOF") in {(c.name, c.reason) for c in r.checks}


def test_inclusion_proof_report():
    key, batch, rec = make_batch(5)
    for i, ev in enumerate(batch.events):
        proof = batch.inclusion_proof(i)
        r = vcp.verify_inclusion_proof(ev["Security"]["EventHash"], i, 5, proof, rec["MerkleRoot"])
        assert r.status == INDETERMINATE  # root not authenticated
        r = vcp.verify_inclusion_proof(ev["Security"]["EventHash"], i, 5, proof, rec["MerkleRoot"], root_authenticated=True)
        assert r.status == VALID
        bad = vcp.verify_inclusion_proof(ev["Security"]["EventHash"], (i + 1) % 5, 5, proof, rec["MerkleRoot"], root_authenticated=True)
        assert bad.status == INVALID


def test_legacy_batch_is_indeterminate_not_invalid():
    key, batch, rec = make_batch(3)
    leaves = [bytes.fromhex(vcp.parse_hash(e["Security"]["EventHash"])) for e in batch.events]
    legacy = vcp.merkle.legacy_example_root(leaves).hex()
    rec2 = dict(rec, MerkleRoot=legacy, Signature=vcp.sign_merkle_root(legacy, key))
    events = copy.deepcopy(batch.events)
    for e in events:
        e["Security"]["MerkleRoot"] = legacy
    r = verify_batch(events, rec2, key.verify_key, external_anchor_verifier=lambda r: True)
    checks = {c.name: c for c in r.checks}
    assert checks["merkle_root"].reason == "LEGACY_MERKLE_CONSTRUCTION"
    assert checks["event_merkle_root"].reason == "LEGACY_MERKLE_CONSTRUCTION"
    assert r.status == INDETERMINATE


def test_unsupported_and_missing():
    key, batch, rec = make_batch(1)
    ev = copy.deepcopy(batch.events[0])
    ev["Security"]["SignAlgo"] = "DILITHIUM2"
    assert {c.reason for c in verify_event(ev, key.verify_key).checks} >= {"ALGORITHM_UNSUPPORTED"}
    ev = copy.deepcopy(batch.events[0])
    del ev["Security"]["Signature"]
    assert verify_event(ev, key.verify_key).status == INDETERMINATE
    ev = copy.deepcopy(batch.events[0])
    ev["Security"]["HashAlgo"] = "SHA3_512"
    ev["Security"]["EventHash"] = vcp.parse_hash(ev["Security"]["EventHash"])
    assert verify_event(ev, key.verify_key).status == INDETERMINATE
    ev = copy.deepcopy(batch.events[0])
    del ev["Header"]["ChainID"]
    assert verify_event(ev, key.verify_key).status == INVALID
    ev = copy.deepcopy(batch.events[0])
    ev["Header"]["EventType"] = "NOPE"
    assert verify_event(ev, key.verify_key).status == INVALID


def test_strict_integers_and_note():
    key = vcp.SigningKey(SEED)
    h = {"TimestampInt": 1791504000000000001}
    with pytest.raises(vcp.CanonicalizationError):
        vcp.compute_event_hash(h, {}, strict_integers=True)
    assert vcp.compute_event_hash(h, {}) != vcp.compute_event_hash({"TimestampInt": 1791504000000000000}, {})
    a, b = {"TimestampInt": 1791504000123456768}, {"TimestampInt": 1791504000123456800}
    assert vcp.compute_event_hash(a, {}) != vcp.compute_event_hash(b, {})
    assert vcp.compute_event_hash(a, {}, strict_integers=True) != vcp.compute_event_hash(a, {})
    p = vcp.Producer(key, "a", "c", "org.example:p", precision="NANOSECOND")
    ev = p.create("INIT", {}, timestamp_ns=1791504000000000001)
    r = verify_event(ev, key.verify_key)
    assert r.status == VALID
    assert any("exact decimal digits" in n for n in r.notes)


def test_policy_identification_mismatch():
    key, batch, rec = make_batch(1)
    ev = copy.deepcopy(batch.events[0])
    ev["PolicyIdentification"] = {"PolicyID": "other", "ConformanceTier": "SILVER"}
    r = verify_event(ev, key.verify_key)
    assert r.status == INVALID
    assert any("outside EventHash" in n for n in r.notes)


def test_chain_prior_hash():
    key, batch, rec = make_batch(3, use_prev_hash=True)
    r = verify_chain(batch.events[1:])
    assert r.status == INDETERMINATE  # predecessor hash not supplied
    r = verify_chain(batch.events[1:], prior_hash=batch.events[0]["Security"]["EventHash"])
    assert r.status == VALID
    _, plain, _ = make_batch(3)
    assert verify_chain(plain.events).status == INDETERMINATE  # PrevHash not used


def test_strict_json():
    with pytest.raises(StrictJSONError):
        loads('{"a":1,"a":2}')
    with pytest.raises(StrictJSONError):
        loads('{"a":NaN}')
    with pytest.raises(StrictJSONError):
        loads(b"\xef\xbb\xbf{}")


def test_timestamps_and_uuid():
    assert vcp.iso_from_ns(1791504000123456789, "NANOSECOND") == "2026-10-09T00:00:00.123456789Z"
    assert vcp.iso_from_ns(1791504000123456789, "MILLISECOND") == "2026-10-09T00:00:00.123Z"
    assert vcp.ns_from_iso("2026-10-09T09:00:00.5+09:00") == (1791504000500000000, 1)
    u = vcp.uuid7(0x0123456789AB, bytes(10))
    assert u == "01234567-89ab-7000-8000-000000000000"


def test_cli(tmp_path, capsys):
    key = vcp.SigningKey(SEED)
    unsigned = tmp_path / "in.jsonl"
    rows = []
    for i in range(3):
        rows.append({"Header": {"EventID": vcp.uuid7(1791504000000 + i), "TimestampISO": vcp.iso_from_ns(1791504000000000000 + i * 1_000_000),
                                "TimestampInt": 1791504000000000000 + i * 1_000_000, "EventType": "SIG" if i else "INIT", "ActorID": "ea-1",
                                "ChainID": "c", "SequenceNum": i, "PolicyID": "org.example:p"},
                     "Payload": {"VCP-TRADE": {"Symbol": "EURUSD", "Price": "1.08"}}})
    unsigned.write_text("".join(json.dumps(r) + "\n" for r in rows))
    out, anc = tmp_path / "sealed.jsonl", tmp_path / "anchor.json"
    kf = tmp_path / "ea.key"
    kf.write_text(SEED)
    kf.chmod(0o644)
    assert cli.main(["seal", str(unsigned), "--private-key-file", str(kf), "--out", str(out), "--anchor-out", str(anc), "--prev-hash", "--allow-missing-hash"]) == 3  # key file too open
    kf.chmod(0o600)
    assert cli.main(["seal", str(unsigned), "--private-key-file", str(kf), "--out", str(out), "--anchor-out", str(anc), "--prev-hash"]) == 3  # no producer hash
    assert cli.main(["seal", str(unsigned), "--private-key-file", str(kf), "--out", str(out), "--anchor-out", str(anc), "--prev-hash", "--allow-missing-hash"]) == 0
    capsys.readouterr()
    code = cli.main(["verify-batch", str(out), "--anchor", str(anc), "--public-key", key.verify_key.to_base64()])
    rep = json.loads(capsys.readouterr().out)
    assert code == 2 and rep["status"] == INDETERMINATE  # no external anchor proof
    assert cli.main(["verify-chain", str(out)]) == 0
    capsys.readouterr()
    first = out.read_text().splitlines()[0]
    (tmp_path / "e.json").write_text(first)
    assert cli.main(["verify-event", str(tmp_path / "e.json"), "--public-key", key.verify_key.to_base64()]) == 0


def _mql5_like_lines(tamper: bool = False) -> str:
    """Lines shaped like CVcpWriter output: Header, Payload, Security{EventHash, HashAlgo[, PrevHash]}."""
    lines, prev = [], None
    for i in range(4):
        h = {"EventID": vcp.uuid7(1791504000000 + i, bytes([i]) * 10), "TimestampISO": vcp.iso_from_ns(1791504000000000000 + i * 1_000_000),
             "TimestampInt": 1791504000000000000 + i * 1_000_000, "EventType": "EXE" if i else "INIT", "ActorID": "mt5",
             "ChainID": "mt5-1", "SequenceNum": i, "PolicyID": "org.example:silver-mt5"}
        p = {"VCP-TRADE": {"Symbol": "USDJPY", "Price": "151.23" + str(i)}}
        eh = vcp.compute_event_hash(h, p, prev_hash=prev)
        sec = {"EventHash": "sha256:" + eh, "HashAlgo": "SHA256"}
        if prev:
            sec["PrevHash"] = "sha256:" + prev
        if tamper and i == 2:
            p["VCP-TRADE"]["Price"] = "999"
        lines.append(vcp.jcs.canonicalize_str({"Header": h, "Payload": p, "Security": sec}))
        prev = eh
    return "\n".join(lines) + "\n"


def test_seal_mql5_output(tmp_path, capsys, monkeypatch):
    src = tmp_path / "mt5.jsonl"
    src.write_text(_mql5_like_lines())
    out, anc = tmp_path / "s.jsonl", tmp_path / "a.json"
    monkeypatch.setenv("VCP_PRIVATE_KEY", SEED)
    assert cli.main(["seal", str(src), "--out", str(out), "--anchor-out", str(anc)]) == 0
    capsys.readouterr()
    assert cli.main(["verify-chain", str(out)]) == 0
    capsys.readouterr()
    src.write_text(_mql5_like_lines(tamper=True))
    assert cli.main(["seal", str(src), "--out", str(out), "--anchor-out", str(anc)]) == 3
    bad = json.loads(_mql5_like_lines().splitlines()[0])
    bad["Header"]["EventType"] = "NOPE"
    src.write_text(json.dumps(bad) + "\n")
    assert cli.main(["seal", str(src), "--out", str(out), "--anchor-out", str(anc)]) == 3


def test_seal_rotated_files(tmp_path, capsys, monkeypatch):
    """A chain split across two files (the MQL5 daily rotation): seal each, check the link."""
    lines = _mql5_like_lines().splitlines(keepends=True)
    day1, day2 = tmp_path / "d1.jsonl", tmp_path / "d2.jsonl"
    day1.write_text("".join(lines[:2]))
    day2.write_text("".join(lines[2:]))
    monkeypatch.setenv("VCP_PRIVATE_KEY", SEED)
    s1, a1, s2, a2 = (tmp_path / n for n in ("s1.jsonl", "a1.json", "s2.jsonl", "a2.json"))
    capsys.readouterr()
    assert cli.main(["seal", str(day1), "--out", str(s1), "--anchor-out", str(a1)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["last_sequence"] == 1
    last = summary["last_event_hash"]
    assert cli.main(["seal", str(day1), "--out", str(s1), "--anchor-out", str(a1), "--prior-hash", last]) == 3  # line 1 has no PrevHash
    assert cli.main(["seal", str(day2), "--out", str(s2), "--anchor-out", str(a2), "--prior-hash", "ab" * 32]) == 3  # wrong link
    assert cli.main(["seal", str(day2), "--out", str(s2), "--anchor-out", str(a2), "--prior-hash", "nothex"]) == 3
    capsys.readouterr()
    assert cli.main(["seal", str(day2), "--out", str(s2), "--anchor-out", str(a2), "--prior-hash", last]) == 0
    capsys.readouterr()
    assert cli.main(["verify-chain", str(s2), "--prior-hash", last]) == 0
    capsys.readouterr()
    assert cli.main(["verify-chain", str(s2)]) == 2  # first link cannot be checked without the prior hash
    capsys.readouterr()
    assert cli.main(["seal", str(day2), "--out", str(s2), "--anchor-out", str(a2)]) == 0
    assert "warning: line 1 links to an earlier event" in capsys.readouterr().err


def test_verifier_signature_hides_internal_context():
    import inspect
    for fn in (vcp.verify_event, vcp.verify_batch, vcp.verify_chain, vcp.verify_inclusion_proof):
        assert "_ctx" not in inspect.signature(fn).parameters


def test_cli_exit_codes(tmp_path, capsys):
    deep = tmp_path / "deep.json"
    deep.write_text('{"Header":' + "[" * 300 + "]" * 300 + "}")
    assert cli.main(["verify-event", str(deep)]) == 3
    with pytest.raises(SystemExit) as e:
        cli.main(["verify-event"])  # missing argument
    assert e.value.code == 3
    key, batch, rec = make_batch(2)
    ev = tmp_path / "e.jsonl"
    ev.write_text("".join(json.dumps(e) + "\n" for e in batch.events))
    anc = tmp_path / "a.json"
    anc.write_text("[]")
    capsys.readouterr()
    assert cli.main(["verify-batch", str(ev), "--anchor", str(anc), "--public-key", key.verify_key.to_base64()]) == 1  # INVALID, not a crash
    out = json.loads(capsys.readouterr().out)
    assert any(c.get("reason") == "BAD_FORMAT" for c in out["checks"])
    kf = tmp_path / "new.key"
    assert cli.main(["keygen", "--out", str(kf)]) == 0
    assert oct(kf.stat().st_mode & 0o777) == "0o600"
    assert cli.main(["keygen", "--out", str(kf)]) == 3  # refuses to overwrite


def test_vector_events_are_schema_valid():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "test-vectors" / "vcp-event-v1.2.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in VECTORS["events"]:
        errors = sorted(validator.iter_errors(row["event"]), key=str)
        assert not errors, [e.message for e in errors]
