"""File-selection regressions for the offline signing CLI.

All inputs and keys are synthetic temporary files; signed fixture bytes are not
edited. These are ordinary path-alias checks, not concurrent-filesystem tests.
"""

import json
import os
from pathlib import Path

import pytest

import veritaschain_vcp as vcp
from veritaschain_vcp import cli


@pytest.fixture
def seal_files(tmp_path):
    key = vcp.generate_key()
    producer = vcp.Producer(key, "test-actor", "test-chain", "org.example:test")
    event = producer.create("INIT", {"test": "synthetic event — preserved"},
                            timestamp_ns=1791504000000000000)
    paths = {name: tmp_path / name for name in ("source", "key", "events", "anchor")}
    paths["source"].write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")
    paths["key"].write_text(key.seed_base64() + "\n", encoding="utf-8")
    paths["key"].chmod(0o600)
    paths["events"].write_bytes(b"existing events output\n")
    paths["anchor"].write_bytes(b"existing anchor output\n")
    return paths, key


def run_seal(paths):
    return cli.main(["seal", str(paths["source"]), "--private-key-file", str(paths["key"]),
                     "--out", str(paths["events"]), "--anchor-out", str(paths["anchor"])])


@pytest.mark.parametrize("output,target", [
    ("events", "anchor"), ("events", "source"), ("anchor", "source"),
    ("events", "key"), ("anchor", "key"),
])
@pytest.mark.parametrize("alias", ["same-path", "relative-path", "symlink", "hardlink"])
def test_seal_refuses_aliases_before_any_file_changes(seal_files, tmp_path, monkeypatch, capsys,
                                                    output, target, alias):
    paths, _ = seal_files
    originals = {path: path.read_bytes() for path in paths.values()}
    if alias == "same-path":
        paths[output] = paths[target]
    elif alias == "relative-path":
        monkeypatch.chdir(tmp_path)
        paths[output] = Path(paths[target].name)
    else:
        destination = tmp_path / "alias"
        if alias == "symlink":
            destination.symlink_to(paths[target])
        else:
            os.link(paths[target], destination)
        paths[output] = destination

    assert run_seal(paths) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "distinct" in captured.err
    for path, before in originals.items():
        assert path.read_bytes() == before, f"refused command modified {path.name}"


def test_seal_refuses_normalized_collision_before_creating_outputs(seal_files, tmp_path, capsys):
    paths, _ = seal_files
    paths["events"] = tmp_path / "new.json"
    folder = tmp_path / "folder"
    folder.mkdir()
    paths["anchor"] = folder / ".." / "new.json"
    assert run_seal(paths) == 3
    assert not paths["events"].exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "distinct" in captured.err


def test_seal_distinct_existing_outputs_preserve_inputs_and_verify(seal_files, capsys):
    paths, key = seal_files
    originals = {name: paths[name].read_bytes() for name in ("source", "key")}
    assert run_seal(paths) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["events"] == 1
    events = [json.loads(line) for line in paths["events"].read_text(encoding="utf-8").splitlines()]
    anchor = json.loads(paths["anchor"].read_text(encoding="utf-8"))
    assert vcp.verify_event(events[0], key.verify_key).status == "VALID"
    report = vcp.verify_batch(events, anchor, key.verify_key)
    assert report.status == "INDETERMINATE"  # No external anchor proof supplied.
    assert not any(check.status == "INVALID" for check in report.checks)
    for name, before in originals.items():
        assert paths[name].read_bytes() == before
