"""Exercise seal through its normal CLI entry point using temporary, synthetic data."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import veritaschain_vcp as vcp
from veritaschain_vcp import cli


class SealPublicationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.events = self.folder / "sealed.jsonl"
        self.anchor = self.folder / "anchor.json"
        self.events.write_bytes(b"previous events")
        self.anchor.write_bytes(b"previous anchor")
        self.key = vcp.generate_key()
        self.key_file = self.folder / "key"
        self.key_file.write_text(self.key.seed_base64())
        self.key_file.chmod(0o600)
        self.source = self.folder / "input"
        self.write_input("A")

    def write_input(self, *policies):
        records = []
        for policy in policies:
            producer = vcp.Producer(self.key, "actor", "chain", policy)
            records.append(producer.create("INIT", {"fixture": True}))
        self.source.write_text(json.dumps(records))

    def seal(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["seal", str(self.source), "--private-key-file", str(self.key_file),
                             "--out", str(self.events), "--anchor-out", str(self.anchor), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_originals(self):
        self.assertEqual(self.events.read_bytes(), b"previous events")
        self.assertEqual(self.anchor.read_bytes(), b"previous anchor")
        self.assertEqual(list(self.folder.glob(".vcp-seal-*")), [])

    def test_explicit_matching_policy(self):
        self.assertEqual(self.seal("--policy-id", "A")[0], 0)
        events = [json.loads(self.events.read_text())]
        record = json.loads(self.anchor.read_text())
        self.assertEqual(record["PolicyID"], "A")
        checked = vcp.verify_batch(events, record, self.key.verify_key)
        self.assertEqual([item.reason for item in checked.failed()], ["MISSING_ANCHOR_PROOF"])

    def test_conflicting_explicit_policy_preserves_pair(self):
        code, stdout, stderr = self.seal("--policy-id", "B")
        self.assertEqual((code, stdout), (3, ""))
        self.assertIn("line 1: Header.PolicyID", stderr)
        self.assert_originals()

    def test_mixed_input_policies_preserve_pair(self):
        self.write_input("A", "B")
        with patch.object(cli, "seal_event", wraps=cli.seal_event) as sign:
            code, stdout, stderr = self.seal()
        sign.assert_not_called()
        self.assertEqual((code, stdout), (3, ""))
        self.assertIn("line 2: Header.PolicyID", stderr)
        self.assert_originals()

    def test_missing_anchor_parent_preserves_events(self):
        self.anchor = self.folder / "missing" / "anchor"
        self.assertEqual(self.seal()[0], 3)
        self.assertEqual(self.events.read_bytes(), b"previous events")
        self.assertFalse(self.anchor.exists())
        self.assertEqual(list(self.folder.glob(".vcp-seal-*")), [])

    def test_failed_second_replace_restores_previous_outputs(self):
        replace = os.replace

        def fail_anchor(source, destination):
            if destination == self.anchor:
                raise OSError("synthetic filesystem error")
            return replace(source, destination)

        for had_events in (True, False):
            with self.subTest(had_events=had_events):
                if not had_events:
                    self.events.unlink()
                with patch("veritaschain_vcp._seal_output.os.replace", side_effect=fail_anchor):
                    self.assertEqual(self.seal()[0], 3)
                self.assertEqual(self.events.exists(), had_events)
                if had_events:
                    self.assert_originals()
                self.assertEqual(self.anchor.read_bytes(), b"previous anchor")
                self.assertEqual(list(self.folder.glob(".vcp-seal-*")), [])
        self.assertEqual(self.seal()[0], 0)  # retry after the transient failure

    def test_overlapping_seal_cannot_publish_during_commit(self):
        replace = os.replace
        overlapping = []

        def while_sealing(source, destination):
            if destination == self.events:
                overlapping.append(self.seal())
            return replace(source, destination)

        with patch("veritaschain_vcp._seal_output.os.replace", side_effect=while_sealing):
            self.assertEqual(self.seal()[0], 0)
        self.assertEqual(len(overlapping), 1)
        self.assertEqual(overlapping[0][0], 3)
        self.assertIn("staging directory already in use", overlapping[0][2])
        self.assertEqual(list(self.folder.glob(".vcp-seal-*")), [])

    def test_failed_rollback_retains_recovery_files(self):
        replace = os.replace

        def fail_anchor_and_rollback(source, destination):
            if destination == self.anchor or source.name == "previous":
                raise OSError("synthetic filesystem error")
            return replace(source, destination)

        with patch("veritaschain_vcp._seal_output.os.replace", side_effect=fail_anchor_and_rollback):
            code, stdout, stderr = self.seal()
        self.assertEqual((code, stdout), (3, ""))
        self.assertIn("recovery files", stderr)
        previous, = self.folder.glob(".vcp-seal-*/previous")
        self.assertEqual(previous.read_bytes(), b"previous events")
        self.assertEqual(self.anchor.read_bytes(), b"previous anchor")
        self.assertEqual(self.seal()[0], 3)

    def test_existing_output_symlink_keeps_its_target(self):
        real_events = self.events
        link = self.folder / "events-link"
        try:
            link.symlink_to(real_events)
        except OSError as error:
            self.skipTest(str(error))
        self.events = link
        self.assertEqual(self.seal()[0], 0)
        self.assertTrue(link.is_symlink())
        self.assertEqual(json.loads(real_events.read_text())["Header"]["PolicyID"], "A")

    def test_cleanup_error_after_commit_reports_success_and_recoverable_warning(self):
        with patch("veritaschain_vcp._seal_output.shutil.rmtree", side_effect=OSError("busy directory")):
            code, stdout, stderr = self.seal()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["events"], 1)
        self.assertIn("warning: could not remove seal staging directory", stderr)
        events = [json.loads(self.events.read_text())]
        record = json.loads(self.anchor.read_text())
        self.assertEqual(record["PolicyID"], "A")
        self.assertEqual(vcp.verify_batch(events, record, self.key.verify_key).status, "INDETERMINATE")
        self.assertEqual(len(list(self.folder.glob(".vcp-seal-*"))), 2)
