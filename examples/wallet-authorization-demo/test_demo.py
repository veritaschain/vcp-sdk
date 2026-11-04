"""Integration checks for the saved SDK records and the pinned companion.

Run with VCP_WALLET_VAP_SPEC set to an explicit local vap-spec checkout.
These are first-party synthetic boundary tests, not conformance tests.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest import mock

import demo
import generate_fixtures


class RecordedEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, cls.trust = demo.read_fixtures()

    def test_without_companion_authorization_is_unknown_not_a_pass(self):
        for case in demo.CASES:
            with self.subTest(case=case):
                item = self.records["cases"][case]
                report = demo.verify_record(
                    item["recorded_event"], self.trust["sdk_recorder"]["public_key_hex"], {},
                    companion=None, evaluation_time=item["evaluation_time"],
                )
                self.assertEqual(report["recorded_event_integrity"]["status"], "VALID")
                for claim in report["wallet_evidence"]["claims"].values():
                    self.assertEqual(claim["verdict"], "INDETERMINATE")
                    self.assertEqual(claim["reasons"], ["COMPANION_NOT_AVAILABLE"])
                self.assertEqual(report["simulated_admission"]["decision"], "DENY")

    def test_cli_reads_existing_signatures_without_companion(self):
        before = (demo.HERE / "fixtures.json").read_bytes()
        completed = subprocess.run(
            [sys.executable, str(demo.HERE / "demo.py"), "--case", "missing_approval"],
            check=True, capture_output=True, text=True,
        )
        report = json.loads(completed.stdout)["reports"]["missing_approval"]
        self.assertEqual(report["recorded_event_integrity"]["status"], "VALID")
        self.assertEqual(report["wallet_evidence"]["claims"]["authorization"]["verdict"], "INDETERMINATE")
        self.assertEqual(report["inputs"]["wallet_trust"], "trust.json#/cases/missing_approval/companion_keys")
        self.assertEqual((demo.HERE / "fixtures.json").read_bytes(), before)


class CompanionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("VCP_WALLET_VAP_SPEC")
        if not configured:
            raise RuntimeError("Set VCP_WALLET_VAP_SPEC to the pinned local vap-spec checkout; see README.md")
        cls.vap_spec = Path(configured)
        cls.companion, cls.lock = demo.load_companion(cls.vap_spec)
        cls.records, cls.trust = demo.read_fixtures()

    def replay(self, case, *, event=None, trusted_keys=None, evaluation_time=None, event_key=True):
        item = self.records["cases"][case]
        return demo.verify_record(
            item["recorded_event"] if event is None else event,
            self.trust["sdk_recorder"]["public_key_hex"] if event_key else None,
            demo.decode_companion_keys(self.trust["cases"][case]["companion_keys"])
            if trusted_keys is None else trusted_keys,
            companion=self.companion,
            evaluation_time=item["evaluation_time"] if evaluation_time is None else evaluation_time,
            record_ref=f"fixtures.json#/cases/{case}/recorded_event",
        )

    def test_signed_record_and_signed_approval_can_contradict_authorization(self):
        report = self.replay("approval_mismatch")
        self.assertEqual(report["recorded_event_integrity"]["status"], "VALID")
        claims = report["wallet_evidence"]["claims"]
        self.assertEqual(claims["integrity"]["verdict"], "VALID")
        self.assertEqual(claims["authorization"]["verdict"], "INVALID")
        self.assertIn("approval:operation_digest_mismatch", claims["authorization"]["reasons"])
        self.assertTrue(claims["authorization"]["evidence_refs"])
        self.assertEqual(report["simulated_admission"]["decision"], "DENY")

    def test_missing_approval_is_unknown_not_a_proven_violation(self):
        report = self.replay("missing_approval")
        self.assertEqual(report["recorded_event_integrity"]["status"], "VALID")
        claims = report["wallet_evidence"]["claims"]
        self.assertEqual(claims["integrity"]["verdict"], "VALID")
        self.assertEqual(claims["authorization"]["verdict"], "INDETERMINATE")
        self.assertIn("approval:missing_or_unverifiable", claims["authorization"]["reasons"])
        self.assertEqual(report["simulated_admission"]["decision"], "DENY")

    def test_offchain_stop_does_not_establish_delegation_clearance(self):
        report = self.replay("stop_with_delegation")
        self.assertEqual(report["recorded_event_integrity"]["status"], "VALID")
        bundle = self.records["cases"]["stop_with_delegation"]["recorded_event"]["Payload"]["ExperimentalWalletEvidence"]["Bundle"]
        self.assertEqual(bundle["evidence"]["execution"]["payload"]["state"], "offchain_stopped")
        self.assertTrue(bundle["evidence"]["chain_observation"]["payload"]["delegation_code"].startswith("0xef0100"))
        state = report["wallet_evidence"]["claims"]["delegation_state"]
        self.assertEqual(state["verdict"], "INVALID")
        self.assertIn("chain:requested_delegation_state_contradicted", state["reasons"])
        self.assertEqual(report["simulated_admission"]["decision"], "DENY")

    def test_clearance_is_only_an_observation_at_the_bound_block(self):
        report = self.replay("clear_observed")
        self.assertEqual(report["recorded_event_integrity"]["status"], "VALID")
        self.assertEqual(report["wallet_evidence"]["claims"]["delegation_state"]["verdict"], "VALID")
        observation = self.records["cases"]["clear_observed"]["recorded_event"]["Payload"]["ExperimentalWalletEvidence"]["Bundle"]["evidence"]["chain_observation"]["payload"]
        self.assertEqual(observation["delegation_code"], "0x")
        self.assertEqual(observation["block_number"], "100")
        self.assertEqual(observation["finality"], "observed_block")
        self.assertEqual(report["simulated_admission"]["decision"], "ALLOW")
        # The same unchanged historical observation does not renew an expired
        # approval or revocation snapshot when the caller advances its clock.
        later = self.replay("clear_observed", evaluation_time=report["evaluation_time"] + 121)
        self.assertEqual(later["recorded_event_integrity"]["status"], "VALID")
        self.assertEqual(later["wallet_evidence"]["claims"]["authorization"]["verdict"], "INVALID")
        self.assertEqual(later["simulated_admission"]["decision"], "DENY")

    def test_record_tampering_cannot_be_promoted_by_valid_companion_evidence(self):
        event = copy.deepcopy(self.records["cases"]["clear_observed"]["recorded_event"])
        event["Payload"]["ExperimentalWalletEvidence"]["Case"] = "changed after signing"
        report = self.replay("clear_observed", event=event)
        self.assertEqual(report["recorded_event_integrity"]["status"], "INVALID")
        self.assertTrue(any(check.get("reason") == "HASH_MISMATCH"
                            for check in report["recorded_event_integrity"]["checks"]))
        self.assertEqual(report["wallet_evidence"]["claims"]["authorization"]["verdict"], "VALID")
        self.assertEqual(report["simulated_admission"]["decision"], "DENY")

    def test_record_signature_does_not_supply_companion_role_trust(self):
        report = self.replay("clear_observed", trusted_keys={})
        self.assertEqual(report["recorded_event_integrity"]["status"], "VALID")
        self.assertEqual(report["wallet_evidence"]["claims"]["authorization"]["verdict"], "INDETERMINATE")
        self.assertEqual(report["simulated_admission"]["decision"], "DENY")
        missing_record_key = self.replay("clear_observed", event_key=False)
        self.assertEqual(missing_record_key["recorded_event_integrity"]["status"], "INDETERMINATE")
        self.assertEqual(missing_record_key["wallet_evidence"]["claims"]["authorization"]["verdict"], "VALID")
        self.assertEqual(missing_record_key["simulated_admission"]["decision"], "DENY")

    def test_fixture_bytes_reproduce_from_pinned_canonical_generator(self):
        first = generate_fixtures.generate(self.vap_spec)
        second = generate_fixtures.generate(self.vap_spec)
        for index, name in enumerate(("fixtures.json", "trust.json")):
            with self.subTest(file=name):
                self.assertEqual(generate_fixtures.json_bytes(first[index]), generate_fixtures.json_bytes(second[index]))
                self.assertEqual(generate_fixtures.json_bytes(first[index]), (demo.HERE / name).read_bytes())

    def test_explicit_companion_source_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            destination = checkout / demo.EXPERIMENT
            destination.mkdir(parents=True)
            for name in self.lock["files"]:
                shutil.copyfile(self.vap_spec / demo.EXPERIMENT / name, destination / name)
            with (destination / "wallet_evidence.py").open("a", encoding="utf-8") as output:
                output.write("\n# modified after source pin\n")
            with self.assertRaisesRegex(ValueError, "source pin mismatch"):
                demo.load_companion(checkout)

    def test_only_verified_bytes_execute_despite_path_change_or_cached_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            destination = checkout / demo.EXPERIMENT
            destination.mkdir(parents=True)
            for name in self.lock["files"]:
                shutil.copyfile(self.vap_spec / demo.EXPERIMENT / name, destination / name)
            target = destination / "wallet_evidence.py"
            cached = ModuleType("wallet_evidence")
            cached.__file__ = str(target)
            cached.RESULT_SCHEMA = "unverified cached code"
            original_read = Path.read_bytes

            def read_then_change(path):
                raw = original_read(path)
                if path == target:
                    path.write_text("raise AssertionError('unverified replacement executed')\n", encoding="utf-8")
                return raw

            with mock.patch.dict(sys.modules, {"wallet_evidence": cached}):
                with mock.patch.object(Path, "read_bytes", read_then_change):
                    loaded, _ = demo.load_companion(checkout)
                self.assertIsNot(loaded, cached)
                self.assertEqual(loaded.RESULT_SCHEMA, demo.COMPANION_SCHEMA)
                self.assertTrue(callable(loaded.verify_bundle))
            self.assertIn("unverified replacement", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
