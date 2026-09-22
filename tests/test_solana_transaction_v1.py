from __future__ import annotations

import unittest

from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.solana_transaction import analyze_observation


SIG = "3" * 88
GENESIS = "4" * 44
BLOCK = "5" * 44
PREV = "6" * 44


class SolanaTransactionV1Tests(unittest.TestCase):
    def included(self):
        tx = {
            "slot": 12345,
            "blockTime": 1790090000,
            "version": 0,
            "meta": {
                "err": None,
                "fee": 5000,
                "computeUnitsConsumed": 1000,
            },
            "transaction": {
                "signatures": [SIG],
                "message": {
                    "accountKeys": [],
                    "instructions": [],
                },
            },
        }
        block = {
            "blockhash": BLOCK,
            "previousBlockhash": PREV,
            "blockHeight": 12000,
            "blockTime": 1790090000,
            "signatures": [SIG],
        }
        return {
            "signature": SIG,
            "genesis_hash_before": GENESIS,
            "genesis_hash_after": GENESIS,
            "signature_status": {
                "slot": 12345,
                "confirmations": None,
                "confirmationStatus": "finalized",
                "err": None,
            },
            "transaction": tx,
            "block_slot": 12345,
            "block_before": dict(block),
            "block_after": dict(block),
            "context_commitment": "finalized",
            "context_slot_before": 13000,
            "context_slot_after": 13002,
            "rpc_origin": "solana.example",
        }

    def analyze(self, observation):
        return analyze_observation(
            observation,
            captured_at="2026-09-22T22:30:00Z",
            analysis_time="2026-09-22T22:30:01Z",
            implementation_revision="test",
        )

    def test_finalized_transaction_is_provider_mediated_not_absolute_finality(self):
        manifest, result = self.analyze(self.included())
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        determinations = {x["kind"]: x for x in result.determinations}
        self.assertEqual(determinations["solana.transaction.observed"]["status"], "ESTABLISHED")
        self.assertEqual(determinations["solana.transaction.execution"]["status"], "PARTIALLY_ESTABLISHED")
        self.assertEqual(determinations["solana.transaction.inclusion"]["status"], "PARTIALLY_ESTABLISHED")
        self.assertEqual(determinations["solana.transaction.commitment"]["status"], "PARTIALLY_ESTABLISHED")
        self.assertTrue(any("not promoted" in x for x in result.limitations))

    def test_signature_mismatch_fails_closed(self):
        value = self.included()
        value["transaction"]["transaction"]["signatures"][0] = "7" * 88
        with self.assertRaisesRegex(ValidationError, "solana-transaction-signature-mismatch"):
            self.analyze(value)

    def test_status_transaction_slot_mismatch_fails_closed(self):
        value = self.included()
        value["signature_status"]["slot"] = 12344
        with self.assertRaisesRegex(ValidationError, "solana-transaction-status-slot-mismatch"):
            self.analyze(value)

    def test_block_change_fails_capture(self):
        value = self.included()
        value["block_after"]["blockhash"] = "8" * 44
        _manifest, result = self.analyze(value)
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")
        self.assertTrue(result.contradictions)

    def test_block_signature_membership_is_required(self):
        value = self.included()
        value["block_after"]["signatures"] = ["7" * 88]
        _manifest, result = self.analyze(value)
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")
        determinations = {x["kind"]: x for x in result.determinations}
        self.assertEqual(determinations["solana.transaction.inclusion"]["status"], "CONTRADICTED")

    def test_context_must_cover_transaction_slot(self):
        value = self.included()
        value["context_slot_before"] = 12000
        value["context_slot_after"] = 12001
        _manifest, result = self.analyze(value)
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")

    def test_status_meta_error_disagreement_fails_capture(self):
        value = self.included()
        value["signature_status"]["err"] = {"InstructionError": [0, "Custom"]}
        _manifest, result = self.analyze(value)
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")
        self.assertTrue(result.contradictions)

    def test_execution_error_is_not_success(self):
        value = self.included()
        value["transaction"]["meta"]["err"] = {"InstructionError": [0, "Custom"]}
        _manifest, result = self.analyze(value)
        determinations = {x["kind"]: x for x in result.determinations}
        self.assertEqual(determinations["solana.transaction.execution"]["status"], "CONTRADICTED")

    def test_provider_absence_is_not_global_nonexistence(self):
        value = {
            "signature": SIG,
            "genesis_hash_before": GENESIS,
            "genesis_hash_after": GENESIS,
            "signature_status": None,
            "transaction": None,
            "context_commitment": "finalized",
            "context_slot_before": 13000,
            "context_slot_after": 13001,
            "rpc_origin": "solana.example",
        }
        _manifest, result = self.analyze(value)
        self.assertEqual(result.evidentiary_status, "NOT_ESTABLISHED")
        self.assertTrue(any(x["kind"] == "solana.transaction.global-existence" for x in result.unresolved))

    def test_status_without_transaction_fails_closed(self):
        value = self.included()
        value["transaction"] = None
        with self.assertRaisesRegex(ValidationError, "solana-status-transaction-presence-mismatch"):
            self.analyze(value)

    def test_genesis_change_fails_capture(self):
        value = self.included()
        value["genesis_hash_after"] = "7" * 44
        _manifest, result = self.analyze(value)
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")
        self.assertTrue(result.contradictions)

    def test_processed_status_does_not_become_positive_commitment(self):
        value = self.included()
        value["signature_status"]["confirmationStatus"] = "processed"
        value["signature_status"]["confirmations"] = 1
        value["context_commitment"] = "confirmed"
        _manifest, result = self.analyze(value)
        determinations = {x["kind"]: x for x in result.determinations}
        self.assertEqual(determinations["solana.transaction.commitment"]["status"], "UNRESOLVED")

    def test_profile_has_no_signing_submission_or_simulation_authority(self):
        _manifest, result = self.analyze(self.included())
        boundary = [x for x in result.observations if x["kind"] == "solana.authority-boundary"][0]
        self.assertFalse(boundary["private_key_accessed"])
        self.assertFalse(boundary["transaction_signed"])
        self.assertFalse(boundary["transaction_submitted"])
        self.assertFalse(boundary["transaction_simulated"])


if __name__ == "__main__":
    unittest.main()
