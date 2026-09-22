from __future__ import annotations

import unittest

from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.evm_transaction import analyze_observation, normalize_tx_hash


TX = "0x" + "1" * 64
BLOCK_HASH = "0x" + "a" * 64


class EVMTransactionV1Tests(unittest.TestCase):
    def observation(self):
        tx = {
            "hash": TX,
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "nonce": "0x1",
            "value": "0x0",
            "input": "0xabcdef",
            "blockNumber": "0x10",
            "blockHash": BLOCK_HASH,
        }
        receipt = {
            "transactionHash": TX,
            "blockNumber": "0x10",
            "blockHash": BLOCK_HASH,
            "transactionIndex": "0x0",
            "status": "0x1",
            "gasUsed": "0x5208",
            "contractAddress": None,
            "logs": [],
        }
        block = {
            "number": "0x10",
            "hash": BLOCK_HASH,
            "parentHash": "0x" + "b" * 64,
            "timestamp": "0x1234",
        }
        return {
            "chain_id": "0x1",
            "transaction_hash": TX,
            "transaction": tx,
            "receipt": receipt,
            "block_before": dict(block),
            "block_after": dict(block),
            "rpc_origin": "rpc.example",
            "finality_state": "UNRESOLVED",
        }

    def test_hash_validation(self):
        self.assertEqual(normalize_tx_hash(TX.upper().replace("0X", "0x")), TX)
        with self.assertRaisesRegex(ValidationError, "invalid-evm-transaction-hash"):
            normalize_tx_hash("0x1234")

    def test_success_receipt_establishes_inclusion_not_downstream_consequence(self):
        manifest, result = analyze_observation(
            self.observation(),
            captured_at="2026-09-22T16:00:00Z",
            analysis_time="2026-09-22T16:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        kinds = {d["kind"]: d for d in result.determinations}
        self.assertEqual(kinds["transaction.inclusion"]["status"], "ESTABLISHED")
        self.assertEqual(kinds["transaction.protocol_execution"]["status"], "ESTABLISHED")
        self.assertEqual(kinds["transaction.downstream_consequence"]["status"], "UNRESOLVED")
        execution = [o for o in result.observations if o["kind"] == "evm.transaction.execution"][0]
        self.assertEqual(execution["protocol_execution_status"], "SUCCESS")

    def test_reverted_receipt_is_not_reported_as_success(self):
        obs = self.observation()
        obs["receipt"]["status"] = "0x0"
        _manifest, result = analyze_observation(
            obs,
            captured_at="2026-09-22T16:00:00Z",
            analysis_time="2026-09-22T16:00:01Z",
            implementation_revision="test",
        )
        execution = [o for o in result.observations if o["kind"] == "evm.transaction.execution"][0]
        self.assertEqual(execution["protocol_execution_status"], "REVERTED")
        downstream = [d for d in result.determinations if d["kind"] == "transaction.downstream_consequence"][0]
        self.assertEqual(downstream["status"], "UNRESOLVED")

    def test_pending_transaction_does_not_establish_inclusion(self):
        obs = self.observation()
        obs["transaction"]["blockNumber"] = None
        obs["transaction"]["blockHash"] = None
        obs["receipt"] = None
        obs["block_before"] = None
        obs["block_after"] = None
        _manifest, result = analyze_observation(
            obs,
            captured_at="2026-09-22T16:00:00Z",
            analysis_time="2026-09-22T16:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "COMPLETE")
        inclusion = [d for d in result.determinations if d["kind"] == "transaction.inclusion"][0]
        self.assertEqual(inclusion["status"], "NOT_ESTABLISHED")

    def test_missing_transaction_is_incomplete(self):
        obs = self.observation()
        obs["transaction"] = None
        obs["receipt"] = None
        obs["block_before"] = None
        obs["block_after"] = None
        _manifest, result = analyze_observation(
            obs,
            captured_at="2026-09-22T16:00:00Z",
            analysis_time="2026-09-22T16:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "INCOMPLETE")
        self.assertEqual(result.evidentiary_status, "NOT_ESTABLISHED")

    def test_inconsistent_block_binding_fails_closed(self):
        obs = self.observation()
        obs["block_after"]["hash"] = "0x" + "c" * 64
        _manifest, result = analyze_observation(
            obs,
            captured_at="2026-09-22T16:00:00Z",
            analysis_time="2026-09-22T16:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")
        inclusion = [d for d in result.determinations if d["kind"] == "transaction.inclusion"][0]
        self.assertEqual(inclusion["status"], "CONTRADICTED")


if __name__ == "__main__":
    unittest.main()
