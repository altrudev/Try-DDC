from __future__ import annotations

import unittest

from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.bitcoin_transaction import analyze_observation


class BitcoinTransactionV1Tests(unittest.TestCase):
    def included(self):
        txid = "1" * 64
        block = "2" * 64
        prev = "3" * 64
        merkle = "4" * 64
        header = {
            "hash": block,
            "height": 900000,
            "previousblockhash": prev,
            "merkleroot": merkle,
            "time": 1790090000,
            "confirmations": 7,
        }
        return {
            "network": "main",
            "transaction_id": txid,
            "transaction": {
                "txid": txid,
                "hash": "5" * 64,
                "version": 2,
                "size": 222,
                "vsize": 141,
                "weight": 564,
                "locktime": 0,
                "vin": [{"txid": "6" * 64, "vout": 0}],
                "vout": [{"value": 0.001, "n": 0}],
                "blockhash": block,
                "confirmations": 7,
            },
            "block_header_before": dict(header),
            "block_header_after": dict(header),
            "best_block_hash": "7" * 64,
            "best_block_height": 900006,
            "rpc_origin": "bitcoin.example",
        }

    def analyze(self, observation):
        return analyze_observation(
            observation,
            captured_at="2026-09-22T22:00:00Z",
            analysis_time="2026-09-22T22:00:01Z",
            implementation_revision="test",
        )

    def test_included_transaction_binds_stable_block_header(self):
        manifest, result = self.analyze(self.included())
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        determinations = {x["kind"]: x for x in result.determinations}
        self.assertEqual(determinations["bitcoin.transaction.observed"]["status"], "ESTABLISHED")
        self.assertEqual(determinations["bitcoin.transaction.inclusion"]["status"], "PARTIALLY_ESTABLISHED")
        self.assertEqual(determinations["bitcoin.transaction.confirmations"]["status"], "PARTIALLY_ESTABLISHED")

    def test_transaction_id_mismatch_fails_closed(self):
        value = self.included()
        value["transaction"]["txid"] = "9" * 64
        with self.assertRaisesRegex(ValidationError, "bitcoin-transaction-id-mismatch"):
            self.analyze(value)

    def test_header_change_fails_capture(self):
        value = self.included()
        value["block_header_after"]["merkleroot"] = "8" * 64
        _manifest, result = self.analyze(value)
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")
        self.assertEqual(result.evidentiary_status, "UNRESOLVED")
        self.assertTrue(result.contradictions)

    def test_unconfirmed_transaction_is_not_inclusion_or_mempool_proof(self):
        value = self.included()
        value["transaction"].pop("blockhash")
        value["transaction"]["confirmations"] = 0
        value["block_header_before"] = None
        value["block_header_after"] = None
        _manifest, result = self.analyze(value)
        determinations = {x["kind"]: x for x in result.determinations}
        self.assertEqual(determinations["bitcoin.transaction.inclusion"]["status"], "NOT_ESTABLISHED")
        self.assertTrue(any(x["kind"] == "bitcoin.mempool-state" for x in result.unresolved))

    def test_provider_absence_is_not_global_nonexistence(self):
        value = {
            "network": "main",
            "transaction_id": "1" * 64,
            "transaction": None,
            "rpc_origin": "bitcoin.example",
        }
        _manifest, result = self.analyze(value)
        self.assertEqual(result.evidentiary_status, "NOT_ESTABLISHED")
        self.assertTrue(any(x["kind"] == "bitcoin.transaction.global-existence" for x in result.unresolved))

    def test_profile_has_no_signing_or_broadcast_authority(self):
        _manifest, result = self.analyze(self.included())
        boundary = [x for x in result.observations if x["kind"] == "bitcoin.authority-boundary"][0]
        self.assertFalse(boundary["private_key_accessed"])
        self.assertFalse(boundary["transaction_signed"])
        self.assertFalse(boundary["transaction_broadcast"])


if __name__ == "__main__":
    unittest.main()
