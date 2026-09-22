from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "adapter" / "ddcal_adapter.py"
_spec = importlib.util.spec_from_file_location("ddcal_adapter_v2_bridge", MODULE_PATH)
adapter = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(adapter)


class AdapterV2BridgeTests(unittest.TestCase):
    def test_v2_evm_capabilities_registered_without_write_methods(self):
        self.assertIn("blockchain.evm.contract.observe", adapter.CAPABILITIES)
        self.assertIn("blockchain.evm.transaction.observe", adapter.CAPABILITIES)
        for method in ("eth_sendTransaction", "eth_sendRawTransaction", "personal_unlockAccount"):
            self.assertNotIn(method, adapter.READONLY_RPC_METHODS)

    def test_agent_replay_report_runs_locally_and_exports_only_commitments(self):
        self.assertIn("agent.replay.report", adapter.CAPABILITIES)
        report = {
            "schema": "agent-replay.incident.v2",
            "input_sha256": "1" * 64,
            "canonical_sha256": "2" * 64,
            "event_count": 1,
            "expectation_coverage": {
                "status": "NO_EXPECTATIONS",
                "events_with_expectations": 0,
                "total_events": 1,
                "ratio": 0.0,
            },
            "timeline": [
                {
                    "event_id": "evt-1",
                    "timestamp": "2026-09-22T17:00:00Z",
                    "actor": "private-agent-label",
                    "kind": "observation",
                    "status": "UNASSESSED",
                    "parent_ids": [],
                }
            ],
            "first_provable_divergence": None,
            "divergences": [],
            "causal_chain": [],
            "attribution": [],
            "confidence": "LOW",
            "evidence_gaps": [{"type": "UNASSESSED_EVENT", "event_id": "evt-1"}],
            "evidence_completeness": "INCOMPLETE",
            "reproducibility": "NOT_TESTED",
            "reconstruction_status": "NO_DIVERGENCE_ESTABLISHED",
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / "work"
            work.mkdir()
            report_path = root / "incident.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            result = adapter.run_agent_replay_report(
                root,
                {"path": "incident.json"},
                work,
            )

        self.assertEqual(result["capability"], "agent.replay.report")
        self.assertEqual(result["status"], "COMPLETE")
        self.assertFalse(result["source_exported"])
        self.assertFalse(result["raw_report_exported"])
        self.assertFalse(result["arbitrary_tool_authority"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("private-agent-label", serialized)
        self.assertNotIn("timeline", serialized)
        self.assertTrue(str(result["result_digest"]).startswith("sha256:"))
        self.assertTrue(str(result["evidence_root"]).startswith("sha256:"))

    def test_transaction_capture_is_read_only_and_rechecks_inclusion_block(self):
        tx_hash = "0x" + "1" * 64
        block_hash = "0x" + "a" * 64
        calls = []
        tx = {
            "hash": tx_hash,
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "nonce": "0x1",
            "value": "0x0",
            "input": "0x",
            "blockNumber": "0x10",
            "blockHash": block_hash,
        }
        receipt = {
            "transactionHash": tx_hash,
            "blockNumber": "0x10",
            "blockHash": block_hash,
            "transactionIndex": "0x0",
            "status": "0x1",
            "gasUsed": "0x5208",
            "contractAddress": None,
            "logs": [],
        }
        block = {
            "number": "0x10",
            "hash": block_hash,
            "parentHash": "0x" + "b" * 64,
            "timestamp": "0x1234",
        }

        def fake_rpc(_url, method, params, request_id):
            calls.append((method, params, request_id))
            if method == "eth_chainId":
                return {"ok": True, "result": "0x1"}
            if method == "eth_getTransactionByHash":
                return {"ok": True, "result": tx}
            if method == "eth_getTransactionReceipt":
                return {"ok": True, "result": receipt}
            if method == "eth_getBlockByNumber":
                return {"ok": True, "result": block}
            raise AssertionError(method)

        original = adapter._rpc_request
        adapter._rpc_request = fake_rpc
        try:
            result = adapter.run_evm_transaction_observe(
                Path("."),
                {"rpc_url": "https://rpc.example", "transaction_hash": tx_hash},
                Path("."),
            )
        finally:
            adapter._rpc_request = original

        self.assertEqual(result["status"], "COMPLETE")
        self.assertFalse(result["transaction_signing_authority"])
        self.assertFalse(result["transaction_broadcast_authority"])
        self.assertFalse(result["private_key_authority"])
        self.assertFalse(result["arbitrary_rpc_authority"])
        methods = [method for method, _params, _request_id in calls]
        self.assertEqual(methods.count("eth_getBlockByNumber"), 2)
        self.assertFalse(any(method.startswith("eth_send") for method in methods))


if __name__ == "__main__":
    unittest.main()
