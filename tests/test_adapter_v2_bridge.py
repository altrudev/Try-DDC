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

    def test_bitcoin_observer_uses_read_only_methods_and_never_wallet_or_broadcast(self):
        self.assertIn("blockchain.bitcoin.transaction.observe", adapter.CAPABILITIES)
        calls = []
        txid = "1" * 64
        block = "2" * 64

        def fake_rpc(_url, method, params, request_id):
            calls.append((method, params, request_id))
            if method == "getblockchaininfo":
                return {"ok": True, "result": {"chain": "main", "blocks": 900006, "bestblockhash": "7" * 64}}
            if method == "getrawtransaction":
                return {"ok": True, "result": {
                    "txid": txid,
                    "hash": "5" * 64,
                    "version": 2,
                    "size": 222,
                    "vsize": 141,
                    "weight": 564,
                    "locktime": 0,
                    "vin": [],
                    "vout": [],
                    "blockhash": block,
                    "confirmations": 7,
                }}
            if method == "getblockheader":
                return {"ok": True, "result": {
                    "hash": block,
                    "height": 900000,
                    "previousblockhash": "3" * 64,
                    "merkleroot": "4" * 64,
                    "time": 1790090000,
                    "confirmations": 7,
                }}
            raise AssertionError(method)

        original = adapter._bitcoin_rpc_request
        adapter._bitcoin_rpc_request = fake_rpc
        try:
            result = adapter.run_bitcoin_transaction_observe(
                Path("."),
                {"rpc_url": "https://bitcoin.example", "transaction_id": txid},
                Path("."),
            )
        finally:
            adapter._bitcoin_rpc_request = original

        self.assertEqual(result["status"], "COMPLETE")
        self.assertFalse(result["transaction_signing_authority"])
        self.assertFalse(result["transaction_broadcast_authority"])
        self.assertFalse(result["private_key_authority"])
        self.assertFalse(result["wallet_authority"])
        self.assertFalse(result["arbitrary_rpc_authority"])
        methods = [item[0] for item in calls]
        self.assertEqual(methods, ["getblockchaininfo", "getrawtransaction", "getblockheader", "getblockheader"])
        self.assertFalse(any(method in methods for method in ("sendrawtransaction", "signrawtransactionwithwallet", "walletpassphrase")))

    def test_bitcoin_provider_missing_tx_is_not_global_nonexistence(self):
        txid = "1" * 64

        def fake_rpc(_url, method, params, request_id):
            if method == "getblockchaininfo":
                return {"ok": True, "result": {"chain": "main", "blocks": 1, "bestblockhash": "7" * 64}}
            if method == "getrawtransaction":
                return {"ok": False, "status": "RPC_ERROR", "rpc_error_code": -5}
            raise AssertionError(method)

        original = adapter._bitcoin_rpc_request
        adapter._bitcoin_rpc_request = fake_rpc
        try:
            result = adapter.run_bitcoin_transaction_observe(
                Path("."),
                {"rpc_url": "https://bitcoin.example", "transaction_id": txid},
                Path("."),
            )
        finally:
            adapter._bitcoin_rpc_request = original

        self.assertEqual(result["status"], "COMPLETE")
        self.assertIsNone(result["observation"]["transaction"])

    def test_mcp_observer_uses_only_discovery_and_list_methods(self):
        self.assertIn("protocol.mcp.observe", adapter.CAPABILITIES)
        calls = []

        def fake_rpc(_endpoint, method, params, request_id):
            calls.append((method, params, request_id))
            if method == "server/discover":
                return {
                    "ok": True,
                    "result": {
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                        "_meta": {
                            "io.modelcontextprotocol/serverInfo": {
                                "name": "fixture",
                                "version": "1.0",
                            }
                        },
                    },
                    "headers": {},
                    "http_protocol": 11,
                }
            if method == "tools/list":
                return {"ok": True, "result": {"tools": [{"name": "lookup", "inputSchema": {"type": "object"}}]}}
            if method == "resources/list":
                return {"ok": True, "result": {"resources": [{"uri": "resource://one", "name": "one"}]}}
            if method == "prompts/list":
                return {"ok": True, "result": {"prompts": [{"name": "summary", "arguments": []}]}}
            raise AssertionError(method)

        original_rpc = adapter._mcp_rpc
        original_tls = adapter._mcp_tls_certificate_sha256
        adapter._mcp_rpc = fake_rpc
        adapter._mcp_tls_certificate_sha256 = lambda _endpoint: "sha256:" + "a" * 64
        try:
            result = adapter.run_mcp_observe(
                Path("."),
                {"endpoint": "https://mcp.example/api", "max_pages": 5},
                Path("."),
            )
        finally:
            adapter._mcp_rpc = original_rpc
            adapter._mcp_tls_certificate_sha256 = original_tls

        self.assertEqual(result["status"], "COMPLETE")
        self.assertFalse(result["tool_invocation_authority"])
        self.assertFalse(result["prompt_invocation_authority"])
        self.assertFalse(result["resource_read_authority"])
        self.assertFalse(result["arbitrary_rpc_authority"])
        methods = [x[0] for x in calls]
        self.assertEqual(methods, ["server/discover", "tools/list", "resources/list", "prompts/list"])
        self.assertFalse(any(method.endswith("/call") for method in methods))
        self.assertTrue(result["snapshot"]["observation_complete"])
        self.assertFalse(result["snapshot"]["transport"]["redirect_followed"])

    def test_mcp_partial_inventory_fails_capture(self):
        calls = []

        def fake_rpc(_endpoint, method, params, request_id):
            calls.append(method)
            if method == "server/discover":
                return {
                    "ok": True,
                    "result": {
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": {"tools": {}},
                    },
                    "headers": {},
                }
            if method == "tools/list":
                return {"ok": False, "status": "TRANSPORT_UNAVAILABLE"}
            raise AssertionError(method)

        original_rpc = adapter._mcp_rpc
        adapter._mcp_rpc = fake_rpc
        try:
            result = adapter.run_mcp_observe(
                Path("."),
                {"endpoint": "https://mcp.example/api"},
                Path("."),
            )
        finally:
            adapter._mcp_rpc = original_rpc

        self.assertEqual(result["status"], "CAPTURE_FAILED")
        self.assertEqual(result["failed_inventory"], "tools")

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
