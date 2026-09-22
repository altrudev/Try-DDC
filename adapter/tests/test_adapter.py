import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "ddcal_adapter.py"
spec = importlib.util.spec_from_file_location("ddcal_adapter", MODULE_PATH)
adapter = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(adapter)


class AdapterTests(unittest.TestCase):
    def plan(self):
        return {
            "schema": "ddcal.assessment-plan.v1",
            "job_id": "ddcal_job_test12345678",
            "profile_id": "ddcal.repo.private.v1",
            "expires_unix": int(time.time()) + 600,
            "target": {"kind": "registered-local-root", "label": "test"},
            "capabilities": [
                {"id": "filesystem.manifest", "params": {"paths": ["."]}}
            ],
            "export_policy": {"allow_source": False, "max_excerpt_bytes": 0},
        }

    def test_valid_plan(self):
        adapter.validate_plan(self.plan())

    def test_unknown_capability_blocks(self):
        plan = self.plan()
        plan["capabilities"] = [{"id": "shell.execute", "params": {"command": "id"}}]
        with self.assertRaises(SystemExit):
            adapter.validate_plan(plan)

    def test_source_export_blocks(self):
        plan = self.plan()
        plan["export_policy"]["allow_source"] = True
        with self.assertRaises(SystemExit):
            adapter.validate_plan(plan)

    def test_expired_plan_blocks(self):
        plan = self.plan()
        plan["expires_unix"] = int(time.time()) - 1
        with self.assertRaises(SystemExit):
            adapter.validate_plan(plan)

    def test_path_escape_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            root.mkdir()
            outside = Path(td) / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            with self.assertRaises(SystemExit):
                adapter.ensure_within(root, root / ".." / "outside.txt")

    def test_manifest_exports_hashes_not_contents(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "private.txt").write_text("CUSTOMER_SECRET_VALUE", encoding="utf-8")
            result = adapter.run_filesystem_manifest(root, {"paths": ["."]}, root / "work")
            self.assertEqual(result["source_exported"], False)
            self.assertEqual(result["files"], 1)
            serialized = json.dumps(result)
            self.assertNotIn("CUSTOMER_SECRET_VALUE", serialized)
            self.assertIn("sha256", result["records"][0])

    def test_rpc_write_methods_are_not_allowlisted(self):
        for method in ("eth_sendTransaction", "eth_sendRawTransaction", "personal_unlockAccount"):
            self.assertNotIn(method, adapter.READONLY_RPC_METHODS)

    def test_evm_contract_capability_is_registered_and_read_only(self):
        self.assertIn("blockchain.evm.contract.observe", adapter.CAPABILITIES)
        for method in ("eth_sendTransaction", "eth_sendRawTransaction", "personal_unlockAccount"):
            self.assertNotIn(method, adapter.READONLY_RPC_METHODS)

    def test_evm_contract_capture_pins_reads_and_rechecks_anchor(self):
        calls = []
        block = {
            "number": "0x10",
            "hash": "0x" + "a" * 64,
            "parentHash": "0x" + "b" * 64,
            "timestamp": "0x1234",
        }
        storage_zero = "0x" + "0" * 64

        def fake_rpc(_url, method, params, request_id):
            calls.append((method, params, request_id))
            if method == "eth_chainId":
                return {"ok": True, "result": "0x1"}
            if method == "eth_getBlockByNumber":
                return {"ok": True, "result": dict(block)}
            if method == "eth_getCode":
                return {"ok": True, "result": "0x6001600055"}
            if method == "eth_getStorageAt":
                return {"ok": True, "result": storage_zero}
            raise AssertionError(method)

        original = adapter._rpc_request
        adapter._rpc_request = fake_rpc
        try:
            result = adapter.run_evm_contract_observe(
                Path("."),
                {
                    "rpc_url": "https://rpc.example",
                    "address": "0x1111111111111111111111111111111111111111",
                    "block_tag": "latest",
                },
                Path("."),
            )
        finally:
            adapter._rpc_request = original

        self.assertEqual(result["status"], "COMPLETE")
        self.assertFalse(result["transaction_signing_authority"])
        self.assertFalse(result["private_key_authority"])
        self.assertFalse(result["arbitrary_rpc_authority"])

        pinned_reads = [
            params
            for method, params, _request_id in calls
            if method in {"eth_getCode", "eth_getStorageAt"}
        ]
        self.assertTrue(pinned_reads)
        self.assertTrue(all(params[-1] == "0x10" for params in pinned_reads))
        block_calls = [params for method, params, _request_id in calls if method == "eth_getBlockByNumber"]
        self.assertEqual(block_calls[0], ["latest", False])
        self.assertEqual(block_calls[-1], ["0x10", False])


if __name__ == "__main__":
    unittest.main()
