from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

from tryddc_v2.profiles.evidence_bundle import analyze_capsule


MODULE_PATH = Path(__file__).resolve().parents[1] / "adapter" / "ddcal_adapter.py"
_spec = importlib.util.spec_from_file_location("ddcal_adapter_bundle_bridge", MODULE_PATH)
adapter = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(adapter)


class EvidenceBundleAdapterBridgeTests(unittest.TestCase):
    def plan(self):
        return {
            "schema": "ddcal.assessment-plan.v1",
            "job_id": "ddcal_job_bundlebridge01",
            "profile_id": "ddcal.repo.private.v1",
            "expires_unix": 4102444800,
            "target": {"kind": "registered-local-root", "label": "private-target"},
            "capabilities": [{"id": "filesystem.manifest", "params": {"paths": ["."]}}],
            "export_policy": {"allow_source": False, "max_excerpt_bytes": 0},
        }

    def test_adapter_v2_capsule_is_digest_only_and_ingestable(self):
        secret = "CUSTOMER_SOURCE_SHOULD_NOT_LEAVE_BOUNDARY"
        results = [{
            "capability": "filesystem.manifest",
            "status": "COMPLETE",
            "files": 1,
            "truncated": False,
            "manifest_sha256": "1" * 64,
            "records": [{"path": "private.py", "size": len(secret), "sha256": "2" * 64}],
            "debug_private_value": secret,
            "source_exported": False,
        }]
        capsule = adapter.build_v2_capsule(self.plan(), results)
        serialized = json.dumps(capsule, sort_keys=True)

        self.assertNotIn(secret, serialized)
        self.assertNotIn("private.py", serialized)
        self.assertFalse(capsule["export"]["raw_capability_payloads_exported"])
        self.assertEqual(capsule["evidence"][0]["classification"], "CUSTOMER_PRIVATE")
        self.assertTrue(capsule["evidence"][0]["digest"].startswith("sha256:"))

        manifest, result = analyze_capsule(
            capsule,
            analysis_time="2026-09-22T17:10:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)

    def test_capsules_are_nonce_and_id_distinct(self):
        results = [{
            "capability": "filesystem.manifest",
            "status": "COMPLETE",
            "files": 0,
            "truncated": False,
            "manifest_sha256": "0" * 64,
            "records": [],
            "source_exported": False,
        }]
        first = adapter.build_v2_capsule(self.plan(), results)
        second = adapter.build_v2_capsule(self.plan(), results)
        self.assertNotEqual(first["capsule_id"], second["capsule_id"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertEqual(first["target_id"], second["target_id"])

    def test_public_protocol_capability_remains_commitment_only(self):
        results = [{
            "capability": "blockchain.evm.transaction.observe",
            "status": "COMPLETE",
            "observation": {"transaction_hash": "0x" + "1" * 64, "sensitive_note": "DO_NOT_EXPORT_RAW"},
            "transaction_signing_authority": False,
            "transaction_broadcast_authority": False,
        }]
        capsule = adapter.build_v2_capsule(self.plan(), results)
        serialized = json.dumps(capsule, sort_keys=True)
        self.assertEqual(capsule["evidence"][0]["classification"], "PUBLIC")
        self.assertNotIn("DO_NOT_EXPORT_RAW", serialized)
        self.assertNotIn("transaction_hash", serialized)


if __name__ == "__main__":
    unittest.main()
