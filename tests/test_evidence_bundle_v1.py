from __future__ import annotations

import copy
import unittest

from tryddc_v2.canonical import sha256_digest
from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.evidence_bundle import analyze_capsule


def capsule():
    value = {
        "schema": "try-ddc-evidence-capsule/2",
        "capsule_id": "capsule:" + "a" * 32,
        "target_id": "target:" + "b" * 24,
        "nonce": "c" * 32,
        "created_at": "2026-09-22T17:00:00Z",
        "producer": {
            "product": "ddcal-adapter",
            "version": "v0.2-candidate",
            "mode": "customer-side",
        },
        "export": {
            "source_code_exported": False,
            "source_excerpts_exported": False,
            "arbitrary_shell_authority": False,
            "private_key_authority": False,
        },
        "evidence": [
            {
                "evidence_id": "evidence:capability:0001",
                "capability_id": "filesystem.manifest",
                "classification": "CUSTOMER_PRIVATE",
                "digest": "sha256:" + "1" * 64,
                "status": "COMPLETE",
            }
        ],
    }
    value["capsule_digest"] = sha256_digest(value)
    return value


class EvidenceBundleV1Tests(unittest.TestCase):
    def test_valid_capsule_freezes_commitments(self):
        manifest, result = analyze_capsule(
            capsule(),
            analysis_time="2026-09-22T17:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        self.assertEqual(result.evidentiary_status, "PARTIALLY_ESTABLISHED")
        self.assertEqual(result.determinations[0]["status"], "ESTABLISHED")
        self.assertEqual(result.determinations[1]["status"], "UNRESOLVED")
        self.assertEqual(result.capabilities[0].capability_id, "evidence.bundle.ingest")

    def test_tamper_breaks_capsule_digest(self):
        value = capsule()
        value["evidence"][0]["status"] = "CAPTURE_FAILED"
        with self.assertRaisesRegex(ValidationError, "capsule-digest-mismatch"):
            analyze_capsule(value, analysis_time="2026-09-22T17:00:01Z", implementation_revision="test")

    def test_duplicate_evidence_ids_rejected(self):
        value = capsule()
        value["evidence"].append(copy.deepcopy(value["evidence"][0]))
        unsigned = dict(value)
        unsigned.pop("capsule_digest")
        value["capsule_digest"] = sha256_digest(unsigned)
        with self.assertRaisesRegex(ValidationError, "capsule-duplicate-evidence-id"):
            analyze_capsule(value, analysis_time="2026-09-22T17:00:01Z", implementation_revision="test")

    def test_unknown_nested_producer_field_rejected(self):
        value = capsule()
        value["producer"]["secret_note"] = "must-not-pass-through"
        unsigned = dict(value)
        unsigned.pop("capsule_digest")
        value["capsule_digest"] = sha256_digest(unsigned)
        with self.assertRaisesRegex(ValidationError, "capsule-producer-unknown-field"):
            analyze_capsule(value, analysis_time="2026-09-22T17:00:01Z", implementation_revision="test")

    def test_unregistered_producer_capability_rejected(self):
        value = capsule()
        value["evidence"][0]["capability_id"] = "unknown.future.capability"
        unsigned = dict(value)
        unsigned.pop("capsule_digest")
        value["capsule_digest"] = sha256_digest(unsigned)
        with self.assertRaisesRegex(ValidationError, "capsule-unregistered-producer-capability"):
            analyze_capsule(value, analysis_time="2026-09-22T17:00:01Z", implementation_revision="test")

    def test_export_authority_must_be_false(self):
        value = capsule()
        value["export"]["private_key_authority"] = True
        unsigned = dict(value)
        unsigned.pop("capsule_digest")
        value["capsule_digest"] = sha256_digest(unsigned)
        with self.assertRaisesRegex(ValidationError, "capsule-export-private_key_authority-must-be-false"):
            analyze_capsule(value, analysis_time="2026-09-22T17:00:01Z", implementation_revision="test")

    def test_prohibited_raw_source_field_rejected(self):
        value = capsule()
        value["evidence"][0]["raw_source"] = "do-not-export"
        unsigned = dict(value)
        unsigned.pop("capsule_digest")
        value["capsule_digest"] = sha256_digest(unsigned)
        with self.assertRaisesRegex(ValidationError, "capsule-prohibited-field"):
            analyze_capsule(value, analysis_time="2026-09-22T17:00:01Z", implementation_revision="test")


if __name__ == "__main__":
    unittest.main()
