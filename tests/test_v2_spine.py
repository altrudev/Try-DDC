from __future__ import annotations

import unittest

from tryddc_v2.activity import aggregate_activity
from tryddc_v2.canonical import sha256_digest
from tryddc_v2.model import (
    ActivityReceipt,
    CapabilityIdentity,
    EvidenceItem,
    EvidenceManifest,
    TryDDCResult,
    ValidationError,
)


CAP = CapabilityIdentity(
    capability_id="software.repository.capture",
    capability_version="2",
    capability_digest="sha256:" + "1" * 64,
    implementation_revision="c7447949a04493f73d4eb0897e141e912fa98cc5",
)


class SpineTests(unittest.TestCase):
    def evidence(self, *, evidence_id="evidence:one", target_id="target:one"):
        return EvidenceItem(
            evidence_id=evidence_id,
            target_id=target_id,
            source_class="PROTOCOL_OBSERVATION",
            capture_capability=CAP,
            digest="sha256:" + "2" * 64,
            captured_at="2026-09-21T23:00:00Z",
            source_identity="github",
            freshness_status="ESTABLISHED",
            reachability="ESTABLISHED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
        )

    def test_manifest_root_is_deterministic(self):
        manifest = EvidenceManifest(
            case_id="case:one",
            target_id="target:one",
            profile_id="software.repository.v2",
            profile_version="2",
            profile_digest="sha256:" + "3" * 64,
            capture_revision=1,
            evidence=(self.evidence(),),
            frozen_at="2026-09-21T23:01:00Z",
        )
        self.assertEqual(manifest.evidence_root, sha256_digest(manifest.payload()))
        self.assertTrue(manifest.evidence_root.startswith("sha256:"))

    def test_cross_target_evidence_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "cross-target-evidence"):
            EvidenceManifest(
                case_id="case:one",
                target_id="target:one",
                profile_id="software.repository.v2",
                profile_version="2",
                profile_digest="sha256:" + "3" * 64,
                capture_revision=1,
                evidence=(self.evidence(target_id="target:other"),),
                frozen_at="2026-09-21T23:01:00Z",
            )

    def test_derived_evidence_requires_provenance(self):
        with self.assertRaisesRegex(ValidationError, "derived-evidence-missing-provenance"):
            EvidenceItem(
                evidence_id="evidence:derived",
                target_id="target:one",
                source_class="DERIVED",
                capture_capability=CAP,
                digest="sha256:" + "4" * 64,
                captured_at="2026-09-21T23:00:00Z",
            )

    def test_secret_prohibited_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "secret-prohibited"):
            EvidenceItem(
                evidence_id="evidence:secret",
                target_id="target:one",
                source_class="USER_SUPPLIED",
                capture_capability=CAP,
                digest="sha256:" + "5" * 64,
                captured_at="2026-09-21T23:00:00Z",
                classification="SECRET_PROHIBITED",
            )

    def test_no_high_risk_requires_complete_minimum_coverage(self):
        with self.assertRaisesRegex(ValidationError, "no-high-risk-without-minimum-coverage"):
            TryDDCResult(
                result_id="result:one",
                case_id="case:one",
                target_id="target:one",
                profile_id="software.repository.v2",
                profile_version="2",
                profile_digest="sha256:" + "3" * 64,
                evidence_root="sha256:" + "6" * 64,
                analysis_status="COMPLETE",
                evidentiary_status="PARTIALLY_ESTABLISHED",
                risk_disposition="NO_HIGH_RISK_OBSERVED",
                analysis_time="2026-09-21T23:02:00Z",
                minimum_coverage_met=False,
            )

    def test_incomplete_run_can_only_require_review_or_high_risk(self):
        result = TryDDCResult(
            result_id="result:two",
            case_id="case:one",
            target_id="target:one",
            profile_id="software.repository.v2",
            profile_version="2",
            profile_digest="sha256:" + "3" * 64,
            evidence_root="sha256:" + "6" * 64,
            analysis_status="RATE_LIMITED",
            evidentiary_status="UNRESOLVED",
            risk_disposition="REVIEW_REQUIRED",
            analysis_time="2026-09-21T23:02:00Z",
        )
        self.assertEqual(result.analysis_status, "RATE_LIMITED")

    def test_activity_snapshot_suppresses_low_volume_counts(self):
        receipts = [
            ActivityReceipt(
                event_id=f"event:{i}",
                capability=CAP,
                analysis_status="COMPLETE",
                risk_disposition="REVIEW_REQUIRED",
                time_bucket="2026-09-21",
            )
            for i in range(3)
        ]
        snapshot = aggregate_activity(
            receipts,
            generated_at="2026-09-21T23:03:00Z",
            privacy_threshold=5,
        )
        self.assertEqual(snapshot["capabilities"][0]["runs"], "<5")
        self.assertEqual(snapshot["capabilities"][0]["completed"], "<5")
        self.assertIn("snapshot_digest", snapshot)

    def test_activity_snapshot_separates_versions(self):
        cap2 = CapabilityIdentity(
            capability_id=CAP.capability_id,
            capability_version="3",
            capability_digest="sha256:" + "7" * 64,
            implementation_revision="future",
        )
        receipts = []
        for i in range(5):
            receipts.append(ActivityReceipt(
                event_id=f"event:a{i}",
                capability=CAP,
                analysis_status="COMPLETE",
                risk_disposition="REVIEW_REQUIRED",
                time_bucket="2026-09-21",
            ))
            receipts.append(ActivityReceipt(
                event_id=f"event:b{i}",
                capability=cap2,
                analysis_status="COMPLETE",
                risk_disposition="REVIEW_REQUIRED",
                time_bucket="2026-09-21",
            ))
        snapshot = aggregate_activity(receipts, generated_at="2026-09-21T23:03:00Z")
        self.assertEqual(len(snapshot["capabilities"]), 2)


if __name__ == "__main__":
    unittest.main()
