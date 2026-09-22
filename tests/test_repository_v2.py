from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from tryddc_v2.profiles.repository import run_repository_v2


class RepositoryV2Tests(unittest.TestCase):
    def make_repo(self) -> Path:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
        (root / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
        return root

    def test_repository_profile_binds_evidence_and_result(self):
        root = self.make_repo()
        manifest, result, legacy = run_repository_v2(
            root,
            frozen_at="2026-09-22T01:00:00Z",
            analysis_time="2026-09-22T01:00:01Z",
            implementation_revision="test-revision",
        )
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        self.assertEqual(result.profile_id, "software.repository.v2")
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertGreaterEqual(len(manifest.evidence), 2)
        self.assertEqual(legacy["tool_version"], "TRY-DDC-GITHUB-0.1")

    def test_repository_profile_is_deterministic_for_same_capture(self):
        root = self.make_repo()
        first, result1, _ = run_repository_v2(
            root,
            frozen_at="2026-09-22T01:00:00Z",
            analysis_time="2026-09-22T01:00:01Z",
            implementation_revision="test-revision",
        )
        second, result2, _ = run_repository_v2(
            root,
            frozen_at="2026-09-22T01:00:00Z",
            analysis_time="2026-09-22T01:00:01Z",
            implementation_revision="test-revision",
        )
        self.assertEqual(first.evidence_root, second.evidence_root)
        self.assertEqual(result1.result_digest, result2.result_digest)

    def test_high_risk_legacy_block_maps_to_high_risk_observed(self):
        root = self.make_repo()
        (root / "Dockerfile").write_text(
            "FROM scratch\nRUN echo x\n# /var/run/docker.sock\n",
            encoding="utf-8",
        )
        _manifest, result, legacy = run_repository_v2(
            root,
            frozen_at="2026-09-22T01:00:00Z",
            analysis_time="2026-09-22T01:00:01Z",
            implementation_revision="test-revision",
        )
        self.assertEqual(legacy["disposition"], "BLOCKED")
        self.assertEqual(result.risk_disposition, "HIGH_RISK_OBSERVED")

    def test_no_high_risk_requires_legacy_minimum_coverage(self):
        root = self.make_repo()
        _manifest, result, legacy = run_repository_v2(
            root,
            frozen_at="2026-09-22T01:00:00Z",
            analysis_time="2026-09-22T01:00:01Z",
            implementation_revision="test-revision",
        )
        if legacy["disposition"] == "NO_HIGH_RISK_OBSERVED":
            self.assertTrue(result.minimum_coverage_met)


if __name__ == "__main__":
    unittest.main()
