from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

from tryddc_v2.model import CapabilityIdentity, TryDDCResult
from tryddc_v2.signing import sign_result, verify_signed_result


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for Ed25519 envelope tests")
class SignedResultEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def result(self):
        cap = CapabilityIdentity(
            capability_id="software.repository.capture",
            capability_version="2",
            capability_digest="sha256:" + "1" * 64,
            implementation_revision="a" * 40,
        )
        return TryDDCResult(
            result_id="result:one",
            case_id="case:one",
            target_id="target:one",
            profile_id="software.repository.v2",
            profile_version="2",
            profile_digest="sha256:" + "2" * 64,
            evidence_root="sha256:" + "3" * 64,
            analysis_status="COMPLETE",
            evidentiary_status="PARTIALLY_ESTABLISHED",
            risk_disposition="REVIEW_REQUIRED",
            analysis_time="2026-09-22T17:00:00Z",
            capabilities=(cap,),
            result_revision=1,
        ).payload()

    def test_sign_and_verify_exact_result(self):
        result = self.result()
        envelope = sign_result(
            result,
            private_key_path=self.private,
            public_key_path=self.public,
            issued_at="2026-09-22T17:01:00Z",
        )
        self.assertTrue(verify_signed_result(envelope, public_key_path=self.public, result=result))
        self.assertEqual(envelope["algorithm"], "ed25519")
        self.assertEqual(envelope["payload"]["result_revision"], 1)
        self.assertEqual(envelope["payload"]["evidence_root"], result["capture"]["evidence_root"])
        self.assertEqual(len(envelope["payload"]["capabilities"]), 1)

    def test_result_tamper_breaks_binding(self):
        result = self.result()
        envelope = sign_result(
            result,
            private_key_path=self.private,
            public_key_path=self.public,
            issued_at="2026-09-22T17:01:00Z",
        )
        tampered = dict(result)
        tampered["risk_disposition"] = "HIGH_RISK_OBSERVED"
        self.assertFalse(verify_signed_result(envelope, public_key_path=self.public, result=tampered))

    def test_envelope_tamper_breaks_signature(self):
        result = self.result()
        envelope = sign_result(
            result,
            private_key_path=self.private,
            public_key_path=self.public,
            issued_at="2026-09-22T17:01:00Z",
        )
        envelope["payload"]["result_revision"] = 2
        self.assertFalse(verify_signed_result(envelope, public_key_path=self.public))

    def test_wrong_public_key_rejected(self):
        result = self.result()
        envelope = sign_result(
            result,
            private_key_path=self.private,
            public_key_path=self.public,
            issued_at="2026-09-22T17:01:00Z",
        )
        other_private = self.root / "other-private.pem"
        other_public = self.root / "other-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(other_private)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(other_private), "-pubout", "-out", str(other_public)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertFalse(verify_signed_result(envelope, public_key_path=other_public, result=result))

    def test_semantics_do_not_claim_certification(self):
        result = self.result()
        envelope = sign_result(
            result,
            private_key_path=self.private,
            public_key_path=self.public,
            issued_at="2026-09-22T17:01:00Z",
        )
        excluded = envelope["payload"]["semantics"]["signature_does_not_establish"]
        self.assertIn("certification", excluded)
        self.assertIn("accreditation", excluded)
        self.assertIn("authorization-to-execute", excluded)


if __name__ == "__main__":
    unittest.main()
