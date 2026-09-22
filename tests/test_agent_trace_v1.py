from __future__ import annotations

import unittest

from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.agent_trace import analyze_agent_replay


class AgentTraceV1Tests(unittest.TestCase):
    def generic(self):
        return {
            "schema": "agent-replay.incident.v2",
            "input_sha256": "1" * 64,
            "canonical_sha256": "2" * 64,
            "event_count": 3,
            "expectation_coverage": {"status": "PARTIAL", "events_with_expectations": 2, "total_events": 3, "ratio": 0.666667},
            "timeline": [
                {"event_id": "a", "timestamp": "2026-09-22T17:00:00Z", "actor": "agent", "kind": "intent", "status": "VALID", "parent_ids": []},
                {"event_id": "b", "timestamp": "2026-09-22T17:00:01Z", "actor": "agent", "kind": "decision", "status": "DIVERGENT", "parent_ids": ["a"]},
                {"event_id": "c", "timestamp": "2026-09-22T17:00:02Z", "actor": "agent", "kind": "retry", "status": "UNASSESSED", "parent_ids": ["a"]},
            ],
            "first_provable_divergence": {"event_id": "b"},
            "divergences": [{"event_id": "b", "field": "route"}],
            "causal_chain": [{"from": "a", "to": "b"}],
            "attribution": {},
            "confidence": {},
            "evidence_gaps": [{"kind": "downstream-effect"}],
            "evidence_completeness": "INCOMPLETE",
            "reconstruction_status": "DIVERGENCE_RECONSTRUCTED",
        }

    def aps(self):
        return {
            "schema": "agent-replay.aps-authority-reconstruction.v2",
            "input_sha256": "3" * 64,
            "adapter_validation": {"revision": "1f4db7a12e8ddf8853c2533f08f8252f7efbe326"},
            "external_conformance": {"fixture": "pass", "outcome": "allowed"},
            "identity": {
                "claimed_actor": "agent-a",
                "intent_issuer": "agent-a",
                "intent_signer": "agent-a",
                "intent_signature_assessment": "CLAIMED_SIGNER_CONSISTENT",
                "independent_authentication": "NOT_VERIFIED",
            },
            "authority": {
                "root_principal": "principal",
                "delegation_path": [{"delegation_id": "d1"}],
                "structural_binding": "COMPLETE",
                "independent_cryptographic_verification": "NOT_VERIFIED",
            },
            "policy": {
                "issuer": "gateway",
                "signer": "gateway",
                "verdict": "permit",
                "reason": "ok",
                "independent_authentication": "NOT_VERIFIED",
            },
            "binding": {
                "status": "COMPLETE",
                "checks": {"action_ref": True, "receipt_link": True, "delegation_ref": True, "delegation_chain": True},
            },
            "execution": {
                "status": "EXECUTION_EVIDENCE_BOUND_TO_ACTION",
                "events": [{"action_ref": "x"}],
                "bound_events": [{"action_ref": "x"}],
                "partially_bound_events": [],
                "unbound_events": [],
                "malformed_event_count": 0,
                "independent_authentication": "NOT_VERIFIED",
                "external_effect_proof": False,
            },
            "observed_execution": [{"action_ref": "x"}],
            "execution_status": "EXECUTION_EVIDENCE_BOUND_TO_ACTION",
            "evidence_boundary": {
                "permit_is_execution": False,
                "external_conformance_is_replay_verification": False,
                "independent_crypto_verification_performed": False,
                "claims": [],
            },
        }

    def test_generic_preserves_branching_and_divergence(self):
        manifest, result = analyze_agent_replay(
            self.generic(),
            captured_at="2026-09-22T17:10:00Z",
            analysis_time="2026-09-22T17:10:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        branch = [o for o in result.observations if o["kind"] == "agent.replay.branch-structure"][0]
        self.assertEqual(branch["branch_points"], ["a"])
        self.assertEqual(len(result.contradictions), 1)
        self.assertTrue(any(x["kind"] == "replay.evidence-gap" for x in result.unresolved))

    def test_generic_does_not_promote_chronology_to_causality(self):
        _manifest, result = analyze_agent_replay(
            self.generic(),
            captured_at="2026-09-22T17:10:00Z",
            analysis_time="2026-09-22T17:10:01Z",
            implementation_revision="test",
        )
        self.assertFalse(result.synthesis["chronology_is_causality"])

    def test_dangling_parent_is_contradicted_not_silently_dropped(self):
        report = self.generic()
        report["timeline"][2]["parent_ids"] = ["missing"]
        _manifest, result = analyze_agent_replay(
            report,
            captured_at="2026-09-22T17:10:00Z",
            analysis_time="2026-09-22T17:10:01Z",
            implementation_revision="test",
        )
        continuity = [d for d in result.determinations if d["kind"] == "replay.parent-continuity"][0]
        self.assertEqual(continuity["status"], "CONTRADICTED")

    def test_aps_keeps_authority_execution_and_effect_separate(self):
        _manifest, result = analyze_agent_replay(
            self.aps(),
            captured_at="2026-09-22T17:10:00Z",
            analysis_time="2026-09-22T17:10:01Z",
            implementation_revision="test",
        )
        kinds = {d["kind"]: d for d in result.determinations}
        self.assertEqual(kinds["agent.structural-binding"]["status"], "ESTABLISHED")
        self.assertEqual(kinds["agent.execution-boundary"]["status"], "PARTIALLY_ESTABLISHED")
        self.assertEqual(kinds["agent.downstream-consequence"]["status"], "UNRESOLVED")
        self.assertTrue(any(x["kind"] == "actor-authentication" for x in result.unresolved))

    def test_aps_rejects_permit_equals_execution_boundary(self):
        report = self.aps()
        report["evidence_boundary"]["permit_is_execution"] = True
        with self.assertRaisesRegex(ValidationError, "permit-execution-boundary-invalid"):
            analyze_agent_replay(
                report,
                captured_at="2026-09-22T17:10:00Z",
                analysis_time="2026-09-22T17:10:01Z",
                implementation_revision="test",
            )

    def test_unsupported_replay_schema_rejected(self):
        report = self.generic()
        report["schema"] = "agent-replay.future.v99"
        with self.assertRaisesRegex(ValidationError, "unsupported-agent-replay-schema"):
            analyze_agent_replay(
                report,
                captured_at="2026-09-22T17:10:00Z",
                analysis_time="2026-09-22T17:10:01Z",
                implementation_revision="test",
            )


if __name__ == "__main__":
    unittest.main()
