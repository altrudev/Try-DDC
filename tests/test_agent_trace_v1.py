from __future__ import annotations

import unittest

from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.agent_trace import (
    AGENT_REPLAY_VALIDATED_REVISION,
    AGENT_REPLAY_VALIDATED_VERSION,
    analyze_agent_replay_report,
)


class AgentTraceV1Tests(unittest.TestCase):
    def incident(self):
        return {
            "schema": "agent-replay.incident.v2",
            "input_sha256": "1" * 64,
            "canonical_sha256": "2" * 64,
            "event_count": 4,
            "expectation_coverage": {
                "status": "PARTIAL",
                "events_with_expectations": 3,
                "total_events": 4,
                "ratio": 0.75,
            },
            "timeline": [
                {"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "actor": "agent", "kind": "intent", "status": "VALID", "parent_ids": []},
                {"event_id": "b", "timestamp": "2026-01-01T00:00:01Z", "actor": "agent", "kind": "decision", "status": "DIVERGENT", "parent_ids": ["a"]},
                {"event_id": "c", "timestamp": "2026-01-01T00:00:02Z", "actor": "tool", "kind": "route-one", "status": "UNASSESSED", "parent_ids": ["b"]},
                {"event_id": "d", "timestamp": "2026-01-01T00:00:02Z", "actor": "tool", "kind": "route-two", "status": "UNASSESSED", "parent_ids": ["b"]},
            ],
            "first_provable_divergence": {
                "event_id": "b",
                "mismatches": [{"field": "policy", "expected": "v2", "observed": "v1"}],
            },
            "divergences": [
                {"event_id": "b", "mismatches": [{"field": "policy", "expected": "v2", "observed": "v1"}]}
            ],
            "causal_chain": [
                {"event_id": "b", "relationship": "ROOT_DIVERGENCE"},
                {"event_id": "c", "relationship": "EXPLICITLY_DOWNSTREAM"},
                {"event_id": "d", "relationship": "TEMPORALLY_DOWNSTREAM"},
            ],
            "attribution": [],
            "confidence": "MEDIUM",
            "evidence_gaps": [{"type": "UNASSESSED_EVENT", "event_id": "c"}],
            "evidence_completeness": "INCOMPLETE",
            "reproducibility": "NOT_TESTED",
            "reconstruction_status": "DIVERGENCE_RECONSTRUCTED",
        }

    def aps(self):
        return {
            "schema": "agent-replay.aps-authority-reconstruction.v2",
            "input_sha256": "3" * 64,
            "adapter_validation": {},
            "input_provenance": {"provenance_status": "UNKNOWN"},
            "external_conformance": {
                "fixture": "pass",
                "outcome": "allowed",
                "authority_status": "SUPPLIED_ALLOWED",
            },
            "identity": {
                "claimed_actor": "did:aps:agent",
                "intent_issuer": "did:aps:agent",
                "intent_signer": "did:aps:agent",
                "independent_authentication": "NOT_VERIFIED",
            },
            "authority": {
                "root_principal": "did:aps:principal",
                "delegation_path": [{"delegation_id": "d1"}],
                "structural_binding": "COMPLETE",
                "independent_cryptographic_verification": "NOT_VERIFIED",
            },
            "policy": {
                "issuer": "did:aps:gateway",
                "signer": "did:aps:gateway",
                "verdict": "permit",
                "reason": "ok",
                "independent_authentication": "NOT_VERIFIED",
            },
            "binding": {
                "status": "COMPLETE",
                "checks": {
                    "action_ref": True,
                    "receipt_link": True,
                    "delegation_ref": True,
                    "delegation_chain": True,
                },
            },
            "execution": {
                "status": "NO_EXECUTION_EVIDENCE",
                "bound_events": [],
                "partially_bound_events": [],
                "unbound_events": [],
                "external_effect_proof": False,
            },
            "observed_execution": [],
            "execution_status": "NO_EXECUTION_EVIDENCE",
            "evidence_boundary": {
                "permit_is_execution": False,
                "external_conformance_is_replay_verification": False,
                "independent_crypto_verification_performed": False,
                "claims": [],
            },
        }

    def analyze(self, report):
        return analyze_agent_replay_report(
            report,
            captured_at="2026-09-22T17:30:00Z",
            analysis_time="2026-09-22T17:30:01Z",
            implementation_revision="test",
        )

    def test_incident_preserves_branch_structure_and_causality_boundary(self):
        manifest, result = self.analyze(self.incident())
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        lineage = [o for o in result.observations if o["kind"] == "agent.trace.lineage"][0]
        self.assertEqual(lineage["branch_points"], [{"event_id": "b", "child_ids": ["c", "d"]}])
        self.assertEqual(lineage["roots"], ["a"])
        self.assertEqual(lineage["leaves"], ["c", "d"])
        self.assertEqual(lineage["branch_interpretation"], "EXPLICIT_PARENT_LINKS_ONLY")
        temporal = [d for d in result.determinations if d["kind"] == "agent.trace.temporal-not-causal"]
        self.assertEqual(len(temporal), 1)

    def test_incident_keeps_actor_authentication_unresolved(self):
        _manifest, result = self.analyze(self.incident())
        identity = [o for o in result.observations if o["kind"] == "agent.trace.identity-boundary"][0]
        self.assertEqual(identity["authentication_status"], "NOT_ESTABLISHED")
        self.assertIsNone(identity["authenticated_actor"])

    def test_incident_does_not_claim_evidence_channel_reconstruction(self):
        _manifest, result = self.analyze(self.incident())
        channel = [o for o in result.observations if o["kind"] == "agent.trace.evidence-channel"][0]
        self.assertEqual(channel["reconstruction_status"], "NOT_RECONSTRUCTED_BY_SUPPLIED_REPORT")
        self.assertEqual(channel["timeliness"], "UNRESOLVED")
        self.assertTrue(any(x["kind"] == "agent.trace.post-action-contamination" for x in result.unresolved))

    def test_incident_report_is_user_supplied_not_promoted_by_shape(self):
        manifest, _result = self.analyze(self.incident())
        self.assertEqual(manifest.evidence[0].source_class, "USER_SUPPLIED")
        self.assertEqual(manifest.evidence[0].trustworthiness, "UNRESOLVED")

    def test_incident_dangling_parent_fails_closed(self):
        report = self.incident()
        report["timeline"][3]["parent_ids"] = ["missing"]
        with self.assertRaisesRegex(ValidationError, "agent-replay-parent-missing"):
            self.analyze(report)

    def test_aps_permit_is_not_execution_or_effect(self):
        _manifest, result = self.analyze(self.aps())
        determinations = {d["kind"]: d for d in result.determinations}
        self.assertEqual(determinations["agent.trace.structural-binding"]["status"], "ESTABLISHED")
        self.assertEqual(determinations["agent.trace.execution"]["status"], "NOT_ESTABLISHED")
        self.assertEqual(determinations["agent.trace.downstream-effect"]["status"], "UNRESOLVED")

    def test_aps_bound_execution_still_does_not_establish_external_effect(self):
        report = self.aps()
        report["execution"]["status"] = "EXECUTION_EVIDENCE_BOUND_TO_ACTION"
        report["execution"]["bound_events"] = [{"event_id": "exec"}]
        report["execution_status"] = "EXECUTION_EVIDENCE_BOUND_TO_ACTION"
        _manifest, result = self.analyze(report)
        determinations = {d["kind"]: d for d in result.determinations}
        self.assertEqual(determinations["agent.trace.execution"]["status"], "ESTABLISHED")
        self.assertEqual(determinations["agent.trace.downstream-effect"]["status"], "UNRESOLVED")

    def test_aps_rejects_permit_equals_execution_boundary(self):
        report = self.aps()
        report["evidence_boundary"]["permit_is_execution"] = True
        with self.assertRaisesRegex(ValidationError, "permit-execution-boundary-invalid"):
            self.analyze(report)

    def test_broken_binding_is_contradiction(self):
        report = self.aps()
        report["binding"]["status"] = "BROKEN"
        report["binding"]["checks"]["action_ref"] = False
        _manifest, result = self.analyze(report)
        self.assertEqual(result.determinations[0]["status"], "CONTRADICTED")
        self.assertEqual(len(result.contradictions), 1)

    def test_agent_replay_validation_pin_is_explicit(self):
        _manifest, result = self.analyze(self.incident())
        self.assertEqual(result.synthesis["agent_replay_validated_version"], AGENT_REPLAY_VALIDATED_VERSION)
        self.assertEqual(result.synthesis["agent_replay_validated_revision"], AGENT_REPLAY_VALIDATED_REVISION)
        self.assertEqual(AGENT_REPLAY_VALIDATED_VERSION, "0.6.0")
        self.assertEqual(AGENT_REPLAY_VALIDATED_REVISION, "1f4db7a12e8ddf8853c2533f08f8252f7efbe326")

    def test_unknown_agent_replay_schema_fails_closed(self):
        report = self.incident()
        report["schema"] = "agent-replay.future.v99"
        with self.assertRaisesRegex(ValidationError, "unsupported-agent-replay-schema"):
            self.analyze(report)


if __name__ == "__main__":
    unittest.main()
