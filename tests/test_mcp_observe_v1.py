from __future__ import annotations

import unittest

from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.mcp_observe import analyze_mcp_observation


class MCPObserveV1Tests(unittest.TestCase):
    def snapshot(self):
        return {
            "schema": "try-ddc-mcp-observation/1",
            "observation_complete": True,
            "endpoint": "https://mcp.example/api",
            "server": {
                "name": "example",
                "version": "1.0",
                "protocol_version": "2026-07-28",
                "supported_versions": ["2026-07-28"],
            },
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "tools": [{
                "name": "lookup",
                "description": "lookup data",
                "input_schema": {"type": "object", "required": ["id"], "additionalProperties": False},
                "annotations": {},
            }],
            "resources": [{"uri": "resource://one", "name": "one"}],
            "prompts": [{"name": "summarize", "arguments": []}],
            "auth": {},
            "transport": {
                "scheme": "https",
                "host": "mcp.example",
                "tls_cert_sha256": "sha256:" + "a" * 64,
                "tls_spki_sha256": None,
                "redirect_followed": False,
            },
        }

    def analyze(self, live, baseline=None):
        return analyze_mcp_observation(
            live,
            baseline_snapshot=baseline,
            captured_at="2026-09-22T18:00:00Z",
            analysis_time="2026-09-22T18:00:01Z",
            implementation_revision="test",
        )

    def test_observation_never_claims_tool_invocation(self):
        _manifest, result = self.analyze(self.snapshot())
        boundary = [o for o in result.observations if o["kind"] == "mcp.authority-boundary"][0]
        self.assertFalse(boundary["advertised_tools_invoked"])
        self.assertFalse(boundary["arbitrary_rpc_invoked"])
        self.assertEqual(result.determinations[1]["status"], "OUT_OF_SCOPE")

    def test_identical_baseline_has_no_drift_but_not_safety_pass(self):
        snap = self.snapshot()
        _manifest, result = self.analyze(snap, baseline=dict(snap))
        self.assertEqual(result.determinations[1]["status"], "ESTABLISHED")
        self.assertEqual(result.risk_disposition, "REVIEW_REQUIRED")
        self.assertEqual(result.synthesis["drift_change_count"], 0)

    def test_new_tool_is_high_risk_drift(self):
        base = self.snapshot()
        live = self.snapshot()
        live["tools"] = list(live["tools"]) + [{"name": "delete_all", "input_schema": {"type": "object"}}]
        _manifest, result = self.analyze(live, baseline=base)
        self.assertEqual(result.risk_disposition, "HIGH_RISK_OBSERVED")
        self.assertTrue(any(c["kind"] == "tool_added" for c in result.contradictions))

    def test_schema_widening_is_high_risk(self):
        base = self.snapshot()
        live = self.snapshot()
        live["tools"] = [dict(live["tools"][0])]
        live["tools"][0]["input_schema"] = {"type": "object", "required": [], "additionalProperties": True}
        _manifest, result = self.analyze(live, baseline=base)
        self.assertTrue(any(c["kind"] == "tool_schema_widened" and c["severity"] == "HIGH" for c in result.contradictions))

    def test_incomplete_inventory_fails_closed(self):
        live = self.snapshot()
        live["observation_complete"] = False
        with self.assertRaisesRegex(ValidationError, "incomplete-live-observation"):
            self.analyze(live)

    def test_self_reported_name_change_is_metadata_not_identity_proof(self):
        base = self.snapshot()
        live = self.snapshot()
        live["server"] = dict(live["server"])
        live["server"]["name"] = "other"
        _manifest, result = self.analyze(live, baseline=base)
        change = [c for c in result.contradictions if c["kind"] == "self_reported_name_changed"][0]
        self.assertEqual(change["severity"], "MEDIUM")
        self.assertTrue(any("self-reported" in x for x in result.limitations))


if __name__ == "__main__":
    unittest.main()
