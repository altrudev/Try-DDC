from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "adapter" / "ddcal_adapter.py"
_spec = importlib.util.spec_from_file_location("ddcal_adapter_agent_trace", MODULE_PATH)
adapter = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(adapter)


class AgentTraceAdapterBridgeTests(unittest.TestCase):
    def report(self):
        return {
            "schema": "agent-replay.incident.v2",
            "input_sha256": "1" * 64,
            "canonical_sha256": "2" * 64,
            "event_count": 2,
            "expectation_coverage": {
                "status": "PARTIAL",
                "events_with_expectations": 1,
                "total_events": 2,
                "ratio": 0.5,
            },
            "timeline": [
                {
                    "event_id": "a",
                    "timestamp": "2026-09-22T17:00:00Z",
                    "actor": "agent",
                    "kind": "intent",
                    "status": "VALID",
                    "parent_ids": [],
                },
                {
                    "event_id": "b",
                    "timestamp": "2026-09-22T17:00:01Z",
                    "actor": "agent",
                    "kind": "decision",
                    "status": "DIVERGENT",
                    "parent_ids": ["a"],
                },
            ],
            "first_provable_divergence": {"event_id": "b"},
            "divergences": [{"event_id": "b", "field": "route"}],
            "causal_chain": [{"from": "a", "to": "b"}],
            "attribution": {},
            "confidence": {},
            "evidence_gaps": [{"kind": "effect"}],
            "evidence_completeness": "INCOMPLETE",
            "reconstruction_status": "DIVERGENCE_RECONSTRUCTED",
        }

    def test_local_replay_report_returns_commitments_not_raw_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / "work"
            report = root / "incident.json"
            report.write_text(json.dumps(self.report()), encoding="utf-8")

            result = adapter.run_agent_replay_report(
                root,
                {"path": "incident.json"},
                work,
            )

            self.assertEqual(result["capability"], "agent.replay.report")
            self.assertEqual(result["status"], "COMPLETE")
            self.assertFalse(result["raw_report_exported"])
            self.assertFalse(result["source_exported"])
            self.assertFalse(result["arbitrary_tool_authority"])
            serialized = json.dumps(result, sort_keys=True)
            self.assertNotIn('"timeline"', serialized)
            self.assertNotIn('"divergences"', serialized)
            self.assertTrue(str(result["result_digest"]).startswith("sha256:"))
            self.assertTrue(str(result["evidence_root"]).startswith("sha256:"))

    def test_agent_replay_report_path_cannot_escape_registered_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            root.mkdir()
            outside = Path(td) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaises(SystemExit):
                adapter.run_agent_replay_report(
                    root,
                    {"path": "../outside.json"},
                    root / "work",
                )


if __name__ == "__main__":
    unittest.main()
