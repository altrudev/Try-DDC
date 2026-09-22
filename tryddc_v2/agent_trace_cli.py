from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from .profiles.agent_trace import analyze_agent_replay_report


MAX_REPORT_BYTES = 8 * 1024 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _revision() -> str:
    root = Path(__file__).resolve().parents[1]
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=4,
        ).strip()
    except Exception:
        return "unavailable"


def _load_report(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_REPORT_BYTES:
        raise SystemExit("Agent Replay report exceeds 8 MiB input bound")

    def reject_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise SystemExit("Agent Replay report must be a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Map an Agent Replay reconstruction into Try DDC agent.trace.v1.")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--out-dir", default="try-ddc-agent-trace-output", type=Path)
    parser.add_argument(
        "--classification",
        choices=["PUBLIC", "CUSTOMER_PRIVATE", "SENSITIVE"],
        default="CUSTOMER_PRIVATE",
    )
    args = parser.parse_args()

    report = _load_report(args.report)
    manifest, result = analyze_agent_replay_report(
        report,
        captured_at=_now(),
        analysis_time=_now(),
        implementation_revision=_revision(),
        classification=args.classification,
    )

    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest_payload = manifest.payload()
    manifest_payload["evidence_root"] = manifest.evidence_root
    result_payload = result.payload()
    result_payload["result_digest"] = result.result_digest

    (out / "evidence-manifest.json").write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "try-ddc-result-v2.json").write_text(
        json.dumps(result_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("TRY_DDC_V2_STATUS=" + result.analysis_status)
    print("TRY_DDC_V2_EVIDENCE=" + result.evidentiary_status)
    print("TRY_DDC_V2_RISK=" + result.risk_disposition)
    print("TRY_DDC_V2_EVIDENCE_ROOT=" + manifest.evidence_root)
    print("TRY_DDC_V2_RESULT_DIGEST=" + result.result_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
