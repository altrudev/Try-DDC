from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from .profiles.evm_contract import analyze_observation


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a bounded EVM contract observation through Try DDC v2.")
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--out-dir", default="try-ddc-evm-output", type=Path)
    args = parser.parse_args()

    raw = json.loads(args.observation.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise SystemExit("observation must be a JSON object")

    captured_at = str(raw.get("captured_at") or _now())
    observation = raw.get("observation", raw)
    if not isinstance(observation, dict):
        raise SystemExit("observation field must be a JSON object")

    manifest, result = analyze_observation(
        observation,
        captured_at=captured_at,
        analysis_time=_now(),
        implementation_revision=_revision(),
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
