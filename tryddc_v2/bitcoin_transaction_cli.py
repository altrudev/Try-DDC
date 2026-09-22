from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from .canonical import strict_json_file
from .profiles.bitcoin_transaction import analyze_observation


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
    parser = argparse.ArgumentParser(description="Analyze a bounded read-only Bitcoin transaction observation.")
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--out-dir", default="try-ddc-bitcoin-transaction-output", type=Path)
    args = parser.parse_args()

    observation = strict_json_file(args.observation)
    manifest, result = analyze_observation(
        observation,
        captured_at=_now(),
        analysis_time=_now(),
        implementation_revision=_revision(),
    )

    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    mp = manifest.payload()
    mp["evidence_root"] = manifest.evidence_root
    rp = result.payload()
    rp["result_digest"] = result.result_digest
    (out / "evidence-manifest.json").write_text(json.dumps(mp, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "try-ddc-result-v2.json").write_text(json.dumps(rp, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("TRY_DDC_V2_STATUS=" + result.analysis_status)
    print("TRY_DDC_V2_EVIDENCE=" + result.evidentiary_status)
    print("TRY_DDC_V2_RISK=" + result.risk_disposition)
    print("TRY_DDC_V2_EVIDENCE_ROOT=" + manifest.evidence_root)
    print("TRY_DDC_V2_RESULT_DIGEST=" + result.result_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
