from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from .profiles.evidence_bundle import analyze_capsule


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
    parser = argparse.ArgumentParser(description="Validate and freeze a Try DDC customer-side evidence capsule.")
    parser.add_argument("--capsule", required=True, type=Path)
    parser.add_argument("--out-dir", default="try-ddc-evidence-bundle-output", type=Path)
    args = parser.parse_args()

    capsule = json.loads(args.capsule.read_text(encoding="utf-8"))
    manifest, result = analyze_capsule(
        capsule,
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
    print("TRY_DDC_V2_EVIDENCE_ROOT=" + manifest.evidence_root)
    print("TRY_DDC_V2_RESULT_DIGEST=" + result.result_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
