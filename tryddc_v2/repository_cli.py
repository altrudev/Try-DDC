from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from datetime import datetime, timezone

from .profiles.repository import run_repository_v2


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _revision(root: Path) -> str:
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
    parser = argparse.ArgumentParser(description="Run Try DDC software.repository.v2")
    parser.add_argument("--root", default=".", type=Path)
    parser.add_argument("--out-dir", default="try-ddc-v2-output", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    capture_time = _now()
    manifest, result, legacy_result = run_repository_v2(
        root,
        frozen_at=capture_time,
        analysis_time=_now(),
        implementation_revision=_revision(Path(__file__).resolve().parents[1]),
    )

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
    (out / "legacy-result.json").write_text(
        json.dumps(legacy_result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("TRY_DDC_V2_STATUS=" + result.analysis_status)
    print("TRY_DDC_V2_RISK=" + result.risk_disposition)
    print("TRY_DDC_V2_EVIDENCE_ROOT=" + manifest.evidence_root)
    print("TRY_DDC_V2_RESULT_DIGEST=" + result.result_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
