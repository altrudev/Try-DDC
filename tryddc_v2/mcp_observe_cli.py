from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from .profiles.mcp_observe import analyze_mcp_observation


MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024


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


def _load(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SystemExit("MCP observation exceeds 8 MiB input bound")
    def reject_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise SystemExit("MCP observation must be a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a bounded read-only MCP observation.")
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--out-dir", default="try-ddc-mcp-output", type=Path)
    parser.add_argument("--classification", choices=["PUBLIC", "CUSTOMER_PRIVATE", "SENSITIVE"], default="CUSTOMER_PRIVATE")
    args = parser.parse_args()

    live = _load(args.snapshot)
    baseline = _load(args.baseline) if args.baseline else None
    manifest, result = analyze_mcp_observation(
        live,
        baseline_snapshot=baseline,
        captured_at=_now(),
        analysis_time=_now(),
        implementation_revision=_revision(),
        classification=args.classification,
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
