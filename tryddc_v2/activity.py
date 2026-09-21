from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Any

from .canonical import sha256_digest
from .model import ActivityReceipt


def aggregate_activity(
    receipts: Iterable[ActivityReceipt],
    *,
    generated_at: str,
    previous_snapshot_digest: str | None = None,
    privacy_threshold: int = 5,
) -> dict[str, Any]:
    """Create a privacy-minimized public activity snapshot.

    Exact low-volume counts stay internal. Public counts below the threshold are
    rendered as "<N" to reduce correlation risk.
    """
    if privacy_threshold < 2:
        raise ValueError("privacy-threshold-too-low")

    grouped: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(
        lambda: {"runs": 0, "completed": 0, "first": None, "last": None}
    )
    for receipt in receipts:
        cap = receipt.capability
        key = (cap.capability_id, cap.capability_version, cap.capability_digest)
        row = grouped[key]
        row["runs"] += 1
        if receipt.analysis_status == "COMPLETE":
            row["completed"] += 1
        day = receipt.time_bucket
        row["first"] = day if row["first"] is None or day < row["first"] else row["first"]
        row["last"] = day if row["last"] is None or day > row["last"] else row["last"]

    def public_count(value: int) -> int | str:
        return value if value >= privacy_threshold else f"<{privacy_threshold}"

    capabilities = []
    for (capability_id, version, digest), row in sorted(grouped.items()):
        capabilities.append(
            {
                "capability_id": capability_id,
                "capability_version": version,
                "capability_digest": digest,
                "runs": public_count(row["runs"]),
                "completed": public_count(row["completed"]),
                "first_exercised": row["first"],
                "last_exercised": row["last"],
            }
        )

    payload: dict[str, Any] = {
        "schema": "try-ddc-public-activity/1",
        "document_class": "TRY_DDC_ACTIVITY_SNAPSHOT",
        "generated_at": generated_at,
        "privacy_threshold": privacy_threshold,
        "semantics": {
            "runs": "bounded Try DDC runs, not unique users or validations",
            "completed": "runs that produced a COMPLETE bounded analysis",
        },
        "capabilities": capabilities,
        "previous_snapshot_digest": previous_snapshot_digest,
    }
    payload["snapshot_digest"] = sha256_digest(payload)
    return payload
