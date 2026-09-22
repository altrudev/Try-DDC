from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import try_ddc as legacy

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult


PROFILE_DESCRIPTOR = {
    "id": "software.repository.v2",
    "version": "2",
    "purpose": "bounded non-executing repository assurance",
    "execution_authority": False,
    "minimum_coverage": "legacy-bounded-selection-v1",
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "software.repository.capture",
    "version": "2",
    "bounds": {
        "max_tree_files": legacy.MAX_TREE_FILES,
        "max_selected_files": legacy.MAX_SELECTED_FILES,
        "max_file_bytes": legacy.MAX_FILE_BYTES,
        "max_total_bytes": legacy.MAX_TOTAL_BYTES,
    },
    "execution_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _bounded_inventory(root: Path) -> tuple[list[tuple[str, int]], list[str], bool]:
    observed: list[tuple[str, int]] = []
    symlinks: list[str] = []
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames if d not in legacy.EXCLUDED]
        for name in filenames:
            path = Path(dirpath) / name
            rel = str((rel_dir / name).as_posix())
            try:
                if path.is_symlink():
                    symlinks.append(rel)
                    continue
                size = path.stat().st_size
            except OSError:
                continue
            observed.append((rel, size))
            if len(observed) >= legacy.MAX_TREE_FILES:
                truncated = True
                break
        if truncated:
            break
    return observed, symlinks, truncated


def _selected(observed: list[tuple[str, int]]) -> list[tuple[str, int, int]]:
    candidates = [
        (rel, size, legacy.priority(rel))
        for rel, size in observed
        if 0 < size <= legacy.MAX_FILE_BYTES and legacy.priority(rel) >= 50
    ]
    candidates.sort(key=lambda value: (-value[2], value[1], value[0]))
    selected: list[tuple[str, int, int]] = []
    total = 0
    for item in candidates:
        if len(selected) >= legacy.MAX_SELECTED_FILES:
            break
        if total + item[1] > legacy.MAX_TOTAL_BYTES:
            continue
        selected.append(item)
        total += item[1]
    return selected


def _identity(root: Path) -> tuple[str, str]:
    commit = legacy.git_value(root, "rev-parse", "HEAD")
    repository = os.getenv("GITHUB_REPOSITORY") or legacy.git_value(
        root, "config", "--get", "remote.origin.url"
    )
    return repository, commit


def run_repository_v2(
    root: Path,
    *,
    frozen_at: str,
    analysis_time: str,
    implementation_revision: str,
) -> tuple[EvidenceManifest, TryDDCResult, dict[str, Any]]:
    """Run the existing bounded scanner through the v2 evidence spine.

    The target repository is never executed. The v2 profile captures file
    commitments for exactly the same bounded selection policy used by the
    legacy scanner, freezes those commitments, then binds the legacy findings
    into a v2 result envelope.
    """
    root = root.resolve()
    observed, symlinks, inventory_truncated = _bounded_inventory(root)
    selected = _selected(observed)
    repository, commit = _identity(root)

    target_descriptor = {
        "repository": repository,
        "commit": commit,
    }
    target_hash = sha256_digest(target_descriptor).split(":", 1)[1]
    target_id = "target:" + target_hash[:24]
    case_id = "case:" + target_hash[24:48]

    capability = CapabilityIdentity(
        capability_id=CAPTURE_DESCRIPTOR["id"],
        capability_version=CAPTURE_DESCRIPTOR["version"],
        capability_digest=CAPTURE_DIGEST,
        implementation_revision=implementation_revision,
    )

    evidence: list[EvidenceItem] = []
    for index, (rel, size, _priority) in enumerate(selected, start=1):
        path = root / rel
        try:
            digest = _sha256_file(path)
        except OSError:
            continue
        evidence.append(
            EvidenceItem(
                evidence_id=f"evidence:file:{index:04d}",
                target_id=target_id,
                source_class="FIRST_PARTY",
                capture_capability=capability,
                digest=digest,
                captured_at=frozen_at,
                source_identity=rel,
                causal_origin="bounded-repository-selection",
                classification="PUBLIC",
                freshness_status="ESTABLISHED",
                freshness_policy="exact-local-file-state-at-capture",
                reachability="ESTABLISHED",
                discoverability="ESTABLISHED",
                accessibility="ESTABLISHED",
                trustworthiness="UNRESOLVED",
                consulted=True,
                limitations=("file-content-not-exported-by-v2-envelope",),
            )
        )

    structure = {
        "files_observed": len(observed),
        "files_selected": len(selected),
        "tree_truncated": inventory_truncated,
        "symlinks": sorted(symlinks),
        "repository": repository,
        "commit": commit,
    }
    evidence.append(
        EvidenceItem(
            evidence_id="evidence:repository:structure",
            target_id=target_id,
            source_class="FIRST_PARTY",
            capture_capability=capability,
            digest=sha256_digest(structure),
            captured_at=frozen_at,
            source_identity="repository-structure",
            causal_origin="bounded-repository-walk",
            classification="PUBLIC",
            freshness_status="ESTABLISHED",
            freshness_policy="exact-local-observation-at-capture",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
        )
    )

    manifest = EvidenceManifest(
        case_id=case_id,
        target_id=target_id,
        profile_id=PROFILE_DESCRIPTOR["id"],
        profile_version=PROFILE_DESCRIPTOR["version"],
        profile_digest=PROFILE_DIGEST,
        capture_revision=1,
        evidence=tuple(evidence),
        frozen_at=frozen_at,
    )

    legacy_result = legacy.scan(root)
    disposition_map = {
        "BLOCKED": "HIGH_RISK_OBSERVED",
        "REVIEW_REQUIRED": "REVIEW_REQUIRED",
        "NO_HIGH_RISK_OBSERVED": "NO_HIGH_RISK_OBSERVED",
    }
    risk = disposition_map.get(legacy_result.get("disposition"), "REVIEW_REQUIRED")
    minimum_coverage_met = legacy_result.get("disposition") == "NO_HIGH_RISK_OBSERVED"

    result_seed = {
        "case_id": case_id,
        "target_id": target_id,
        "evidence_root": manifest.evidence_root,
        "profile_digest": PROFILE_DIGEST,
    }
    result_id = "result:" + sha256_digest(result_seed).split(":", 1)[1][:24]

    observations = (
        {
            "kind": "repository.coverage",
            "evidence_refs": ["evidence:repository:structure"],
            "value": dict(legacy_result.get("coverage", {})),
        },
    )
    determinations = tuple(
        {
            "kind": "ddc.signal",
            "name": signal.get("name"),
            "status": signal.get("status"),
            "detail": signal.get("detail"),
            "evidence_refs": ["evidence:repository:structure"],
        }
        for signal in legacy_result.get("ddc_signals", [])
    )
    findings = tuple(
        {
            **finding,
            "evidence_refs": [
                "evidence:repository:structure"
                if not finding.get("location")
                else next(
                    (
                        item.evidence_id
                        for item in evidence
                        if item.source_identity
                        and finding.get("location", "").split(":", 1)[0] == item.source_identity
                    ),
                    "evidence:repository:structure",
                )
            ],
            "analyzer": "legacy.try-ddc.static.v0.1",
        }
        for finding in legacy_result.get("findings", [])
    )

    result = TryDDCResult(
        result_id=result_id,
        case_id=case_id,
        target_id=target_id,
        profile_id=PROFILE_DESCRIPTOR["id"],
        profile_version=PROFILE_DESCRIPTOR["version"],
        profile_digest=PROFILE_DIGEST,
        evidence_root=manifest.evidence_root,
        analysis_status="COMPLETE",
        evidentiary_status="PARTIALLY_ESTABLISHED",
        risk_disposition=risk,
        analysis_time=analysis_time,
        claims=(),
        observations=observations,
        determinations=determinations,
        findings=findings,
        contradictions=(),
        unresolved=tuple(
            {"kind": "limitation", "detail": limitation}
            for limitation in legacy_result.get("limitations", [])
        ),
        limitations=tuple(legacy_result.get("limitations", [])),
        synthesis={
            "method": "software.repository.v2-migration",
            "version": "1",
            "legacy_tool_version": legacy.VERSION,
            "legacy_disposition": legacy_result.get("disposition"),
        },
        minimum_coverage_met=minimum_coverage_met,
    )
    return manifest, result, legacy_result
