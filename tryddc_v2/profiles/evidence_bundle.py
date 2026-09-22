from __future__ import annotations

import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError


PROFILE_DESCRIPTOR = {
    "id": "evidence.bundle.v1",
    "version": "1",
    "purpose": "validate and freeze a privacy-minimized customer-side evidence capsule",
    "execution_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "evidence.bundle.ingest",
    "version": "1",
    "execution_authority": False,
    "source_code_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

_NONCE_RE = re.compile(r"^[0-9a-f]{32,128}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _validate_capsule(capsule: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(capsule, dict):
        raise ValidationError("capsule-must-be-object")
    if capsule.get("schema") != "try-ddc-evidence-capsule/2":
        raise ValidationError("unsupported-capsule-schema")

    capsule_id = capsule.get("capsule_id")
    target_id = capsule.get("target_id")
    nonce = capsule.get("nonce")
    created_at = capsule.get("created_at")
    evidence = capsule.get("evidence")

    if not isinstance(capsule_id, str) or not re.fullmatch(r"capsule:[0-9a-f]{32}", capsule_id):
        raise ValidationError("invalid-capsule-id")
    if not isinstance(target_id, str) or not re.fullmatch(r"target:[0-9a-f]{24}", target_id):
        raise ValidationError("invalid-capsule-target-id")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise ValidationError("invalid-capsule-nonce")
    if not isinstance(created_at, str) or not created_at:
        raise ValidationError("invalid-capsule-created-at")
    if not isinstance(evidence, list) or not evidence:
        raise ValidationError("capsule-evidence-empty")

    unsigned = dict(capsule)
    supplied_digest = unsigned.pop("capsule_digest", None)
    if not isinstance(supplied_digest, str) or not _DIGEST_RE.fullmatch(supplied_digest):
        raise ValidationError("invalid-capsule-digest")
    if sha256_digest(unsigned) != supplied_digest:
        raise ValidationError("capsule-digest-mismatch")

    seen: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            raise ValidationError("capsule-evidence-item-invalid")
        eid = item.get("evidence_id")
        digest = item.get("digest")
        if not isinstance(eid, str) or not re.fullmatch(r"evidence:[a-z0-9._:-]{1,96}", eid):
            raise ValidationError("capsule-evidence-id-invalid")
        if eid in seen:
            raise ValidationError("capsule-duplicate-evidence-id")
        seen.add(eid)
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            raise ValidationError("capsule-evidence-digest-invalid")
        if item.get("classification") not in {"PUBLIC", "CUSTOMER_PRIVATE", "SENSITIVE"}:
            raise ValidationError("capsule-classification-invalid")
        if "raw_source" in item or "secret" in item:
            raise ValidationError("capsule-prohibited-field")
    return capsule


def analyze_capsule(
    capsule: dict[str, Any],
    *,
    analysis_time: str,
    implementation_revision: str,
) -> tuple[EvidenceManifest, TryDDCResult]:
    capsule = _validate_capsule(capsule)
    target_id = capsule["target_id"]
    capsule_hash = sha256_digest({
        "capsule_id": capsule["capsule_id"],
        "target_id": target_id,
        "nonce": capsule["nonce"],
    }).split(":", 1)[1]
    case_id = "case:" + capsule_hash[:24]

    capability = CapabilityIdentity(
        capability_id=CAPTURE_DESCRIPTOR["id"],
        capability_version=CAPTURE_DESCRIPTOR["version"],
        capability_digest=CAPTURE_DIGEST,
        implementation_revision=implementation_revision,
    )

    evidence_items = []
    for item in capsule["evidence"]:
        evidence_items.append(
            EvidenceItem(
                evidence_id=item["evidence_id"],
                target_id=target_id,
                source_class="USER_SUPPLIED",
                capture_capability=capability,
                digest=item["digest"],
                captured_at=capsule["created_at"],
                source_identity=str(item.get("capability_id") or "customer-side-adapter"),
                causal_origin="customer-side-bounded-capture",
                classification=item["classification"],
                authorization_status="UNRESOLVED",
                representation="DIGEST_COMMITMENT",
                time_source="customer-side-adapter",
                time_trust="UNRESOLVED",
                freshness_status=str(item.get("freshness_status") or "UNRESOLVED"),
                freshness_policy=str(item.get("freshness_policy") or "capsule-created-at"),
                reachability="ESTABLISHED",
                discoverability="ESTABLISHED",
                accessibility="ESTABLISHED",
                trustworthiness="UNRESOLVED",
                consulted=True,
                limitations=(
                    "capsule-commitment-does-not-prove-underlying-evidence-truth",
                    "producer-time-and-environment-not-independently-attested",
                ),
            )
        )

    manifest = EvidenceManifest(
        case_id=case_id,
        target_id=target_id,
        profile_id=PROFILE_DESCRIPTOR["id"],
        profile_version=PROFILE_DESCRIPTOR["version"],
        profile_digest=PROFILE_DIGEST,
        capture_revision=1,
        evidence=tuple(evidence_items),
        frozen_at=capsule["created_at"],
    )

    producer = capsule.get("producer", {})
    export = capsule.get("export", {})
    observations = (
        {
            "kind": "evidence.bundle.integrity",
            "capsule_id": capsule["capsule_id"],
            "capsule_digest": capsule["capsule_digest"],
            "nonce_bound": True,
            "evidence_items": len(evidence_items),
            "evidence_refs": [item.evidence_id for item in evidence_items],
        },
        {
            "kind": "evidence.bundle.producer",
            "producer": producer,
            "export": export,
            "evidence_refs": [item.evidence_id for item in evidence_items],
        },
    )

    determinations = (
        {
            "kind": "bundle.structural_integrity",
            "status": "ESTABLISHED",
            "detail": "The capsule is internally digest-bound, nonce-bound, target-bound, and contains only registered commitment records accepted by this profile.",
            "evidence_refs": [item.evidence_id for item in evidence_items],
        },
        {
            "kind": "bundle.underlying_evidence_truth",
            "status": "UNRESOLVED",
            "detail": "Capsule integrity does not independently establish that the customer-side observations are true, complete, contemporaneous, or sufficient for another assurance question.",
            "evidence_refs": [item.evidence_id for item in evidence_items],
        },
    )

    limitations = (
        "The capsule proves bounded commitment integrity, not independent truth of the underlying evidence.",
        "Customer-side capture environment, clock, and local authority are not independently authenticated by this profile.",
        "Digest-only evidence cannot be reinterpreted beyond the claims supported by its registered producer capability.",
        "No source code, private key, arbitrary command, or execution authority is created by ingesting the capsule.",
    )

    seed = {
        "case_id": case_id,
        "target_id": target_id,
        "evidence_root": manifest.evidence_root,
        "profile_digest": PROFILE_DIGEST,
        "capsule_digest": capsule["capsule_digest"],
    }
    result_id = "result:" + sha256_digest(seed).split(":", 1)[1][:24]

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
        risk_disposition="REVIEW_REQUIRED",
        analysis_time=analysis_time,
        observations=observations,
        determinations=determinations,
        limitations=limitations,
        unresolved=(
            {
                "kind": "underlying-evidence-truth",
                "detail": "The bundle is structurally valid but underlying evidence truth remains unresolved.",
            },
        ),
        synthesis={
            "method": "evidence.bundle.v1",
            "version": "1",
            "capsule_digest": capsule["capsule_digest"],
        },
        capabilities=(capability,),
        minimum_coverage_met=False,
    )
    return manifest, result
