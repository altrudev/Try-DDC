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
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")

_TOP_FIELDS = {
    "schema", "capsule_id", "target_id", "nonce", "created_at",
    "producer", "export", "evidence", "capsule_digest",
}
_PRODUCER_FIELDS = {"product", "version", "mode", "plan_digest", "profile_id"}
_EXPORT_FIELDS = {
    "source_code_exported",
    "source_excerpts_exported",
    "arbitrary_shell_authority",
    "private_key_authority",
    "transaction_signing_authority",
    "transaction_broadcast_authority",
    "raw_capability_payloads_exported",
}
_EVIDENCE_FIELDS = {
    "evidence_id",
    "capability_id",
    "classification",
    "status",
    "digest",
    "freshness_status",
    "freshness_policy",
}
_REGISTERED_PRODUCER_CAPABILITIES = {
    "repo.static",
    "filesystem.manifest",
    "api.http.readonly",
    "blockchain.rpc.readonly",
    "blockchain.evm.contract.observe",
    "blockchain.evm.transaction.observe",
    "blockchain.bitcoin.transaction.observe",
    "agent.replay.report",
    "protocol.mcp.observe",
}
_ALLOWED_STATUSES = {
    "COMPLETE",
    "INCOMPLETE",
    "UNSUPPORTED",
    "RATE_LIMITED",
    "CAPTURE_FAILED",
    "BLOCKED",
}
_ALLOWED_FRESHNESS = {"ESTABLISHED", "PARTIALLY_ESTABLISHED", "UNRESOLVED", "STALE"}


def _reject_unknown_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValidationError(f"{label}-unknown-field:" + ",".join(sorted(unknown)))


def _validate_capsule(capsule: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(capsule, dict):
        raise ValidationError("capsule-must-be-object")
    _reject_unknown_fields(capsule, _TOP_FIELDS, "capsule")
    if capsule.get("schema") != "try-ddc-evidence-capsule/2":
        raise ValidationError("unsupported-capsule-schema")

    capsule_id = capsule.get("capsule_id")
    target_id = capsule.get("target_id")
    nonce = capsule.get("nonce")
    created_at = capsule.get("created_at")
    evidence = capsule.get("evidence")
    producer = capsule.get("producer", {})
    export = capsule.get("export", {})

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
    if not isinstance(producer, dict):
        raise ValidationError("capsule-producer-invalid")
    if not isinstance(export, dict):
        raise ValidationError("capsule-export-invalid")

    _reject_unknown_fields(producer, _PRODUCER_FIELDS, "capsule-producer")
    _reject_unknown_fields(export, _EXPORT_FIELDS, "capsule-export")
    for key, value in producer.items():
        if not isinstance(value, str):
            raise ValidationError(f"capsule-producer-{key}-invalid")
        if len(value) > 256:
            raise ValidationError(f"capsule-producer-{key}-too-long")
    if producer.get("plan_digest") is not None and not _DIGEST_RE.fullmatch(producer["plan_digest"]):
        raise ValidationError("capsule-producer-plan-digest-invalid")
    if producer.get("profile_id") is not None and not _ID_RE.fullmatch(producer["profile_id"]):
        raise ValidationError("capsule-producer-profile-id-invalid")
    for key, value in export.items():
        if value is not False:
            raise ValidationError(f"capsule-export-{key}-must-be-false")

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
        _reject_unknown_fields(item, _EVIDENCE_FIELDS, "capsule-evidence")
        eid = item.get("evidence_id")
        digest = item.get("digest")
        capability_id = item.get("capability_id")
        status = item.get("status")
        freshness = item.get("freshness_status", "UNRESOLVED")
        freshness_policy = item.get("freshness_policy")
        if not isinstance(eid, str) or not re.fullmatch(r"evidence:[a-z0-9._:-]{1,96}", eid):
            raise ValidationError("capsule-evidence-id-invalid")
        if eid in seen:
            raise ValidationError("capsule-duplicate-evidence-id")
        seen.add(eid)
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            raise ValidationError("capsule-evidence-digest-invalid")
        if item.get("classification") not in {"PUBLIC", "CUSTOMER_PRIVATE", "SENSITIVE"}:
            raise ValidationError("capsule-classification-invalid")
        if capability_id not in _REGISTERED_PRODUCER_CAPABILITIES:
            raise ValidationError("capsule-unregistered-producer-capability")
        if status not in _ALLOWED_STATUSES:
            raise ValidationError("capsule-evidence-status-invalid")
        if freshness not in _ALLOWED_FRESHNESS:
            raise ValidationError("capsule-evidence-freshness-invalid")
        if freshness_policy is not None and (
            not isinstance(freshness_policy, str) or len(freshness_policy) > 256
        ):
            raise ValidationError("capsule-evidence-freshness-policy-invalid")
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
