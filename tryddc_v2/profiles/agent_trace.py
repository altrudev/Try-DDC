from __future__ import annotations

import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError


PROFILE_DESCRIPTOR = {
    "id": "agent.trace.v1",
    "version": "1",
    "purpose": "consume bounded Agent Replay reconstruction evidence without upgrading unsupported authority or consequence claims",
    "execution_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "agent.trace.agent-replay-ingest",
    "version": "1",
    "accepted_schemas": [
        "agent-replay.incident.v2",
        "agent-replay.aps-authority-reconstruction.v2",
    ],
    "execution_authority": False,
    "tool_invocation_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

_SHA256_RAW_RE = re.compile(r"^[0-9a-f]{64}$")


def _raw_sha(value: Any, name: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not _SHA256_RAW_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value


def _identity(report: dict[str, Any]) -> tuple[str, str, str]:
    schema = report.get("schema")
    if schema not in CAPTURE_DESCRIPTOR["accepted_schemas"]:
        raise ValidationError("unsupported-agent-replay-schema")
    input_sha = _raw_sha(report.get("input_sha256"), "agent-replay-input-sha256", allow_none=True)
    stable = {
        "schema": schema,
        "input_sha256": input_sha,
        "canonical_sha256": report.get("canonical_sha256"),
        "fixture": (report.get("external_conformance") or {}).get("fixture")
        if isinstance(report.get("external_conformance"), dict) else None,
    }
    digest = sha256_digest(stable).split(":", 1)[1]
    return schema, "target:" + digest[:24], "case:" + digest[24:48]


def _generic(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    canonical_sha = _raw_sha(report.get("canonical_sha256"), "agent-replay-canonical-sha256")
    timeline = report.get("timeline")
    divergences = report.get("divergences")
    causal_chain = report.get("causal_chain")
    evidence_gaps = report.get("evidence_gaps")
    if not isinstance(timeline, list) or not isinstance(divergences, list) or not isinstance(causal_chain, list) or not isinstance(evidence_gaps, list):
        raise ValidationError("agent-replay-generic-shape-invalid")

    ids: set[str] = set()
    parent_ref_count: dict[str, int] = {}
    for event in timeline:
        if not isinstance(event, dict):
            raise ValidationError("agent-replay-timeline-event-invalid")
        event_id = event.get("event_id")
        parents = event.get("parent_ids", [])
        if not isinstance(event_id, str) or not event_id or event_id in ids:
            raise ValidationError("agent-replay-event-id-invalid")
        if not isinstance(parents, list) or any(not isinstance(p, str) or not p for p in parents):
            raise ValidationError("agent-replay-parent-ids-invalid")
        ids.add(event_id)
        for parent in parents:
            parent_ref_count[parent] = parent_ref_count.get(parent, 0) + 1

    dangling = sorted(parent for parent in parent_ref_count if parent not in ids)
    branch_points = sorted(parent for parent, count in parent_ref_count.items() if count > 1)

    first = report.get("first_provable_divergence")
    observations = [
        {
            "kind": "agent.replay.reconstruction",
            "schema": report["schema"],
            "input_sha256": report.get("input_sha256"),
            "canonical_sha256": canonical_sha,
            "event_count": report.get("event_count"),
            "reconstruction_status": report.get("reconstruction_status"),
            "expectation_coverage": report.get("expectation_coverage"),
            "evidence_completeness": report.get("evidence_completeness"),
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.replay.branch-structure",
            "branch_points": branch_points,
            "dangling_parent_ids": dangling,
            "branch_structure_preserved": True,
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.replay.first-provable-divergence",
            "value": first,
            "evidence_refs": ["evidence:agent-replay-report"],
        },
    ]

    determinations = [
        {
            "kind": "reconstruction.available",
            "status": "ESTABLISHED",
            "detail": "A structurally accepted Agent Replay reconstruction was supplied and bound into the Try DDC evidence set.",
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "chronology-vs-causality",
            "status": "PARTIALLY_ESTABLISHED",
            "detail": "Replay timeline ordering and explicit parent/causal structures are preserved separately; chronological order alone is not promoted to causality.",
            "evidence_refs": ["evidence:agent-replay-report"],
        },
    ]
    if dangling:
        determinations.append({
            "kind": "replay.parent-continuity",
            "status": "CONTRADICTED",
            "detail": "One or more parent references are absent from the supplied reconstruction.",
            "evidence_refs": ["evidence:agent-replay-report"],
        })
    else:
        determinations.append({
            "kind": "replay.parent-continuity",
            "status": "ESTABLISHED",
            "detail": "All explicit parent references resolve within the supplied reconstruction.",
            "evidence_refs": ["evidence:agent-replay-report"],
        })

    contradictions = [
        {"kind": "replay.divergence", "value": item, "evidence_refs": ["evidence:agent-replay-report"]}
        for item in divergences
    ]
    unresolved = [
        {"kind": "replay.evidence-gap", "value": item, "evidence_refs": ["evidence:agent-replay-report"]}
        for item in evidence_gaps
    ]
    limitations = [
        "Agent Replay expected-state assertions are caller supplied unless independently authenticated by separate evidence.",
        "Agent Replay structural confidence is not independent proof of truth, identity, policy provenance, or complete telemetry.",
        "Chronology is not treated as causality; only explicit reconstructed links are preserved as causal claims.",
        "Later reconstruction does not become contemporaneous evidence of an earlier event.",
    ]
    return observations, determinations, contradictions, unresolved, limitations


def _aps(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    for key in ("identity", "authority", "policy", "binding", "execution", "evidence_boundary", "external_conformance"):
        if not isinstance(report.get(key), dict):
            raise ValidationError(f"agent-replay-aps-{key}-invalid")

    identity = report["identity"]
    authority = report["authority"]
    policy = report["policy"]
    binding = report["binding"]
    execution = report["execution"]
    boundary = report["evidence_boundary"]

    if boundary.get("permit_is_execution") is not False:
        raise ValidationError("agent-replay-aps-permit-execution-boundary-invalid")
    if boundary.get("external_conformance_is_replay_verification") is not False:
        raise ValidationError("agent-replay-aps-conformance-boundary-invalid")
    if execution.get("external_effect_proof") is not False:
        raise ValidationError("agent-replay-aps-external-effect-boundary-invalid")

    observations = [
        {
            "kind": "agent.authority.identity",
            "claimed_actor": identity.get("claimed_actor"),
            "intent_issuer": identity.get("intent_issuer"),
            "intent_signer": identity.get("intent_signer"),
            "intent_signature_assessment": identity.get("intent_signature_assessment"),
            "independent_authentication": identity.get("independent_authentication"),
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.authority.delegation",
            "root_principal": authority.get("root_principal"),
            "delegation_path": authority.get("delegation_path"),
            "structural_binding": authority.get("structural_binding"),
            "independent_cryptographic_verification": authority.get("independent_cryptographic_verification"),
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.authority.policy",
            "issuer": policy.get("issuer"),
            "signer": policy.get("signer"),
            "verdict": policy.get("verdict"),
            "reason": policy.get("reason"),
            "independent_authentication": policy.get("independent_authentication"),
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.authority.execution",
            "execution_status": report.get("execution_status"),
            "bound_events": execution.get("bound_events", []),
            "partially_bound_events": execution.get("partially_bound_events", []),
            "unbound_events": execution.get("unbound_events", []),
            "external_effect_proof": False,
            "evidence_refs": ["evidence:agent-replay-report"],
        },
    ]

    checks = binding.get("checks")
    if not isinstance(checks, dict):
        raise ValidationError("agent-replay-aps-binding-checks-invalid")
    binding_status = binding.get("status")
    binding_map = {"COMPLETE": "ESTABLISHED", "PARTIAL": "PARTIALLY_ESTABLISHED", "BROKEN": "CONTRADICTED"}
    if binding_status not in binding_map:
        raise ValidationError("agent-replay-aps-binding-status-invalid")

    determinations = [
        {
            "kind": "agent.structural-binding",
            "status": binding_map[binding_status],
            "detail": "Agent Replay structural action/receipt/delegation binding is preserved without upgrading it to independent cryptographic authentication.",
            "checks": checks,
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.execution-boundary",
            "status": "PARTIALLY_ESTABLISHED" if execution.get("bound_events") else "NOT_ESTABLISHED",
            "detail": "Bound post-dispatch execution evidence is kept separate from policy permit and from downstream external effect proof.",
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.downstream-consequence",
            "status": "UNRESOLVED",
            "detail": "No supplied Agent Replay execution event is promoted to proof of an external downstream effect.",
            "evidence_refs": ["evidence:agent-replay-report"],
        },
    ]

    contradictions = []
    if binding_status == "BROKEN":
        contradictions.append({
            "kind": "agent.binding-contradiction",
            "checks": checks,
            "evidence_refs": ["evidence:agent-replay-report"],
        })

    unresolved = []
    if identity.get("independent_authentication") != "VERIFIED":
        unresolved.append({
            "kind": "actor-authentication",
            "detail": "Claimed actor identity is not independently authenticated by the supplied Replay reconstruction.",
            "evidence_refs": ["evidence:agent-replay-report"],
        })
    if authority.get("independent_cryptographic_verification") != "VERIFIED":
        unresolved.append({
            "kind": "authority-cryptography",
            "detail": "Delegated authority cryptography is not independently verified by the supplied Replay reconstruction.",
            "evidence_refs": ["evidence:agent-replay-report"],
        })
    unresolved.append({
        "kind": "external-effect",
        "detail": "External downstream effect proof remains absent.",
        "evidence_refs": ["evidence:agent-replay-report"],
    })

    limitations = [
        "Claimed actor, authenticated actor, delegated authority, policy decision, dispatch/execution evidence, and downstream effect are not collapsed into one status.",
        "External APS conformance outcomes remain external evidence and are not treated as Replay verification.",
        "A policy permit is not execution evidence.",
        "A bound action-result receipt is a post-dispatch observation, not proof of an external effect.",
        "Later reconstruction does not become contemporaneous authority or evidence for the earlier action.",
    ]
    return observations, determinations, contradictions, unresolved, limitations


def analyze_agent_replay(
    report: dict[str, Any],
    *,
    captured_at: str,
    analysis_time: str,
    implementation_revision: str,
) -> tuple[EvidenceManifest, TryDDCResult]:
    if not isinstance(report, dict):
        raise ValidationError("agent-replay-report-must-be-object")

    schema, target_id, case_id = _identity(report)
    capability = CapabilityIdentity(
        capability_id=CAPTURE_DESCRIPTOR["id"],
        capability_version=CAPTURE_DESCRIPTOR["version"],
        capability_digest=CAPTURE_DIGEST,
        implementation_revision=implementation_revision,
    )

    evidence = (
        EvidenceItem(
            evidence_id="evidence:agent-replay-report",
            target_id=target_id,
            source_class="DERIVED",
            capture_capability=capability,
            digest=sha256_digest(report),
            captured_at=captured_at,
            source_identity="Agent-Replay",
            causal_origin="agent-replay-reconstruction",
            classification="CUSTOMER_PRIVATE",
            derived_from=("evidence:agent-replay-input-commitment",),
            derivation_method="Agent-Replay",
            derivation_method_version=str(report.get("adapter_validation", {}).get("revision") or report.get("tool_revision") or "UNSPECIFIED"),
            authorization_status="UNRESOLVED",
            representation="AGENT_REPLAY_RECONSTRUCTION",
            time_source="replay-capture",
            time_trust="UNRESOLVED",
            freshness_status="UNRESOLVED",
            freshness_policy="reconstruction-time-is-not-event-time",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
            limitations=("derived-reconstruction-not-contemporaneous-source-evidence",),
        ),
        EvidenceItem(
            evidence_id="evidence:agent-replay-input-commitment",
            target_id=target_id,
            source_class="USER_SUPPLIED",
            capture_capability=capability,
            digest="sha256:" + (_raw_sha(report.get("input_sha256"), "agent-replay-input-sha256", allow_none=True) or "0" * 64),
            captured_at=captured_at,
            source_identity="agent-replay-input",
            causal_origin="input-digest-reported-by-agent-replay",
            classification="CUSTOMER_PRIVATE",
            authorization_status="UNRESOLVED",
            representation="DIGEST_COMMITMENT",
            time_source="replay-report",
            time_trust="UNRESOLVED",
            freshness_status="UNRESOLVED",
            reachability="UNRESOLVED",
            discoverability="UNRESOLVED",
            accessibility="UNRESOLVED",
            trustworthiness="UNRESOLVED",
            consulted=True,
            limitations=("zero-digest-sentinel-means-input-digest-not-established",) if report.get("input_sha256") is None else (),
        ),
    )

    # EvidenceManifest validates derived parent existence regardless of tuple order.
    manifest = EvidenceManifest(
        case_id=case_id,
        target_id=target_id,
        profile_id=PROFILE_DESCRIPTOR["id"],
        profile_version=PROFILE_DESCRIPTOR["version"],
        profile_digest=PROFILE_DIGEST,
        capture_revision=1,
        evidence=evidence,
        frozen_at=captured_at,
    )

    if schema == "agent-replay.incident.v2":
        observations, determinations, contradictions, unresolved, limitations = _generic(report)
    else:
        observations, determinations, contradictions, unresolved, limitations = _aps(report)

    result_id = "result:" + sha256_digest({
        "case_id": case_id,
        "target_id": target_id,
        "evidence_root": manifest.evidence_root,
        "profile_digest": PROFILE_DIGEST,
    }).split(":", 1)[1][:24]

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
        observations=tuple(observations),
        determinations=tuple(determinations),
        contradictions=tuple(contradictions),
        unresolved=tuple(unresolved),
        limitations=tuple(limitations),
        synthesis={
            "method": "agent.trace.v1",
            "version": "1",
            "source_schema": schema,
            "chronology_is_causality": False,
            "permit_is_execution": False,
            "execution_is_downstream_consequence": False,
        },
        capabilities=(capability,),
        minimum_coverage_met=False,
    )
    return manifest, result
