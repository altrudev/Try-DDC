from __future__ import annotations

from collections import defaultdict
import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError


PROFILE_DESCRIPTOR = {
    "id": "agent.trace.v1",
    "version": "1",
    "purpose": "map Agent Replay reconstruction evidence into the Try DDC evidence model without strengthening claims",
    "execution_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "agent.trace.agent-replay-report",
    "version": "1",
    "accepted_schemas": [
        "agent-replay.incident.v2",
        "agent-replay.aps-authority-reconstruction.v2",
    ],
    "execution_authority": False,
    "network_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

AGENT_REPLAY_VALIDATED_VERSION = "0.6.0"
AGENT_REPLAY_VALIDATED_REVISION = "1f4db7a12e8ddf8853c2533f08f8252f7efbe326"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CLASSIFICATIONS = {"PUBLIC", "CUSTOMER_PRIVATE", "SENSITIVE"}


def _digest64(value: Any, name: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value


def _report_target(report: dict[str, Any]) -> tuple[str, str]:
    seed = {
        "schema": report.get("schema"),
        "input_sha256": report.get("input_sha256"),
        "canonical_sha256": report.get("canonical_sha256"),
        "fixture": (report.get("external_conformance") or {}).get("fixture")
        if isinstance(report.get("external_conformance"), dict)
        else None,
    }
    h = sha256_digest(seed).split(":", 1)[1]
    return "target:" + h[:24], "case:" + h[24:48]


def _lineage(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    ids: set[str] = set()
    parents: dict[str, tuple[str, ...]] = {}
    children: dict[str, list[str]] = defaultdict(list)
    for event in timeline:
        eid = event.get("event_id")
        if not isinstance(eid, str) or not eid:
            raise ValidationError("agent-replay-event-id-invalid")
        if eid in ids:
            raise ValidationError("agent-replay-duplicate-event-id")
        ids.add(eid)
        raw_parents = event.get("parent_ids", [])
        if not isinstance(raw_parents, list) or any(not isinstance(x, str) or not x for x in raw_parents):
            raise ValidationError("agent-replay-parent-ids-invalid")
        parents[eid] = tuple(raw_parents)
    for eid, raw_parents in parents.items():
        for parent in raw_parents:
            if parent not in ids:
                raise ValidationError("agent-replay-parent-missing")
            children[parent].append(eid)

    roots = sorted(eid for eid in ids if not parents[eid])
    leaves = sorted(eid for eid in ids if not children.get(eid))
    branches = [
        {"event_id": eid, "child_ids": sorted(child_ids)}
        for eid, child_ids in sorted(children.items())
        if len(child_ids) > 1
    ]
    return {
        "roots": roots,
        "leaves": leaves,
        "branch_points": branches,
        "branch_structure_preserved": True,
        "branch_interpretation": "EXPLICIT_PARENT_LINKS_ONLY",
    }


def _incident_mapping(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    timeline = report.get("timeline")
    if not isinstance(timeline, list) or len(timeline) > 10000:
        raise ValidationError("agent-replay-timeline-invalid")
    if any(not isinstance(item, dict) for item in timeline):
        raise ValidationError("agent-replay-timeline-item-invalid")

    lineage = _lineage(timeline)
    first = report.get("first_provable_divergence")
    gaps = report.get("evidence_gaps", [])
    if not isinstance(gaps, list):
        raise ValidationError("agent-replay-evidence-gaps-invalid")

    observations = [
        {
            "kind": "agent.trace.reconstruction",
            "schema": report["schema"],
            "event_count": report.get("event_count"),
            "reconstruction_status": report.get("reconstruction_status"),
            "expectation_coverage": report.get("expectation_coverage"),
            "evidence_completeness": report.get("evidence_completeness"),
            "reproducibility": report.get("reproducibility"),
            "evidence_ref": "evidence:agent-replay-report",
        },
        {
            "kind": "agent.trace.lineage",
            **lineage,
            "evidence_ref": "evidence:agent-replay-report",
        },
        {
            "kind": "agent.trace.identity-boundary",
            "claimed_actors": sorted({
                str(item.get("actor"))
                for item in timeline
                if item.get("actor") not in (None, "")
            }),
            "authenticated_actor": None,
            "authentication_status": "NOT_ESTABLISHED",
            "evidence_ref": "evidence:agent-replay-report",
        },
        {
            "kind": "agent.trace.evidence-channel",
            "existence": "PARTIALLY_ESTABLISHED" if timeline else "NOT_ESTABLISHED",
            "reachability": "UNRESOLVED",
            "discoverability": "UNRESOLVED",
            "timeliness": "UNRESOLVED",
            "accessibility": "UNRESOLVED",
            "trustworthiness": "UNRESOLVED",
            "consultation": "PARTIALLY_ESTABLISHED" if timeline else "UNRESOLVED",
            "reconstruction_status": "NOT_RECONSTRUCTED_BY_SUPPLIED_REPORT",
            "evidence_ref": "evidence:agent-replay-report",
        },
    ]

    determinations: list[dict[str, Any]] = []
    if first is None:
        determinations.append({
            "kind": "agent.trace.first-provable-divergence",
            "status": "NOT_ESTABLISHED",
            "detail": "The supplied Agent Replay report does not establish a first provable divergence.",
            "evidence_refs": ["evidence:agent-replay-report"],
        })
    elif isinstance(first, dict):
        determinations.append({
            "kind": "agent.trace.first-provable-divergence",
            "status": "ESTABLISHED",
            "detail": "A first provable divergence is asserted by the supplied deterministic Agent Replay reconstruction.",
            "event_id": first.get("event_id"),
            "mismatches": first.get("mismatches", []),
            "claim_scope": "SUPPLIED_AGENT_REPLAY_RECONSTRUCTION",
            "evidence_refs": ["evidence:agent-replay-report"],
        })
    else:
        raise ValidationError("agent-replay-first-divergence-invalid")

    causal_chain = report.get("causal_chain", [])
    if not isinstance(causal_chain, list):
        raise ValidationError("agent-replay-causal-chain-invalid")
    for item in causal_chain:
        if isinstance(item, dict) and item.get("relationship") == "TEMPORALLY_DOWNSTREAM":
            determinations.append({
                "kind": "agent.trace.temporal-not-causal",
                "status": "ESTABLISHED",
                "event_id": item.get("event_id"),
                "detail": "This event is temporally downstream in the supplied report; causality is not established by chronology alone.",
                "evidence_refs": ["evidence:agent-replay-report"],
            })

    contradictions = [
        {
            "kind": "agent.trace.divergence",
            "event_id": item.get("event_id"),
            "mismatches": item.get("mismatches", []),
            "evidence_refs": ["evidence:agent-replay-report"],
        }
        for item in report.get("divergences", [])
        if isinstance(item, dict)
    ]

    unresolved = [
        {
            "kind": "agent.trace.evidence-gap",
            "gap": gap,
            "evidence_refs": ["evidence:agent-replay-report"],
        }
        for gap in gaps
    ]
    unresolved.extend([
        {
            "kind": "agent.trace.actor-authentication",
            "detail": "Actor labels in the supplied incident report are not independently authenticated by this Try DDC profile.",
        },
        {
            "kind": "agent.trace.evidence-channel",
            "detail": "The supplied Agent Replay incident report does not itself reconstruct existence, reachability, discoverability, timeliness, accessibility, trustworthiness, and consultation for each evidence channel.",
        },
        {
            "kind": "agent.trace.post-action-contamination",
            "detail": "Post-action contamination is unresolved unless explicitly represented in supplied evidence.",
        },
    ])

    limitations = [
        "Try DDC does not reinterpret caller-supplied expected-state assertions as independently authenticated policy.",
        "Chronology is not upgraded to causality; only explicit parent/relationship evidence is preserved.",
        "Actor labels remain claimed identities unless separately authenticated.",
        "Later reconstruction does not become contemporaneous evidence.",
        "Branch structure is preserved from explicit parent links and is not collapsed into one final timeline.",
        "Evidence-channel adequacy remains unresolved unless separately captured.",
    ]
    return observations, determinations, contradictions, unresolved, limitations


def _aps_mapping(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    identity = report.get("identity")
    authority = report.get("authority")
    policy = report.get("policy")
    binding = report.get("binding")
    execution = report.get("execution")
    boundary = report.get("evidence_boundary")
    external = report.get("external_conformance")
    if not all(isinstance(x, dict) for x in (identity, authority, policy, binding, execution, boundary, external)):
        raise ValidationError("agent-replay-aps-shape-invalid")
    if boundary.get("permit_is_execution") is not False:
        raise ValidationError("agent-replay-aps-permit-execution-boundary-invalid")
    if boundary.get("external_conformance_is_replay_verification") is not False:
        raise ValidationError("agent-replay-aps-conformance-boundary-invalid")
    if execution.get("external_effect_proof") is not False:
        raise ValidationError("agent-replay-aps-external-effect-boundary-invalid")

    observations = [
        {
            "kind": "agent.trace.actor",
            "claimed_actor": identity.get("claimed_actor"),
            "intent_issuer": identity.get("intent_issuer"),
            "intent_signer": identity.get("intent_signer"),
            "authentication_status": identity.get("independent_authentication"),
            "evidence_ref": "evidence:agent-replay-report",
        },
        {
            "kind": "agent.trace.delegated-authority",
            "root_principal": authority.get("root_principal"),
            "delegation_path": authority.get("delegation_path", []),
            "structural_binding": authority.get("structural_binding"),
            "cryptographic_verification": authority.get("independent_cryptographic_verification"),
            "evidence_ref": "evidence:agent-replay-report",
        },
        {
            "kind": "agent.trace.policy-decision",
            "issuer": policy.get("issuer"),
            "signer": policy.get("signer"),
            "verdict": policy.get("verdict"),
            "reason": policy.get("reason"),
            "authentication_status": policy.get("independent_authentication"),
            "evidence_ref": "evidence:agent-replay-report",
        },
        {
            "kind": "agent.trace.execution",
            "status": report.get("execution_status"),
            "bound_event_count": len(execution.get("bound_events", [])) if isinstance(execution.get("bound_events"), list) else 0,
            "partially_bound_event_count": len(execution.get("partially_bound_events", [])) if isinstance(execution.get("partially_bound_events"), list) else 0,
            "unbound_event_count": len(execution.get("unbound_events", [])) if isinstance(execution.get("unbound_events"), list) else 0,
            "external_effect_proof": False,
            "evidence_ref": "evidence:agent-replay-report",
        },
        {
            "kind": "agent.trace.evidence-channel",
            "existence": "PARTIALLY_ESTABLISHED",
            "reachability": "UNRESOLVED",
            "discoverability": "UNRESOLVED",
            "timeliness": "UNRESOLVED",
            "accessibility": "UNRESOLVED",
            "trustworthiness": "UNRESOLVED",
            "consultation": "UNRESOLVED",
            "reconstruction_status": "NOT_RECONSTRUCTED_BY_SUPPLIED_REPORT",
            "evidence_ref": "evidence:agent-replay-report",
        },
    ]

    binding_status = binding.get("status")
    binding_map = {"COMPLETE": "ESTABLISHED", "PARTIAL": "PARTIALLY_ESTABLISHED", "BROKEN": "CONTRADICTED"}
    if binding_status not in binding_map or not isinstance(binding.get("checks"), dict):
        raise ValidationError("agent-replay-aps-binding-invalid")

    execution_status = report.get("execution_status")
    execution_map = {
        "EXECUTION_EVIDENCE_BOUND_TO_ACTION": "ESTABLISHED",
        "EXECUTION_EVIDENCE_PARTIALLY_BOUND": "PARTIALLY_ESTABLISHED",
        "EXECUTION_EVIDENCE_UNBOUND": "NOT_ESTABLISHED",
        "NO_EXECUTION_EVIDENCE": "NOT_ESTABLISHED",
    }
    if execution_status not in execution_map:
        raise ValidationError("agent-replay-aps-execution-status-invalid")

    determinations = [
        {
            "kind": "agent.trace.structural-binding",
            "status": binding_map[binding_status],
            "detail": "Structural receipt/delegation binding is mapped from the supplied Agent Replay APS reconstruction.",
            "checks": binding.get("checks", {}),
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.trace.execution",
            "status": execution_map[execution_status],
            "detail": "Execution status preserves Agent Replay binding semantics and does not treat permit as execution.",
            "evidence_refs": ["evidence:agent-replay-report"],
        },
        {
            "kind": "agent.trace.downstream-effect",
            "status": "UNRESOLVED",
            "detail": "A bound execution event is not automatically proof of an external downstream effect.",
            "evidence_refs": ["evidence:agent-replay-report"],
        },
    ]

    contradictions = []
    if binding_status == "BROKEN":
        contradictions.append({
            "kind": "agent.trace.binding-contradiction",
            "checks": binding.get("checks", {}),
            "evidence_refs": ["evidence:agent-replay-report"],
        })

    unresolved = []
    if identity.get("independent_authentication") != "VERIFIED":
        unresolved.append({
            "kind": "agent.trace.authenticated-actor",
            "detail": "Claimed actor is preserved separately from independently authenticated actor identity.",
        })
    if authority.get("independent_cryptographic_verification") != "VERIFIED":
        unresolved.append({
            "kind": "agent.trace.authority-authentication",
            "detail": "Delegation structure is not upgraded to independently verified authority.",
        })
    unresolved.extend([
        {
            "kind": "agent.trace.external-conformance",
            "detail": "External conformance fields remain a separate evidence layer and are not treated as Agent Replay verification.",
        },
        {
            "kind": "agent.trace.evidence-channel",
            "detail": "Evidence-channel adequacy and propagation latency remain unresolved unless separately captured.",
        },
        {
            "kind": "agent.trace.post-action-contamination",
            "detail": "Post-action contamination remains unresolved unless the source evidence explicitly reconstructs it.",
        },
    ])

    limitations = [
        "Permit is not execution.",
        "Dispatch or bound action-result evidence is not automatically downstream consequence proof.",
        "Claimed actor, delegated authority, policy decision, structural binding, and observed execution remain separate evidence dimensions.",
        "External conformance is not silently upgraded to Replay verification.",
        "Evidence-channel existence, reachability, discoverability, freshness, access, trust, and consultation are not inferred when absent.",
    ]
    return observations, determinations, contradictions, unresolved, limitations


def analyze_agent_replay_report(
    report: dict[str, Any],
    *,
    captured_at: str,
    analysis_time: str,
    implementation_revision: str,
    classification: str = "CUSTOMER_PRIVATE",
) -> tuple[EvidenceManifest, TryDDCResult]:
    if not isinstance(report, dict):
        raise ValidationError("agent-replay-report-must-be-object")
    if classification not in _CLASSIFICATIONS:
        raise ValidationError("invalid-agent-trace-classification")

    schema = report.get("schema")
    if schema not in CAPTURE_DESCRIPTOR["accepted_schemas"]:
        raise ValidationError("unsupported-agent-replay-schema")

    _digest64(report.get("input_sha256"), "agent-replay-input-sha256", allow_none=(schema != "agent-replay.incident.v2"))
    if schema == "agent-replay.incident.v2":
        _digest64(report.get("canonical_sha256"), "agent-replay-canonical-sha256")
        mapped = _incident_mapping(report)
    else:
        mapped = _aps_mapping(report)

    target_id, case_id = _report_target(report)
    capability = CapabilityIdentity(
        capability_id=CAPTURE_DESCRIPTOR["id"],
        capability_version=CAPTURE_DESCRIPTOR["version"],
        capability_digest=CAPTURE_DIGEST,
        implementation_revision=implementation_revision,
    )

    # A report passed to Try DDC is caller supplied unless a separate transport/
    # signature layer proves otherwise. Its contents may describe derived Agent
    # Replay findings, but input shape alone never upgrades source provenance.
    evidence = (
        EvidenceItem(
            evidence_id="evidence:agent-replay-report",
            target_id=target_id,
            source_class="USER_SUPPLIED",
            capture_capability=capability,
            digest=sha256_digest(report),
            captured_at=captured_at,
            source_identity="agent-replay-report",
            causal_origin="caller-supplied-agent-replay-reconstruction",
            classification=classification,
            authorization_status="UNRESOLVED",
            representation="CANONICAL_JSON_REPORT",
            time_source="caller-supplied-capture-time",
            time_trust="UNRESOLVED",
            freshness_status="UNRESOLVED",
            freshness_policy="report-capture-time-only",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
            limitations=(
                "report-origin-not-independently-authenticated",
                "agent-replay-report-does-not-prove-underlying-evidence-truth",
            ),
        ),
    )

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

    observations, determinations, contradictions, unresolved, limitations = mapped
    result_seed = {
        "case_id": case_id,
        "target_id": target_id,
        "evidence_root": manifest.evidence_root,
        "profile_digest": PROFILE_DIGEST,
        "agent_replay_report_digest": evidence[0].digest,
    }
    result_id = "result:" + sha256_digest(result_seed).split(":", 1)[1][:24]

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
            "agent_replay_validated_version": AGENT_REPLAY_VALIDATED_VERSION,
            "agent_replay_validated_revision": AGENT_REPLAY_VALIDATED_REVISION,
            "source_report_schema": schema,
            "claim_rule": "DO_NOT_STRENGTHEN_SOURCE_REPORT",
        },
        capabilities=(capability,),
        minimum_coverage_met=False,
    )
    return manifest, result
