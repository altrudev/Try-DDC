from __future__ import annotations

import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError


PROFILE_DESCRIPTOR = {
    "id": "protocol.mcp.observe.v1",
    "version": "1",
    "purpose": "read-only MCP endpoint surface observation and bounded baseline drift analysis",
    "execution_authority": False,
    "tool_invocation_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "protocol.mcp.observe",
    "version": "1",
    "methods": ["server/discover", "tools/list", "resources/list", "prompts/list"],
    "tool_invocation_authority": False,
    "prompt_invocation_authority": False,
    "resource_read_authority": False,
    "execution_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

SNAPSHOT_SCHEMA = "try-ddc-mcp-observation/1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_snapshot(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != SNAPSHOT_SCHEMA:
        raise ValidationError(f"invalid-{label}-snapshot")
    endpoint = value.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
        raise ValidationError(f"invalid-{label}-endpoint")
    if value.get("observation_complete") is not True:
        raise ValidationError(f"incomplete-{label}-observation")
    server = value.get("server")
    transport = value.get("transport")
    if not isinstance(server, dict) or not isinstance(transport, dict):
        raise ValidationError(f"invalid-{label}-identity")
    for key in ("tools", "resources", "prompts"):
        if not isinstance(value.get(key, []), list):
            raise ValidationError(f"invalid-{label}-{key}")
    return value


def _tool_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in snapshot.get("tools", []):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
            raise ValidationError("invalid-mcp-tool")
        if item["name"] in out:
            raise ValidationError("duplicate-mcp-tool")
        out[item["name"]] = item
    return out


def _keyed(items: list[Any], *, key_fields: tuple[str, ...], label: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValidationError(f"invalid-mcp-{label}")
        key = next((item.get(k) for k in key_fields if isinstance(item.get(k), str) and item.get(k)), None)
        if key is None:
            raise ValidationError(f"invalid-mcp-{label}-identity")
        if key in out:
            raise ValidationError(f"duplicate-mcp-{label}")
        out[key] = item
    return out


def _schema_change(before: Any, after: Any) -> tuple[str, str]:
    if before == after:
        return "UNCHANGED", "NONE"
    if not isinstance(before, dict) or not isinstance(after, dict):
        return "CHANGED_DIRECTION_UNRESOLVED", "HIGH"
    widened = False
    narrowed = False

    ba = before.get("additionalProperties")
    aa = after.get("additionalProperties")
    if isinstance(ba, bool) and isinstance(aa, bool) and ba != aa:
        widened |= (ba is False and aa is True)
        narrowed |= (ba is True and aa is False)

    br = set(x for x in before.get("required", []) if isinstance(x, str)) if isinstance(before.get("required", []), list) else set()
    ar = set(x for x in after.get("required", []) if isinstance(x, str)) if isinstance(after.get("required", []), list) else set()
    widened |= bool(br - ar)
    narrowed |= bool(ar - br)

    be = before.get("enum")
    ae = after.get("enum")
    if isinstance(be, list) and isinstance(ae, list):
        bs = {repr(x) for x in be}
        aset = {repr(x) for x in ae}
        widened |= bs < aset
        narrowed |= aset < bs

    if widened:
        return "WIDENED", "HIGH"
    if narrowed:
        return "NARROWED", "MEDIUM"
    return "CHANGED_DIRECTION_UNRESOLVED", "HIGH"


def _compare(baseline: dict[str, Any], live: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if baseline["endpoint"] != live["endpoint"]:
        changes.append({"category": "identity", "kind": "endpoint_changed", "severity": "HIGH"})

    bt, lt = baseline["transport"], live["transport"]
    if bt.get("tls_spki_sha256") and lt.get("tls_spki_sha256"):
        if bt.get("tls_spki_sha256") != lt.get("tls_spki_sha256"):
            changes.append({"category": "identity", "kind": "tls_spki_changed", "severity": "HIGH"})
    elif bt.get("tls_cert_sha256") and lt.get("tls_cert_sha256") and bt.get("tls_cert_sha256") != lt.get("tls_cert_sha256"):
        changes.append({
            "category": "identity",
            "kind": "tls_certificate_changed",
            "severity": "MEDIUM",
            "limitation": "SPKI identity unavailable; certificate change direction cannot be reduced to key rotation semantics.",
        })

    bs, ls = baseline["server"], live["server"]
    if bs.get("protocol_version") != ls.get("protocol_version"):
        changes.append({"category": "protocol", "kind": "protocol_version_changed", "severity": "MEDIUM"})
    if bs.get("supported_versions") != ls.get("supported_versions"):
        changes.append({"category": "protocol", "kind": "supported_versions_changed", "severity": "MEDIUM"})
    if bs.get("name") != ls.get("name"):
        changes.append({"category": "metadata", "kind": "self_reported_name_changed", "severity": "MEDIUM"})

    btools, ltools = _tool_map(baseline), _tool_map(live)
    for name in sorted(ltools.keys() - btools.keys()):
        changes.append({"category": "capability", "kind": "tool_added", "name": name, "severity": "HIGH"})
    for name in sorted(btools.keys() - ltools.keys()):
        changes.append({"category": "capability", "kind": "tool_removed", "name": name, "severity": "MEDIUM"})
    for name in sorted(btools.keys() & ltools.keys()):
        b, l = btools[name], ltools[name]
        kind, severity = _schema_change(b.get("input_schema"), l.get("input_schema"))
        if kind != "UNCHANGED":
            changes.append({"category": "authority", "kind": "tool_schema_" + kind.lower(), "name": name, "severity": severity})
        if b.get("annotations") != l.get("annotations"):
            changes.append({"category": "capability", "kind": "tool_annotations_changed", "name": name, "severity": "MEDIUM"})
        if b.get("description") != l.get("description"):
            changes.append({"category": "description", "kind": "tool_description_changed", "name": name, "severity": "LOW"})

    for label, keys in (("resource", ("uri", "name")), ("prompt", ("name",))):
        bm = _keyed(baseline.get(label + "s", []), key_fields=keys, label=label)
        lm = _keyed(live.get(label + "s", []), key_fields=keys, label=label)
        for name in sorted(lm.keys() - bm.keys()):
            changes.append({"category": "capability", "kind": label + "_added", "name": name, "severity": "MEDIUM"})
        for name in sorted(bm.keys() - lm.keys()):
            changes.append({"category": "capability", "kind": label + "_removed", "name": name, "severity": "LOW"})
        for name in sorted(bm.keys() & lm.keys()):
            if bm[name] != lm[name]:
                changes.append({"category": "capability", "kind": label + "_changed", "name": name, "severity": "MEDIUM"})

    if baseline.get("auth") != live.get("auth"):
        changes.append({"category": "authorization", "kind": "authorization_metadata_changed", "severity": "HIGH"})
    return changes


def analyze_mcp_observation(
    live_snapshot: dict[str, Any],
    *,
    captured_at: str,
    analysis_time: str,
    implementation_revision: str,
    baseline_snapshot: dict[str, Any] | None = None,
    classification: str = "CUSTOMER_PRIVATE",
) -> tuple[EvidenceManifest, TryDDCResult]:
    live = _require_snapshot(live_snapshot, "live")
    baseline = _require_snapshot(baseline_snapshot, "baseline") if baseline_snapshot is not None else None
    if classification not in {"PUBLIC", "CUSTOMER_PRIVATE", "SENSITIVE"}:
        raise ValidationError("invalid-mcp-classification")

    endpoint_hash = sha256_digest({
        "endpoint": live["endpoint"],
        "transport_host": live["transport"].get("host"),
    }).split(":", 1)[1]
    target_id = "target:" + endpoint_hash[:24]
    case_id = "case:" + endpoint_hash[24:48]

    capability = CapabilityIdentity(
        capability_id=CAPTURE_DESCRIPTOR["id"],
        capability_version=CAPTURE_DESCRIPTOR["version"],
        capability_digest=CAPTURE_DIGEST,
        implementation_revision=implementation_revision,
    )
    evidence = [
        EvidenceItem(
            evidence_id="evidence:mcp-live-snapshot",
            target_id=target_id,
            source_class="PROTOCOL_OBSERVATION",
            capture_capability=capability,
            digest=sha256_digest(live),
            captured_at=captured_at,
            source_identity=str(live["transport"].get("host") or live["endpoint"]),
            causal_origin="read-only-mcp-discovery-and-list-observation",
            classification=classification,
            authorization_status="ANONYMOUS_OBSERVATION",
            representation="MCP_OBSERVABLE_SURFACE",
            time_source="observer-clock",
            time_trust="UNRESOLVED",
            freshness_status="ESTABLISHED",
            freshness_policy="single-bounded-observation",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
            limitations=("self-reported-server-metadata-is-not-cryptographic-identity",),
        )
    ]
    if baseline is not None:
        evidence.append(EvidenceItem(
            evidence_id="evidence:mcp-baseline-snapshot",
            target_id=target_id,
            source_class="USER_SUPPLIED",
            capture_capability=capability,
            digest=sha256_digest(baseline),
            captured_at=captured_at,
            source_identity="caller-supplied-mcp-baseline",
            causal_origin="baseline-supplied-for-bounded-drift-comparison",
            classification=classification,
            authorization_status="UNRESOLVED",
            representation="MCP_OBSERVABLE_SURFACE_BASELINE",
            time_source="caller-supplied",
            time_trust="UNRESOLVED",
            freshness_status="UNRESOLVED",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
            limitations=("baseline-approval-and-authenticity-not-established-by-input-shape",),
        ))

    manifest = EvidenceManifest(
        case_id=case_id,
        target_id=target_id,
        profile_id=PROFILE_DESCRIPTOR["id"],
        profile_version=PROFILE_DESCRIPTOR["version"],
        profile_digest=PROFILE_DIGEST,
        capture_revision=1,
        evidence=tuple(evidence),
        frozen_at=captured_at,
    )

    changes = _compare(baseline, live) if baseline is not None else []
    high = any(c["severity"] == "HIGH" for c in changes)
    observations = (
        {
            "kind": "mcp.endpoint.identity",
            "endpoint": live["endpoint"],
            "server_name": live["server"].get("name"),
            "server_version": live["server"].get("version"),
            "protocol_version": live["server"].get("protocol_version"),
            "supported_versions": live["server"].get("supported_versions", []),
            "self_reported_identity": True,
            "transport": live["transport"],
            "evidence_refs": ["evidence:mcp-live-snapshot"],
        },
        {
            "kind": "mcp.surface.inventory",
            "tools": len(live.get("tools", [])),
            "resources": len(live.get("resources", [])),
            "prompts": len(live.get("prompts", [])),
            "capabilities_digest": sha256_digest(live.get("capabilities", {})),
            "inventory_digest": sha256_digest({
                "tools": live.get("tools", []),
                "resources": live.get("resources", []),
                "prompts": live.get("prompts", []),
            }),
            "evidence_refs": ["evidence:mcp-live-snapshot"],
        },
        {
            "kind": "mcp.authority-boundary",
            "advertised_tools_invoked": False,
            "advertised_prompts_invoked": False,
            "resources_read": False,
            "arbitrary_rpc_invoked": False,
            "evidence_refs": ["evidence:mcp-live-snapshot"],
        },
    )

    determinations = [{
        "kind": "mcp.observation.complete",
        "status": "ESTABLISHED",
        "detail": "Advertised MCP inventories were completely enumerated within configured bounds; no advertised tool was invoked.",
        "evidence_refs": ["evidence:mcp-live-snapshot"],
    }]
    if baseline is None:
        determinations.append({
            "kind": "mcp.baseline-drift",
            "status": "OUT_OF_SCOPE",
            "detail": "No baseline snapshot was supplied, so drift is not evaluated.",
            "evidence_refs": ["evidence:mcp-live-snapshot"],
        })
    else:
        determinations.append({
            "kind": "mcp.baseline-drift",
            "status": "CONTRADICTED" if changes else "ESTABLISHED",
            "detail": "Observed surface differs from the supplied baseline." if changes else "No bounded observable-surface drift was detected against the supplied baseline.",
            "change_count": len(changes),
            "evidence_refs": ["evidence:mcp-live-snapshot", "evidence:mcp-baseline-snapshot"],
        })

    contradictions = tuple({
        "kind": "mcp.surface-drift",
        **change,
        "evidence_refs": ["evidence:mcp-live-snapshot", "evidence:mcp-baseline-snapshot"],
    } for change in changes)

    unresolved = [
        {
            "kind": "mcp.backend-identity",
            "detail": "An unchanged observable MCP surface does not establish unchanged source, binary, container, dependency, or backend implementation.",
        },
        {
            "kind": "mcp.baseline-approval",
            "detail": "Supplying a baseline does not establish that the baseline was approved, safe, or authentic.",
        },
    ]
    if not live["transport"].get("tls_spki_sha256"):
        unresolved.append({
            "kind": "mcp.transport-key-identity",
            "detail": "TLS certificate identity may be observed while SPKI identity remains unavailable in this capture path.",
        })

    limitations = (
        "MCP server name/version are self-reported metadata, not cryptographic identity.",
        "The profile observes advertised surface only and never invokes advertised tools.",
        "A stable externally observable surface does not prove a stable backend implementation.",
        "A baseline match is an integrity comparison, not a safety determination.",
        "Authentication bypass is not attempted; inaccessible protected inventories fail capture rather than being guessed.",
    )

    result_seed = {
        "case_id": case_id,
        "target_id": target_id,
        "evidence_root": manifest.evidence_root,
        "profile_digest": PROFILE_DIGEST,
    }
    result = TryDDCResult(
        result_id="result:" + sha256_digest(result_seed).split(":", 1)[1][:24],
        case_id=case_id,
        target_id=target_id,
        profile_id=PROFILE_DESCRIPTOR["id"],
        profile_version=PROFILE_DESCRIPTOR["version"],
        profile_digest=PROFILE_DIGEST,
        evidence_root=manifest.evidence_root,
        analysis_status="COMPLETE",
        evidentiary_status="CONTRADICTED" if changes else "PARTIALLY_ESTABLISHED",
        risk_disposition="HIGH_RISK_OBSERVED" if high else "REVIEW_REQUIRED",
        analysis_time=analysis_time,
        observations=observations,
        determinations=tuple(determinations),
        contradictions=contradictions,
        unresolved=tuple(unresolved),
        limitations=limitations,
        synthesis={
            "method": "protocol.mcp.observe.v1",
            "version": "1",
            "baseline_supplied": baseline is not None,
            "drift_change_count": len(changes),
            "tool_invocation_performed": False,
        },
        capabilities=(capability,),
        minimum_coverage_met=False,
    )
    return manifest, result
