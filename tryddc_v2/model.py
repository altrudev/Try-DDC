from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any

from .canonical import sha256_digest

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")

ANALYSIS_STATUSES = {
    "COMPLETE",
    "INCOMPLETE",
    "UNSUPPORTED",
    "RATE_LIMITED",
    "CAPTURE_FAILED",
}
EVIDENTIARY_STATUSES = {
    "ESTABLISHED",
    "PARTIALLY_ESTABLISHED",
    "NOT_ESTABLISHED",
    "CONTRADICTED",
    "UNRESOLVED",
    "OUT_OF_SCOPE",
}
RISK_DISPOSITIONS = {
    "HIGH_RISK_OBSERVED",
    "REVIEW_REQUIRED",
    "NO_HIGH_RISK_OBSERVED",
}
SOURCE_CLASSES = {
    "FIRST_PARTY",
    "PROTOCOL_OBSERVATION",
    "THIRD_PARTY_ATTESTATION",
    "USER_SUPPLIED",
    "DERIVED",
}
CLASSIFICATIONS = {"PUBLIC", "CUSTOMER_PRIVATE", "SENSITIVE", "SECRET_PROHIBITED"}


class ValidationError(ValueError):
    pass


def _utc(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValidationError("invalid-time") from exc
    if parsed.tzinfo is None:
        raise ValidationError("time-must-have-timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_id(value: str, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value


def _require_digest(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value


@dataclass(frozen=True)
class CapabilityIdentity:
    capability_id: str
    capability_version: str
    capability_digest: str
    implementation_revision: str

    def __post_init__(self) -> None:
        _require_id(self.capability_id, "capability-id")
        _require_id(self.capability_version, "capability-version")
        _require_digest(self.capability_digest, "capability-digest")
        if not isinstance(self.implementation_revision, str) or not self.implementation_revision:
            raise ValidationError("invalid-implementation-revision")

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "capability_version": self.capability_version,
            "capability_digest": self.capability_digest,
            "implementation_revision": self.implementation_revision,
        }


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    target_id: str
    source_class: str
    capture_capability: CapabilityIdentity
    digest: str
    captured_at: str
    target_time: str | None = None
    source_identity: str | None = None
    causal_origin: str | None = None
    classification: str = "PUBLIC"
    derived_from: tuple[str, ...] = ()
    derivation_method: str | None = None
    derivation_method_version: str | None = None
    authorization_status: str = "UNRESOLVED"
    representation: str = "RAW_BYTES_DIGEST"
    time_source: str | None = None
    time_trust: str = "UNRESOLVED"
    freshness_status: str = "UNRESOLVED"
    freshness_policy: str | None = None
    reachability: str = "UNRESOLVED"
    discoverability: str = "UNRESOLVED"
    accessibility: str = "UNRESOLVED"
    trustworthiness: str = "UNRESOLVED"
    consulted: bool = False
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_id(self.evidence_id, "evidence-id")
        _require_id(self.target_id, "target-id")
        if self.source_class not in SOURCE_CLASSES:
            raise ValidationError("invalid-source-class")
        if self.classification not in CLASSIFICATIONS:
            raise ValidationError("invalid-classification")
        if self.classification == "SECRET_PROHIBITED":
            raise ValidationError("secret-prohibited")
        _require_digest(self.digest, "evidence-digest")
        object.__setattr__(self, "captured_at", _utc(self.captured_at))
        if self.target_time is not None:
            object.__setattr__(self, "target_time", _utc(self.target_time))
        for parent in self.derived_from:
            _require_id(parent, "derived-from")
        if self.source_class == "DERIVED":
            if not self.derived_from or not self.derivation_method or not self.derivation_method_version:
                raise ValidationError("derived-evidence-missing-provenance")
        elif self.derived_from:
            raise ValidationError("captured-evidence-cannot-have-derived-from")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "target_id": self.target_id,
            "source_class": self.source_class,
            "capture_capability": self.capture_capability.to_dict(),
            "digest": self.digest,
            "captured_at": self.captured_at,
            "target_time": self.target_time,
            "source_identity": self.source_identity,
            "causal_origin": self.causal_origin,
            "classification": self.classification,
            "derived_from": list(self.derived_from),
            "derivation_method": self.derivation_method,
            "derivation_method_version": self.derivation_method_version,
            "authorization_status": self.authorization_status,
            "representation": self.representation,
            "time_source": self.time_source,
            "time_trust": self.time_trust,
            "freshness_status": self.freshness_status,
            "freshness_policy": self.freshness_policy,
            "reachability": self.reachability,
            "discoverability": self.discoverability,
            "accessibility": self.accessibility,
            "trustworthiness": self.trustworthiness,
            "consulted": self.consulted,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class EvidenceManifest:
    case_id: str
    target_id: str
    profile_id: str
    profile_version: str
    profile_digest: str
    capture_revision: int
    evidence: tuple[EvidenceItem, ...]
    frozen_at: str

    def __post_init__(self) -> None:
        _require_id(self.case_id, "case-id")
        _require_id(self.target_id, "target-id")
        _require_id(self.profile_id, "profile-id")
        _require_id(self.profile_version, "profile-version")
        _require_digest(self.profile_digest, "profile-digest")
        if not isinstance(self.capture_revision, int) or self.capture_revision < 1:
            raise ValidationError("invalid-capture-revision")
        object.__setattr__(self, "frozen_at", _utc(self.frozen_at))
        ids: set[str] = set()
        for item in self.evidence:
            if item.target_id != self.target_id:
                raise ValidationError("cross-target-evidence")
            if item.evidence_id in ids:
                raise ValidationError("duplicate-evidence-id")
            ids.add(item.evidence_id)
        for item in self.evidence:
            if any(parent not in ids for parent in item.derived_from):
                raise ValidationError("derived-parent-missing")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": "try-ddc-evidence-manifest/2",
            "case_id": self.case_id,
            "target_id": self.target_id,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_digest": self.profile_digest,
            "capture_revision": self.capture_revision,
            "frozen_at": self.frozen_at,
            "evidence": [item.to_dict() for item in self.evidence],
        }

    @property
    def evidence_root(self) -> str:
        return sha256_digest(self.payload())


@dataclass(frozen=True)
class TryDDCResult:
    result_id: str
    case_id: str
    target_id: str
    profile_id: str
    profile_version: str
    profile_digest: str
    evidence_root: str
    analysis_status: str
    evidentiary_status: str
    risk_disposition: str
    analysis_time: str
    claims: tuple[dict[str, Any], ...] = ()
    observations: tuple[dict[str, Any], ...] = ()
    determinations: tuple[dict[str, Any], ...] = ()
    findings: tuple[dict[str, Any], ...] = ()
    contradictions: tuple[dict[str, Any], ...] = ()
    unresolved: tuple[dict[str, Any], ...] = ()
    limitations: tuple[str, ...] = ()
    synthesis: dict[str, Any] = field(default_factory=dict)
    capabilities: tuple[CapabilityIdentity, ...] = ()
    result_revision: int = 1
    minimum_coverage_met: bool = False
    predecessor_result_id: str | None = None
    retry_reason: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.result_id, "result-id"),
            (self.case_id, "case-id"),
            (self.target_id, "target-id"),
            (self.profile_id, "profile-id"),
            (self.profile_version, "profile-version"),
        ):
            _require_id(value, name)
        _require_digest(self.profile_digest, "profile-digest")
        _require_digest(self.evidence_root, "evidence-root")
        if self.analysis_status not in ANALYSIS_STATUSES:
            raise ValidationError("invalid-analysis-status")
        if self.evidentiary_status not in EVIDENTIARY_STATUSES:
            raise ValidationError("invalid-evidentiary-status")
        if self.risk_disposition not in RISK_DISPOSITIONS:
            raise ValidationError("invalid-risk-disposition")
        object.__setattr__(self, "analysis_time", _utc(self.analysis_time))
        if not isinstance(self.result_revision, int) or self.result_revision < 1:
            raise ValidationError("invalid-result-revision")
        seen_caps: set[tuple[str, str, str, str]] = set()
        for cap in self.capabilities:
            key = (
                cap.capability_id,
                cap.capability_version,
                cap.capability_digest,
                cap.implementation_revision,
            )
            if key in seen_caps:
                raise ValidationError("duplicate-result-capability")
            seen_caps.add(key)
        if self.risk_disposition == "NO_HIGH_RISK_OBSERVED":
            if self.analysis_status != "COMPLETE" or not self.minimum_coverage_met:
                raise ValidationError("no-high-risk-without-minimum-coverage")
        if self.analysis_status != "COMPLETE" and self.risk_disposition == "NO_HIGH_RISK_OBSERVED":
            raise ValidationError("incomplete-cannot-pass")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": "try-ddc-result/2",
            "document_class": "TRY_DDC_DEMO_RESULT",
            "result_id": self.result_id,
            "case_id": self.case_id,
            "target_id": self.target_id,
            "profile": {
                "id": self.profile_id,
                "version": self.profile_version,
                "digest": self.profile_digest,
            },
            "capture": {"evidence_root": self.evidence_root},
            "analysis_status": self.analysis_status,
            "evidentiary_status": self.evidentiary_status,
            "risk_disposition": self.risk_disposition,
            "analysis_time": self.analysis_time,
            "result_revision": self.result_revision,
            "capabilities": [cap.to_dict() for cap in self.capabilities],
            "claims": list(self.claims),
            "observations": list(self.observations),
            "determinations": list(self.determinations),
            "findings": list(self.findings),
            "contradictions": list(self.contradictions),
            "unresolved": list(self.unresolved),
            "limitations": list(self.limitations),
            "synthesis": dict(self.synthesis),
            "minimum_coverage_met": self.minimum_coverage_met,
            "predecessor_result_id": self.predecessor_result_id,
            "retry_reason": self.retry_reason,
        }

    @property
    def result_digest(self) -> str:
        return sha256_digest(self.payload())


@dataclass(frozen=True)
class ActivityReceipt:
    event_id: str
    capability: CapabilityIdentity
    analysis_status: str
    risk_disposition: str
    time_bucket: str
    document_class: str = "TRY_DDC_ACTIVITY_RECEIPT"

    def __post_init__(self) -> None:
        _require_id(self.event_id, "event-id")
        if self.analysis_status not in ANALYSIS_STATUSES:
            raise ValidationError("invalid-analysis-status")
        if self.risk_disposition not in RISK_DISPOSITIONS:
            raise ValidationError("invalid-risk-disposition")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.time_bucket):
            raise ValidationError("invalid-time-bucket")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": "try-ddc-activity-receipt/1",
            "document_class": self.document_class,
            "event_id": self.event_id,
            "capability": self.capability.to_dict(),
            "analysis_status": self.analysis_status,
            "risk_disposition": self.risk_disposition,
            "time_bucket": self.time_bucket,
        }
