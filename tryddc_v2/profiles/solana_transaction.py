from __future__ import annotations

import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError


PROFILE_DESCRIPTOR = {
    "id": "blockchain.solana.transaction.v1",
    "version": "1",
    "purpose": "read-only Solana transaction observation, slot binding, and provider-mediated commitment evidence",
    "execution_authority": False,
    "transaction_signing_authority": False,
    "transaction_broadcast_authority": False,
    "private_key_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "blockchain.solana.transaction.observe",
    "version": "1",
    "rpc_methods": [
        "getGenesisHash",
        "getSignatureStatuses",
        "getTransaction",
        "getBlock",
        "getSlot",
    ],
    "execution_authority": False,
    "transaction_signing_authority": False,
    "transaction_broadcast_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
_COMMITMENT = {"processed", "confirmed", "finalized"}


def _base58(value: Any, name: str, *, min_len: int = 32, max_len: int = 128) -> str:
    if not isinstance(value, str) or not (min_len <= len(value) <= max_len) or not _BASE58_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value


def _slot(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError(f"invalid-{name}")
    return value


def _status_record(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError("invalid-solana-signature-status")
    slot = _slot(value.get("slot"), "solana-status-slot")
    confirmation_status = value.get("confirmationStatus")
    if confirmation_status not in _COMMITMENT:
        raise ValidationError("invalid-solana-confirmation-status")
    confirmations = value.get("confirmations")
    if confirmations is not None and (
        not isinstance(confirmations, int) or isinstance(confirmations, bool) or confirmations < 0
    ):
        raise ValidationError("invalid-solana-confirmations")
    return {
        "slot": slot,
        "confirmationStatus": confirmation_status,
        "confirmations": confirmations,
        "err": value.get("err"),
    }


def analyze_observation(
    observation: dict[str, Any],
    *,
    captured_at: str,
    analysis_time: str,
    implementation_revision: str,
) -> tuple[EvidenceManifest, TryDDCResult]:
    if not isinstance(observation, dict):
        raise ValidationError("observation-must-be-object")

    signature = _base58(observation.get("signature"), "solana-signature", min_len=64, max_len=128)
    genesis_before = _base58(observation.get("genesis_hash_before"), "solana-genesis-hash-before")
    genesis_after = _base58(observation.get("genesis_hash_after"), "solana-genesis-hash-after")
    genesis_stable = genesis_before == genesis_after

    status = _status_record(observation.get("signature_status"))
    tx = observation.get("transaction")
    if tx is not None and not isinstance(tx, dict):
        raise ValidationError("solana-transaction-must-be-object-or-null")

    context_commitment = observation.get("context_commitment")
    if context_commitment not in {"confirmed", "finalized"}:
        raise ValidationError("invalid-solana-context-commitment")
    context_slot_before = _slot(observation.get("context_slot_before"), "solana-context-slot-before")
    context_slot_after = _slot(observation.get("context_slot_after"), "solana-context-slot-after")
    context_monotonic = context_slot_after >= context_slot_before

    target_hash = sha256_digest({
        "ecosystem": "solana",
        "genesis_hash": genesis_before,
        "signature": signature,
    }).split(":", 1)[1]
    target_id = "target:" + target_hash[:24]
    case_id = "case:" + target_hash[24:48]

    capability = CapabilityIdentity(
        capability_id=CAPTURE_DESCRIPTOR["id"],
        capability_version=CAPTURE_DESCRIPTOR["version"],
        capability_digest=CAPTURE_DIGEST,
        implementation_revision=implementation_revision,
    )

    if status is None and tx is None:
        evidence = (
            EvidenceItem(
                evidence_id="evidence:solana-transaction-query",
                target_id=target_id,
                source_class="PROTOCOL_OBSERVATION",
                capture_capability=capability,
                digest=sha256_digest({
                    "signature": signature,
                    "genesis_hash_before": genesis_before,
                    "genesis_hash_after": genesis_after,
                    "context_commitment": context_commitment,
                    "context_slot_before": context_slot_before,
                    "context_slot_after": context_slot_after,
                    "status": None,
                    "transaction": None,
                }),
                captured_at=captured_at,
                source_identity=str(observation.get("rpc_origin") or "solana-rpc"),
                causal_origin="read-only-solana-rpc-query",
                classification="PUBLIC",
                authorization_status="READ_ONLY_OBSERVATION",
                representation="SOLANA_RPC_TRANSACTION_LOOKUP",
                time_source="observer-clock",
                time_trust="UNRESOLVED",
                freshness_status="ESTABLISHED" if genesis_stable and context_monotonic else "UNRESOLVED",
                freshness_policy="provider-genesis-and-context-slot-recheck",
                reachability="ESTABLISHED",
                discoverability="ESTABLISHED",
                accessibility="ESTABLISHED",
                trustworthiness="UNRESOLVED",
                consulted=True,
                limitations=(
                    "single-provider-absence-is-not-global-nonexistence-proof",
                    "rpc-observation-is-not-independent-consensus-verification",
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
        result = TryDDCResult(
            result_id="result:" + sha256_digest({
                "case_id": case_id,
                "target_id": target_id,
                "evidence_root": manifest.evidence_root,
                "profile_digest": PROFILE_DIGEST,
            }).split(":", 1)[1][:24],
            case_id=case_id,
            target_id=target_id,
            profile_id=PROFILE_DESCRIPTOR["id"],
            profile_version=PROFILE_DESCRIPTOR["version"],
            profile_digest=PROFILE_DIGEST,
            evidence_root=manifest.evidence_root,
            analysis_status="COMPLETE",
            evidentiary_status="NOT_ESTABLISHED",
            risk_disposition="REVIEW_REQUIRED",
            analysis_time=analysis_time,
            observations=({
                "kind": "solana.transaction.lookup",
                "signature": signature,
                "observed": False,
                "genesis_hash": genesis_before,
                "context_commitment": context_commitment,
                "context_slot_before": context_slot_before,
                "context_slot_after": context_slot_after,
                "evidence_refs": ["evidence:solana-transaction-query"],
            },),
            determinations=({
                "kind": "solana.transaction.observed",
                "status": "NOT_ESTABLISHED",
                "detail": "The configured provider returned neither a signature status nor a transaction. This does not establish global nonexistence.",
                "evidence_refs": ["evidence:solana-transaction-query"],
            },),
            unresolved=({
                "kind": "solana.transaction.global-existence",
                "detail": "Global transaction existence remains unresolved from a single provider observation.",
            },),
            limitations=(
                "A single provider returning no status and no transaction is not proof that the transaction does not exist.",
                "No transaction is created, signed, submitted, simulated, or authorized by this profile.",
            ),
            synthesis={
                "method": "blockchain.solana.transaction.v1",
                "version": "1",
                "provider_observation_only": True,
            },
            capabilities=(capability,),
            minimum_coverage_met=False,
        )
        return manifest, result

    if status is None or tx is None:
        raise ValidationError("solana-status-transaction-presence-mismatch")

    tx_slot = _slot(tx.get("slot"), "solana-transaction-slot")
    if tx_slot != status["slot"]:
        raise ValidationError("solana-transaction-status-slot-mismatch")

    transaction_obj = tx.get("transaction")
    if not isinstance(transaction_obj, dict):
        raise ValidationError("solana-transaction-object-invalid")
    signatures = transaction_obj.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ValidationError("solana-transaction-signatures-invalid")
    tx_primary_signature = _base58(signatures[0], "solana-primary-signature", min_len=64, max_len=128)
    if tx_primary_signature != signature:
        raise ValidationError("solana-transaction-signature-mismatch")

    meta = tx.get("meta")
    if not isinstance(meta, dict):
        raise ValidationError("solana-transaction-meta-invalid")
    execution_succeeded = meta.get("err") is None

    block_before = observation.get("block_before")
    block_after = observation.get("block_after")
    if not isinstance(block_before, dict) or not isinstance(block_after, dict):
        raise ValidationError("solana-transaction-missing-block-anchors")

    def block_identity(block: dict[str, Any], label: str) -> tuple[str, str, int | None, int | None]:
        blockhash = _base58(block.get("blockhash"), f"{label}-blockhash")
        previous = _base58(block.get("previousBlockhash"), f"{label}-previous-blockhash")
        block_height = block.get("blockHeight")
        if block_height is not None:
            block_height = _slot(block_height, f"{label}-block-height")
        block_time = block.get("blockTime")
        if block_time is not None and (not isinstance(block_time, int) or isinstance(block_time, bool)):
            raise ValidationError(f"invalid-{label}-block-time")
        return blockhash, previous, block_height, block_time

    before_id = block_identity(block_before, "solana-block-before")
    after_id = block_identity(block_after, "solana-block-after")
    block_stable = before_id == after_id

    status_commitment = status["confirmationStatus"]
    commitment_sufficient = (
        status_commitment == "finalized"
        or (status_commitment == "confirmed" and context_commitment in {"confirmed", "finalized"})
        or (status_commitment == "processed" and context_commitment in {"confirmed", "finalized"})
    )
    context_covers_transaction_slot = context_slot_before >= tx_slot and context_slot_after >= tx_slot

    raw_items = (
        ("evidence:solana-signature-status", status, "rpc:getSignatureStatuses"),
        ("evidence:solana-transaction", tx, "rpc:getTransaction"),
        ("evidence:solana-block-before", block_before, "rpc:getBlock"),
        ("evidence:solana-block-after", block_after, "rpc:getBlock"),
        ("evidence:solana-chain-context", {
            "genesis_hash_before": genesis_before,
            "genesis_hash_after": genesis_after,
            "context_commitment": context_commitment,
            "context_slot_before": context_slot_before,
            "context_slot_after": context_slot_after,
        }, "rpc:getGenesisHash+getSlot"),
    )

    evidence = tuple(
        EvidenceItem(
            evidence_id=eid,
            target_id=target_id,
            source_class="PROTOCOL_OBSERVATION",
            capture_capability=capability,
            digest=sha256_digest(value),
            captured_at=captured_at,
            source_identity=str(observation.get("rpc_origin") or source),
            causal_origin="read-only-solana-rpc-capture",
            classification="PUBLIC",
            authorization_status="READ_ONLY_OBSERVATION",
            representation="SOLANA_RPC_OBSERVATION",
            time_source="observer-clock",
            time_trust="UNRESOLVED",
            freshness_status=(
                "ESTABLISHED"
                if genesis_stable and context_monotonic and block_stable and context_covers_transaction_slot
                else "UNRESOLVED"
            ),
            freshness_policy="genesis-plus-context-slot-plus-block-recheck",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
            limitations=("rpc-observation-is-provider-mediated-not-independent-consensus-proof",),
        )
        for eid, value, source in raw_items
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

    capture_ok = genesis_stable and context_monotonic and block_stable and context_covers_transaction_slot
    analysis_status = "COMPLETE" if capture_ok else "CAPTURE_FAILED"
    evidentiary_status = "PARTIALLY_ESTABLISHED" if capture_ok else "UNRESOLVED"

    observations = (
        {
            "kind": "solana.transaction.identity",
            "signature": signature,
            "slot": tx_slot,
            "genesis_hash": genesis_before,
            "block_time": tx.get("blockTime"),
            "transaction_version": tx.get("version"),
            "evidence_refs": ["evidence:solana-transaction"],
        },
        {
            "kind": "solana.transaction.execution",
            "provider_execution_succeeded": execution_succeeded,
            "meta_error": meta.get("err"),
            "fee": meta.get("fee"),
            "compute_units_consumed": meta.get("computeUnitsConsumed"),
            "evidence_refs": ["evidence:solana-transaction"],
        },
        {
            "kind": "solana.transaction.commitment",
            "provider_confirmation_status": status_commitment,
            "provider_confirmations": status.get("confirmations"),
            "context_commitment": context_commitment,
            "context_slot_before": context_slot_before,
            "context_slot_after": context_slot_after,
            "block_stable": block_stable,
            "context_covers_transaction_slot": context_covers_transaction_slot,
            "genesis_stable": genesis_stable,
            "evidence_refs": [
                "evidence:solana-signature-status",
                "evidence:solana-block-before",
                "evidence:solana-block-after",
                "evidence:solana-chain-context",
            ],
        },
        {
            "kind": "solana.authority-boundary",
            "private_key_accessed": False,
            "transaction_signed": False,
            "transaction_submitted": False,
            "transaction_simulated": False,
            "arbitrary_rpc_invoked": False,
            "evidence_refs": ["evidence:solana-transaction"],
        },
    )

    determinations = (
        {
            "kind": "solana.transaction.observed",
            "status": "ESTABLISHED",
            "detail": "The configured provider returned a transaction whose primary signature and slot agree with the provider signature-status record.",
            "evidence_refs": ["evidence:solana-signature-status", "evidence:solana-transaction"],
        },
        {
            "kind": "solana.transaction.execution",
            "status": "ESTABLISHED" if execution_succeeded else "CONTRADICTED",
            "detail": (
                "The provider transaction metadata reports no execution error."
                if execution_succeeded
                else "The provider transaction metadata reports an execution error."
            ),
            "evidence_refs": ["evidence:solana-transaction"],
        },
        {
            "kind": "solana.transaction.commitment",
            "status": "PARTIALLY_ESTABLISHED" if capture_ok and commitment_sufficient else "UNRESOLVED",
            "detail": (
                "The provider reports a commitment state over a stable bounded slot/block observation. This is provider-mediated commitment evidence, not independent consensus finality proof."
                if capture_ok and commitment_sufficient
                else "The bounded observation does not establish a stable provider commitment view for this transaction."
            ),
            "evidence_refs": [
                "evidence:solana-signature-status",
                "evidence:solana-block-before",
                "evidence:solana-block-after",
                "evidence:solana-chain-context",
            ],
        },
    )

    unresolved = (
        {
            "kind": "solana.consensus-independence",
            "detail": "Provider confirmation status and slot/block observations are not independent cluster-consensus verification.",
        },
        {
            "kind": "solana.downstream-effect",
            "detail": "Successful transaction execution does not itself establish business, legal, ownership, authorization, or downstream economic consequence.",
        },
        {
            "kind": "solana.program-semantics",
            "detail": "This profile does not independently interpret all invoked program semantics or prove the intended state transition.",
        },
    )

    contradictions = ()
    if not capture_ok:
        contradictions = ({
            "kind": "solana.capture-contradiction",
            "detail": "Genesis identity, provider context slots, or slot block identity were inconsistent during the bounded capture.",
            "genesis_stable": genesis_stable,
            "context_monotonic": context_monotonic,
            "block_stable": block_stable,
            "context_covers_transaction_slot": context_covers_transaction_slot,
            "evidence_refs": [
                "evidence:solana-block-before",
                "evidence:solana-block-after",
                "evidence:solana-chain-context",
            ],
        },)

    limitations = (
        "Provider confirmation status is evidence from that RPC provider, not independent Solana cluster consensus verification.",
        "A provider-reported finalized state is not promoted to an absolute finality guarantee.",
        "Successful transaction metadata does not establish authority, intended semantics, ownership, or downstream economic consequence.",
        "No private key, signing, sendTransaction, simulateTransaction, or transaction-construction authority exists.",
    )

    result = TryDDCResult(
        result_id="result:" + sha256_digest({
            "case_id": case_id,
            "target_id": target_id,
            "evidence_root": manifest.evidence_root,
            "profile_digest": PROFILE_DIGEST,
        }).split(":", 1)[1][:24],
        case_id=case_id,
        target_id=target_id,
        profile_id=PROFILE_DESCRIPTOR["id"],
        profile_version=PROFILE_DESCRIPTOR["version"],
        profile_digest=PROFILE_DIGEST,
        evidence_root=manifest.evidence_root,
        analysis_status=analysis_status,
        evidentiary_status=evidentiary_status,
        risk_disposition="REVIEW_REQUIRED",
        analysis_time=analysis_time,
        observations=observations,
        determinations=determinations,
        contradictions=contradictions,
        unresolved=unresolved,
        limitations=limitations,
        synthesis={
            "method": "blockchain.solana.transaction.v1",
            "version": "1",
            "provider_observation_only": True,
            "transaction_signing_performed": False,
            "transaction_submission_performed": False,
            "transaction_simulation_performed": False,
        },
        capabilities=(capability,),
        minimum_coverage_met=False,
    )
    return manifest, result
