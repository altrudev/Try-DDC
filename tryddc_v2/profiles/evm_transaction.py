from __future__ import annotations

import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError


PROFILE_DESCRIPTOR = {
    "id": "blockchain.evm.transaction.v1",
    "version": "1",
    "purpose": "read-only EVM transaction inclusion and execution reconstruction",
    "execution_authority": False,
    "transaction_signing_authority": False,
    "private_key_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "blockchain.evm.transaction.observe",
    "version": "1",
    "rpc_methods": [
        "eth_chainId",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_getBlockByNumber",
    ],
    "execution_authority": False,
    "transaction_signing_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_QTY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")


def normalize_tx_hash(value: str) -> str:
    if not isinstance(value, str) or not _TX_HASH_RE.fullmatch(value):
        raise ValidationError("invalid-evm-transaction-hash")
    return value.lower()


def _address_or_none(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value.lower()


def _quantity_or_none(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _HEX_QTY_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value.lower()


def _receipt_status(value: Any) -> str:
    if value is None:
        return "UNRESOLVED"
    raw = _quantity_or_none(value, "receipt-status")
    if raw == "0x1":
        return "SUCCESS"
    if raw == "0x0":
        return "REVERTED"
    return "UNKNOWN"


def analyze_observation(
    observation: dict[str, Any],
    *,
    captured_at: str,
    analysis_time: str,
    implementation_revision: str,
) -> tuple[EvidenceManifest, TryDDCResult]:
    if not isinstance(observation, dict):
        raise ValidationError("observation-must-be-object")

    chain_id = str(observation.get("chain_id") or "")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", chain_id):
        raise ValidationError("invalid-chain-id")

    requested_hash = normalize_tx_hash(str(observation.get("transaction_hash") or ""))
    tx = observation.get("transaction")
    receipt = observation.get("receipt")
    block_before = observation.get("block_before")
    block_after = observation.get("block_after")

    if tx is not None and not isinstance(tx, dict):
        raise ValidationError("transaction-must-be-object-or-null")
    if receipt is not None and not isinstance(receipt, dict):
        raise ValidationError("receipt-must-be-object-or-null")

    tx_observed = tx is not None
    if tx_observed:
        observed_hash = normalize_tx_hash(str(tx.get("hash") or ""))
        if observed_hash != requested_hash:
            raise ValidationError("transaction-hash-mismatch")
        _address_or_none(tx.get("from"), "transaction-from")
        _address_or_none(tx.get("to"), "transaction-to")

    included = receipt is not None
    stable_anchor = False
    block_consistent = False
    receipt_status = "UNRESOLVED"

    if included:
        receipt_hash = normalize_tx_hash(str(receipt.get("transactionHash") or ""))
        if receipt_hash != requested_hash:
            raise ValidationError("receipt-transaction-hash-mismatch")
        receipt_status = _receipt_status(receipt.get("status"))
        receipt_block_number = _quantity_or_none(receipt.get("blockNumber"), "receipt-block-number")
        receipt_block_hash = str(receipt.get("blockHash") or "").lower()
        if not re.fullmatch(r"0x[0-9a-f]{64}", receipt_block_hash):
            raise ValidationError("invalid-receipt-block-hash")

        if not isinstance(block_before, dict) or not isinstance(block_after, dict):
            raise ValidationError("included-transaction-missing-block-anchor")
        for anchor, label in ((block_before, "block-before"), (block_after, "block-after")):
            for key in ("number", "hash", "parentHash", "timestamp"):
                if not isinstance(anchor.get(key), str) or not anchor.get(key):
                    raise ValidationError(f"invalid-{label}-{key}")

        stable_anchor = (
            block_before["number"].lower() == block_after["number"].lower()
            and block_before["hash"].lower() == block_after["hash"].lower()
        )
        block_consistent = (
            block_before["number"].lower() == receipt_block_number
            and block_before["hash"].lower() == receipt_block_hash
        )
        if tx_observed and tx.get("blockHash") is not None:
            block_consistent = block_consistent and str(tx.get("blockHash")).lower() == receipt_block_hash
        if tx_observed and tx.get("blockNumber") is not None:
            block_consistent = block_consistent and str(tx.get("blockNumber")).lower() == receipt_block_number

    target_descriptor = {
        "ecosystem": "evm",
        "chain_id": chain_id.lower(),
        "transaction_hash": requested_hash,
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

    raw_items: list[tuple[str, Any, str]] = [
        ("evidence:transaction-query", tx, "rpc:eth_getTransactionByHash"),
        ("evidence:receipt-query", receipt, "rpc:eth_getTransactionReceipt"),
    ]
    if included:
        raw_items.extend([
            ("evidence:inclusion-block", block_before, "rpc:eth_getBlockByNumber"),
            ("evidence:inclusion-block-recheck", block_after, "rpc:eth_getBlockByNumber"),
        ])

    evidence = tuple(
        EvidenceItem(
            evidence_id=eid,
            target_id=target_id,
            source_class="PROTOCOL_OBSERVATION",
            capture_capability=capability,
            digest=sha256_digest(value),
            captured_at=captured_at,
            source_identity=source,
            causal_origin="explicit-read-only-rpc-capture",
            classification="PUBLIC",
            freshness_status=(
                "ESTABLISHED"
                if (not included or (stable_anchor and block_consistent))
                else "UNRESOLVED"
            ),
            freshness_policy="transaction-observation-with-inclusion-anchor-recheck",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED" if tx_observed else "UNRESOLVED",
            accessibility="ESTABLISHED",
            trustworthiness="UNRESOLVED",
            consulted=True,
            limitations=("rpc-observation-is-not-consensus-verification",),
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

    if not tx_observed:
        analysis_status = "INCOMPLETE"
        evidentiary_status = "NOT_ESTABLISHED"
    elif included and (not stable_anchor or not block_consistent):
        analysis_status = "CAPTURE_FAILED"
        evidentiary_status = "UNRESOLVED"
    else:
        analysis_status = "COMPLETE"
        evidentiary_status = "PARTIALLY_ESTABLISHED"

    observations: list[dict[str, Any]] = [{
        "kind": "evm.transaction.identity",
        "ecosystem": "evm",
        "chain_id": chain_id.lower(),
        "transaction_hash": requested_hash,
        "rpc_source": str(observation.get("rpc_origin") or "unknown"),
        "transaction_observed": tx_observed,
        "evidence_refs": ["evidence:transaction-query"],
    }]

    if tx_observed:
        observations.append({
            "kind": "evm.transaction.request",
            "from": _address_or_none(tx.get("from"), "transaction-from"),
            "to": _address_or_none(tx.get("to"), "transaction-to"),
            "nonce": _quantity_or_none(tx.get("nonce"), "transaction-nonce"),
            "value": _quantity_or_none(tx.get("value"), "transaction-value"),
            "input_digest": sha256_digest(str(tx.get("input") or "0x").lower()),
            "evidence_refs": ["evidence:transaction-query"],
        })

    observations.append({
        "kind": "evm.transaction.inclusion",
        "included": included,
        "block_number": receipt.get("blockNumber") if included else None,
        "block_hash": receipt.get("blockHash") if included else None,
        "transaction_index": receipt.get("transactionIndex") if included else None,
        "anchor_stable": stable_anchor if included else None,
        "block_consistent": block_consistent if included else None,
        "finality_state": str(observation.get("finality_state") or "UNRESOLVED"),
        "evidence_refs": (
            ["evidence:receipt-query", "evidence:inclusion-block", "evidence:inclusion-block-recheck"]
            if included else ["evidence:receipt-query"]
        ),
    })

    observations.append({
        "kind": "evm.transaction.execution",
        "protocol_execution_status": receipt_status,
        "gas_used": receipt.get("gasUsed") if included else None,
        "contract_address": (
            _address_or_none(receipt.get("contractAddress"), "receipt-contract-address")
            if included else None
        ),
        "logs_count": len(receipt.get("logs", [])) if included and isinstance(receipt.get("logs"), list) else 0,
        "logs_digest": sha256_digest(receipt.get("logs", [])) if included else None,
        "evidence_refs": ["evidence:receipt-query"],
    })

    determinations: list[dict[str, Any]] = []
    determinations.append({
        "kind": "transaction.observed",
        "status": "ESTABLISHED" if tx_observed else "NOT_ESTABLISHED",
        "detail": (
            "The requested transaction hash was returned by the configured RPC source."
            if tx_observed else
            "The configured RPC source did not return a transaction for the requested hash."
        ),
        "evidence_refs": ["evidence:transaction-query"],
    })

    determinations.append({
        "kind": "transaction.inclusion",
        "status": (
            "ESTABLISHED" if included and stable_anchor and block_consistent
            else "CONTRADICTED" if included and (not stable_anchor or not block_consistent)
            else "NOT_ESTABLISHED"
        ),
        "detail": (
            "Receipt and transaction evidence bind to a stable observed inclusion block."
            if included and stable_anchor and block_consistent else
            "Receipt/block evidence is internally inconsistent or the inclusion anchor changed during capture."
            if included else
            "No receipt was observed; inclusion is not established by this capture."
        ),
        "evidence_refs": (
            ["evidence:receipt-query", "evidence:inclusion-block", "evidence:inclusion-block-recheck"]
            if included else ["evidence:receipt-query"]
        ),
    })

    if included and stable_anchor and block_consistent:
        determinations.append({
            "kind": "transaction.protocol_execution",
            "status": "ESTABLISHED" if receipt_status in {"SUCCESS", "REVERTED"} else "UNRESOLVED",
            "detail": (
                "The observed receipt status indicates protocol execution completed without revert."
                if receipt_status == "SUCCESS" else
                "The observed receipt status indicates protocol execution reverted."
                if receipt_status == "REVERTED" else
                "The receipt does not provide a recognized binary execution status."
            ),
            "evidence_refs": ["evidence:receipt-query"],
        })

    determinations.append({
        "kind": "transaction.downstream_consequence",
        "status": "UNRESOLVED",
        "detail": "Transaction inclusion or receipt success does not by itself establish intended business, economic, human-authority, or off-chain downstream consequences.",
        "evidence_refs": ["evidence:transaction-query", "evidence:receipt-query"],
    })

    limitations = [
        "RPC observations are provider-mediated and are not independent consensus verification.",
        "This profile establishes only what the captured transaction, receipt, and inclusion-block evidence support.",
        "A successful receipt does not establish business intent, human authorization, economic correctness, or off-chain consequence.",
        "Logs are recorded as bounded evidence but are not automatically treated as proof of downstream consequence.",
        "No transaction is signed, submitted, replaced, cancelled, or broadcast by Try DDC.",
    ]
    if tx_observed and not included:
        limitations.append("The transaction was observed without a receipt; inclusion and execution remain not established.")
    if included and not stable_anchor:
        limitations.append("The inclusion block anchor changed during capture.")
    if included and not block_consistent:
        limitations.append("Transaction, receipt, and block evidence did not bind consistently to one inclusion block.")

    result_seed = {
        "case_id": case_id,
        "target_id": target_id,
        "evidence_root": manifest.evidence_root,
        "profile_digest": PROFILE_DIGEST,
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
        analysis_status=analysis_status,
        evidentiary_status=evidentiary_status,
        risk_disposition="REVIEW_REQUIRED",
        analysis_time=analysis_time,
        observations=tuple(observations),
        determinations=tuple(determinations),
        limitations=tuple(limitations),
        unresolved=tuple({"kind": "limitation", "detail": item} for item in limitations),
        synthesis={
            "method": "blockchain.evm.transaction.v1",
            "version": "1",
            "semantics": [
                "transaction_observed",
                "included",
                "protocol_execution",
                "downstream_consequence",
            ],
        },
        minimum_coverage_met=False,
    )
    return manifest, result
