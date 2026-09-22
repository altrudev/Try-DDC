from __future__ import annotations

import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError


PROFILE_DESCRIPTOR = {
    "id": "blockchain.bitcoin.transaction.v1",
    "version": "1",
    "purpose": "read-only Bitcoin transaction observation, inclusion binding, and provider-mediated confirmation evidence",
    "execution_authority": False,
    "transaction_signing_authority": False,
    "transaction_broadcast_authority": False,
    "private_key_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "blockchain.bitcoin.transaction.observe",
    "version": "1",
    "rpc_methods": ["getblockchaininfo", "getrawtransaction", "getblockheader", "getblockhash"],
    "execution_authority": False,
    "transaction_signing_authority": False,
    "transaction_broadcast_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_NETWORKS = {"main", "test", "regtest", "signet"}


def normalize_txid(value: str) -> str:
    if not isinstance(value, str) or not _TXID_RE.fullmatch(value):
        raise ValidationError("invalid-bitcoin-transaction-id")
    return value.lower()


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    return value.lower()


def _require_nonnegative_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError(f"invalid-{name}")
    return value


def analyze_observation(
    observation: dict[str, Any],
    *,
    captured_at: str,
    analysis_time: str,
    implementation_revision: str,
) -> tuple[EvidenceManifest, TryDDCResult]:
    if not isinstance(observation, dict):
        raise ValidationError("observation-must-be-object")

    network = observation.get("network")
    if network not in _NETWORKS:
        raise ValidationError("invalid-bitcoin-network")
    requested_txid = normalize_txid(str(observation.get("transaction_id") or ""))
    tx = observation.get("transaction")
    header_before = observation.get("block_header_before")
    header_after = observation.get("block_header_after")
    best_block_hash = _require_hash(observation.get("best_block_hash"), "bitcoin-best-block-hash")
    best_block_height = _require_nonnegative_int(observation.get("best_block_height"), "bitcoin-best-block-height")
    best_block_hash_after = _require_hash(observation.get("best_block_hash_after"), "bitcoin-best-block-hash-after")
    best_block_height_after = _require_nonnegative_int(observation.get("best_block_height_after"), "bitcoin-best-block-height-after")
    chain_context_stable = (
        best_block_hash == best_block_hash_after
        and best_block_height == best_block_height_after
    )

    if tx is None:
        target_hash = sha256_digest({
            "ecosystem": "bitcoin",
            "network": network,
            "transaction_id": requested_txid,
        }).split(":", 1)[1]
        target_id = "target:" + target_hash[:24]
        case_id = "case:" + target_hash[24:48]
        capability = CapabilityIdentity(
            capability_id=CAPTURE_DESCRIPTOR["id"],
            capability_version=CAPTURE_DESCRIPTOR["version"],
            capability_digest=CAPTURE_DIGEST,
            implementation_revision=implementation_revision,
        )
        evidence = (
            EvidenceItem(
                evidence_id="evidence:bitcoin-transaction-query",
                target_id=target_id,
                source_class="PROTOCOL_OBSERVATION",
                capture_capability=capability,
                digest=sha256_digest({
                    "network": network,
                    "transaction_id": requested_txid,
                    "observed": None,
                    "best_block_hash": best_block_hash,
                    "best_block_height": best_block_height,
                    "best_block_hash_after": best_block_hash_after,
                    "best_block_height_after": best_block_height_after,
                }),
                captured_at=captured_at,
                source_identity=str(observation.get("rpc_origin") or "bitcoin-rpc"),
                causal_origin="read-only-bitcoin-rpc-query",
                classification="PUBLIC",
                authorization_status="READ_ONLY_OBSERVATION",
                representation="BITCOIN_RPC_TRANSACTION_LOOKUP",
                time_source="observer-clock",
                time_trust="UNRESOLVED",
                freshness_status="ESTABLISHED" if chain_context_stable else "UNRESOLVED",
                freshness_policy="single-provider-observation",
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
                "kind": "bitcoin.transaction.lookup",
                "network": network,
                "transaction_id": requested_txid,
                "observed": False,
                "provider_best_block_hash": best_block_hash,
                "provider_best_block_height": best_block_height,
                "provider_best_block_hash_after": best_block_hash_after,
                "provider_best_block_height_after": best_block_height_after,
                "provider_chain_context_stable": chain_context_stable,
                "evidence_refs": ["evidence:bitcoin-transaction-query"],
            },),
            determinations=({
                "kind": "bitcoin.transaction.observed",
                "status": "NOT_ESTABLISHED",
                "detail": "The configured provider did not return the transaction. This does not establish global nonexistence.",
                "evidence_refs": ["evidence:bitcoin-transaction-query"],
            },),
            unresolved=({
                "kind": "bitcoin.transaction.global-existence",
                "detail": "Global transaction existence remains unresolved from a single provider observation.",
            },),
            limitations=(
                "A single provider failing to return a transaction is not proof that the transaction does not exist.",
                "No transaction is created, signed, broadcast, or authorized by this profile.",
            ),
            synthesis={
                "method": "blockchain.bitcoin.transaction.v1",
                "version": "1",
                "provider_observation_only": True,
            "merkle_membership_verified": False,
            "provider_chain_context_stable": chain_context_stable,
            },
            capabilities=(capability,),
            minimum_coverage_met=False,
        )
        return manifest, result

    if not isinstance(tx, dict):
        raise ValidationError("bitcoin-transaction-must-be-object-or-null")
    observed_txid = normalize_txid(str(tx.get("txid") or ""))
    if observed_txid != requested_txid:
        raise ValidationError("bitcoin-transaction-id-mismatch")

    tx_hash = tx.get("hash")
    if tx_hash is not None:
        _require_hash(tx_hash, "bitcoin-wtxid")

    block_hash_raw = tx.get("blockhash")
    included = block_hash_raw is not None
    confirmations = _require_nonnegative_int(tx.get("confirmations", 0), "bitcoin-confirmations")
    active_block_hash_before_raw = observation.get("active_block_hash_before")
    active_block_hash_after_raw = observation.get("active_block_hash_after")

    stable_anchor = False
    anchor_consistent = False
    active_chain_consistent = False
    block_hash = None
    block_height = None
    if included:
        block_hash = _require_hash(block_hash_raw, "bitcoin-block-hash")
        if not isinstance(header_before, dict) or not isinstance(header_after, dict):
            raise ValidationError("bitcoin-included-transaction-missing-block-anchors")

        def validate_header(header: dict[str, Any], label: str) -> tuple[str, int, str, str]:
            h = _require_hash(header.get("hash"), f"{label}-hash")
            height = _require_nonnegative_int(header.get("height"), f"{label}-height")
            prev = _require_hash(header.get("previousblockhash"), f"{label}-previous-block-hash") if height > 0 else "0" * 64
            merkle = _require_hash(header.get("merkleroot"), f"{label}-merkle-root")
            _require_nonnegative_int(header.get("time"), f"{label}-time")
            return h, height, prev, merkle

        before_id = validate_header(header_before, "bitcoin-header-before")
        after_id = validate_header(header_after, "bitcoin-header-after")
        stable_anchor = before_id == after_id
        anchor_consistent = before_id[0] == block_hash
        block_height = before_id[1]
        active_before = _require_hash(active_block_hash_before_raw, "bitcoin-active-block-hash-before")
        active_after = _require_hash(active_block_hash_after_raw, "bitcoin-active-block-hash-after")
        active_chain_consistent = active_before == block_hash and active_after == block_hash

    target_hash = sha256_digest({
        "ecosystem": "bitcoin",
        "network": network,
        "transaction_id": requested_txid,
    }).split(":", 1)[1]
    target_id = "target:" + target_hash[:24]
    case_id = "case:" + target_hash[24:48]
    capability = CapabilityIdentity(
        capability_id=CAPTURE_DESCRIPTOR["id"],
        capability_version=CAPTURE_DESCRIPTOR["version"],
        capability_digest=CAPTURE_DIGEST,
        implementation_revision=implementation_revision,
    )

    raw_items: list[tuple[str, Any, str]] = [
        ("evidence:bitcoin-transaction", tx, "rpc:getrawtransaction"),
        ("evidence:bitcoin-chain-context", {
            "network": network,
            "best_block_hash": best_block_hash,
            "best_block_height": best_block_height,
            "best_block_hash_after": best_block_hash_after,
            "best_block_height_after": best_block_height_after,
            "stable": chain_context_stable,
        }, "rpc:getblockchaininfo"),
    ]
    if included:
        raw_items.extend([
            ("evidence:bitcoin-block-header-before", header_before, "rpc:getblockheader"),
            ("evidence:bitcoin-active-block-before", active_block_hash_before_raw, "rpc:getblockhash"),
            ("evidence:bitcoin-block-header-after", header_after, "rpc:getblockheader"),
            ("evidence:bitcoin-active-block-after", active_block_hash_after_raw, "rpc:getblockhash"),
        ])

    evidence = tuple(
        EvidenceItem(
            evidence_id=eid,
            target_id=target_id,
            source_class="PROTOCOL_OBSERVATION",
            capture_capability=capability,
            digest=sha256_digest(value),
            captured_at=captured_at,
            source_identity=str(observation.get("rpc_origin") or source),
            causal_origin="read-only-bitcoin-rpc-capture",
            classification="PUBLIC",
            authorization_status="READ_ONLY_OBSERVATION",
            representation="BITCOIN_RPC_OBSERVATION",
            time_source="observer-clock",
            time_trust="UNRESOLVED",
            freshness_status="ESTABLISHED" if (chain_context_stable and (not included or (stable_anchor and active_chain_consistent))) else "UNRESOLVED",
            freshness_policy="transaction-plus-block-header-recheck",
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

    capture_ok = (not included) or (stable_anchor and anchor_consistent and active_chain_consistent)
    analysis_status = "COMPLETE" if capture_ok else "CAPTURE_FAILED"
    evidentiary_status = "PARTIALLY_ESTABLISHED" if capture_ok else "UNRESOLVED"

    observations = [
        {
            "kind": "bitcoin.transaction.identity",
            "network": network,
            "transaction_id": requested_txid,
            "wtxid": str(tx_hash).lower() if isinstance(tx_hash, str) else None,
            "version": tx.get("version"),
            "size": tx.get("size"),
            "vsize": tx.get("vsize"),
            "weight": tx.get("weight"),
            "locktime": tx.get("locktime"),
            "vin_count": len(tx.get("vin", [])) if isinstance(tx.get("vin"), list) else None,
            "vout_count": len(tx.get("vout", [])) if isinstance(tx.get("vout"), list) else None,
            "evidence_refs": ["evidence:bitcoin-transaction"],
        },
        {
            "kind": "bitcoin.transaction.inclusion",
            "included": included,
            "block_hash": block_hash,
            "block_height": block_height,
            "provider_confirmations": confirmations,
            "provider_chain_context_stable": chain_context_stable,
            "stable_header_recheck": stable_anchor if included else None,
            "header_matches_transaction_block": anchor_consistent if included else None,
            "active_chain_matches_before": active_chain_consistent if included else None,
            "active_chain_matches_after": active_chain_consistent if included else None,
            "evidence_refs": (
                ["evidence:bitcoin-transaction", "evidence:bitcoin-block-header-before", "evidence:bitcoin-active-block-before", "evidence:bitcoin-block-header-after", "evidence:bitcoin-active-block-after"]
                if included else ["evidence:bitcoin-transaction"]
            ),
        },
        {
            "kind": "bitcoin.authority-boundary",
            "wallet_accessed": False,
            "private_key_accessed": False,
            "transaction_signed": False,
            "transaction_broadcast": False,
            "mempool_acceptance_tested": False,
            "evidence_refs": ["evidence:bitcoin-transaction"],
        },
    ]

    determinations = [{
        "kind": "bitcoin.transaction.observed",
        "status": "ESTABLISHED",
        "detail": "The configured provider returned a transaction whose txid matches the requested transaction identifier.",
        "evidence_refs": ["evidence:bitcoin-transaction"],
    }]
    if included:
        determinations.append({
            "kind": "bitcoin.transaction.inclusion",
            "status": "PARTIALLY_ESTABLISHED" if stable_anchor and anchor_consistent and active_chain_consistent else "CONTRADICTED",
            "detail": (
                "The provider binds the transaction to a block whose header identity was stable and whose height resolved to the same active-chain block hash before and after the bounded capture. No independent Merkle membership proof is performed."
                if stable_anchor and anchor_consistent and active_chain_consistent
                else "Block inclusion evidence was unstable or inconsistent during the bounded capture."
            ),
            "evidence_refs": [
                "evidence:bitcoin-transaction",
                "evidence:bitcoin-block-header-before",
                "evidence:bitcoin-active-block-before",
                "evidence:bitcoin-block-header-after",
                "evidence:bitcoin-active-block-after",
            ],
        })
        determinations.append({
            "kind": "bitcoin.transaction.confirmations",
            "status": "PARTIALLY_ESTABLISHED" if chain_context_stable else "UNRESOLVED",
            "detail": (
                "Confirmation count is reported by the configured provider against a stable observed provider tip and is not independently consensus-verified."
                if chain_context_stable
                else "Provider chain tip changed during capture; a single frozen confirmation count is not established."
            ),
            "provider_confirmations": confirmations,
            "evidence_refs": ["evidence:bitcoin-transaction", "evidence:bitcoin-chain-context"],
        })
    else:
        determinations.append({
            "kind": "bitcoin.transaction.inclusion",
            "status": "NOT_ESTABLISHED",
            "detail": "The provider returned the transaction without a block hash; confirmed inclusion is not established.",
            "evidence_refs": ["evidence:bitcoin-transaction"],
        })

    unresolved = [
        {
            "kind": "bitcoin.consensus-independence",
            "detail": "The observation is provider-mediated and does not independently verify Bitcoin consensus.",
        },
        {
            "kind": "bitcoin.economic-consequence",
            "detail": "Transaction presence or confirmation does not by itself establish business, legal, ownership, authorization, or economic consequence.",
        },
    ]
    if not chain_context_stable:
        unresolved.append({
            "kind": "bitcoin.provider-tip-stability",
            "detail": "The provider chain tip changed during capture; time-sensitive confirmation evidence remains unresolved.",
        })
    if not included:
        unresolved.append({
            "kind": "bitcoin.mempool-state",
            "detail": "A returned unconfirmed transaction is not treated as proof of network-wide mempool acceptance or future inclusion.",
        })

    limitations = (
        "Provider-reported active-chain binding and confirmations are evidence from that provider, not independent consensus or Merkle-membership verification.",
        "Transaction inclusion does not establish authorization, ownership, business meaning, or downstream economic consequence.",
        "No wallet, private key, signing, broadcast, fee-bump, or transaction-construction authority exists.",
        "Unconfirmed observation does not establish network-wide mempool acceptance.",
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
        observations=tuple(observations),
        determinations=tuple(determinations),
        contradictions=(
            ({
                "kind": "bitcoin.block-inclusion-contradiction",
                "detail": "The transaction block reference and bounded header observations do not form one stable inclusion view.",
                "evidence_refs": [
                    "evidence:bitcoin-transaction",
                    "evidence:bitcoin-block-header-before",
                    "evidence:bitcoin-block-header-after",
                ],
            },) if included and not capture_ok else ()
        ),
        unresolved=tuple(unresolved),
        limitations=limitations,
        synthesis={
            "method": "blockchain.bitcoin.transaction.v1",
            "version": "1",
            "provider_observation_only": True,
            "transaction_signing_performed": False,
            "transaction_broadcast_performed": False,
        },
        capabilities=(capability,),
        minimum_coverage_met=False,
    )
    return manifest, result
