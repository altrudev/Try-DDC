from __future__ import annotations

import re
from typing import Any

from ..canonical import sha256_digest
from ..model import CapabilityIdentity, EvidenceItem, EvidenceManifest, TryDDCResult, ValidationError

EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

PROFILE_DESCRIPTOR = {
    "id": "blockchain.evm.contract.v1",
    "version": "1",
    "purpose": "read-only block-pinned EVM contract observation",
    "execution_authority": False,
    "transaction_signing_authority": False,
    "private_key_authority": False,
}
PROFILE_DIGEST = sha256_digest(PROFILE_DESCRIPTOR)

CAPTURE_DESCRIPTOR = {
    "id": "blockchain.evm.contract.observe",
    "version": "1",
    "rpc_methods": ["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_call"],
    "execution_authority": False,
    "transaction_signing_authority": False,
}
CAPTURE_DIGEST = sha256_digest(CAPTURE_DESCRIPTOR)

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")
_MINIMAL_PROXY_RE = re.compile(
    r"^0x363d3d373d3d3d363d73([0-9a-fA-F]{40})5af43d82803e903d91602b57fd5bf3$"
)


def normalize_address(value: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValidationError("invalid-evm-address")
    return value.lower()


def _require_hex(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
        raise ValidationError(f"invalid-{name}")
    if len(value) % 2 != 0:
        raise ValidationError(f"odd-length-{name}")
    return value.lower()


def _slot_address(value: Any) -> str | None:
    raw = _require_hex(value, "storage-slot")
    body = raw[2:].rjust(64, "0")
    if len(body) != 64:
        raise ValidationError("invalid-storage-slot-width")
    address = body[-40:]
    if int(address, 16) == 0:
        return None
    return "0x" + address


def detect_minimal_proxy(runtime_code: str) -> str | None:
    code = _require_hex(runtime_code, "runtime-code")
    match = _MINIMAL_PROXY_RE.fullmatch(code)
    return ("0x" + match.group(1).lower()) if match else None


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
    address = normalize_address(str(observation.get("contract_address") or ""))

    before = observation.get("anchor_before")
    after = observation.get("anchor_after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValidationError("missing-block-anchor")

    for anchor, label in ((before, "anchor-before"), (after, "anchor-after")):
        for key in ("number", "hash", "parentHash", "timestamp"):
            if not isinstance(anchor.get(key), str) or not anchor.get(key):
                raise ValidationError(f"invalid-{label}-{key}")

    stable_anchor = before["number"].lower() == after["number"].lower() and before["hash"].lower() == after["hash"].lower()
    runtime_code = _require_hex(observation.get("runtime_code"), "runtime-code")
    implementation = _slot_address(observation.get("implementation_slot", "0x"))
    admin = _slot_address(observation.get("admin_slot", "0x"))
    beacon = _slot_address(observation.get("beacon_slot", "0x"))
    minimal_impl = detect_minimal_proxy(runtime_code)
    beacon_impl_raw = observation.get("beacon_implementation")
    beacon_impl = normalize_address(beacon_impl_raw) if beacon_impl_raw else None

    proxy_conflict = implementation is not None and beacon is not None
    proxy_kind = "NONE_OBSERVED"
    active_impl = None
    if proxy_conflict:
        proxy_kind = "CONFLICTING_EIP1967_SLOTS"
    elif implementation is not None:
        proxy_kind = "EIP1967_IMPLEMENTATION"
        active_impl = implementation
    elif beacon is not None:
        proxy_kind = "EIP1967_BEACON"
        active_impl = beacon_impl
    elif minimal_impl is not None:
        proxy_kind = "EIP1167_MINIMAL"
        active_impl = minimal_impl

    target_descriptor = {
        "ecosystem": "evm",
        "chain_id": chain_id.lower(),
        "contract_address": address,
        "block_number": before["number"].lower(),
        "block_hash": before["hash"].lower(),
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

    raw_items = [
        ("evidence:block-anchor-before", before, "rpc:block-anchor-before"),
        ("evidence:block-anchor-after", after, "rpc:block-anchor-after"),
        ("evidence:runtime-code", runtime_code, "rpc:eth_getCode"),
        ("evidence:eip1967-implementation", observation.get("implementation_slot", "0x"), "rpc:eth_getStorageAt"),
        ("evidence:eip1967-admin", observation.get("admin_slot", "0x"), "rpc:eth_getStorageAt"),
        ("evidence:eip1967-beacon", observation.get("beacon_slot", "0x"), "rpc:eth_getStorageAt"),
    ]
    if beacon_impl:
        raw_items.append(("evidence:beacon-implementation", beacon_impl, "rpc:eth_call"))

    evidence = tuple(
        EvidenceItem(
            evidence_id=eid,
            target_id=target_id,
            source_class="PROTOCOL_OBSERVATION",
            capture_capability=capability,
            digest=sha256_digest(value),
            captured_at=captured_at,
            target_time=None,
            source_identity=source,
            causal_origin="explicit-read-only-rpc-capture",
            classification="PUBLIC",
            freshness_status="ESTABLISHED" if stable_anchor else "UNRESOLVED",
            freshness_policy="block-pinned-observation-with-anchor-recheck",
            reachability="ESTABLISHED",
            discoverability="ESTABLISHED",
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

    code_present = runtime_code not in {"0x", "0x00"}
    analysis_status = "COMPLETE" if stable_anchor and code_present else "CAPTURE_FAILED"
    evidentiary_status = (
        "CONTRADICTED" if proxy_conflict
        else "PARTIALLY_ESTABLISHED" if analysis_status == "COMPLETE"
        else "UNRESOLVED"
    )

    observations = (
        {
            "kind": "evm.contract.identity",
            "ecosystem": "evm",
            "chain_id": chain_id.lower(),
            "contract_address": address,
            "block_number": before["number"].lower(),
            "block_hash": before["hash"].lower(),
            "parent_hash": before["parentHash"].lower(),
            "block_timestamp": before["timestamp"].lower(),
            "finality_state": str(observation.get("finality_state") or "UNRESOLVED"),
            "rpc_source": str(observation.get("rpc_origin") or "unknown"),
            "runtime_code_digest": sha256_digest(runtime_code),
            "evidence_refs": ["evidence:block-anchor-before", "evidence:block-anchor-after", "evidence:runtime-code"],
        },
        {
            "kind": "evm.proxy.topology",
            "proxy_kind": proxy_kind,
            "implementation_address": active_impl,
            "admin_address": admin,
            "beacon_address": beacon,
            "evidence_refs": [
                "evidence:eip1967-implementation",
                "evidence:eip1967-admin",
                "evidence:eip1967-beacon",
            ],
        },
    )

    determinations: list[dict[str, Any]] = []
    if not stable_anchor:
        determinations.append({
            "kind": "capture.anchor",
            "status": "CONTRADICTED",
            "detail": "Block anchor changed during capture; the observation is not treated as a stable frozen chain state.",
            "evidence_refs": ["evidence:block-anchor-before"],
        })
    else:
        determinations.append({
            "kind": "capture.anchor",
            "status": "ESTABLISHED",
            "detail": "The same block number and hash were observed before and after bounded capture.",
            "evidence_refs": ["evidence:block-anchor-before"],
        })

    if proxy_conflict:
        determinations.append({
            "kind": "proxy.topology",
            "status": "CONTRADICTED",
            "detail": "Both ERC-1967 implementation and beacon slots are non-zero; Try DDC does not choose one silently.",
            "evidence_refs": [
                "evidence:eip1967-implementation",
                "evidence:eip1967-beacon",
            ],
        })
    elif proxy_kind != "NONE_OBSERVED":
        determinations.append({
            "kind": "proxy.topology",
            "status": "ESTABLISHED" if active_impl else "PARTIALLY_ESTABLISHED",
            "detail": f"Observed proxy topology: {proxy_kind}.",
            "evidence_refs": [
                "evidence:eip1967-implementation",
                "evidence:eip1967-beacon",
                "evidence:runtime-code",
            ],
        })

    if admin:
        determinations.append({
            "kind": "upgrade.authority",
            "status": "PARTIALLY_ESTABLISHED",
            "detail": "A non-zero ERC-1967 admin slot was observed. This establishes an observed admin address, not the full governance or signing authority behind it.",
            "evidence_refs": ["evidence:eip1967-admin"],
        })

    limitations = [
        "RPC observations are provider-mediated and are not independent consensus verification.",
        "Finality is not inferred unless explicitly supplied by a qualified capture source.",
        "This profile observes code identity and common proxy slots; it does not prove source correspondence or contract safety.",
        "No transaction is signed or broadcast and no private key authority exists.",
    ]
    if not code_present:
        limitations.append("No non-empty runtime code was observed at the target address for the pinned block.")
    if not stable_anchor:
        limitations.append("The block anchor changed during capture, so the evidence set is not treated as a stable chain-state observation.")
    if proxy_conflict:
        limitations.append("Conflicting non-zero ERC-1967 implementation and beacon slots require review; no active implementation is inferred.")

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
        risk_disposition="HIGH_RISK_OBSERVED" if proxy_conflict else "REVIEW_REQUIRED",
        analysis_time=analysis_time,
        observations=observations,
        determinations=tuple(determinations),
        limitations=tuple(limitations),
        unresolved=tuple({"kind": "limitation", "detail": item} for item in limitations),
        synthesis={
            "method": "blockchain.evm.contract.v1",
            "version": "1",
            "proxy_detection": ["ERC1967_IMPLEMENTATION", "ERC1967_BEACON", "EIP1167_MINIMAL"],
        },
        capabilities=(capability,),
        minimum_coverage_met=False,
    )
    return manifest, result
