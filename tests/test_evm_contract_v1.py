from __future__ import annotations

import unittest

from tryddc_v2.model import ValidationError
from tryddc_v2.profiles.evm_contract import (
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPLEMENTATION_SLOT,
    analyze_observation,
    detect_minimal_proxy,
    normalize_address,
)


def slot(address: str | None) -> str:
    if address is None:
        return "0x" + "0" * 64
    return "0x" + "0" * 24 + address[2:]


class EVMContractV1Tests(unittest.TestCase):
    def observation(self):
        return {
            "chain_id": "0x1",
            "contract_address": "0x1111111111111111111111111111111111111111",
            "anchor_before": {
                "number": "0x10",
                "hash": "0x" + "a" * 64,
                "parentHash": "0x" + "b" * 64,
                "timestamp": "0x1234",
            },
            "anchor_after": {
                "number": "0x10",
                "hash": "0x" + "a" * 64,
                "parentHash": "0x" + "b" * 64,
                "timestamp": "0x1234",
            },
            "runtime_code": "0x6001600055",
            "implementation_slot": slot(None),
            "admin_slot": slot(None),
            "beacon_slot": slot(None),
            "rpc_origin": "rpc.example",
            "finality_state": "UNRESOLVED",
        }

    def test_standard_slots_are_exact(self):
        self.assertEqual(EIP1967_IMPLEMENTATION_SLOT, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
        self.assertEqual(EIP1967_ADMIN_SLOT, "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
        self.assertEqual(EIP1967_BEACON_SLOT, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")

    def test_address_validation(self):
        self.assertEqual(
            normalize_address("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD"),
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        )
        with self.assertRaisesRegex(ValidationError, "invalid-evm-address"):
            normalize_address("0x1234")

    def test_plain_contract_observation_is_block_bound(self):
        manifest, result = analyze_observation(
            self.observation(),
            captured_at="2026-09-22T14:00:00Z",
            analysis_time="2026-09-22T14:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "COMPLETE")
        self.assertEqual(result.evidence_root, manifest.evidence_root)
        self.assertEqual(result.risk_disposition, "REVIEW_REQUIRED")
        self.assertEqual(result.observations[1]["proxy_kind"], "NONE_OBSERVED")

    def test_eip1967_proxy_and_admin_are_observed(self):
        obs = self.observation()
        impl = "0x2222222222222222222222222222222222222222"
        admin = "0x3333333333333333333333333333333333333333"
        obs["implementation_slot"] = slot(impl)
        obs["admin_slot"] = slot(admin)
        _manifest, result = analyze_observation(
            obs,
            captured_at="2026-09-22T14:00:00Z",
            analysis_time="2026-09-22T14:00:01Z",
            implementation_revision="test",
        )
        topology = result.observations[1]
        self.assertEqual(topology["proxy_kind"], "EIP1967_IMPLEMENTATION")
        self.assertEqual(topology["implementation_address"], impl)
        self.assertEqual(topology["admin_address"], admin)

    def test_minimal_proxy_detection(self):
        impl = "2222222222222222222222222222222222222222"
        code = "0x363d3d373d3d3d363d73" + impl + "5af43d82803e903d91602b57fd5bf3"
        self.assertEqual(detect_minimal_proxy(code), "0x" + impl)

    def test_anchor_change_fails_closed(self):
        obs = self.observation()
        obs["anchor_after"]["hash"] = "0x" + "c" * 64
        _manifest, result = analyze_observation(
            obs,
            captured_at="2026-09-22T14:00:00Z",
            analysis_time="2026-09-22T14:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")
        self.assertEqual(result.evidentiary_status, "UNRESOLVED")

    def test_empty_code_fails_closed(self):
        obs = self.observation()
        obs["runtime_code"] = "0x"
        _manifest, result = analyze_observation(
            obs,
            captured_at="2026-09-22T14:00:00Z",
            analysis_time="2026-09-22T14:00:01Z",
            implementation_revision="test",
        )
        self.assertEqual(result.analysis_status, "CAPTURE_FAILED")


if __name__ == "__main__":
    unittest.main()
