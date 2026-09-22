from __future__ import annotations

import json
from pathlib import Path
import unittest

from tryddc_v2.profiles import agent_trace, bitcoin_transaction, evidence_bundle, evm_contract, evm_transaction, mcp_observe, repository, solana_transaction


class ProfileRegistryTests(unittest.TestCase):
    def test_registry_digests_match_implementation_descriptors(self):
        registry = json.loads(Path("profiles/registry.json").read_text(encoding="utf-8"))
        actual = {
            repository.PROFILE_DESCRIPTOR["id"]: repository.PROFILE_DIGEST,
            evm_contract.PROFILE_DESCRIPTOR["id"]: evm_contract.PROFILE_DIGEST,
            evm_transaction.PROFILE_DESCRIPTOR["id"]: evm_transaction.PROFILE_DIGEST,
            bitcoin_transaction.PROFILE_DESCRIPTOR["id"]: bitcoin_transaction.PROFILE_DIGEST,
            solana_transaction.PROFILE_DESCRIPTOR["id"]: solana_transaction.PROFILE_DIGEST,
            evidence_bundle.PROFILE_DESCRIPTOR["id"]: evidence_bundle.PROFILE_DIGEST,
            agent_trace.PROFILE_DESCRIPTOR["id"]: agent_trace.PROFILE_DIGEST,
            mcp_observe.PROFILE_DESCRIPTOR["id"]: mcp_observe.PROFILE_DIGEST,
        }
        entries = {item["id"]: item for item in registry["profiles"]}
        self.assertEqual(set(entries), set(actual))
        for profile_id, digest in actual.items():
            self.assertEqual(entries[profile_id]["profile_digest"], digest)
            self.assertFalse(entries[profile_id]["execution_authority"])


if __name__ == "__main__":
    unittest.main()
