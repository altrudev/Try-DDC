from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from .signing import sign_result, verify_signed_result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an Ed25519 Try DDC signed result envelope.")
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--out", default=Path("try-ddc-signed-result-envelope.json"), type=Path)
    parser.add_argument("--signer-role", default="try-ddc-result-signer")
    args = parser.parse_args()

    result = json.loads(args.result.read_text(encoding="utf-8"))
    envelope = sign_result(
        result,
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        issued_at=_now(),
        signer_role=args.signer_role,
    )
    if not verify_signed_result(envelope, public_key_path=args.public_key, result=result):
        raise SystemExit("signed envelope failed immediate verification")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("TRY_DDC_SIGNED_ENVELOPE=" + str(args.out.resolve()))
    print("TRY_DDC_SIGNER=" + envelope["key_fingerprint"])
    print("TRY_DDC_RESULT_DIGEST=" + envelope["payload"]["result_digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
