from __future__ import annotations

import argparse
from pathlib import Path

from .canonical import strict_json_file
from .signing import verify_signed_result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Try DDC signed result envelope.")
    parser.add_argument("--envelope", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--result", type=Path, help="Require binding to this exact Try DDC result.")
    args = parser.parse_args()

    envelope = strict_json_file(args.envelope)
    result = strict_json_file(args.result) if args.result else None
    ok = verify_signed_result(
        envelope,
        public_key_path=args.public_key,
        result=result,
    )
    if not ok:
        print("TRY_DDC_SIGNATURE_VALID=false")
        return 2
    print("TRY_DDC_SIGNATURE_VALID=true")
    print("TRY_DDC_BINDING_MODE=" + ("RESULT_BOUND" if result is not None else "ENVELOPE_ONLY"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
