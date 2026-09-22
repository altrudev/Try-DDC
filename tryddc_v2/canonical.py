from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_MAX_JSON_BYTES = 8 * 1024 * 1024


def canonical_bytes(value: Any) -> bytes:
    """Deterministic UTF-8 JSON used for all v2 digests.

    This is the Try DDC v2 canonical form. It is intentionally narrow:
    sorted object keys, UTF-8, compact separators, finite JSON numbers, and
    one trailing LF. Cross-language implementations must reproduce these
    bytes exactly before claiming digest interoperability.
    """
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json_loads(raw: bytes | str, *, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> Any:
    if isinstance(raw, str):
        encoded = raw.encode("utf-8")
    elif isinstance(raw, (bytes, bytearray)):
        encoded = bytes(raw)
    else:
        raise ValueError("json-input-type-invalid")
    if len(encoded) > max_bytes:
        raise ValueError("json-input-too-large")

    def reject_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate-json-key:{key}")
            out[key] = value
        return out

    try:
        return json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite-json-number:{value}")),
        )
    except UnicodeDecodeError as exc:
        raise ValueError("json-not-utf8") from exc


def strict_json_file(path: Path, *, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> Any:
    path = path.resolve()
    if not path.is_file():
        raise ValueError("json-file-missing")
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError("json-input-too-large")
    return strict_json_loads(path.read_bytes(), max_bytes=max_bytes)
