from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

from .canonical import canonical_bytes, sha256_digest
from .model import ValidationError


_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


def _utc(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValidationError("invalid-issued-at") from exc
    if parsed.tzinfo is None:
        raise ValidationError("issued-at-must-have-timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise RuntimeError("openssl-unavailable")
    return path


def _run(argv: list[str], *, stdin: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("openssl-execution-failed") from exc
    if proc.returncode != 0:
        raise RuntimeError("openssl-operation-failed")
    return proc.stdout


def public_key_der(public_key_path: Path) -> bytes:
    path = public_key_path.resolve()
    if not path.is_file():
        raise ValidationError("public-key-missing")
    return _run([
        _openssl(),
        "pkey",
        "-pubin",
        "-in",
        str(path),
        "-outform",
        "DER",
    ])


def signer_fingerprint(public_key_path: Path) -> str:
    return "sha256:" + hashlib.sha256(public_key_der(public_key_path)).hexdigest()


def _sign_bytes(payload: bytes, private_key_path: Path) -> bytes:
    path = private_key_path.resolve()
    if not path.is_file():
        raise ValidationError("private-key-missing")
    with tempfile.TemporaryDirectory() as td:
        message = Path(td) / "message.bin"
        signature = Path(td) / "signature.bin"
        message.write_bytes(payload)
        _run([
            _openssl(),
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(path),
            "-in",
            str(message),
            "-out",
            str(signature),
        ])
        return signature.read_bytes()


def _verify_bytes(payload: bytes, signature: bytes, public_key_path: Path) -> bool:
    path = public_key_path.resolve()
    if not path.is_file():
        raise ValidationError("public-key-missing")
    with tempfile.TemporaryDirectory() as td:
        message = Path(td) / "message.bin"
        sig = Path(td) / "signature.bin"
        message.write_bytes(payload)
        sig.write_bytes(signature)
        try:
            _run([
                _openssl(),
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(path),
                "-in",
                str(message),
                "-sigfile",
                str(sig),
            ])
        except RuntimeError:
            return False
        return True


def _capability_binding(result: dict[str, Any]) -> list[dict[str, str]]:
    capabilities = result.get("capabilities", [])
    if not isinstance(capabilities, list):
        raise ValidationError("result-capabilities-invalid")
    bound: list[dict[str, str]] = []
    for item in capabilities:
        if not isinstance(item, dict):
            raise ValidationError("result-capability-invalid")
        cap = {
            "capability_id": item.get("capability_id"),
            "capability_version": item.get("capability_version"),
            "capability_digest": item.get("capability_digest"),
            "implementation_revision": item.get("implementation_revision"),
        }
        if not all(isinstance(v, str) and v for v in cap.values()):
            raise ValidationError("result-capability-binding-invalid")
        if not _SHA256_RE.fullmatch(cap["capability_digest"]):
            raise ValidationError("result-capability-digest-invalid")
        bound.append(cap)
    return sorted(
        bound,
        key=lambda x: (
            x["capability_id"],
            x["capability_version"],
            x["capability_digest"],
            x["implementation_revision"],
        ),
    )


def build_signature_payload(
    result: dict[str, Any],
    *,
    issued_at: str,
    signer_fingerprint_value: str,
    signer_role: str = "try-ddc-result-signer",
) -> dict[str, Any]:
    if not isinstance(result, dict) or result.get("schema") != "try-ddc-result/2":
        raise ValidationError("unsupported-result-schema")
    result_id = result.get("result_id")
    case_id = result.get("case_id")
    target_id = result.get("target_id")
    profile = result.get("profile")
    capture = result.get("capture")
    result_revision = result.get("result_revision")
    if not all(isinstance(v, str) and _ID_RE.fullmatch(v) for v in (result_id, case_id, target_id)):
        raise ValidationError("result-identity-invalid")
    if not isinstance(profile, dict) or not isinstance(capture, dict):
        raise ValidationError("result-binding-invalid")
    if not isinstance(result_revision, int) or result_revision < 1:
        raise ValidationError("result-revision-invalid")

    profile_digest = profile.get("digest")
    evidence_root = capture.get("evidence_root")
    if not isinstance(profile_digest, str) or not _SHA256_RE.fullmatch(profile_digest):
        raise ValidationError("profile-digest-invalid")
    if not isinstance(evidence_root, str) or not _SHA256_RE.fullmatch(evidence_root):
        raise ValidationError("evidence-root-invalid")
    if not isinstance(signer_fingerprint_value, str) or not _SHA256_RE.fullmatch(signer_fingerprint_value):
        raise ValidationError("signer-fingerprint-invalid")
    if not isinstance(signer_role, str) or not _ID_RE.fullmatch(signer_role):
        raise ValidationError("signer-role-invalid")

    result_digest = sha256_digest(result)
    return {
        "schema": "try-ddc-result-signature-payload/1",
        "document_class": "TRY_DDC_SIGNED_RESULT_ENVELOPE",
        "result_id": result_id,
        "result_revision": result_revision,
        "case_id": case_id,
        "target_id": target_id,
        "result_digest": result_digest,
        "evidence_root": evidence_root,
        "profile": {
            "id": profile.get("id"),
            "version": profile.get("version"),
            "digest": profile_digest,
        },
        "capabilities": _capability_binding(result),
        "signer": {
            "fingerprint": signer_fingerprint_value,
            "role": signer_role,
        },
        "issued_at": _utc(issued_at),
        "semantics": {
            "signature_establishes": "origin-and-integrity-of-this-envelope-binding",
            "signature_does_not_establish": [
                "certification",
                "accreditation",
                "safety",
                "correctness",
                "authorization-to-execute",
            ],
        },
    }


def sign_result(
    result: dict[str, Any],
    *,
    private_key_path: Path,
    public_key_path: Path,
    issued_at: str,
    signer_role: str = "try-ddc-result-signer",
) -> dict[str, Any]:
    fingerprint = signer_fingerprint(public_key_path)
    payload = build_signature_payload(
        result,
        issued_at=issued_at,
        signer_fingerprint_value=fingerprint,
        signer_role=signer_role,
    )
    payload_bytes = canonical_bytes(payload)
    signature = _sign_bytes(payload_bytes, private_key_path)
    if not _verify_bytes(payload_bytes, signature, public_key_path):
        raise ValidationError("signing-key-pair-mismatch")
    return {
        "schema": "try-ddc-signed-result-envelope/1",
        "algorithm": "ed25519",
        "key_fingerprint": fingerprint,
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_signed_result(
    envelope: dict[str, Any],
    *,
    public_key_path: Path,
    result: dict[str, Any] | None = None,
) -> bool:
    if not isinstance(envelope, dict) or envelope.get("schema") != "try-ddc-signed-result-envelope/1":
        return False
    if envelope.get("algorithm") != "ed25519":
        return False
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != "try-ddc-result-signature-payload/1":
        return False
    try:
        expected_fp = signer_fingerprint(public_key_path)
    except (RuntimeError, ValidationError):
        return False
    if envelope.get("key_fingerprint") != expected_fp:
        return False
    signer = payload.get("signer")
    if not isinstance(signer, dict) or signer.get("fingerprint") != expected_fp:
        return False

    if result is not None:
        try:
            expected_payload = build_signature_payload(
                result,
                issued_at=str(payload.get("issued_at") or ""),
                signer_fingerprint_value=expected_fp,
                signer_role=str(signer.get("role") or ""),
            )
        except ValidationError:
            return False
        if expected_payload != payload:
            return False

    sig_b64 = envelope.get("signature_b64")
    if not isinstance(sig_b64, str):
        return False
    try:
        signature = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    return _verify_bytes(canonical_bytes(payload), signature, public_key_path)
