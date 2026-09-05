#!/usr/bin/env python3
"""DDCAL customer-side adapter v0.1.

The adapter runs inside the customer's environment. It accepts only a bounded
assessment plan containing registered capability IDs. It never evaluates shell
text from a plan and never exports source code by default.

Current v0.1 capabilities:
- repo.static                -> invokes the local Try DDC analyzer
- filesystem.manifest        -> hashes bounded local files without exporting contents
- api.http.readonly          -> anonymous GET/HEAD/OPTIONS against an explicit HTTPS URL
- blockchain.rpc.readonly    -> allowlisted read-only Ethereum JSON-RPC methods

The output is a DDCAL Evidence Capsule. Optional HMAC signing uses a local key
file that is never supplied by the remote plan.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

VERSION = "ddcal-adapter-v0.1"
PLAN_SCHEMA = "ddcal.assessment-plan.v1"
CAPSULE_SCHEMA = "ddcal.evidence-capsule.v1"
MAX_MANIFEST_FILES = 20000
MAX_HTTP_BYTES = 512 * 1024
MAX_RPC_BYTES = 1024 * 1024

READONLY_RPC_METHODS = {
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_call",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getBlockByNumber",
    "eth_getLogs",
}

CAPABILITIES = {
    "repo.static": "Local Try DDC bounded static repository review",
    "filesystem.manifest": "Local path/file manifest and SHA-256 commitments",
    "api.http.readonly": "Anonymous HTTPS GET/HEAD/OPTIONS observation",
    "blockchain.rpc.readonly": "Allowlisted read-only Ethereum-compatible JSON-RPC observation",
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(message: str) -> "NoReturn":
    print(f"BLOCKED: {message}", file=sys.stderr)
    raise SystemExit(2)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"cannot read JSON input: {exc.__class__.__name__}")
    if not isinstance(value, dict):
        fail("JSON input must be an object")
    return value


def safe_job_id(value: Any) -> str:
    text = str(value or "")
    if not re.fullmatch(r"ddcal_job_[A-Za-z0-9_-]{8,80}", text):
        fail("assessment plan contains an invalid job ID")
    return text


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("schema") != PLAN_SCHEMA:
        fail("unsupported assessment-plan schema")
    safe_job_id(plan.get("job_id"))
    profile = str(plan.get("profile_id") or "")
    if not re.fullmatch(r"ddcal\.[A-Za-z0-9_.-]{3,100}", profile):
        fail("assessment plan contains an invalid profile ID")
    expires = plan.get("expires_unix")
    if not isinstance(expires, int) or expires <= int(time.time()):
        fail("assessment plan is expired or lacks an expiry")
    capabilities = plan.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        fail("assessment plan has no capabilities")
    for item in capabilities:
        if not isinstance(item, dict):
            fail("capability entries must be objects")
        cap_id = str(item.get("id") or "")
        if cap_id not in CAPABILITIES:
            fail(f"unregistered capability requested: {cap_id}")
        params = item.get("params", {})
        if not isinstance(params, dict):
            fail(f"capability params must be an object: {cap_id}")
    export = plan.get("export_policy", {})
    if not isinstance(export, dict):
        fail("export_policy must be an object")
    if export.get("allow_source") is True:
        fail("v0.1 adapter refuses plans that authorize source-code export")
    if int(export.get("max_excerpt_bytes", 0) or 0) != 0:
        fail("v0.1 adapter does not export source excerpts")


def ensure_within(root: Path, candidate: Path) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        fail(f"path escapes registered root: {candidate}")
    return candidate


def run_repo_static(repo_root: Path, params: dict[str, Any], work: Path) -> dict[str, Any]:
    analyzer = Path(__file__).resolve().parents[1] / "try_ddc.py"
    if not analyzer.is_file():
        fail("local Try DDC analyzer is missing")
    target_rel = str(params.get("root") or ".")
    target = ensure_within(repo_root, repo_root / target_rel)
    out = work / "repo-static"
    out.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(analyzer), "--root", str(target), "--out-dir", str(out)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    result_file = out / "try-ddc-review.json"
    if proc.returncode != 0 or not result_file.is_file():
        return {
            "capability": "repo.static",
            "status": "BLOCKED",
            "exit_code": proc.returncode,
            "stderr_sha256": sha256_bytes(proc.stderr.encode("utf-8", errors="replace")),
            "source_exported": False,
        }
    result = read_json(result_file)
    return {
        "capability": "repo.static",
        "status": "COMPLETE",
        "result": result,
        "result_sha256": sha256_file(result_file),
        "source_exported": False,
    }


def run_filesystem_manifest(repo_root: Path, params: dict[str, Any], _work: Path) -> dict[str, Any]:
    requested = params.get("paths", ["."])
    if not isinstance(requested, list) or not requested or len(requested) > 50:
        fail("filesystem.manifest paths must contain 1..50 entries")
    records: list[dict[str, Any]] = []
    truncated = False
    for raw in requested:
        rel = str(raw)
        target = ensure_within(repo_root, repo_root / rel)
        candidates: list[Path]
        if target.is_file():
            candidates = [target]
        elif target.is_dir():
            candidates = [p for p in target.rglob("*") if p.is_file() and ".git" not in p.parts]
        else:
            continue
        for path in candidates:
            if len(records) >= MAX_MANIFEST_FILES:
                truncated = True
                break
            try:
                relpath = path.resolve().relative_to(repo_root.resolve()).as_posix()
                st = path.stat()
                digest = sha256_file(path)
            except (OSError, ValueError):
                continue
            records.append({"path": relpath, "size": st.st_size, "sha256": digest})
        if truncated:
            break
    records.sort(key=lambda x: x["path"])
    manifest_digest = sha256_bytes(canonical_bytes(records))
    return {
        "capability": "filesystem.manifest",
        "status": "COMPLETE",
        "files": len(records),
        "truncated": truncated,
        "manifest_sha256": manifest_digest,
        "records": records,
        "source_exported": False,
    }


def validate_https_url(value: str) -> str:
    try:
        parsed = urlparse(value)
    except ValueError:
        fail("invalid URL")
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        fail("adapter network targets must be credential-free HTTPS URLs")
    return value


def run_http_readonly(_repo_root: Path, params: dict[str, Any], _work: Path) -> dict[str, Any]:
    url = validate_https_url(str(params.get("url") or ""))
    method = str(params.get("method") or "HEAD").upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        fail("api.http.readonly permits only GET, HEAD, or OPTIONS")
    req = Request(url, method=method, headers={"User-Agent": f"DDCAL-Adapter/{VERSION}", "Accept": "*/*"})
    started = time.monotonic()
    try:
        with urlopen(req, timeout=15) as response:
            body = response.read(MAX_HTTP_BYTES + 1)
            status = response.status
            headers = {k.lower(): v[:1000] for k, v in response.headers.items() if k.lower() in {
                "content-type", "content-length", "cache-control", "etag", "last-modified",
                "strict-transport-security", "content-security-policy", "x-content-type-options",
            }}
    except HTTPError as exc:
        status = exc.code
        body = exc.read(MAX_HTTP_BYTES + 1)
        headers = {}
    except URLError:
        return {"capability": "api.http.readonly", "status": "BLOCKED", "transport": "unavailable", "source_exported": False}
    elapsed_ms = int((time.monotonic() - started) * 1000)
    truncated = len(body) > MAX_HTTP_BYTES
    body = body[:MAX_HTTP_BYTES]
    return {
        "capability": "api.http.readonly",
        "status": "COMPLETE",
        "url": url,
        "method": method,
        "http_status": status,
        "elapsed_ms": elapsed_ms,
        "headers": headers,
        "body_sha256": sha256_bytes(body),
        "body_bytes_observed": len(body),
        "body_truncated": truncated,
        "body_exported": False,
        "source_exported": False,
    }


def run_blockchain_rpc(_repo_root: Path, params: dict[str, Any], _work: Path) -> dict[str, Any]:
    rpc_url = validate_https_url(str(params.get("rpc_url") or ""))
    calls = params.get("calls")
    if not isinstance(calls, list) or not calls or len(calls) > 50:
        fail("blockchain.rpc.readonly requires 1..50 calls")
    observations: list[dict[str, Any]] = []
    for index, call in enumerate(calls, start=1):
        if not isinstance(call, dict):
            fail("RPC call entries must be objects")
        method = str(call.get("method") or "")
        if method not in READONLY_RPC_METHODS:
            fail(f"RPC method is not allowlisted as read-only: {method}")
        rpc_params = call.get("params", [])
        if not isinstance(rpc_params, list):
            fail("RPC params must be an array")
        payload = canonical_bytes({"jsonrpc": "2.0", "id": index, "method": method, "params": rpc_params})
        req = Request(rpc_url, method="POST", data=payload, headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"DDCAL-Adapter/{VERSION}",
        })
        try:
            with urlopen(req, timeout=20) as response:
                raw = response.read(MAX_RPC_BYTES + 1)
        except (HTTPError, URLError):
            observations.append({"method": method, "status": "BLOCKED", "response_sha256": None})
            continue
        truncated = len(raw) > MAX_RPC_BYTES
        raw = raw[:MAX_RPC_BYTES]
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            decoded = None
        observations.append({
            "method": method,
            "status": "COMPLETE" if decoded is not None else "INCONCLUSIVE",
            "response_sha256": sha256_bytes(raw),
            "response": decoded,
            "response_truncated": truncated,
        })
    return {
        "capability": "blockchain.rpc.readonly",
        "status": "COMPLETE",
        "rpc_origin": urlparse(rpc_url).netloc,
        "calls": observations,
        "transaction_signing_authority": False,
        "private_key_authority": False,
        "source_exported": False,
    }


RUNNERS = {
    "repo.static": run_repo_static,
    "filesystem.manifest": run_filesystem_manifest,
    "api.http.readonly": run_http_readonly,
    "blockchain.rpc.readonly": run_blockchain_rpc,
}


def sign_capsule(capsule: dict[str, Any], key_file: Path | None) -> dict[str, Any]:
    unsigned = dict(capsule)
    unsigned.pop("signature", None)
    digest = sha256_bytes(canonical_bytes(unsigned))
    signature: dict[str, Any] = {"capsule_sha256": digest, "algorithm": "none"}
    if key_file is not None:
        try:
            if key_file.stat().st_mode & 0o077:
                fail("adapter signing key file permissions are too broad")
            key = key_file.read_bytes().strip()
        except OSError:
            fail("adapter signing key file is unavailable")
        if len(key) < 32:
            fail("adapter signing key must contain at least 32 bytes")
        signature = {
            "capsule_sha256": digest,
            "algorithm": "hmac-sha256",
            "value": hmac.new(key, canonical_bytes(unsigned), hashlib.sha256).hexdigest(),
        }
    capsule["signature"] = signature
    return capsule


def run_plan(plan_path: Path, repo_root: Path, out_dir: Path, signing_key: Path | None) -> dict[str, Any]:
    plan = read_json(plan_path)
    validate_plan(plan)
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / ".work"
    work.mkdir(parents=True, exist_ok=True)
    results = []
    for item in plan["capabilities"]:
        cap_id = item["id"]
        results.append(RUNNERS[cap_id](repo_root, item.get("params", {}), work))
    plan_digest = sha256_bytes(canonical_bytes(plan))
    capsule = {
        "schema": CAPSULE_SCHEMA,
        "adapter_version": VERSION,
        "job_id": safe_job_id(plan["job_id"]),
        "profile_id": plan["profile_id"],
        "assessment_plan_sha256": plan_digest,
        "target": plan.get("target", {}),
        "executed_capabilities": [r["capability"] for r in results],
        "results": results,
        "export": {
            "source_code_exported": False,
            "source_excerpts_exported": False,
            "arbitrary_shell_authority": False,
            "private_key_authority": False,
        },
        "created_unix": int(time.time()),
    }
    sign_capsule(capsule, signing_key)
    capsule_path = out_dir / "ddcal-evidence-capsule.json"
    capsule_path.write_bytes(canonical_bytes(capsule) + b"\n")
    (out_dir / "ddcal-evidence-capsule.json.sha256").write_text(
        f"{sha256_file(capsule_path)}  {capsule_path.name}\n", encoding="utf-8"
    )
    return {"capsule": str(capsule_path), "sha256": sha256_file(capsule_path)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="List locally registered capabilities")
    run = sub.add_parser("run", help="Execute one bounded assessment plan locally")
    run.add_argument("--plan", required=True, type=Path)
    run.add_argument("--root", default=".", type=Path, help="Registered customer-controlled root")
    run.add_argument("--out-dir", default="ddcal-adapter-output", type=Path)
    run.add_argument("--signing-key-file", type=Path, default=None)
    args = parser.parse_args()

    if args.command == "capabilities":
        print(json.dumps({"adapter_version": VERSION, "capabilities": CAPABILITIES}, indent=2, sort_keys=True))
        return 0
    if args.command == "run":
        result = run_plan(args.plan.resolve(), args.root.resolve(), args.out_dir.resolve(), args.signing_key_file.resolve() if args.signing_key_file else None)
        print(json.dumps(result, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
