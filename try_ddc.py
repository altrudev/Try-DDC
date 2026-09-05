#!/usr/bin/env python3
"""Try DDC public GitHub/local edition.

A bounded, non-executing static preflight. It does not install dependencies,
run target code, or contact ddcal.ca. Output is review evidence only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

VERSION = "TRY-DDC-GITHUB-0.1"
MAX_TREE_FILES = 12000
MAX_SELECTED_FILES = 22
MAX_FILE_BYTES = 120000
MAX_TOTAL_BYTES = 650000
MAX_PUBLIC_FINDINGS = 8

EXCLUDED = {
    ".git", "node_modules", "vendor", "dist", "build", "coverage", ".next",
    "target", ".venv", "venv", "__pycache__",
}
CRITICAL_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "poetry.lock",
    "pdm.lock", "uv.lock", "cargo.lock", "go.mod", "go.sum", "composer.lock",
    "gemfile.lock", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml", "pom.xml", "build.gradle", "build.gradle.kts",
    "package.json",
}
LOCK_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "poetry.lock", "uv.lock",
    "cargo.lock", "composer.lock", "gemfile.lock", "go.sum",
}
SOURCE_EXTENSIONS = {
    ".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".sh", ".bash",
    ".ps1", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".php", ".rb", ".go", ".rs", ".java", ".kt", ".cs", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".swift", ".txt",
}

RULES = [
    ("high", "Secrets", "Private key material",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I),
     "Private key material appears in source; matched values are never copied into the report.",
     "Rotate/remove exposed key material and use a scoped secret store."),
    ("high", "Secrets", "GitHub token-like value",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"),
     "Credential-like GitHub token material appears in source; matched values are redacted.",
     "Revoke/rotate the token and remove it from repository history where appropriate."),
    ("high", "Secrets", "AWS access-key-like value",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS credential-like material appears in source; matched values are redacted.",
     "Rotate the credential and remove it from repository history."),
    ("medium", "Secrets", "Hard-coded secret-like assignment",
     re.compile(r"\b(api[_-]?key|secret|password|passwd|access[_-]?token)\b\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']", re.I),
     "A secret-like value may be hard-coded; the value is not included in this result.",
     "Move secrets to a scoped secret mechanism and verify repository history."),
    ("critical", "Execution boundary", "Docker socket exposure",
     re.compile(r"/var/run/docker\.sock", re.I),
     "A Docker socket reference can collapse container-to-host isolation if exposed to untrusted workloads.",
     "Remove Docker socket access from untrusted execution paths."),
    ("critical", "Execution boundary", "Privileged container configuration",
     re.compile(r"^\s*privileged\s*:\s*true\s*$", re.I | re.M),
     "A privileged container configuration was observed.",
     "Do not use privileged containers for untrusted or generated code."),
    ("high", "Command execution", "Shell pipeline installer",
     re.compile(r"\b(curl|wget)\b[^\n|]{0,180}\|\s*(?:sudo\s+)?(?:sh|bash)\b", re.I),
     "Network-fetched content is piped directly to a shell.",
     "Pin and verify installer artifacts before execution."),
    ("high", "Command execution", "Dynamic evaluation primitive",
     re.compile(r"\b(eval|Function)\s*\(", re.I),
     "Dynamic code evaluation was observed in a selected source file.",
     "Avoid dynamic evaluation for untrusted input; prefer explicit parsing or dispatch."),
    ("high", "Command execution", "Python subprocess shell mode",
     re.compile(r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(.{0,300}?shell\s*=\s*True", re.I | re.S),
     "Python subprocess execution with shell=True was observed.",
     "Prefer argv-style execution and keep untrusted values out of shell parsing."),
    ("high", "Transport security", "TLS verification disabled",
     re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0", re.I),
     "TLS certificate verification appears to be disabled.",
     "Keep certificate verification enabled and fix trust configuration instead."),
    ("medium", "Filesystem", "World-writable permission",
     re.compile(r"chmod\s+(?:-R\s+)?777\b", re.I),
     "World-writable permissions were observed.",
     "Use the minimum required file permissions."),
    ("medium", "CI authority", "Broad workflow write authority",
     re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.I | re.M),
     "A GitHub workflow declares broad write-all permissions.",
     "Grant only the permissions required by the job."),
    ("medium", "Deserialization", "Unsafe Python pickle usage",
     re.compile(r"\bpickle\.(?:loads?|Unpickler)\b"),
     "Python pickle deserialization was observed; pickle is unsafe for untrusted data.",
     "Use a non-executable serialization format for untrusted input."),
    ("medium", "Cryptography", "Weak hash primitive",
     re.compile(r"\b(md5|sha1)\s*\(", re.I),
     "A weak hash primitive was observed and may be inappropriate for security or integrity decisions.",
     "Use SHA-256 or stronger where collision resistance matters."),
]


def priority(rel: str) -> int:
    p = rel.lower()
    base = Path(rel).name.lower()
    if base in CRITICAL_NAMES:
        return 100
    if p.startswith(".github/workflows/") or "/.github/workflows/" in p:
        return 95
    if base.endswith(".env.example") or Path(base).suffix in {".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".sh", ".bash", ".ps1"}:
        return 80
    if Path(base).suffix in SOURCE_EXTENSIONS:
        return 60
    return 10


def git_value(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=4,
        ).strip()
    except Exception:
        return "unavailable"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def add_finding(findings: list[dict[str, Any]], severity: str, category: str,
                title: str, summary: str, location: str = "", suggestion: str = "") -> None:
    findings.append({
        "severity": severity,
        "category": category,
        "title": title,
        "summary": summary,
        "location": location,
        "suggestion": suggestion,
    })


def scan(root: Path) -> dict[str, Any]:
    observed: list[tuple[str, int]] = []
    symlinks: list[str] = []
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED]
        for name in filenames:
            p = Path(dirpath) / name
            rel = str((rel_dir / name).as_posix())
            try:
                if p.is_symlink():
                    symlinks.append(rel)
                    continue
                size = p.stat().st_size
            except OSError:
                continue
            observed.append((rel, size))
            if len(observed) >= MAX_TREE_FILES:
                truncated = True
                break
        if truncated:
            break

    candidates = [
        (rel, size, priority(rel))
        for rel, size in observed
        if 0 < size <= MAX_FILE_BYTES and priority(rel) >= 50
    ]
    candidates.sort(key=lambda x: (-x[2], x[1], x[0]))

    selected: list[tuple[str, int, int]] = []
    total = 0
    for item in candidates:
        if len(selected) >= MAX_SELECTED_FILES:
            break
        if total + item[1] > MAX_TOTAL_BYTES:
            continue
        selected.append(item)
        total += item[1]

    findings: list[dict[str, Any]] = []
    authority_workflow = False
    analyzed = 0

    if symlinks:
        add_finding(
            findings, "low", "Repository structure", "Symbolic links observed",
            "Symbolic links exist in the repository and should be reviewed before execution.",
            symlinks[0],
            "Confirm every link target stays within the intended trust boundary.",
        )
    if (root / ".gitmodules").exists():
        add_finding(
            findings, "medium", "Supply chain", "Git submodule configuration observed",
            "Submodules introduce separately versioned code and trust dependencies.",
            ".gitmodules",
            "Pin and review each submodule source and commit before execution.",
        )

    for rel, _size, _prio in selected:
        p = root / rel
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        analyzed += 1

        for severity, category, title, rx, summary, suggestion in RULES:
            m = rx.search(text)
            if not m:
                continue
            line = text.count("\n", 0, m.start()) + 1
            add_finding(findings, severity, category, title, summary, f"{rel}:{line}", suggestion)

        low = rel.lower()
        if ".github/workflows/" in low and re.search(r"^\s*(?:push|pull_request_target)\s*:", text, re.I | re.M):
            authority_workflow = True

        if Path(rel).name.lower() == "dockerfile" and not re.search(r"^\s*USER\s+\S+", text, re.I | re.M):
            add_finding(
                findings, "medium", "Container", "Container user not explicitly constrained",
                "A selected Dockerfile does not declare a non-root USER.", rel,
                "Declare a non-root runtime user unless root is explicitly required and separately constrained.",
            )

    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings.sort(key=lambda f: (-rank.get(f["severity"].lower(), 0), f["location"], f["title"]))

    critical_high = sum(1 for f in findings if f["severity"] in {"critical", "high"})
    critical = sum(1 for f in findings if f["severity"] == "critical")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low_info = len(findings) - critical_high - medium

    minimum_analyzed = min(8, max(1, (len(selected) + 1) // 2)) if selected else 1
    coverage_insufficient = not selected or analyzed < minimum_analyzed or truncated
    disposition = (
        "BLOCKED" if critical else
        "REVIEW_REQUIRED" if critical_high or coverage_insufficient else
        "NO_HIGH_RISK_OBSERVED"
    )
    lock_observed = any(Path(rel).name.lower() in LOCK_NAMES for rel, _, _ in selected)

    commit = git_value(root, "rev-parse", "HEAD")
    repository = os.getenv("GITHUB_REPOSITORY") or git_value(root, "config", "--get", "remote.origin.url")

    summary = (
        "The pre-execution gate observed a condition that would block dynamic execution eligibility."
        if disposition == "BLOCKED" else
        "High-risk signals were observed and require review before any future execution decision."
        if critical_high else
        "Coverage was insufficient for a clean demo signal; review is required and no execution authority is created."
        if coverage_insufficient else
        "No high-risk signal was observed in the bounded scanned subset; this is not a safety determination."
    )

    return {
        "schema": "https://ddcal.ca/schema/try-ddc-github-v0.1",
        "tool_version": VERSION,
        "repository": repository,
        "commit": commit,
        "title": "Try DDC GitHub/local static pre-execution review",
        "summary": summary,
        "disposition": disposition,
        "coverage": {
            "files_observed": len(observed),
            "files_selected": len(selected),
            "files_analyzed": analyzed,
            "tree_truncated": truncated,
            "dependency_advisory_lookup": "NOT_RUN_LOCAL",
        },
        "counts": {
            "critical_high": critical_high,
            "medium": medium,
            "low_info": low_info,
            "dependency_advisories": 0,
        },
        "findings": findings[:MAX_PUBLIC_FINDINGS],
        "ddc_signals": [
            {
                "name": "Repository provenance",
                "status": "INCONCLUSIVE",
                "detail": f"Result is bound to local commit {commit[:12] if commit != 'unavailable' else 'unavailable'}; Git identity alone does not prove artifact provenance.",
            },
            {
                "name": "Authority boundary",
                "status": "INCONCLUSIVE",
                "detail": "Workflow-triggered authority was observed and requires contextual review." if authority_workflow else "Static source alone does not establish the full runtime authority model.",
            },
            {
                "name": "Dependency immutability",
                "status": "INCONCLUSIVE",
                "detail": "At least one lock/resolution artifact was observed, but static subset analysis does not establish immutability of every build input." if lock_observed else "No supported lock/resolution artifact was observed in the analyzed subset.",
            },
            {
                "name": "Verifier independence",
                "status": "INCONCLUSIVE",
                "detail": "A local static review cannot establish independence of production and verification dependencies, credentials, assumptions, or evidence sources.",
            },
            {
                "name": "Transition assurance",
                "status": "INCONCLUSIVE",
                "detail": "The source predecessor is pinned, but runtime successor verification and acceptance are outside this non-executing review.",
            },
            {
                "name": "Recovery independence",
                "status": "NOT ASSESSED",
                "detail": "Recovery evidence and recovery authority are not exercised by this non-executing review.",
            },
        ],
        "limitations": [
            "Only a bounded selected subset of text files is analyzed.",
            "No repository code, installer, dependency, build, test, or script is executed.",
            "Static rules can miss vulnerabilities and can produce false positives.",
            "Dependency advisory lookup is not run in the local GitHub version v0.1.",
        ] + (["The file walk hit its maximum bound, so repository coverage is partial."] if truncated else []),
        "boundary": "This is a reduced Try DDC review artifact, not a DDC Assurance Lab assessment, certification, accredited result, penetration test, security guarantee, or authorization to execute the repository.",
    }


def markdown(result: dict[str, Any], digest: str) -> str:
    c = result["coverage"]
    n = result["counts"]
    lines = [
        "# Try DDC Review",
        "",
        f"**Disposition:** `{result['disposition']}`  ",
        f"**Repository:** `{result['repository']}`  ",
        f"**Commit:** `{result['commit']}`  ",
        f"**Canonical result SHA-256:** `{digest}`",
        "",
        result["summary"],
        "",
        "## Coverage",
        "",
        f"- Files observed: {c['files_observed']}",
        f"- Files selected: {c['files_selected']}",
        f"- Files analyzed: {c['files_analyzed']}",
        f"- Tree truncated: {c['tree_truncated']}",
        f"- Dependency advisory lookup: {c['dependency_advisory_lookup']}",
        "",
        "## Counts",
        "",
        f"- Critical/high: {n['critical_high']}",
        f"- Medium: {n['medium']}",
        f"- Low/informational: {n['low_info']}",
        "",
        "## Representative findings",
        "",
    ]
    if not result["findings"]:
        lines.append("No representative finding was emitted from the bounded scanned subset. This is not a clean-bill-of-health statement.")
    else:
        for f in result["findings"]:
            lines += [
                f"### {f['severity'].upper()} · {f['title']}",
                "",
                f["summary"],
                "",
                f"- Category: {f['category']}",
                f"- Location: `{f['location'] or 'not specified'}`",
                f"- Suggested review: {f['suggestion']}",
                "",
            ]

    lines += ["## DDC assurance signals", ""]
    for signal in result["ddc_signals"]:
        lines.append(f"- **{signal['name']} — {signal['status']}:** {signal['detail']}")

    lines += ["", "## Limitations", ""]
    lines += [f"- {x}" for x in result["limitations"]]
    lines += [
        "", "---", "", result["boundary"], "",
        "Full DDCAL services: https://ddcal.ca/services.html", "",
    ]
    return "\n".join(lines)


def wrap(text: str, width: int = 88) -> list[str]:
    words = text.replace("\t", " ").split()
    if not words:
        return [""]
    out, line = [], words[0]
    for word in words[1:]:
        if len(line) + 1 + len(word) <= width:
            line += " " + word
        else:
            out.append(line)
            line = word
    out.append(line)
    return out


def pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(result: dict[str, Any], result_digest: str) -> bytes:
    lines: list[str] = [
        "DDC Assurance Lab — Try DDC Review",
        "",
        f"Disposition: {result['disposition']}",
        f"Repository: {result['repository']}",
        f"Commit: {result['commit']}",
        f"Canonical result SHA-256: {result_digest}",
        "",
    ]
    lines += wrap(result["summary"])
    lines += ["", "Coverage"]
    c = result["coverage"]
    lines += [
        f"Files observed: {c['files_observed']}",
        f"Files selected: {c['files_selected']}",
        f"Files analyzed: {c['files_analyzed']}",
        f"Tree truncated: {c['tree_truncated']}",
        "",
        "Representative findings",
    ]

    if not result["findings"]:
        lines += wrap("No representative finding was emitted from the bounded scanned subset. This is not a clean-bill-of-health statement.")
    else:
        for f in result["findings"]:
            lines.append("")
            lines += wrap(f"[{f['severity'].upper()}] {f['title']}")
            lines += wrap(f"Location: {f['location'] or 'not specified'}")
            lines += wrap(f["summary"])
            lines += wrap(f"Suggested review: {f['suggestion']}")

    lines += ["", "DDC assurance signals"]
    for s in result["ddc_signals"]:
        lines += wrap(f"{s['name']} — {s['status']}: {s['detail']}")

    lines += ["", "Limitations"]
    for item in result["limitations"]:
        lines += wrap("• " + item)

    lines += ["", "Boundary"]
    lines += wrap(result["boundary"])
    lines += ["", "Full DDCAL services: https://ddcal.ca/services.html"]

    # Replace characters outside the built-in PDF font's practical range.
    safe_lines = [line.encode("latin-1", "replace").decode("latin-1") for line in lines]
    per_page = 48
    pages = [safe_lines[i:i + per_page] for i in range(0, len(safe_lines), per_page)] or [[""]]

    objects: list[str] = [""]
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    objects.append("")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    page_refs = []
    for page in pages:
        page_obj = len(objects)
        content_obj = page_obj + 1
        page_refs.append(f"{page_obj} 0 R")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_obj} 0 R >>")

        stream_lines = ["BT", "/F1 9 Tf", "11 TL", "45 750 Td"]
        for idx, line in enumerate(page):
            font = "/F2 11 Tf" if idx == 0 and page is pages[0] else "/F1 9 Tf"
            stream_lines.append(font)
            stream_lines.append(f"({pdf_escape(line)}) Tj")
            stream_lines.append("T*")
        stream_lines.append("ET")
        stream = "\n".join(stream_lines)
        objects.append(f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream")

    objects[2] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>"

    pdf = "%PDF-1.4\n%DDCAL\n"
    offsets = [0]
    for i in range(1, len(objects)):
        offsets.append(len(pdf.encode("latin-1")))
        pdf += f"{i} 0 obj\n{objects[i]}\nendobj\n"

    xref = len(pdf.encode("latin-1"))
    pdf += f"xref\n0 {len(objects)}\n0000000000 65535 f \n"
    for off in offsets[1:]:
        pdf += f"{off:010d} 00000 n \n"
    pdf += f"trailer\n<< /Size {len(objects)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    return pdf.encode("latin-1")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repository root to inspect")
    parser.add_argument("--out-dir", default="try-ddc-output", help="Output directory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    result = scan(root)
    canonical = canonical_bytes(result)
    result_digest = hashlib.sha256(canonical).hexdigest()

    json_name = "try-ddc-review.json"
    md_name = "try-ddc-review.md"
    pdf_name = "try-ddc-review.pdf"

    (out / json_name).write_bytes(canonical + b"\n")
    (out / md_name).write_text(markdown(result, result_digest), encoding="utf-8")

    pdf = build_pdf(result, result_digest)
    pdf_digest = hashlib.sha256(pdf).hexdigest()
    (out / pdf_name).write_bytes(pdf)

    (out / f"{json_name}.sha256").write_text(
        f"{result_digest}  {json_name}\n",
        encoding="utf-8",
    )
    (out / f"{pdf_name}.sha256").write_text(
        f"{pdf_digest}  {pdf_name}\n"
        f"{result_digest}  canonical-reduced-result-json\n"
        "note=SHA-256 provides tamper evidence, not issuer authentication or certification.\n",
        encoding="utf-8",
    )

    print(f"TRY_DDC_DISPOSITION={result['disposition']}")
    print(f"TRY_DDC_RESULT_SHA256={result_digest}")
    print(f"TRY_DDC_PDF_SHA256={pdf_digest}")
    print(f"TRY_DDC_OUTPUT={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
