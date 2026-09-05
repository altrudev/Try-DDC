# Try DDC

A reduced, auditable version of **Try DDC** that runs on your own machine or GitHub Actions runner.

It is for people who want to inspect a repository without submitting that repository to an unfamiliar website.

## What it does

Try DDC performs a bounded, static pre-execution review of a checked-out repository. It looks for selected signals involving repository structure, secrets, execution boundaries, CI authority, containers, transport security, filesystem permissions, deserialization, cryptography, provenance, dependency-resolution evidence, verification, transition, and recovery boundaries.

It does **not**:

- upload your source code to DDC Assurance Lab;
- contact `ddcal.ca` during analysis;
- execute repository code;
- install dependencies;
- run builds, tests, installers, package scripts, or target-repository workflows.

## Output

Each run produces:

- `try-ddc-review.md` — human-readable review;
- `try-ddc-review.json` — deterministic machine-readable result;
- `try-ddc-review.json.sha256` — SHA-256 for the canonical JSON result;
- the same Markdown review in the GitHub Actions job summary.

The hosted Try DDC page at https://ddcal.ca/try.html may also provide a PDF review artifact.

## GitHub Actions

Use an exact commit SHA when referencing this action:

```yaml
name: Try DDC

on:
  workflow_dispatch:
  pull_request:

permissions:
  contents: read

jobs:
  try-ddc:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout exact repository state
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run Try DDC
        uses: altrudev/Try-DDC@<EXACT_COMMIT_SHA>

      - name: Upload review artifacts
        uses: actions/upload-artifact@v4
        with:
          name: try-ddc-review-${{ github.sha }}
          path: |
            try-ddc-output/try-ddc-review.md
            try-ddc-output/try-ddc-review.json
            try-ddc-output/try-ddc-review.json.sha256
          if-no-files-found: error
```

Pinning to an exact commit lets you inspect precisely what analyzer code you are trusting.

## Local use

```bash
python3 try_ddc.py --root . --out-dir try-ddc-output
```

Only the Python standard library is required.

## Result semantics

Possible reduced-review dispositions are:

- `BLOCKED` — a critical static execution-boundary condition was observed.
- `REVIEW_REQUIRED` — high-risk evidence or insufficient bounded coverage requires review.
- `NO_HIGH_RISK_OBSERVED` — no high-risk signal was observed in the bounded scanned subset.

`NO_HIGH_RISK_OBSERVED` is **not** a safety determination or a clean bill of health.

## Assurance boundary

This repository provides a reduced Try DDC review tool. Its output is **not** a DDC Assurance Lab assessment, certification, accredited result, penetration test, security guarantee, or authorization to execute a repository.

For a defined DDCAL assessment using broader evidence and an explicit scope, see:

https://ddcal.ca/services.html

## Security and privacy model

The default action requests only `contents: read`. The recommended checkout configuration disables persisted GitHub credentials. The analyzer itself makes no network request.

Review this repository and pin the exact commit you choose to trust before using it on sensitive code.
