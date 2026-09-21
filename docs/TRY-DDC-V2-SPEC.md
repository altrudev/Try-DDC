# Try DDC v2 — implementation baseline

Status: implementation candidate. This document defines the common evidence spine; it does not authorize public release or formal DDCAL assurance use.

## Purpose

Try DDC v2 is a bounded evidence-assurance router. It captures evidence about a typed target, freezes that evidence, runs registered analysis capabilities, and reports what the evidence establishes, contradicts, or leaves unresolved.

It is not a generic executor and does not inherit authority from submitted content.

## Hard invariants

1. Input is never authority.
2. Evidence is never authority.
3. Missing evidence is never PASS.
4. Later evidence never becomes contemporaneous evidence.
5. Captured evidence and derived evidence remain distinct.
6. Claim, observation, and determination remain distinct.
7. Usage is not qualification.
8. Run count is not unique users.
9. Result signature is not certification.
10. Local use produces no telemetry without explicit opt-in.
11. Public activity contains no customer target identifiers.
12. Dynamic target execution requires a separate DSR/DDCRE authority boundary.

## Common pipeline

```
TARGET
  -> REGISTERED PROFILE
  -> REGISTERED CAPABILITY
  -> BOUNDED CAPTURE
  -> EVIDENCE MANIFEST + ROOT
  -> REPRESENTATION / BOUNDARY / REPLAY ANALYSIS
  -> VERSIONED SYNTHESIS
  -> CANONICAL RESULT
  -> JSON / PDF / SIGNATURE
  -> RESULT FROZEN
  -> ANONYMOUS ACTIVITY RECEIPT
  -> SIGNED PUBLIC AGGREGATE SNAPSHOT
```

Activity publication is downstream of result freeze and must never affect analysis status.

## Initial profiles

- `software.repository.v2`
- `blockchain.evm.contract.v1`
- `blockchain.evm.transaction.v1`
- `evidence.bundle.v1`
- later: `agent.trace.v1`
- later: `protocol.mcp.observe.v1`

A profile ID/version is immutable in meaning. Material changes require a new version.

## Evidence model

Every evidence item binds a case, target, capture capability, digest, capture time, source class, classification, and evidence-channel state. Derived evidence also names its parent evidence and derivation method.

Source classes:

- FIRST_PARTY
- PROTOCOL_OBSERVATION
- THIRD_PARTY_ATTESTATION
- USER_SUPPLIED
- DERIVED

Public Try DDC rejects `SECRET_PROHIBITED` evidence.

## Time model

Target time, capture time, and analysis time are separate concepts. Profiles define freshness policy; freshness is not inferred from age alone.

## Result model

Analysis status:

- COMPLETE
- INCOMPLETE
- UNSUPPORTED
- RATE_LIMITED
- CAPTURE_FAILED

Evidentiary status:

- ESTABLISHED
- PARTIALLY_ESTABLISHED
- NOT_ESTABLISHED
- CONTRADICTED
- UNRESOLVED
- OUT_OF_SCOPE

Risk disposition:

- HIGH_RISK_OBSERVED
- REVIEW_REQUIRED
- NO_HIGH_RISK_OBSERVED

`NO_HIGH_RISK_OBSERVED` is forbidden unless the profile minimum coverage floor is met and analysis is COMPLETE.

## Activity provenance

Hosted runs may emit a minimal activity receipt after result freeze. The receipt contains capability identity, analysis status, risk disposition, and a daily time bucket. It contains no repository URL, address, transaction hash, user identity, IP address, submitted question, findings, or public result linkage.

Public activity snapshots apply a minimum count threshold to reduce correlation risk and state explicitly that run counts are neither unique users nor validations.

Local/GitHub Action use sends no activity telemetry by default.

## Execution boundary

Observation, static analysis, and reconstruction can occur within Try DDC. Executing target-controlled code requires a separately authorized DSR request and DDCRE sandbox. DSR evidence may later be consumed by Try DDC but cannot be silently substituted for the original evidence set.
