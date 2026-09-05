# DDCAL Adapter Protocol v0.1

## Purpose

This protocol defines how a managed DDCAL assessment can interact with a customer-side adapter without receiving the customer's source code and without turning DDCAL into a general remote-execution service.

## Transport model

The adapter initiates all managed communication over outbound HTTPS. No inbound listener is required.

Production transport endpoints are expected to follow this logical model:

- `GET /adapter/v1/plan` — obtain the next authorized plan for an enrolled installation;
- `POST /adapter/v1/evidence` — submit one bounded Evidence Capsule;
- `POST /adapter/v1/ack` — acknowledge plan acceptance/rejection and local completion state.

Those server endpoints must authenticate an enrolled installation and must reject replay, stale timestamps, unknown installations, duplicate capsule identities, oversized payloads, and plans whose authorization has expired.

The public adapter can operate offline until the managed transport is enabled.

## Assessment Plan

A plan is data, not code.

Minimum shape:

```json
{
  "schema": "ddcal.assessment-plan.v1",
  "job_id": "ddcal_job_example1234",
  "profile_id": "ddcal.repo.private.v1",
  "expires_unix": 1790000000,
  "target": {
    "kind": "registered-local-root",
    "label": "customer-product"
  },
  "capabilities": [
    {"id": "repo.static", "params": {"root": "."}},
    {"id": "filesystem.manifest", "params": {"paths": ["."]}}
  ],
  "export_policy": {
    "allow_source": false,
    "max_excerpt_bytes": 0
  }
}
```

The adapter must fail closed when:

- the schema is unknown;
- the job or profile identity is malformed;
- the plan is expired;
- any capability is unregistered locally;
- capability parameters violate local constraints;
- a requested path leaves the registered root;
- the plan attempts to authorize source export;
- the plan attempts to provide executable shell/script text.

## Capability registry

A remote plan can select only a capability already implemented by the installed adapter version.

A capability owns its own parameter validation and authority boundary. Adding a capability is a software release, not a remote configuration change.

Examples:

- `repo.static`
- `filesystem.manifest`
- `api.http.readonly`
- `blockchain.rpc.readonly`

Future examples may include:

- `agent.trace.review`
- `container.inspect`
- `supplychain.sbom`
- `cloud.iam.readonly`
- `kubernetes.posture.readonly`
- `runtime.sandbox.test`

The names do not create authority until a corresponding reviewed implementation exists.

## Evidence Capsule

The adapter returns observations, commitments, hashes, and bounded derived findings rather than source code.

Required capsule identity includes:

- adapter version;
- DDCAL job ID;
- profile ID;
- assessment-plan SHA-256;
- target identity/commitments;
- capabilities actually executed;
- per-capability evidence/results;
- export declarations;
- created timestamp;
- capsule SHA-256;
- optional customer-side adapter signature.

The capsule must explicitly state whether source code, source excerpts, signing authority, or arbitrary shell authority were present. v0.1 requires all of those to be false.

## Disclosure levels

A capability may later support controlled disclosure levels, but the default is the least-disclosing useful evidence:

0. hash/commitment only;
1. structural metadata;
2. derived graph/AST/invariant evidence;
3. customer-approved redacted excerpt;
4. encrypted selected evidence;
5. separately authorized full-source access.

A higher level may never be inferred merely because a lower-level assessment is insufficient.

## Blockchain boundary

`blockchain.rpc.readonly` allows only explicitly registered read-only Ethereum-compatible JSON-RPC methods. It has no method for transaction submission, account unlocking, signing, private-key access, deployment, or administrative RPC operations.

A blockchain assessment should bind relevant evidence to the network/chain ID, block identity, contract address, deployed bytecode, source identity when available, proxy/implementation topology, and material authority/dependency addresses.

## Report boundary

Evidence transport and report release are different authorities.

An Evidence Capsule can support a DDCAL conclusion, but it cannot become a released customer report directly. DDCAL customer reports must pass the separate controlled-document generation, identity, evidence verification, acceptance, and release gates maintained by DDC Assurance Lab.

## Security invariants

The production managed protocol must preserve all of these:

1. outbound-only customer connectivity;
2. no arbitrary command execution;
3. no source export by default;
4. no remote installation of new capabilities;
5. exact plan and target binding;
6. replay/staleness protection;
7. capability-local parameter validation;
8. secrets remain local unless separately authorized;
9. assessment evidence is not report-release authority;
10. customer-visible disclosure of what leaves the environment.
