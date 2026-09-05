# DDCAL Adapter

The DDCAL Adapter is the customer-side execution boundary for assessments where source code, private infrastructure, or sensitive technical material should remain inside the customer's environment.

It is part of **Try DDC** because it extends the same trust model: inspect the code, pin the exact version, keep authority local, and export evidence rather than source.

## Core rule

**Your source code does not have to leave your environment.**

The adapter receives a bounded assessment plan containing only registered capability IDs. It does not accept arbitrary shell commands from DDCAL and it refuses plans that authorize source-code export in v0.1.

The customer can inspect:

- the exact adapter code;
- the exact assessment plan;
- the requested capability IDs;
- the target boundary;
- the evidence that will be exported;
- the final Evidence Capsule before it leaves the environment.

## Current v0.1 capabilities

| Capability | Purpose | Source exported? |
|---|---|---:|
| `repo.static` | Run the local Try DDC bounded static repository review | No |
| `filesystem.manifest` | Create file/path SHA-256 commitments and metadata | No file contents |
| `api.http.readonly` | Observe an anonymous HTTPS endpoint with GET/HEAD/OPTIONS | No implementation source |
| `blockchain.rpc.readonly` | Use allowlisted read-only Ethereum-compatible JSON-RPC methods | No signing/private keys |

Additional capability modules can be added without changing the authority model. Planned families include agent/AI traces, containers, CI/CD, SBOM/supply chain, cloud configuration, Kubernetes, databases, runtime behaviour, mobile/desktop evidence, and controlled dynamic testing.

## Local use

List the registered capabilities:

```bash
python3 adapter/ddcal_adapter.py capabilities
```

Run a bounded plan:

```bash
python3 adapter/ddcal_adapter.py run \
  --plan adapter/examples/assessment-plan.json \
  --root . \
  --out-dir ddcal-adapter-output
```

Optional local Evidence Capsule signing:

```bash
umask 077
openssl rand 32 > ~/.config/ddcal/adapter-hmac.key

python3 adapter/ddcal_adapter.py run \
  --plan assessment-plan.json \
  --root /path/to/customer/project \
  --out-dir ddcal-adapter-output \
  --signing-key-file ~/.config/ddcal/adapter-hmac.key
```

The signing key is local configuration. It is never supplied by an assessment plan.

## Evidence Capsule

A run produces:

- `ddcal-evidence-capsule.json`
- `ddcal-evidence-capsule.json.sha256`

The capsule records the adapter version, assessment-plan digest, target identity, capabilities actually executed, bounded results, export declarations, and capsule integrity/signature data.

The source itself is not included.

## External hookup model

The intended managed DDCAL service uses **outbound HTTPS only** from the customer environment:

```text
Customer environment
      |
      | outbound HTTPS
      v
DDCAL assessment service
```

No inbound SSH, remote desktop, Tailscale, arbitrary command channel, or permanently open customer firewall port is required.

The production protocol is defined in [`PROTOCOL.md`](PROTOCOL.md). The current public adapter can also operate entirely offline from a locally supplied assessment plan.

## Authority boundary

An assessment plan may choose only capability IDs compiled into the adapter. It cannot supply:

- shell commands;
- scripts to execute;
- package-install commands;
- private keys;
- wallet signing requests;
- arbitrary filesystem paths outside the registered root;
- arbitrary RPC methods;
- source-export instructions.

A new capability requires a reviewed adapter change. Transport does not create execution authority.

## DDCAL report boundary

The Evidence Capsule is **assessment evidence**, not the final DDCAL report.

Customer-facing DDCAL reports are released separately through the DDCAL controlled-document system. A capsule cannot itself become a certification, assurance conclusion, or released report merely because it contains findings.
