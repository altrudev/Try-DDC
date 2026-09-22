# Try DDC agent.trace.v1

`agent.trace.v1` maps Agent Replay reconstruction output into the Try DDC v2 evidence/result model without strengthening what the source evidence can prove.

Validated Agent Replay baseline:

- version: `0.6.0`
- revision: `1f4db7a12e8ddf8853c2533f08f8252f7efbe326`

Accepted source schemas:

- `agent-replay.incident.v2`
- `agent-replay.aps-authority-reconstruction.v2`

## Boundary

Agent Replay remains the reconstruction engine. Try DDC does not silently recreate or replace its incident reconstruction logic.

A Replay report supplied to Try DDC is treated as `USER_SUPPLIED` evidence unless a separate transport/signature/provenance layer proves more. The contents may describe deterministic Agent Replay findings, but document shape alone never upgrades source provenance or trustworthiness.

The integration executes no agent action, policy action, external tool, network operation, or target-system command.

## Preserved distinctions

The profile preserves these dimensions separately:

- chronology != causality;
- claimed actor != authenticated actor;
- delegated authority != policy permit;
- structural binding != independent cryptographic verification;
- permit != dispatch/execution;
- execution observation != downstream consequence;
- later reconstruction != contemporaneous evidence;
- external conformance != Replay verification;
- actor compliance != evidence-channel adequacy.

## Branches and retries

Explicit `parent_ids` are preserved as a graph. Try DDC records roots, leaves, and branch points rather than collapsing alternate execution lineages into a single final timeline.

Only explicit parent/relationship evidence is used for causal structure. A later timestamp is not enough to establish causality.

## Evidence-channel boundary

Agent Replay v0.6.0 does not by itself fully reconstruct every evidence-channel dimension required by the broader DDC evidence model. When those facts are absent, Try DDC leaves them unresolved rather than inferring them:

- evidence existence;
- reachability;
- discoverability;
- timeliness/freshness;
- accessibility/authorization;
- trustworthiness;
- actual consultation;
- propagation latency;
- post-action contamination.

Missing evidence is never converted into a pass.

## Customer-side Adapter

The DDCAL Adapter candidate capability `agent.replay.report` accepts a local Replay JSON report inside the registered customer root and runs `agent.trace.v1` locally.

The adapter exports only result commitments/status metadata. It does not export the raw Replay report, timeline, divergence contents, source code, credentials, or private keys.

## Local use

```bash
python3 -m tryddc_v2.agent_trace_cli \
  --report incident.json \
  --out-dir try-ddc-agent-trace-output
```

The default evidence classification is `CUSTOMER_PRIVATE`. Use `--classification PUBLIC` only when the report is appropriate for public handling.

The resulting document remains a bounded Try DDC candidate result. It is not a certification, accreditation result, safety guarantee, or authorization to execute.
