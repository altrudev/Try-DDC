# Try DDC agent.trace.v1

`agent.trace.v1` binds Agent Replay reconstruction output into the Try DDC v2 evidence/result model.

## Boundary

Agent Replay remains the reconstruction engine. Try DDC does not silently recreate or replace Replay's incident reconstruction logic. The profile consumes only two explicitly supported Replay schemas:

- `agent-replay.incident.v2`
- `agent-replay.aps-authority-reconstruction.v2`

The reconstruction is treated as **derived evidence**. Its source input digest is kept as a separate evidence commitment.

## Preserved distinctions

The profile preserves these boundaries instead of collapsing them:

- chronology != causality;
- claimed actor != authenticated actor;
- delegated authority != policy permit;
- permit != execution;
- execution observation != downstream consequence;
- later reconstruction != contemporaneous evidence;
- external conformance result != Replay verification.

Generic Replay reports preserve explicit parent relationships, branch points, divergences and evidence gaps. APS reports preserve identity, delegation, policy, structural binding and execution evidence as separate layers.

## Customer-side use

The DDCAL Adapter capability `agent.replay.report` accepts a local Replay JSON report inside the registered customer root. It runs `agent.trace.v1` locally and exports only the resulting commitments/status metadata. The raw Replay report, timeline and divergence contents are not included in the adapter capability result.

This capability grants no arbitrary tool invocation, shell, source export, private-key, or agent-action authority.

## Example

```bash
python3 -m tryddc_v2.agent_trace_cli \
  --replay-report incident.json \
  --out-dir try-ddc-agent-trace-output
```

The resulting Try DDC document remains a bounded demo result unless separately qualified and authorized for another use.
