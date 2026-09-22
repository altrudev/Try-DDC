# Try DDC protocol.mcp.observe.v1

`protocol.mcp.observe.v1` performs bounded, read-only observation of an MCP endpoint's externally advertised surface.

The profile is informed by the security model already developed in **MCP DriftGuard**, but Try DDC keeps this capability inside the common v2 evidence/result model.

## Authority boundary

The observer permits only these MCP methods:

- `server/discover`
- `tools/list`
- `resources/list`
- `prompts/list`

It does **not** invoke advertised tools, prompts, resources, arbitrary RPC methods, shell commands, or target code.

The current Adapter candidate supports anonymous HTTPS observation of the modern MCP `2026-07-28` discovery flow. Authentication bypass is not attempted. If a protected endpoint cannot be completely observed anonymously, capture fails rather than inventing a smaller surface.

## Completeness

If an advertised inventory exists, every page must be enumerated successfully within configured limits. Partial inventory is a capture failure and cannot become a baseline or a successful observation.

Current bounds include:

- HTTPS only;
- no followed redirects;
- maximum 1 MiB per RPC response;
- maximum 100 pages;
- maximum 5,000 inventory entries per category.

## Identity

Self-reported server name/version are metadata only.

Transport evidence can include the TLS certificate SHA-256. The current Python Adapter capture does not derive SPKI SHA-256, so public-key continuity remains unresolved unless supplied by another qualified capture path.

A certificate or SPKI observation is still only one observer's transport evidence, not proof of backend/source identity.

## Baseline drift

When a baseline snapshot is supplied, the profile detects bounded observable drift including:

- endpoint identity;
- protocol version/support;
- TLS identity evidence;
- authorization metadata;
- tool additions/removals;
- tool input-schema widening/narrowing/change;
- tool annotations/descriptions;
- resource changes;
- prompt changes.

A matching baseline means only that no drift was observed in the bounded surface. It is **not** a safety determination and does not establish that the baseline itself was approved or safe.

## Backend boundary

An unchanged MCP surface does not prove that the server's source code, binary, container, dependencies, runtime, or backend behavior are unchanged.

## Local Adapter use

The Adapter capability is:

```text
protocol.mcp.observe
```

A v2 Evidence Capsule contains only a commitment to the local capability result, not the raw MCP snapshot.

This implementation remains a candidate until the normal qualification/public-release/QMS gates are satisfied.
