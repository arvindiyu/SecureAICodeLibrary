# ADR 0002 — Manthan scan-gate contract

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** Secure AI Code Library maintainers
- **Consulted:** Manthan upstream maintainer (`arvindiyu/manthan`)
- **Informed:** Consumer-project integrators; downstream Phase 4 hook authors

## Context

The library must enforce a **scan-before-merge** gate that integrates with existing SAST / SCA / IaC / secrets / DAST scanners without re-implementing them. Three integration options:

1. **Bundle scanners directly (rejected).** Vendor or include SAST/SCA/IaC tooling. Hugely expands the library's footprint, ties it to specific scanner choices, and breaks the "thin canonical library" thesis.
2. **Define an open scan contract but leave orchestration to consumers (rejected as primary).** Consumers wire their own orchestrator. Workable but the consumer integration surface is wide; every consumer re-implements the same scaffolding.
3. **Adopt a single ASOC orchestration partner with a documented contract (chosen).** The library specifies an HTTP contract that an Application Security Orchestration and Correlation (ASOC) gateway must satisfy. The library targets [arvindiyu/manthan](https://github.com/arvindiyu/manthan) as the reference implementation but **does not bundle Manthan**.

Additional considerations:

- The same `hooks/pre-commit.sh` must work locally (pre-commit) and in CI (`merge-gate.yml`); a single endpoint contract simplifies dual-context behaviour.
- Findings must include sufficient metadata for the library's `gaps-risk-classification` rule to map them to C/H/M/L deterministically.
- Manthan exposes its catalog and scan capabilities via Model Context Protocol (MCP), but the primary integration path is HTTP — MCP is a secondary, native-Tier-A bonus.
- Manthan may be unavailable (developer offline; air-gapped environment); the hook must **fail closed** with a clear message.

## Decision

Define the scan-gate contract as **HTTP endpoints on a Manthan gateway**, documented in [`docs/MANTHAN-CONTRACT.md`](../MANTHAN-CONTRACT.md). The library:

- **Does not bundle Manthan.** Consumers install Manthan separately from upstream.
- **Documents three endpoints:** `GET /healthz`, `POST /v1/scan`, `POST /v1/events/commit`. Plus `/mcp/sse` and `/mcp/call` as documented secondary surfaces.
- **Fixes the request and response payload schemas.** The `quality_gate.decision` is one of `pass`, `warn`, `block`, `error`; findings carry `severity`, `engine_class`, `cwe`, `path`, `line`, `message`.
- **Maps responses to POSIX exit codes** (table in `MANTHAN-CONTRACT.md`). Exit 0 = pass/warn, exit 1 = block, exit 2 = Manthan error, exit 3 = unreachable, exit 4 = schema mismatch, exit 78 = local compliance failure before Manthan call.
- **Fails closed** when Manthan is unreachable. Default `manthan_endpoint` is `http://localhost:8080`; consumers can set `manthan_endpoint: null` in `hooks/config.yaml` to opt out (only acceptable for personal projects).
- **Calls one endpoint per commit** (`POST /v1/events/commit`) — the hook is synchronous and bounded by `--timeout` (default 30 s).

The contract is pinned per library MAJOR release. Breaking changes require a new ADR extending this one.

## Consequences

### Positive

- **Scanner-neutral.** Consumers can swap Manthan for any orchestrator that satisfies the contract.
- **Thin library.** No scanner code, no scanner versioning, no scanner CVE exposure inside this repository.
- **Same script local + CI.** `hooks/pre-commit.sh` runs identically in both contexts; CI cost-effective.
- **Determinism preserved.** The library classifies findings via its own `gaps-risk-classification` rule; Manthan provides raw data, not the gate decision. This matches the Glasswing-era posture in [`THREAT_MODEL.md`](../../THREAT_MODEL.md): the gate is not LLM-dependent.
- **Fail-closed posture.** Air-gapped or offline environments cannot accidentally bypass the gate.

### Negative

- **Consumers must run Manthan** (or a compatible service). Documented in [`docs/INSTALL.md`](../INSTALL.md), but adds an installation step for first-time users. Mitigated by Manthan's own docker / native installer.
- **Network dependency at commit-time.** Even for loopback. Latency budget is bounded by the 30 s timeout; in practice the overhead is small.
- **No native offline mode in v1.** A future enhancement could cache Manthan responses for unchanged file sets, but it is out of scope for v1.

### Neutral

- The library's audit log captures Manthan's `scan_id` per commit, enabling later forensic reconstruction.
- MCP `/mcp/*` endpoints are documented but not required by `hooks/pre-commit.sh`; native (Tier A) subagents can use them for richer Cursor / Claude Code / Windsurf integration.

## Failure modes considered

| Failure | Posture |
|---|---|
| Manthan unreachable | Fail closed (exit 3). |
| Manthan returns 500 | Fail closed (exit 2). |
| Manthan returns malformed response | Fail closed (exit 4). |
| Scanner timeout inside Manthan | Manthan returns `engines_failed`; hook treats as warn (configurable to block). |
| Manthan accepts but returns no findings (false negative) | Hook trusts the response — Manthan is the authority for the scan-gate decision. Consumer mitigation: also enable Tier C subagent runners (which the hook already does, providing defence in depth). |
| Consumer points `manthan_endpoint` at a rogue scanner that always returns `pass` | Out of scope for the library. Consumer security configuration is the consumer's responsibility (per [`THREAT_MODEL.md`](../../THREAT_MODEL.md) TB4). |

## Follow-up

- Phase 4: implement `hooks/pre-commit.sh` + `hooks/config.yaml`; ship the full contract.
- Phase 6: `merge-gate.yml` reuses `hooks/pre-commit.sh` server-side.
- Roadmap M3: Sigstore signing + SLSA attestation, which may piggy-back on the Manthan event endpoint.

## References

- [`docs/MANTHAN-CONTRACT.md`](../MANTHAN-CONTRACT.md) — endpoint contracts, payload examples, exit-code mapping, severity matrix.
- Manthan upstream: <https://github.com/arvindiyu/manthan>.
- Model Context Protocol: <https://modelcontextprotocol.io/>.
- ADR 0003 — Severity-thresholds policy (consumes Manthan severities).
- ADR 0001 — Registry and adapter architecture (which the hook and Manthan together gate).
