# ADR 0003 — Severity-thresholds policy

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** Secure AI Code Library maintainers
- **Consulted:** OWASP risk-rating discussion; CVSS v3.1 qualitative severity tiers; consumer-project security leads (OSS, regulated)
- **Informed:** Consumer-project integrators

## Context

The library needs to decide:

1. **Whether to ship a fixed gating policy** or **make severity-gating configurable**.
2. **What the default policy should be** if configurable.
3. **How severities map between scanner output, the library's GAPS classification, and the eventual gate decision.**

Constraints:

- The library is consumed by **OSS projects**, **enterprise teams**, and **regulated workloads** (SOX, PCI, HIPAA). One fixed policy fits none of them.
- The default should fail-safe for a typical enterprise team — not too noisy (every Low blocking), not too permissive (Critical findings silently warning).
- The policy must align with documented industry practice (NIST AI RMF, OWASP severity vocabulary) so consumers can defend the choice to auditors.
- An additional risk-floor adjustment must apply when commits are flagged as AI-assisted, given the Glasswing-era posture in [`THREAT_MODEL.md`](../../THREAT_MODEL.md).

## Decision

### Configurable threshold with a sensible default

The library ships a **configurable** `severity_threshold` in `hooks/config.yaml` (Phase 4), with **`high`** as the default:

```yaml
severity_threshold: high
# Other valid values: critical | medium | low
```

Effective gating behaviour per threshold:

| Threshold value | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| `critical` | block | warn | warn | warn | warn |
| `high` (default) | block | block | warn | warn | warn |
| `medium` | block | block | block | warn | warn |
| `low` | block | block | block | block | warn |

`info` always warns (never blocks). `critical` is always block-eligible.

### Standard severity matrix

The classification of findings into Critical / High / Medium / Low / Info uses the canonical matrix in [`docs/MANTHAN-CONTRACT.md`](../MANTHAN-CONTRACT.md):

| Severity | Definition | SLA |
|---|---|---|
| **CRITICAL** | RCE, secret leak, broken auth, supply-chain compromise | 24 hours |
| **HIGH** | Exploitable injection, missing authn/authz, weak crypto with realistic attack path | 7 days |
| **MEDIUM** | Hardening gaps, defence-in-depth misses, weak crypto without immediate attack path | 30 days |
| **LOW / INFO** | Style, documentation, very-low-likelihood findings | Backlog |

### GAPS risk classification

`registry/rules/precommit/gaps-risk-classification.rule.yaml` (Phase 2) maps each finding to C/H/M/L deterministically using:

```
GAPS class = f(
  finding.severity,           // from the scanner
  finding.engine_class,       // sast / sca / iac / secrets / dast
  finding.cwe,                // CWE mapping table
  finding.asvs_control_id,    // ASVS criticality
  context.is_ai_assisted      // raises floor by one band when true
)
```

### AI-assistance risk floor

When `context.is_ai_assisted: true` (Co-Authored-By trailer detected for an AI agent), the **GAPS floor rises by one band**:

- An otherwise-Medium SAST finding on AI-authored code is treated as High.
- An otherwise-Low IaC finding on AI-authored code is treated as Medium.
- An otherwise-High finding remains High (no escalation past High → Critical without explicit scanner signal).

Rationale: per the Glasswing-era posture in [`THREAT_MODEL.md`](../../THREAT_MODEL.md), AI-generated code that looks idiomatic but is wrong is a real and growing risk class. Raising the floor is a structural mitigation that does not require a scanner upgrade.

### Configurability for regulated environments

Documented in [`docs/INSTALL.md`](../INSTALL.md):

- `severity_threshold: medium` recommended for **PCI / SOX / HIPAA workloads**.
- `severity_threshold: high` recommended as the **default for enterprise teams**.
- `severity_threshold: critical` acceptable for **OSS or low-risk projects**.
- `severity_threshold: low` discouraged (noisy gates; consumer must justify).

## Consequences

### Positive

- **Defensible to auditors.** The matrix maps cleanly to OWASP / NIST vocabulary; the threshold is configurable per workload risk profile.
- **Sensible default.** `high` blocks the most damaging findings without being so noisy that teams disable the gate.
- **Structural AI mitigation.** The is-ai-assisted floor adjustment requires no scanner change — purely a rule + config-driven response.
- **Single-knob configurability.** One YAML value tunes the entire policy; downstream `gaps-risk-classification.rule.yaml` does the per-finding work.

### Negative

- **Risk of consumers lowering threshold under pressure.** Mitigated by requiring an ADR in the consumer project for any threshold lower than `high` (documented in [`AGENTS.md`](../../AGENTS.md) hard-rule #2).
- **GAPS classification table size.** The CWE → ASVS criticality mapping table is non-trivial to maintain. Phase 2 ships the initial table; Phase 6 lints it for consistency.

### Neutral

- The `info` severity never blocks. This is intentional; `info` findings exist to surface telemetry but not interrupt flow.
- The matrix is a per-finding policy. **Aggregate** signals (e.g., "too many Medium findings in one PR") are out of scope for v1; M4 (time-to-patch SLA enforcement) is the path.
- The same matrix is reused by `merge-gate.yml` (Phase 6); CI and local pre-commit behave identically.

## Follow-up

- Phase 2: implement `registry/rules/policies/severity-thresholds.rule.yaml` (declarative version of this ADR) and `registry/rules/precommit/gaps-risk-classification.rule.yaml`.
- Phase 4: ship `hooks/config.yaml` with the `severity_threshold` field documented inline.
- Phase 6: `registry-ci.yml` lints the GAPS classification table for completeness.
- M4: time-to-patch SLA enforcement consumes the same severity vocabulary.

## References

- [`docs/MANTHAN-CONTRACT.md`](../MANTHAN-CONTRACT.md) — severity matrix lives there as the operational canonical form.
- [`docs/INSTALL.md`](../INSTALL.md) — per-workload threshold recommendations.
- [`THREAT_MODEL.md`](../../THREAT_MODEL.md) — Glasswing-era posture motivating the AI-assistance floor.
- NIST AI RMF 1.0 — `MEASURE-2.7` and `MANAGE-2.3` informing the SLA values.
- OWASP Risk Rating Methodology: <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>.
- ADR 0002 — Manthan scan-gate contract (consumes this threshold).
