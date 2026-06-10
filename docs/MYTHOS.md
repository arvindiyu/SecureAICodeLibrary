# Mythos

> **Mythos-Aligned AI Control Plane.** This document is the library's honesty artefact. The first section is the **alignment matrix** — what is substantiated today, with evidence pointers. The second section is the **roadmap** — dated milestones M1 through M8 that turn today's honest gap into a credible trajectory. Until M1–M8 are delivered, the public-facing claim stays "Mythos-Aligned Foundation".

The word **"Mythos-Ready"** appears in this repository only in the § Roadmap section below and in ADR 0004 — never as a claim about current state.

The Mythos pillar framing is cross-referenced to OWASP, NIST AI RMF, and ISO/IEC 42001 so the claim survives even if the CSA briefing is revised, retracted, or never publicly republished with a stable URL.

---

## § Alignment

The substantiation matrix below maps each CSA "Mythos-Ready Security Program" pillar to (a) what this library substantiates today, (b) the in-tree evidence, and (c) the roadmap milestone that closes any gap.

| Pillar | Substantiation | In-tree evidence | Gap → roadmap |
|---|---|---|---|
| **AI Governance** | **substantiated** | 20 SCEC + 2 Mythos-era rules under `registry/rules/ai-governance/` (Phase 2); 6 subagents under `registry/subagents/` (Phase 3); `ai-audit-logging`, `agentic-obo-auth`, `agentic-tool-scoping` Tier 0 rules; ISO/IEC 42001:2023 control mapping in [`CONSTITUTION.md`](../CONSTITUTION.md) §D | — |
| **Secure-by-Design** | **substantiated** | 14 cross-language coding-standards rules + 10 per-language rules (Phase 2); ~12 framework spec sheets (Phase 5); `coding-standards-reviewer` and `secure-developer-mentor` subagents; pre-commit hook (Phase 4); OWASP ASVS v5 control mapping in [`CONSTITUTION.md`](../CONSTITUTION.md) §A–C | — |
| **Supply Chain** | **aligned** | `sbom-check` (precommit), `sbom-freshness` (policy), `dependency-management` rule, `sbom.cdx.json`, SBOM regen in `registry-ci.yml`; NIST SSDF + CycloneDX 1.5 references | M3 (SLSA L3 attestation template, Sigstore signing, CycloneDX VEX, auto-remediation bot) |
| **Proactive Defense** | **aligned** | Commit-time scan-gate via Manthan documented in [`docs/MANTHAN-CONTRACT.md`](./MANTHAN-CONTRACT.md); `severity-thresholds` policy with configurable threshold | M1 (runtime telemetry, MTTD/MTTR), M4 (time-to-patch SLA enforcement) |
| **Incident Response** | **roadmap** | `ai-kill-switch`, `ai-human-oversight`, `ai-audit-logging` rules describe controls; no runbooks, drills, or tabletops in v1 | M2 (IR runbook templates, kill-switch drill SOP, quarterly tabletop kit) |
| **AI-Augmented Defense** | **roadmap** | None in v1 — we ship reviewer subagents, not autonomous defenders | M5 (AI-driven triage / dedup / auto-fix pilot via local Ollama / vLLM, with evaluation harness) |
| **Workforce Readiness** | **aligned** | `secure-developer-mentor` subagent; curated workforce section to be added to `docs/EXTERNAL-RESOURCES.md` (Phase 5); existing `prompts/workforce-enablement/` preserved | M6 (drill calendar template, competency rubric, quarterly secure-coding game day) |
| **Quantitative Posture** | **roadmap** | Audit-log JSON-lines format defined; no aggregation, no dashboard | M1 (OpenTelemetry spec for adapter/hook usage, dashboard schema, reference Grafana JSON) |
| **External Validation** | **roadmap** | Self-attestation only via `SPEC.md` §5 conformance levels | M7 (assessment checklist mapped to pillars, public attestation template, reviewer list, opt-in conformance badge) |
| **IDE Coverage** | **aligned** | 3 adapters in v1: Cursor, Copilot, AGENTS.md (Phase 3) | M8 (Claude Code `CLAUDE.md` adapter, Windsurf `.windsurfrules` adapter) |

### Summary statement (defensible claim)

**Today: 2 pillars substantiated, 4 pillars aligned, 4 pillars roadmap with dated milestones.** Verifiable from the matrix above and the rule files themselves. The cell-level evidence pointers all resolve to files in this repository; CI cross-link lint (Phase 6) ensures they do not rot.

### How `mythos_alignment.substantiation` is enforced per rule

Every rule file under `registry/rules/` declares `mythos_alignment.substantiation` as one of:

- **`substantiated`** — the rule is implemented end-to-end in this repository (rule + subagent reference + gate wiring + evidence pointers in `mythos_alignment.evidence`). CI verifies the evidence paths exist.
- **`aligned`** — the rule is defined and an in-tree control implements part of the contract, but a complete implementation depends on a roadmap milestone. The rule names the milestone in `mythos_alignment.evidence`.
- **`roadmap`** — the rule is defined as a placeholder for a roadmap milestone; intentionally not enforced today. The roadmap milestone is named.

This three-value vocabulary (rather than a boolean) is the library's main defence against "ready theatre". Phase 2 cannot mark `ai-kill-switch.rule.yaml` as `substantiated` until a real kill-switch SOP lands (M2).

---

## § Roadmap

Dated, ungated, public roadmap. Each milestone has an `owner: TBD`, `target: TBD`, `status: not-started`, and an `acceptance:` checklist so contributors can claim and ship the work. When the library can credibly demonstrate all M1–M8 milestones, the claim line evolves from **"Mythos-Aligned Foundation"** to **"Mythos-Ready"** (and `docs/MYTHOS.md` is republished to reflect that).

### M1 — Runtime telemetry

- **Closes pillars:** Proactive Defense, Quantitative Posture.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - OpenTelemetry semantic conventions for adapter and hook usage (spans for `subagent.invoke`, `hook.run`, `manthan.scan`).
  - Aggregated dashboard schema for MTTD, MTTR, rule coverage %, token-spend per subagent.
  - Reference Grafana JSON exportable to consumer projects.
  - Audit-log → OTLP converter (Tier C runner option).
- **Acceptance:**
  - [ ] OTel span names + attributes documented in `docs/MEASUREMENT.md` (new in M1).
  - [ ] Grafana JSON validates against Grafana v10.
  - [ ] Converter passes round-trip on `.securecode/audit.log` fixtures.

### M2 — AI-vuln incident response

- **Closes pillar:** Incident Response.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - IR runbook templates for Mythos-class disclosure events (model jailbreak, MCP server compromise, training-data leak, audit-log gap).
  - Kill-switch drill SOP linked to `ai-kill-switch.rule.yaml`.
  - Quarterly tabletop kit (scenarios, facilitator notes, post-mortem template).
  - PagerDuty / Opsgenie integration spec (no code; declarative contract).
- **Acceptance:**
  - [ ] 4 runbook templates merged to `docs/runbooks/`.
  - [ ] Kill-switch drill SOP merged.
  - [ ] One tabletop scenario rehearsed by maintainers and post-mortem published.

### M3 — Supply-chain hardening

- **Closes pillar:** Supply Chain.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - SLSA L3 attestation template (provenance + builder identity).
  - Sigstore cosign workflow (`.github/workflows/sign-release.yml`).
  - CycloneDX VEX support in `sbom.cdx.json`.
  - Auto-remediation PR bot spec (Dependabot / Renovate integration; no runtime code shipped — spec only).
- **Acceptance:**
  - [ ] SLSA template merged.
  - [ ] Signed release on the next `vX.Y.Z` tag.
  - [ ] `sbom.cdx.json` carries a VEX block.

### M4 — Time-to-patch SLA enforcement

- **Closes pillar:** Proactive Defense.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - 24h-critical / 7d-high SLA workflow tied to `severity-thresholds`.
  - Auto-PR creation spec from Manthan findings (referencing `MANTHAN-CONTRACT.md` exit codes).
  - SLA breach escalation pattern (issue label + assignee rotation).
- **Acceptance:**
  - [ ] SLA workflow merged.
  - [ ] One closed-loop demo: Manthan finding → auto-PR → merged within SLA.

### M5 — AI-augmented defense

- **Closes pillar:** AI-Augmented Defense.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - Pilot spec for AI-driven triage / dedup / auto-fix using local Ollama or vLLM endpoints.
  - Evaluation harness with deterministic test fixtures.
  - Bias + false-positive measurement methodology and reporting template.
- **Acceptance:**
  - [ ] Pilot spec merged.
  - [ ] Evaluation harness produces a baseline report against the v1 rule set.

### M6 — Workforce readiness

- **Closes pillar:** Workforce Readiness.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - Drill calendar template.
  - Competency rubric (junior / mid / senior / champion).
  - Quarterly secure-coding game day playbook.
  - Metrics: drill attendance, rubric coverage.
- **Acceptance:**
  - [ ] Calendar template and rubric merged.
  - [ ] One game-day playbook published.

### M7 — Third-party validation

- **Closes pillar:** External Validation.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - Assessment checklist mapped to CSA Mythos-Ready pillars.
  - Public attestation template (signed, dated).
  - Reference reviewer list (independent, named).
  - Opt-in conformance badge programme.
- **Acceptance:**
  - [ ] Assessment checklist merged.
  - [ ] At least one independent reviewer signs the public attestation.
  - [ ] First consumer-project badge issued.

### M8 — Additional IDE adapters

- **Closes pillar:** IDE Coverage.
- **Owner:** TBD. **Target:** TBD. **Status:** not-started.
- **Deliverables:**
  - Claude Code adapter (`CLAUDE.md` lowering target) under `adapters/claude-code/`.
  - Windsurf adapter (`.windsurfrules` lowering target) under `adapters/windsurf/`.
  - Reuse existing `adapters/agents-md/` lowering logic where possible.
- **Acceptance:**
  - [ ] Both adapters validate against `install.sh` idempotency.
  - [ ] Both adapters tested against a sample consumer repo.

---

## Why "Mythos-Aligned" rather than "Mythos-Ready" today

- **Conformance body:** none exists. Until M7 lands and an independent reviewer signs a public attestation, "ready" is a self-claim.
- **Runtime / IR / metrics:** explicitly out of scope for v1 per [`SPEC.md`](../SPEC.md) §1.2. M1, M2, and M5 close these gaps.
- **Red-team evaluation:** the Glasswing-era threat posture in [`THREAT_MODEL.md`](../THREAT_MODEL.md) is structural mitigation, not demonstrated red-team result. M5 is the path.

We will not retroactively edit this document to soften the claim ladder. When milestones land, this file will be updated **forward** with the dated change in `CHANGELOG.md`.

## References

- CSA "Mythos-Ready Security Program" — treated as background framing; pillar set cross-referenced to OWASP / NIST / ISO so the claim survives revision.
- [`CONSTITUTION.md`](../CONSTITUTION.md) — primary-anchor standards.
- [`THREAT_MODEL.md`](../THREAT_MODEL.md) — Glasswing-era posture.
- [`docs/AI-CONTROL-MAP.md`](./AI-CONTROL-MAP.md) — swim-lane that anchors the alignment cells.
- [`docs/SOURCES.md`](./SOURCES.md) — verifiable-source allowlist.
- ADR 0004 — Claim hygiene and sourcing.
