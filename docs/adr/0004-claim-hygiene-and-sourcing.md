# ADR 0004 — Claim hygiene and sourcing

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** Secure AI Code Library maintainers
- **Consulted:** Reviewers of [`docs/MYTHOS.md`](../MYTHOS.md), [`docs/SOURCES.md`](../SOURCES.md), and [`THREAT_MODEL.md`](../../THREAT_MODEL.md)
- **Informed:** Consumer-project integrators, downstream contributors

## Context

The library makes substantive claims:

- "Aligned to the CSA Mythos-Ready Security Program."
- "Implements N of the 5+ Mythos pillars."
- "Compliant with OWASP ASVS v5 §X.Y.Z."
- "Hardened against attack pattern AML.T0051."

In a domain saturated with vendor marketing, **claim hygiene** matters more than the claims themselves. We must decide:

1. Which sources are acceptable as primary citations.
2. How to enforce sourcing automatically (CI lint).
3. How to model the gap between "supported by this repository" and "supported in this repository" — i.e., what verbiage to use when a control is partially implemented or roadmapped.
4. How to scope vendor product references (Anthropic Claude Mythos, GitHub Copilot, Cursor) so the library can talk about them as context without slipping into "we are protected against them".
5. Whether to ship a Tier B chat-prompt fallback for subagents.

Four risks shape the decision:

- **Vendor announcement creep.** Citing a Claude Mythos announcement as a threat statistic is unfalsifiable and erodes the library's credibility.
- **Undated assertions.** "AI is increasing breach rates" without a citation cannot survive review.
- **Inflated alignment claims.** Marking every rule as "ready" without in-tree evidence is dishonest.
- **Subagent surface bloat.** Hand-authored chat-prompt fallbacks would duplicate `subagent.yaml` and drift.

## Decision

### Sourcing policy: verifiable-only allowlist

[`docs/SOURCES.md`](../SOURCES.md) is the **operational allowlist**. Every citation in the repository must resolve to an entry in that document. Specifically:

- **Threat-intel citations** must cite a dated public primary report from a fixed allowlist: Mandiant M-Trends, Verizon DBIR, CrowdStrike GTR, Google TAG, Microsoft DDR, CISA advisories, ENISA Threat Landscape, MITRE ATT&CK / ATLAS.
- **Standards citations** must use the section-ID form for OWASP, ISO, NIST, MITRE, etc. Marketing names of standards (e.g., "Top 10 for LLM Applications") may be used in prose but the canonical ID is the source of truth.
- **Regulatory citations** must use the explicit article / section number.
- **Vendor product references** (Claude Mythos, GitHub Copilot, etc.) are allowed as **product / capability context** only — never as a threat-intel source. CI blocks vendor names appearing in a paragraph that asserts a numeric threat statistic without a primary-source citation.

CI workflow `source-hygiene.yml` (Phase 6) enforces this via regex passes against the allowlist.

### Three-value substantiation vocabulary

`mythos_alignment.substantiation` in every rule file must be one of:

- **`substantiated`** — implemented end-to-end in this repository. Required `mythos_alignment.evidence: [...]` listing file paths. CI verifies the paths exist.
- **`aligned`** — partially implemented; a roadmap milestone names the path to full implementation.
- **`roadmap`** — defined but not enforced today; the rule is a placeholder for a roadmap milestone.

This is the library's main defence against "ready theatre". A rule cannot quietly inflate its substantiation; the field is enforced by JSON Schema and the evidence pointers are verified by CI cross-link lint.

### Verbiage decisions

- The library publicly claims **"Mythos-Aligned Foundation"**, not "Mythos-Ready" or "Mythos-Certified". "Mythos-Ready" appears only in [`docs/MYTHOS.md`](../MYTHOS.md) § Roadmap and in this ADR — never as a current-state claim.
- "Compliant with" is reserved for cases where a control is `substantiated` with in-tree evidence.
- "Maps to" / "Aligns to" / "Cross-references" are used where a rule references a standard without claiming full compliance.

### Tier B chat-prompt fallback: dropped

Subagents ship **Tier A (native agentic)** and **Tier C (headless deterministic)** only. Tier B chat-prompt fallback would be hand-authored `.md` chat templates parallel to `subagent.yaml`. Rejected because:

1. **Drift.** Two sources of truth (`subagent.yaml` and `prompts/_subagent-templates/<id>.md`) would inevitably diverge.
2. **Maintenance cost.** N subagents × M IDE chat surfaces = many files to keep in sync.
3. **Coverage.** Copilot Chat users have two compliant paths: read the lowered `.cursor/skills/<id>/SKILL.md`, or invoke the Tier C runner from a terminal. Neither requires a Tier B.
4. **Quality.** Tier C runners are deterministic; Tier A runs the canonical `subagent.yaml`. Tier B would be the noisiest of the three by construction.

[`docs/SUBAGENT-FLOWS.md`](../SUBAGENT-FLOWS.md) documents the tier matrix; ADR 0001 documents the registry architecture that makes the dual-tier approach possible.

### Tool-scope discipline

Every subagent declares an explicit `tool_scope.allowed` / `tool_scope.denied`. The `denied` list MUST include `shell` and `network` by default (Tier C runners may opt into a narrow network scope for `$SECUREAI_LLM_ENDPOINT` only, when set). This is part of claim hygiene because over-scoped agents create false claims about what is safely automated.

## Consequences

### Positive

- **Defensible to auditors.** Every claim cites a primary source; every substantiation has an in-tree evidence pointer.
- **CI-enforced.** `source-hygiene.yml` cannot be bypassed without a maintainer PR review.
- **No vendor-announcement creep.** The allowlist is positive (explicit allow) rather than negative (block list).
- **Honest substantiation vocabulary.** `substantiated` / `aligned` / `roadmap` makes the gap explicit; consumers cannot be misled.
- **Single source of truth for subagents.** No Tier B chat-prompt duplication.

### Negative

- **Higher contributor friction.** Authors must look up primary citations and date them. Mitigated by the rule-author checklist in [`CONTRIBUTING.md`](../../CONTRIBUTING.md).
- **Allowlist maintenance.** New sources require a PR adding them to `docs/SOURCES.md` plus a CI regex update.
- **No graceful path for "I read it in a vendor blog".** Contributors must find a primary citation or omit the claim.

### Neutral

- The Mythos pillar set is cross-referenced to OWASP / NIST / ISO so the alignment claim survives even if the CSA briefing is updated, retracted, or never publicly republished with a stable URL. The library is not load-bearing on any single private source.
- Mermaid blocks MUST include `accTitle` and `accDescr` directives (Mermaid v10+); `source-hygiene.yml` warns on missing directives. Accessibility is part of claim hygiene because inaccessible diagrams aren't truly published.

## Follow-up

- Phase 6: implement `source-hygiene.yml` (regex extraction, allowlist cross-reference, threat-statistic context check, Mermaid accessibility lint).
- Maintainer review on every PR: source hygiene is the #1 reason for PR rejection per [`CONTRIBUTING.md`](../../CONTRIBUTING.md).
- ADR 0005 (token economy) extends this ADR with the cache-stability rules.

## References

- [`docs/SOURCES.md`](../SOURCES.md) — verifiable-source allowlist.
- [`docs/MYTHOS.md`](../MYTHOS.md) — alignment matrix using the three-value substantiation vocabulary.
- [`THREAT_MODEL.md`](../../THREAT_MODEL.md) — Glasswing-era section that follows the claim hygiene rules in this ADR.
- [`docs/SUBAGENT-FLOWS.md`](../SUBAGENT-FLOWS.md) — tier matrix (no Tier B).
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — source-hygiene checklist.
- ADR 0001 — Registry and adapter architecture (single source of truth).
