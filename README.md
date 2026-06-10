# Secure AI Code Library :: Secure-by-Design AI Control Plane for the SDLC. Mythos-Aligned Foundation.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-Mythos--Aligned%20Foundation-blueviolet)](./docs/MYTHOS.md)
[![Plane](https://img.shields.io/badge/AI%20Control%20Plane-Secure--by--Design-informational)](./docs/AI-CONTROL-MAP.md)

> An IDE-agnostic, secure-by-design AI control plane for the software development lifecycle. A canonical YAML rule registry, IDE adapters, deterministic headless subagent runners, and a scan-before-merge contract — wired to OWASP ASVS v5, ISO/IEC 27001:2022, ISO/IEC 42001:2023, NIST AI RMF 1.0 + GenAI Profile, and MITRE ATLAS.

**New here? Start with the [AI Control Map](./docs/AI-CONTROL-MAP.md).** It is a single-page swim-lane mapping every stage of the AI-assisted SDLC (model select → prompt → context → generation → review → commit → deploy → monitor) to the rules, subagents, and gates that govern it. Everything else in this repository is implementation.

---

## Project posture <a id="project-posture"></a>

This repository is a **personal research project**, authored and maintained by an individual with 15+ years of AppSec experience and active AI-practitioner literacy. It is offered as a *de facto, point-in-time* representation of secure-by-design controls for AI-assisted software development as of **mid-2026**.

Two implications follow:

1. **Relevance window.** Industry threat-posture, AI-model capabilities, IDE-agent APIs, and regulatory expectations all evolve on quarterly cycles. Specific rule wording, subagent flows, citation freshness, and even architectural assumptions in this repository may diminish in relevance as the underlying technology matures. The [`docs/SOURCES.md`](./docs/SOURCES.md) allowlist and `freshness-check` pre-commit help, but they cannot guarantee currency between releases.
2. **Maintenance pace.** The maintainer will try to keep the registry, adapters, and threat-intel citations current, but updates may not be agile. There is no SLA on PR triage, security-advisory turnaround, or roadmap delivery. Issues are best-effort.

For production deployments, treat this library as a **baseline reference** — pair it with your organization's current standards, your AI-coding-assistant vendor's latest security advisories, and an internal red-team evaluation of the rules that matter most to you. This repository's value is in the *framing*, the *control mapping*, and the *integration contracts* — not in being the sole source of truth.

If you want to contribute fixes, fresher sources, or new rules, see [`CONTRIBUTING.md`](./CONTRIBUTING.md). If you want to fork and diverge for your own context, that is also a fully supported use case — MIT-licensed and explicitly encouraged.

---

## Honest claim ladder

We are explicit about what we do and do not claim. The Mythos-Aligned label is a substantiated foundation — not a certification.

| Claim | Allowed? | Why |
|---|---|---|
| "Mythos-Aligned Foundation" / "Aligned to CSA Mythos-Ready pillars" | **Yes** | Substantiated by the registry + adapters + hooks + OWASP / ISO / NIST AI RMF traceability matrix in [`docs/MYTHOS.md`](./docs/MYTHOS.md). |
| "Implements 3 of 5+ CSA Mythos-Ready pillars: AI governance, secure-by-design, supply chain" | **Yes** | Quantifiable; mapped in `docs/MYTHOS.md` § Alignment. |
| "Mythos-Ready Roadmap published" | **Yes** | Dated milestones M1–M8 in `docs/MYTHOS.md` § Roadmap. |
| "Mythos-Ready" / "Mythos-Certified" | **No** | No conformance body, no certification, no runtime / IR / metrics in v1 scope. |
| "Hardened against Claude Mythos" | **No** | Unfalsifiable without demonstrated red-team evaluation. |

Sourcing policy ([`docs/SOURCES.md`](./docs/SOURCES.md)): threat-intel claims must cite **dated, public, primary sources only** (Mandiant M-Trends, Verizon DBIR, CrowdStrike GTR, Google TAG, Microsoft DDR, CISA advisories, ENISA Threat Landscape, MITRE ATT&CK / ATLAS). Standards citations restricted to OWASP, ISO, NIST, SLSA, CycloneDX, SPDX. Vendor announcements (including Anthropic Claude Mythos and Project Glasswing) are cited only as **product context**, never as threat statistics. Enforced by `source-hygiene.yml` (Phase 6).

---

## Layered table of contents

Read in order if you are new; jump to a layer if you know what you need.

### Layer 0 — The elevator pitch
- [`docs/AI-CONTROL-MAP.md`](./docs/AI-CONTROL-MAP.md) — single-page swim-lane: AI SDLC stages × control points × rule IDs × subagent IDs × gates.

### Layer 1 — Governance anchors
- [`CONSTITUTION.md`](./CONSTITUTION.md) — OWASP ASVS v5 + ISO/IEC 27001:2022 + ISO/IEC 42001:2023 + NIST AI RMF 1.0 control mapping.
- [`SPEC.md`](./SPEC.md) — library scope, contracts, acceptance criteria, explicit out-of-scope, registry / rule versioning policy.
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — STRIDE per trust boundary (Dev → IDE → AI → MCP → Manthan → CI), plus a Glasswing-era posture section.
- [`AGENTS.md`](./AGENTS.md) — IDE-agnostic consumer agent guidelines.

### Layer 2 — Architecture & design records
- [`docs/adr/0001-registry-and-adapter-architecture.md`](./docs/adr/0001-registry-and-adapter-architecture.md)
- [`docs/adr/0002-manthan-scan-gate-contract.md`](./docs/adr/0002-manthan-scan-gate-contract.md)
- [`docs/adr/0003-severity-thresholds-policy.md`](./docs/adr/0003-severity-thresholds-policy.md)
- [`docs/adr/0004-claim-hygiene-and-sourcing.md`](./docs/adr/0004-claim-hygiene-and-sourcing.md)
- [`docs/adr/0005-token-economy-architecture.md`](./docs/adr/0005-token-economy-architecture.md)

### Layer 3 — Operational docs
- [`docs/MYTHOS.md`](./docs/MYTHOS.md) — alignment matrix + roadmap.
- [`docs/SOURCES.md`](./docs/SOURCES.md) — verifiable-source allowlist.
- [`docs/INSTALL.md`](./docs/INSTALL.md) — per-IDE install matrix + pre-commit hook wiring patterns.
- [`docs/MANTHAN-CONTRACT.md`](./docs/MANTHAN-CONTRACT.md) — endpoint contracts + severity-threshold matrix + freshness definition.
- [`docs/SUBAGENT-FLOWS.md`](./docs/SUBAGENT-FLOWS.md) — per-subagent 2-tier flows.
- [`docs/TOKEN-ECONOMICS.md`](./docs/TOKEN-ECONOMICS.md) — two-layer rule loading, INDEX discovery, token budgets, cache stability.
- [`docs/EXTERNAL-RESOURCES.md`](./docs/EXTERNAL-RESOURCES.md) — curated AI-centric external references (populated in Phase 5).

### Layer 4 — Registry (v2)
- [`registry/INDEX.md`](./registry/INDEX.md) — auto-generated discovery file; ~3K tokens; one row per rule.
- `registry/rules/{ai-governance,coding-standards,policies,precommit}/*.rule.yaml` — populated in Phase 2.
- `registry/subagents/<id>/` — populated in Phase 3.
- `registry/framework-specs/*.spec.yaml` — populated in Phase 5.
- [`registry/schemas/`](./registry/schemas/) — JSON Schemas (rule, subagent, framework-spec, constitution).

### Layer 5 — Repo hygiene
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — rule-author checklist, schema links, PR self-check.
- [`SECURITY.md`](./SECURITY.md) — vulnerability disclosure policy for the library itself.
- [`Makefile`](./Makefile) — local targets: `validate`, `index`, `search-index`, `sbom`, `source-hygiene`, `token-budget`, `dogfood`, `site`, `all`.
- [`CHANGELOG.md`](./CHANGELOG.md) — Keep-a-Changelog format.
- [`sbom.cdx.json`](./sbom.cdx.json) — CycloneDX SBOM for this repository.

### Layer 6 — Legacy v1 content (preserved)
- `prompts/` — original prompt library (preserved).
- `.github/copilot/` — original Copilot custom instruction files (preserved).
- `guidelines/` — original general security guidelines (preserved).

---

## v1 prompts vs. v2 registry — both are first-class

This repository ships **two complementary surfaces**. They are not in conflict, and v2 does not deprecate v1.

**v1 surface — `prompts/`, `.github/copilot/`, `guidelines/`.** Hand-authored markdown chat prompts and Copilot custom instructions, organized by category (cloud, mobile, backend frameworks, threat modeling, secrets management, validation, workforce enablement). v1 is optimised for humans copy-pasting into a chat or pasting into Copilot custom-instruction settings. Backward compatibility is a hard requirement: nothing under `prompts/`, `.github/copilot/`, or `guidelines/` is renamed, removed, or restructured by v2. New v1 prompts can still be contributed — see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

**v2 surface — `registry/`, `adapters/`, `hooks/`, `docs/`.** A canonical YAML rule registry (rule schema enforced by JSON Schema; required `summary` ≤300 chars; required `sources.primary`; required `mythos_alignment.substantiation`), three IDE adapters (Cursor → `.cursor/rules/<id>.mdc` + `.cursor/skills/<subagent-id>/SKILL.md`; Copilot → top-level `.github/copilot-instructions.md` INDEX; AGENTS.md → glob-scoped sections), six secure-by-design subagents with two-tier execution (native agentic + deterministic headless), and a Manthan-driven scan-before-merge contract. v2 is optimised for **machine consumption inside an IDE or CI**: token-budget-aware, cache-stable, schema-validated, and CI-enforced.

**How they connect.** Several v1 prompts have a corresponding v2 rule (for example, the v1 "Threat-Model : General" prompt maps to the v2 `threat-modeler` subagent + `threat-model-required` policy rule). `docs/EXTERNAL-RESOURCES.md` (Phase 5) consolidates v1 framework prompts into a single AI-centric reference that points consumers at the right v2 rule IDs and subagent IDs. Where v2 ships richer machine-readable structure, v1 stays as the human-readable narrative — both ship, neither blocks the other.

---

## Catch-all subagent pattern

The v2 catalog is intentionally finite. We ship **6 subagents** and **~12 framework spec sheets** in v1, not 50+ bespoke per-framework prompts. The reason is quality: per-language coding-standards rules plus the `coding-standards-reviewer` and `secure-developer-mentor` subagents already cover most framework concerns, and OWASP / CIS / vendor cheat sheets exist for every framework we declined to wrap. Shipping 50 shallow stubs dilutes signal and increases maintenance cost.

For any framework, language, or topic **not in the catalog**, the canonical pattern is: invoke the `secure-developer-mentor` subagent with the closest applicable language rule from `registry/rules/coding-standards/per-language/`, and the closest framework spec from `registry/framework-specs/` (if any). Cite the authoritative external source (OWASP cheat sheet, CIS benchmark, framework security docs) from `docs/EXTERNAL-RESOURCES.md`. Tag the resulting work in your PR as `coverage: synthesized` so a reviewer can decide whether to promote the topic to a real rule or spec sheet in a subsequent PR.

This pattern is **codified in `secure-developer-mentor`'s `subagent.yaml`** so the catch-all behaviour is reproducible — not folklore. Native (Tier A) invocations carry it interactively; headless (Tier C) invocations emit a `coverage: synthesized` flag in the SARIF output for downstream auditing. The pattern is the same on every supported IDE because the subagent is the single source of truth and the IDE adapters are lowering targets.

---

## Quick start

```bash
git clone https://github.com/arvindiyu/SecureAICodeLibrary
cd SecureAICodeLibrary
make validate     # schema-validate registry/ (Phase 2+ content)
make index        # regenerate registry/INDEX.md
make sbom         # regenerate sbom.cdx.json
make all          # validate + index + sbom + source-hygiene + token-budget
```

Per-IDE install matrix and pre-commit hook wiring is documented in [`docs/INSTALL.md`](./docs/INSTALL.md). Manthan integration is documented in [`docs/MANTHAN-CONTRACT.md`](./docs/MANTHAN-CONTRACT.md). Manthan upstream: <https://github.com/arvindiyu/manthan>.

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the rule-author checklist, schema links, and PR self-check covering schema validation, token-budget compliance, and source hygiene. All threat-intel claims must be on the [`docs/SOURCES.md`](./docs/SOURCES.md) allowlist with a dated citation. Security-relevant disclosures: see [`SECURITY.md`](./SECURITY.md).

---

## Attribution and license

Original `arvindiyu/SecureAICodeLibrary` v1 content (`prompts/`, `.github/copilot/`, `guidelines/`) authored by the upstream maintainer; preserved verbatim in this distribution. v2 content (`registry/`, `adapters/`, `hooks/`, `docs/`, governance anchors) authored in this branch and offered for upstream merge.

Licensed under the MIT License — see [`LICENSE`](./LICENSE). All third-party standards (OWASP, ISO, NIST, MITRE ATLAS, CycloneDX, SPDX, SLSA) are referenced under their own respective licenses; this repository ships only mappings, not the standards themselves.
