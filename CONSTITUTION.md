# Constitution

> The Secure AI Code Library is governed by a fixed set of external standards. This document maps every governance anchor in this repository to its **primary source standard**, with explicit section identifiers. Every rule under `registry/rules/` declares its mapping to one or more of these standards via the `asvs_controls`, `iso_controls`, `iso42001_controls`, `nist_ai_rmf`, `cwe`, and `mitre_atlas` fields.

This Constitution is **narrative**. A machine-readable form is defined by [`registry/schemas/constitution.schema.json`](./registry/schemas/constitution.schema.json); if a future phase splits this document into a YAML mapping, the schema is authoritative.

## Principles

1. **Verifiability over fashion.** Every control claim cites a section ID in a dated, public, primary standard. No vendor announcements. No undated marketing claims.
2. **Minimal but complete.** We map controls only where this library demonstrably implements or measures the control. Roadmap items are listed as `substantiation: roadmap` in the alignment matrix ([`docs/MYTHOS.md`](./docs/MYTHOS.md)) — never falsely claimed as "ready".
3. **Cross-referenced.** Where multiple standards cover the same control (for example, secrets handling is in OWASP ASVS V6, ISO/IEC 27001 A.5.17, and NIST SSDF), we cite all of them so rule authors can pick the most appropriate primary citation.
4. **Stable identifiers.** Standard section IDs are stable. Marketing names ("Top 10 for LLM Applications") may evolve; the section IDs are the canonical reference.

---

## Standards in scope

The library maps to four standards as primary anchors, plus three secondary catalogs.

### Primary anchors

| Standard | Version | Issuer | Role in this library |
|---|---|---|---|
| **OWASP Application Security Verification Standard (ASVS)** | v5.0 (2024) | OWASP Foundation | Application-layer control catalog. Every `coding-standards` rule maps to one or more ASVS controls via `asvs_controls`. |
| **ISO/IEC 27001:2022** (Annex A) | 2022 | ISO/IEC | Information security management system controls. Mapped via `iso_controls`. |
| **ISO/IEC 42001:2023** | 2023 | ISO/IEC | AI management system controls. Mapped via `iso42001_controls`. AI-governance rules MUST declare at least one ISO 42001 control. |
| **NIST AI Risk Management Framework (AI RMF)** | 1.0 (2023) + GenAI Profile (2024) | NIST | AI risk functions (GOVERN, MAP, MEASURE, MANAGE). Mapped via `nist_ai_rmf`. |

### Secondary catalogs

| Catalog | Role |
|---|---|
| **MITRE ATT&CK** ((2024) v15) | Adversary technique IDs cited in threat-intel context only. |
| **MITRE ATLAS** ((2024)) | Adversarial ML technique IDs. AI-governance rules SHOULD declare `mitre_atlas` IDs where applicable; CI warns on missing. |
| **CWE** (4.14 (2024)) | Weakness IDs. Coding-standards rules SHOULD declare `cwe` IDs; CI warns on missing. |
| **OWASP Top 10 for LLM Applications** ((2025)) | Authoritative LLM-app threat enumeration; cross-referenced in AI-governance rules where relevant. |
| **NIST SSDF (SP 800-218)** ((2022)) | Secure software development practices. Cited where the library defines practice-level guidance (CI/CD, supply chain). |
| **SLSA** (v1.0 (2023)) | Supply-chain integrity levels. Referenced in supply-chain roadmap milestones. |
| **CycloneDX** (1.5 (2024)) | SBOM format used by `sbom.cdx.json`. |

URLs for each standard are on the allowlist in [`docs/SOURCES.md`](./docs/SOURCES.md). The `source-hygiene.yml` CI workflow (Phase 6) enforces that every threat-intel citation matches the allowlist.

---

## Control map

The following sections map this library's principal control areas to the primary anchors. Each row references the rule IDs that implement the control (Phase 2+ content) and the gate(s) that enforce them at runtime.

### A. Identity, authentication, authorisation

Primary anchors:
- **OWASP ASVS v5** — V2 (Authentication), V3 (Session Management), V4 (Access Control).
- **ISO/IEC 27001:2022 Annex A** — A.5.15 (Access control), A.5.16 (Identity management), A.5.17 (Authentication information), A.8.2 (Privileged access rights), A.8.3 (Information access restriction).
- **NIST AI RMF** — `GOVERN-1.4` (Roles and responsibilities), `MAP-1.6` (System purpose constrains access).

Implementation locus (Phase 2+):
- `registry/rules/coding-standards/auth-patterns.rule.yaml`
- `registry/rules/coding-standards/session-management.rule.yaml`
- `registry/rules/ai-governance/agentic-obo-auth.rule.yaml`
- `registry/rules/ai-governance/agentic-tool-scoping.rule.yaml`

Gates: pre-commit `coding-standards-reviewer`; CI scan-before-merge gate via Manthan.

### B. Secrets and credential handling

Primary anchors:
- **OWASP ASVS v5** — V6 (Stored Cryptography), V14 (Configuration).
- **ISO/IEC 27001:2022 Annex A** — A.5.17 (Authentication information), A.8.24 (Use of cryptography).
- **NIST SSDF** — `PO.5` (Implement supporting toolchains).

Implementation locus (Phase 2+):
- `registry/rules/coding-standards/no-hardcoded-secrets.rule.yaml` (Tier 0, always-on)
- `registry/rules/policies/sbom-freshness.rule.yaml`

Gates: pre-commit secrets check; CI source-hygiene + scan gate.

### C. Input validation, output encoding, injection prevention

Primary anchors:
- **OWASP ASVS v5** — V5 (Validation, Sanitization, and Encoding).
- **OWASP Top 10 for LLM Applications (2025)** — LLM01 Prompt Injection, LLM02 Insecure Output Handling.
- **CWE** — CWE-79, CWE-89, CWE-94, CWE-1336.
- **NIST AI RMF GenAI Profile** — `MAP-2.3` (Context).

Implementation locus (Phase 2+):
- `registry/rules/coding-standards/output-encoding.rule.yaml`
- `registry/rules/ai-governance/prompt-injection-prevention.rule.yaml` (Tier 0, always-on)
- `registry/rules/ai-governance/llm-output-sanitization.rule.yaml`

Gates: pre-commit `coding-standards-reviewer` + `ai-governance-auditor`.

### D. AI governance, agentic safety, and tool scoping

Primary anchors:
- **ISO/IEC 42001:2023** — A.6 (AI system life cycle), A.7 (Data for AI systems), A.8 (Information for interested parties), A.9 (Use of AI systems).
- **NIST AI RMF** — `GOVERN-1.1` (Legal and regulatory requirements understood), `GOVERN-3.2` (Policies for AI), `MAP-2.1` (Task and method understood), `MANAGE-2.3` (Procedures to handle risks).
- **MITRE ATLAS** — `AML.T0051` (LLM Prompt Injection), `AML.T0048` (Erode ML Model Integrity).
- **OWASP Top 10 for LLM Applications (2025)** — full top-10.

Implementation locus (Phase 2+):
- All 20+ rules under `registry/rules/ai-governance/`.
- All 6 subagents under `registry/subagents/`.
- `.securecode/audit.log` per `ai-audit-logging` rule.

Gates: pre-commit `ai-governance-auditor` runner; CI registry-ci.yml; runtime audit log.

### E. Supply chain integrity and SBOM

Primary anchors:
- **NIST SSDF** — `PS.3` (Archive and protect each software release), `PW.4` (Reuse existing, well-secured software).
- **SLSA v1.0** — Build, Source, Dependencies tracks.
- **CycloneDX 1.5** — SBOM data format.
- **ISO/IEC 27001:2022 Annex A** — A.5.19 (Information security in supplier relationships).

Implementation locus (Phase 2+):
- `registry/rules/policies/sbom-freshness.rule.yaml`
- `registry/rules/precommit/sbom-check.rule.yaml`
- [`sbom.cdx.json`](./sbom.cdx.json)

Gates: pre-commit `sbom-check`; CI `make sbom` regen.

### F. Logging, monitoring, audit

Primary anchors:
- **OWASP ASVS v5** — V8 (Logging and Error Handling).
- **ISO/IEC 27001:2022 Annex A** — A.8.15 (Logging), A.8.16 (Monitoring activities).
- **NIST AI RMF** — `MEASURE-2.7` (System security and resilience), `MANAGE-4.1` (Post-deployment AI system monitoring).

Implementation locus (Phase 2+):
- `registry/rules/ai-governance/ai-audit-logging.rule.yaml` (Tier 0, always-on)
- `.securecode/audit.log` write contract (JSON-lines).

Gates: subagent runtime audit-log emission; CI lint to ensure rule references are valid.

### G. Threat modelling and architectural risk

Primary anchors:
- **OWASP ASVS v5** — V1 (Architecture).
- **NIST AI RMF** — `MAP-1.1` (Context), `MAP-3.1` (Identification of risks).
- **ISO/IEC 27001:2022 Annex A** — A.5.7 (Threat intelligence), A.5.30 (ICT readiness for business continuity).

Implementation locus (Phase 1):
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — STRIDE per trust boundary.
- Subagent: `threat-modeler` (Phase 3).
- Policy: `registry/rules/policies/threat-model-required.rule.yaml` (Phase 2).

Gates: pre-commit `threat-model-check`.

### H. Incident response, kill-switch, oversight

Primary anchors:
- **ISO/IEC 42001:2023** — A.9.3 (Process for reporting concerns).
- **NIST AI RMF** — `MANAGE-2.4` (Mechanisms in place to address risks).
- **ISO/IEC 27001:2022 Annex A** — A.5.24 (Information security incident management planning and preparation), A.5.26 (Response to information security incidents).

Implementation locus (Phase 2):
- `registry/rules/ai-governance/ai-kill-switch.rule.yaml`
- `registry/rules/ai-governance/ai-human-oversight.rule.yaml`

Substantiation today: **roadmap** for the operational playbooks (runbooks, drills) — see [`docs/MYTHOS.md`](./docs/MYTHOS.md) M2.

### I. Provenance, attribution, AI-generated code disclosure

Primary anchors:
- **ISO/IEC 42001:2023** — A.8.4 (Information for users about AI system characteristics).
- **NIST AI RMF GenAI Profile** — `GOVERN-1.6` (Mechanisms to track AI components).
- **OWASP Top 10 for LLM Applications (2025)** — LLM05 (Improper Output Handling) and LLM09 (Misinformation) context.

Implementation locus (Phase 2):
- `registry/rules/ai-governance/ai-code-provenance.rule.yaml`
- `registry/rules/precommit/ai-attribution-check.rule.yaml` (BLOCKING by default; verifies Co-Authored-By trailer on AI-flagged commits).

Gates: pre-commit `ai-attribution-check`.

---

## Versioning and amendment

This Constitution is amended only via PR. Amendments must:
1. Reference the new or updated primary standard, with dated citation.
2. Update [`docs/SOURCES.md`](./docs/SOURCES.md) if a new source is introduced.
3. Update affected rule files' `asvs_controls` / `iso_controls` / `iso42001_controls` / `nist_ai_rmf` fields in the same PR (or open a follow-up issue tracked in `CHANGELOG.md`).
4. Bump the library version per [`SPEC.md`](./SPEC.md) versioning policy when the change is breaking for rule authors.

Standards are pinned by year-revision (for example, ASVS v5, ISO/IEC 27001:2022). When an anchor standard issues a new revision, the library opens a tracked migration PR; the previous mapping remains valid until the migration PR merges.

---

## References

- OWASP Application Security Verification Standard v5.0: <https://owasp.org/www-project-application-security-verification-standard/>
- ISO/IEC 27001:2022: <https://www.iso.org/standard/27001> (Annex A control catalog)
- ISO/IEC 42001:2023: <https://www.iso.org/standard/81230.html>
- NIST AI RMF 1.0: <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST AI RMF GenAI Profile (NIST AI 600-1, 2024): <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- MITRE ATT&CK: <https://attack.mitre.org/>
- MITRE ATLAS: <https://atlas.mitre.org/>
- CWE: <https://cwe.mitre.org/>
- OWASP Top 10 for LLM Applications (2025): <https://genai.owasp.org/llm-top-10/>
- NIST SSDF (SP 800-218): <https://csrc.nist.gov/publications/detail/sp/800-218/final>
- SLSA v1.0: <https://slsa.dev/>
- CycloneDX 1.5: <https://cyclonedx.org/specification/overview/>
