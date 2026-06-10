# Changelog

All notable changes to the Secure AI Code Library are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) per [`SPEC.md`](./SPEC.md) §4.

## [2.0.0] - 2026-06-10

Complete v2 rebrand: Secure-by-Design AI Control Plane :: Mythos-Aligned Foundation.
Delivered across 8 phases and integrated by Wave 4.

### Added

**Phase 1 — Foundation (Wave 1)**
- `CONSTITUTION.md` — OWASP ASVS v5 + ISO/IEC 27001:2022 + ISO/IEC 42001:2023 + NIST AI RMF 1.0 mapping.
- `SPEC.md` — library scope, contracts, acceptance criteria, explicit out-of-scope section, registry / rule versioning policy.
- `THREAT_MODEL.md` — STRIDE per trust boundary (TB1–TB6) plus Glasswing-era residual posture section.
- `AGENTS.md` — IDE-agnostic consumer agent guidelines.
- `CONTRIBUTING.md`, `SECURITY.md`, `Makefile` — contributor toolchain.
- `sbom.cdx.json` — CycloneDX 1.5 SBOM for the library itself (auto-regenerated).
- `docs/AI-CONTROL-MAP.md` — elevator pitch: Mermaid swim-lane mapping AI SDLC stages × rules × subagents × gates.
- `docs/MYTHOS.md` — pillar alignment matrix (substantiated/aligned/roadmap) + M1–M8 dated roadmap.
- `docs/SOURCES.md` — verifiable-source allowlist (OWASP, ISO, NIST, MITRE, etc.); CI-enforced.
- `docs/INSTALL.md`, `docs/MANTHAN-CONTRACT.md`, `docs/SUBAGENT-FLOWS.md`, `docs/TOKEN-ECONOMICS.md`.
- Five ADRs (0001–0005) covering registry architecture, Manthan contract, severity thresholds, claim hygiene, and token-economy architecture.
- `registry/schemas/` — 4 JSON Schemas (rule, subagent, framework-spec, constitution); CI-validated.

**Phase 2 — Rules (Wave 2)**
- 23 AI-governance rules under `registry/rules/ai-governance/` (20 baseline + `llm-output-sanitization`, `ai-kill-switch`, `ai-code-provenance`).
- 14 cross-language coding-standards rules + 10 per-language rules (uses `extends:` inheritance).
- 6 policy rules (`severity-thresholds`, `scan-before-merge`, etc.) + 9 pre-commit rules including `ai-attribution-check` (BLOCKING by default).
- `registry/INDEX.md` auto-generated from rule summaries (≤3K tokens total).

**Phase 3 — Adapters + Subagents (Waves 3a and 3b)**
- 3 IDE adapters: `adapters/cursor/`, `adapters/copilot/`, `adapters/agents-md/` + `adapters/install.sh`.
- 6 subagents (Tier A native + Tier C headless): `adr-author`, `threat-modeler`, `ai-governance-auditor`, `coding-standards-reviewer`, `mcp-builder`, `secure-developer-mentor`.

**Phase 4 — Hooks (Wave 4 of Phase 4)**
- `hooks/pre-commit.sh` — single script for pre-commit + CI; invokes Tier C runners; 7 compliance checks; audit-log; SARIF aggregation.
- `hooks/config.yaml` — configurable severity threshold, freshness window, Manthan endpoint, subagent enable/disable.

**Phase 5 — Catalog (Wave 5)**
- `docs/EXTERNAL-RESOURCES.md` — AI-centric consolidated reference with "What AI typically gets wrong" column.
- 12 framework spec sheets under `registry/framework-specs/` (Angular, Vue, Svelte, Spring Boot, ASP.NET Core, Express, Django, Rails, FastAPI, Flask, Go-Gin, React Native).
- 3 net-new bespoke prompts: `prompts/infra-testing/mcp-builder.md`, `prompts/content-verification/rag-live-content-review.md`, `prompts/validation/pentest-scenario-builder.md`.

**Phase 6 — CI (Wave 6)**
- `.github/workflows/registry-ci.yml` — schema validation, INDEX.md regen, SBOM regen, token-budget lint, cross-link lint.
- `.github/workflows/merge-gate.yml` — dogfood pre-commit.sh against this repo itself.
- `.github/workflows/source-hygiene.yml` — citation allowlist + dated-citation enforcement + Mermaid accessibility lint.
- `scripts/` — 8 supporting scripts (`validate.sh`, `build-index.sh`, `build-sbom.sh`, `build-search-index.sh`, `source-hygiene-lint.sh`, `token-budget-lint.sh`, `cross-link-lint.sh`, `lint-js-size.sh`).

**Phase 7 — Site (Wave 7)**
- `index.html` — rebrand to Mythos-Aligned Foundation, new nav, Mermaid v10 + js-yaml v4 + Lunr lazy-loaded, `[WIP]` markers replaced with real links.
- `js/yaml-loader.js` — `?yaml=path` SPA mode for YAML files.
- `js/search-index.json` — auto-generated Lunr search index (89 items).
- `css/site.css` — `.mermaid-scroll`, `.callout`, `.pill.mythos-aligned`.

**Phase 8 — Roadmap (Wave 8)**
- M1–M8 dated milestones added to `docs/MYTHOS.md` § Roadmap (runtime telemetry, IR runbooks, SLSA, SLA enforcement, AI-augmented defense, workforce readiness, external validation, additional IDE adapters).

### Changed

- **Rebrand:** Repository identity changed from a prompts-only library to "Secure AI Code Library :: Secure-by-Design AI Control Plane for the SDLC — Mythos-Aligned Foundation." (Wave 1)
- **Two-layer rule loading:** `summary` (≤300 chars, always-on) + `content` (on-demand); ~10× token reduction vs. naive always-on approach. (Waves 1–2, ADR 0005)
- **AI-Control-Map as elevator pitch:** `docs/AI-CONTROL-MAP.md` is the entry point for new users and the primary human-readable description of what the library controls. (Wave 1)
- `README.md` rewritten with claim ladder, layered TOC, catch-all subagent pattern, v1-prompts-vs-v2-registry section. (Wave 1)
- `_config.yml` updated with title, description, and Jekyll exclude list. (Wave 7)
- `js/markdown-loader.js` extended with Mermaid post-render, YAML link rewriting, and lazy Prism loading. (Wave 7)

### Deprecated

None in 2.0.0.

### Removed

- `.github/ISSUE_TEMPLATE/` and `pull_request_template.md` — dropped in Phase 0 (plan decision); guidance moved to `CONTRIBUTING.md`. (Wave 1)

### Fixed

**Wave 4 integration pass (this release)**
- `registry/subagents/coding-standards-reviewer/subagent.yaml`: corrected 4 rule-ID drift errors (`error-handling-logging` → `error-handling`; `sql-injection-prevention` → `no-sql-injection`; dropped non-existent `file-upload-security`, `secure-headers`). Same fix applied to `prompts/system.md`.
- `hooks/config.yaml`: changed `on_unreachable: warn` → `on_unreachable: block` (fail-closed per `docs/MANTHAN-CONTRACT.md` § Failure modes).
- `docs/MANTHAN-CONTRACT.md`: reconciled `window_commits` to `10` (from `5`) and removed `CONSTITUTION.md` from the freshness rotation (it is checked unconditionally in Compliance Check 1).
- `prompts/api-security/README.md`, `prompts/cloud-security/README.md`: removed dead "Coming soon" links; replaced with references to `docs/EXTERNAL-RESOURCES.md`.
- `prompts/infra-testing/mcp-builder.md`: replaced dead link to non-existent `run.sh` with link to `subagent.yaml` (mcp-builder is interactive-only; `tiers.headless: not_applicable`).
- `scripts/source-hygiene-lint.sh`: fixed OWASP ASVS §V-prefix pattern, RFC trailing-text pattern, intra-repo path allowance, code-fence stripping for URL checks, localhost/example host exemptions, vendor-announcement false positives in policy documents.
- `registry/subagents/*/run.sh`: added `--scope` argument support (pre-commit.sh passes `--scope` in `--all` mode; runners were rejecting it with exit 64).
- `hooks/pre-commit.sh`: fixed bash 4+ compatibility shim (macOS ships bash 3.2; added `/opt/homebrew/bin` PATH prepend for bash 5 associative-array support); changed runner invocation from `bash "${runner}"` to `"${runner}"` to respect the script shebang.

### Security

**New AI-governance rules shipped in Phase 2 (Wave 2):**
- `prompt-injection-prevention` (Tier 0, always-on, CRITICAL) — blocks prompt-injection patterns in LLM inputs.
- `mcp-server-safety` (Tier 0, always-on, HIGH) — enforces tool-scope limits and auth requirements on MCP servers.
- `ai-attribution-check` (precommit, BLOCKING by default) — verifies `Co-Authored-By:` AI trailer on AI-assisted commits.
- `llm-output-sanitization` (HIGH) — requires output encoding before rendering LLM responses in HTML/API context.
- `ai-kill-switch` (HIGH) — requires each AI-enabled feature to expose a graceful disable path.
- `ai-code-provenance` (MEDIUM) — enforces SBOM registration and source traceability for AI-generated code artifacts.

---

## [0.x] — v1 prompts-only library (historical)

Pre-rebrand state: `prompts/`, `.github/copilot/`, `guidelines/`, `index.html`, `_config.yml`, and `js/markdown-loader.js`. Preserved in this distribution; not retroactively versioned.

---

[Unreleased]: https://github.com/arvindiyu/SecureAICodeLibrary/compare/main...HEAD
