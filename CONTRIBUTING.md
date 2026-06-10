# Contributing

> Thanks for contributing to the Secure AI Code Library. This file replaces issue and PR templates. Read it once; it is the single contract for rule authors, subagent authors, framework-spec authors, and doc contributors.

## How to think about this repo

This is a **canonical YAML registry** of security rules and subagents, plus IDE adapters and a pre-commit hook. Three values guide every PR:

1. **Verifiability** — every claim is mapped to a primary standard with a dated citation. No vendor announcements as threat statistics.
2. **Token-economy discipline** — every rule has a `summary` ≤300 chars (Layer 1, always-on) and full `content` (Layer 2, on-demand). Field ordering is frozen for cache stability.
3. **Honesty** — `mythos_alignment.substantiation` is `substantiated` only when evidence is in-tree. `aligned` and `roadmap` are first-class statuses, not failure modes.

## What to contribute

| Surface | Where | Schema |
|---|---|---|
| **A new rule** | `registry/rules/<category>/<id>.rule.yaml` | [`registry/schemas/rule.schema.json`](./registry/schemas/rule.schema.json) |
| **A new subagent** | `registry/subagents/<id>/subagent.yaml` + `run.sh` | [`registry/schemas/subagent.schema.json`](./registry/schemas/subagent.schema.json) |
| **A new framework spec** | `registry/framework-specs/<id>.spec.yaml` | [`registry/schemas/framework-spec.schema.json`](./registry/schemas/framework-spec.schema.json) |
| **A net-new v1 prompt** | `prompts/<category>/<file>.md` | (existing convention; preserved) |
| **A doc** | `docs/<DOC>.md` or root anchor (`SPEC.md`, etc.) | Markdown only; cite sources via [`docs/SOURCES.md`](./docs/SOURCES.md). |
| **An ADR** | `docs/adr/NNNN-<slug>.md` | MADR (Status / Context / Decision / Consequences). |
| **An adapter change** | `adapters/<ide>/` | Idempotent install.sh; byte-identical output for same registry state. |

## Rule-author checklist

Before opening a PR for a new or updated rule, walk this list end-to-end. The PR will not merge until every item is checked.

### Schema
- [ ] File path matches `registry/rules/<ai-governance|coding-standards|coding-standards/per-language|policies|precommit>/<id>.rule.yaml`.
- [ ] `metadata.id` is kebab-case and matches the filename (without `.rule.yaml`).
- [ ] `metadata.name` and `metadata.description` are present.
- [ ] Rule validates against [`registry/schemas/rule.schema.json`](./registry/schemas/rule.schema.json) — run `make validate` locally if available.
- [ ] If per-language: `extends: <cross-language-rule-id>`; only language-specific delta in this file.
- [ ] If framework-spec: see [`registry/schemas/framework-spec.schema.json`](./registry/schemas/framework-spec.schema.json) instead.

### Summary (Layer 1, always-on)
- [ ] `summary` is present, single-line, ≤300 chars (UTF-8). CI blocks at 301.
- [ ] `summary` reads like "do X; reject Y; rationale Z". Imperative voice.
- [ ] `summary` is not a paraphrase of `metadata.description` — it is the **agent-facing instruction**.

### Sources (verifiable-only)
- [ ] `sources.primary` is non-empty and cites at least one of: OWASP ASVS v5, ISO/IEC 27001:2022, ISO/IEC 42001:2023, NIST AI RMF, NIST SSDF, CWE, MITRE ATT&CK, MITRE ATLAS, OWASP Top 10 for LLM.
- [ ] If `sources.threat_intel` is set, every entry is on the [`docs/SOURCES.md`](./docs/SOURCES.md) allowlist and dated (e.g., `(2024)` or `as of YYYY-MM-DD`).
- [ ] No vendor announcement is cited as a threat statistic.

### Mythos alignment
- [ ] `mythos_alignment.pillar` is one of: `ai-governance`, `secure-by-design`, `supply-chain`, `proactive-defense`, `incident-response`.
- [ ] `mythos_alignment.substantiation` is one of: `substantiated` (evidence in-tree, with `evidence: [...]` paths), `aligned` (in-tree but partial), `roadmap` (deferred to a milestone in `docs/MYTHOS.md`).
- [ ] `mythos_alignment.evidence` lists file paths in this repo when `substantiation: substantiated`.

### Token budget
- [ ] `summary` ≤300 chars (re-stated; this is the single biggest cost lever).
- [ ] `content` body is bounded — guidance + BAD/GOOD + checklist + refs. No filler.
- [ ] Examples are minimal and language-specific only where the language affects security (e.g., string interpolation in Python vs Java).
- [ ] If the rule is non-Tier-0, `scope.always_apply: false` is set (default), and `scope.globs` is narrow.

### Cache-stability
- [ ] Top-level YAML field order matches the schema (verified by `make validate`).
- [ ] Markdown headings under `content` follow the established template order: Principle → Rationale → BAD/GOOD examples → Checklist → References.
- [ ] No reordering of fields in existing rules unless a schema bump is in the same PR.

### Cross-references
- [ ] `references.rules` (if present) lists only IDs that exist; cross-link lint will fail otherwise.
- [ ] `extends:` (if present) references an existing parent rule ID.

### PR self-check (do this before requesting review)
- [ ] `make validate` passes.
- [ ] `make token-budget` shows no warnings above 80% of declared budget (or you have a justification in the PR description).
- [ ] `make source-hygiene` passes.
- [ ] `make index` regenerates `registry/INDEX.md` cleanly with no stale entries.

## Subagent-author checklist

- [ ] Directory created: `registry/subagents/<id>/`.
- [ ] `subagent.yaml` validates against [`registry/schemas/subagent.schema.json`](./registry/schemas/subagent.schema.json).
- [ ] `tiers.native` and `tiers.headless` both declared (set `tiers.headless: not_applicable` when truly interactive-only, like `secure-developer-mentor`).
- [ ] `token_budget.{input_max, output_max, warn_at}` declared.
- [ ] `audit_log.enabled` is `true`; `audit_log.path` defaults to `.securecode/audit.log`.
- [ ] `tool_scope.allowed` and `tool_scope.denied` are explicit and narrow.
- [ ] `references.rules` is a closed list of rule IDs the subagent will load (bounded blast radius).
- [ ] `run.sh` is POSIX shell, deterministic, exits non-zero on policy violation.
- [ ] If `run.sh` calls `$SECUREAI_LLM_ENDPOINT`, it is opt-in and the gate decision is independent of the LLM response.

## Framework-spec checklist

- [ ] File path: `registry/framework-specs/<id>.spec.yaml`.
- [ ] `metadata.id`, `metadata.name`, `applies_to.{language,framework}` set.
- [ ] `extends:` references the appropriate per-language rule ID.
- [ ] `security_relevant_defaults` lists framework-specific gotchas (CSRF middleware name, default cookie settings, autoescape defaults).
- [ ] `authoritative_refs` includes at least one OWASP cheat sheet or vendor security doc URL.
- [ ] `applicable_rules` lists cross-language and per-language rule IDs that compose with this spec.

## Doc contributor checklist

- [ ] Markdown only. Mermaid diagrams MUST include `accTitle` and `accDescr` (Mermaid v10+ accessibility directives).
- [ ] Inline citations use one of: a URL on the [`docs/SOURCES.md`](./docs/SOURCES.md) allowlist, a dated reference (`(YYYY)` or `as of YYYY-MM-DD`), or both.
- [ ] Cross-links use relative paths so the SPA loader (`?md=...`) and GitHub web view both resolve correctly.
- [ ] No `[WIP]` markers in net-new docs.

## ADR contributor checklist

- [ ] Filename: `docs/adr/NNNN-<slug>.md` with zero-padded sequence.
- [ ] Standard MADR sections: **Status**, **Context**, **Decision**, **Consequences**.
- [ ] Status starts as `Proposed`; updated to `Accepted` by maintainer at merge.
- [ ] Context cites the constraint or option being decided.
- [ ] Consequences enumerate positive, negative, and neutral effects, plus a follow-up list.

## PR self-check (universal)

Every PR runs these CI workflows automatically (Phase 6); you should run them locally first:

1. **`make validate`** — JSON Schema validates everything under `registry/` against the four schemas.
2. **`make index`** — Regenerates `registry/INDEX.md`. Diff must be in-PR (no stale INDEX).
3. **`make sbom`** — Regenerates `sbom.cdx.json`. Diff must be in-PR if dependencies changed.
4. **`make token-budget`** — `tiktoken`-based count for every subagent system prompt and every rule `summary`. Warns at 80% of declared budget; blocks on `summary` >300 chars.
5. **`make source-hygiene`** — Regex-cross-references every citation against `docs/SOURCES.md`. Warns on Mermaid blocks lacking `accTitle`/`accDescr`.
6. **`make dogfood`** — Runs `hooks/pre-commit.sh` against this repo.

The aggregate `make all` runs everything.

## Branch and commit style

- Topic branches off `main`. Naming: `feat/<short-slug>`, `fix/<short-slug>`, `docs/<short-slug>`, `chore/<short-slug>`.
- Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).
- If any commit in the PR is AI-assisted, include a `Co-Authored-By:` trailer attesting to AI involvement. The `ai-attribution-check` pre-commit rule will block otherwise.

## Coding standards (for `hooks/`, `adapters/`, `run.sh` scripts)

- POSIX shell, `set -euo pipefail`, no bashisms in scripts that ship in `hooks/` or `registry/subagents/*/run.sh` (these must run on Linux, macOS, Alpine).
- Tools assumed available: `rg`, `yq`, `jq`, `git`, `curl`, `sha256sum` / `shasum`. Document any others in the script header.
- No network calls in Tier C runners unless `$SECUREAI_LLM_ENDPOINT` is set; even then, gate-decision logic is local.

## Source hygiene reminder

This is repeated because it is the most common PR rejection reason.

**Allowed citations** (see [`docs/SOURCES.md`](./docs/SOURCES.md) for the full list):
- OWASP (ASVS, ASVS Top 10, LLM Top 10, cheat sheets) — direct URLs only.
- ISO/IEC standards — by ID + year (e.g., `ISO/IEC 27001:2022 A.5.17`).
- NIST publications — by SP number + year.
- MITRE ATT&CK / ATLAS — by technique ID.
- Mandiant M-Trends, Verizon DBIR, CrowdStrike GTR, Google TAG, Microsoft DDR — dated reports.
- CISA advisories — by advisory ID.
- ENISA Threat Landscape — by year.

**Not allowed** (CI blocks):
- Vendor blog posts as the sole source for a threat statistic.
- "AI experts say…" without a dated study.
- Undated or unattributed claims.
- Confidential / paywalled sources without a public restatement.

## Triage and review

- Maintainers will label PRs with `area:rules`, `area:subagents`, `area:specs`, `area:docs`, `area:adapters`, `area:ci`, `area:hooks`, `area:site`.
- Reviews focus on: source hygiene, token-budget compliance, cross-reference integrity, and adherence to the rule-author checklist above.
- Substantive design changes require an ADR before code lands.

## Questions

Open an issue. Tag with `question`. We will route to the right area maintainer.
