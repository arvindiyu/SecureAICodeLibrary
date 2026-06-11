# ADR 0005 — Token economy architecture

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** Secure AI Code Library maintainers
- **Consulted:** Cursor adapter prototypes; Copilot index sizing experiments
- **Informed:** All contributors (rule authors, subagent authors, adapter authors)

## Context

Mythos-class frontier models (as of 2026-06) price input tokens at ~$10 / M and output tokens at ~$50 / M. A naive AI Control Plane that ships full rule content into every IDE's always-on context, calls an LLM for every gate decision, and writes verbose prose findings would cost ~10× more per developer-day than necessary. The library must engineer for token economy from day one, not bolt it on later.

Six tensions shape the design:

1. **Always-on vs on-demand.** Some rules must be present every turn (Tier 0). Others should activate only when relevant (scope globs).
2. **Discoverability vs context size.** Agents need to know what rules exist, but enumerating all rule content is expensive.
3. **Authoring inheritance vs file size.** Per-language and per-framework deltas should not duplicate cross-language guidance.
4. **Structured vs narrative output.** Prose explanations are token-expensive; SARIF / JSON-lines findings are cheap.
5. **LLM-anywhere vs LLM-on-demand.** Pre-commit / CI flows should not consume tokens by default.
6. **Cache prefix stability vs readability churn.** Reordering YAML fields breaks KV-cache hits empirically by ~90%.

## Decision

Adopt a **ten-strategy token-economy architecture**, codified across schema, adapters, hooks, and CI. Full detail in [`docs/TOKEN-ECONOMICS.md`](../TOKEN-ECONOMICS.md); this ADR records the architectural decisions.

### 1. Two-layer rule loading (single biggest lever)

Every rule has two fields that matter:

- **`summary`** — Layer 1. Required. ≤300 chars (~80 tokens). Loaded into always-on context (Tier 0) or scope-glob-activated context (others).
- **`content`** — Layer 2. Markdown body. Loaded on demand when (a) agent reads by ID, or (b) scope matches and rule is in agent's active list.

Schema enforces `summary` ≤300 chars. CI blocks at 301.

### 2. Scoped activation via globs

Non-Tier-0 rules default to `scope.always_apply: false`. Scope `globs` activate the rule only when matching files are in agent context. Cursor's `.mdc` adapter supports `alwaysApply: false` natively.

**Tier 0 (always-on) set (~5 rules):**
- `no-hardcoded-secrets`
- `prompt-injection-prevention`
- `agentic-human-approval`
- `ai-audit-logging`
- `mcp-server-safety`

### 3. `registry/INDEX.md` as cheap discovery

Auto-generated single file (~3K tokens) lists every rule ID + `summary` + tags + globs. Agents read INDEX once per session.

### 4. Subagent token budgets

Every subagent declares an explicit budget:

```yaml
token_budget:
  input_max: 12000
  output_max: 4000
  warn_at: 0.8
```

CI uses `tiktoken` to count and: warn at 80%, block at 100% (input side), block always on `summary > 300 chars`.

### 5. Inheritance via `extends:`

Per-language rules `extends:` cross-language parents. Framework specs `extends:` language rules. Children carry the language- or framework-specific **delta only**. CI cross-link lint validates `extends:` references.

### 6. Structured findings as default output

Subagents emit SARIF or JSON-lines by default. Prose remediation is on-demand (per-finding `?explain=true` or an interactive Tier A round-trip).

### 7. Headless-first for pre-commit / CI

`hooks/pre-commit.sh` invokes **Tier C runners**, which spend zero LLM tokens by default. LLM consumed only when:
- A developer interactively asks (Tier A), or
- Consumer opts into `$SECUREAI_LLM_ENDPOINT` for prose remediation (deterministic gate decision unchanged).

### 8. Cache-stable ordering

KV-cache prefix hits cut input cost ~90% for repeat invocations. Therefore:

- **YAML field ordering is frozen by schema.** Rule authors do not reorder top-level fields.
- **Markdown section ordering is frozen by template.** Principle → Rationale → BAD/GOOD examples → Checklist → References.
- **INDEX.md row ordering is alphabetical by `id` per category.**

Contributors are reminded in [`CONTRIBUTING.md`](../../CONTRIBUTING.md) Rule-author checklist.

### 9. Adapter-side compression

Each adapter is tuned to the smallest viable always-on payload:

- **Cursor**: `.mdc` frontmatter + `summary` inline; full content via `@rule:<id>`. ~500 tokens per file.
- **Copilot**: `.github/copilot-instructions.md` is a ≤2K-token INDEX only.
- **AGENTS.md**: glob-scoped sections + summary inline; content referenced.

### 10. Measurement hooks for the roadmap

Subagents emit JSON-lines audit entries with `token_in` + `token_out`. Feeds the M1 telemetry dashboard (per [`docs/MYTHOS.md`](../MYTHOS.md)) — measurement exists in v1.

## Net token targets

| Surface | Budget | Enforcement |
|---|---|---|
| `.github/copilot-instructions.md` (always-on) | ≤ 2K tokens | `registry-ci.yml` |
| `AGENTS.md` (always-on summaries) | ≤ 4K tokens | `registry-ci.yml` |
| `registry/INDEX.md` | ≤ 3K tokens | `registry-ci.yml` |
| Each subagent system prompt | ≤ `token_budget.input_max` | `registry-ci.yml` (warn 80%, block 100%) |
| Cursor `.cursor/rules/<id>.mdc` per file | ≤ 500 tokens | `registry-ci.yml` |
| `summary` (Layer 1) | ≤ 300 chars (~80 tokens) | JSON Schema; CI blocks at 301 |

## Consequences

### Positive

- **~10× reduction in always-on context** vs naive "ship all content always".
- **~90% input-cost reduction on repeat invocations** due to cache-stable ordering.
- **Zero LLM cost** at commit-time by default.
- **Predictable spend.** Token budgets are declared in `subagent.yaml`; CI enforces.
- **Measurement baseline** exists from day one, feeding the M1 telemetry milestone.

### Negative

- **Authoring discipline required.** Contributors must write tight `summary` lines and respect field ordering. Mitigated by checklists and CI feedback.
- **Tooling dependency.** CI needs `tiktoken` (Python). Mitigated by pinning a specific encoding and providing a local-equivalent in the Makefile.
- **No graceful degradation if a model changes encoding.** If the model family changes its tokenizer significantly, the budget table needs updating. Acceptable: budgets are conservative.

### Neutral

- Cache-stability is a contributor rule, not a schema-enforced invariant. The schema fixes the field set; ordering is by convention. CI surface (Phase 6) could be extended to a `yamllint`-style check if drift becomes an issue.
- The two-layer split (`summary` vs `content`) means the SPA `?yaml=` loader (Phase 7) must render both correctly — that is, the SPA's "expand full content" UX must remain available.
- The library's own audit log is JSON-lines (file write) — zero infrastructure cost, easy to aggregate later (M1).

## Anti-patterns explicitly closed off

1. **Inlining `content` into adapter output.** Adapters write `summary` only.
2. **Reordering YAML fields to "improve readability".** Breaks prefix-cache.
3. **Adding asvs/iso/nist mapping arrays as long bullet lists.** Use structured fields; their ordering is fixed.
4. **Embedding multi-language code examples in `summary`.** Examples belong in `content`. `summary` is the agent-facing imperative.
5. **Calling `$SECUREAI_LLM_ENDPOINT` for gate decisions.** It is for prose remediation only.
6. **Writing a Tier B chat prompt because Tier A "is too expensive".** Use Tier C — zero LLM tokens. ADR 0004 closed off Tier B for other reasons; this ADR closes it off for cost reasons too.

## Follow-up

- Phase 1: ships the schemas (this ADR's `summary` ≤300 constraint is in `rule.schema.json`).
- Phase 2: rule porting must respect the budgets; the rule-author checklist gates each PR.
- Phase 3: adapters are sized to their token target.
- Phase 6: `registry-ci.yml` ships the `tiktoken`-based lint.
- M1: token-spend dashboard consumes the audit log.

## References

- [`docs/TOKEN-ECONOMICS.md`](../TOKEN-ECONOMICS.md) — operational expression of this ADR.
- [`registry/schemas/rule.schema.json`](../../registry/schemas/rule.schema.json) — `summary` constraint.
- [`registry/schemas/subagent.schema.json`](../../registry/schemas/subagent.schema.json) — `token_budget` contract.
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — rule-author and subagent-author checklists.
- ADR 0001 — Registry and adapter architecture (the two-layer split is structural).
- ADR 0004 — Claim hygiene and sourcing (closes off Tier B for honesty reasons).
- `tiktoken` library: <https://github.com/openai/tiktoken>.
