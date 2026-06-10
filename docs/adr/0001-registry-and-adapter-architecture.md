# ADR 0001 — Registry and adapter architecture

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** Secure AI Code Library maintainers
- **Consulted:** Cursor and Copilot adapter prototypes; SCEC (`securecode-enterprise-control`) reference architecture
- **Informed:** Consumer-project integrators

## Context

The library must serve at least three IDE / agent surfaces (Cursor, GitHub Copilot, AGENTS.md-respecting agents) with a future requirement to add Claude Code and Windsurf (Phase 8 M8). It must also serve a headless / CI surface (`hooks/pre-commit.sh`, `merge-gate.yml`) and a static documentation site.

Three options were considered for organising the content:

1. **Per-IDE authoring (rejected).** Maintain `cursor/`, `copilot/`, `agents-md/` trees of hand-authored content. Allows each IDE to be tuned independently but multiplies maintenance burden by N adapters, and risks drift (the Cursor rule says X, the AGENTS.md section says Y, the Copilot file says Z, all on the same topic).
2. **Single markdown source with manual lowering (rejected).** Author once in markdown; each adapter manually transforms. Reduces drift but the markdown becomes a half-spec, half-instructions hybrid and the lowering scripts grow brittle.
3. **Canonical YAML registry with thin adapters (chosen).** Author once in structured YAML (validated by JSON Schema). Each adapter is a small, idempotent lowering routine that emits the IDE-native file format. Drift is impossible by construction: every adapter reads the same source.

Additional considerations:

- **Token economics** (per ADR 0005 and [`docs/TOKEN-ECONOMICS.md`](../TOKEN-ECONOMICS.md)) requires a two-layer rule contract — `summary` always-on, `content` on-demand. Structured YAML accommodates both fields natively; markdown frontmatter is awkward for the same purpose.
- **Schema-validated cross-links** (rule `extends:`, subagent `references.rules`) are practical in YAML + JSON Schema and impractical in pure markdown.
- **Subagents** are a separate first-class concept from rules; they need a different schema and a `run.sh` runner. A single tree per concept (rules, subagents, framework-specs) keeps the registry navigable.

## Decision

Adopt **Option 3 — canonical YAML registry with thin adapters**.

Specifically:

- `registry/rules/*/<id>.rule.yaml` — every rule, with required `summary` ≤300 chars, required non-empty `sources.primary`, required `mythos_alignment.substantiation`, and a markdown `content` body. Schema: `registry/schemas/rule.schema.json`.
- `registry/subagents/<id>/subagent.yaml` + `run.sh` — every subagent. Schema: `registry/schemas/subagent.schema.json`.
- `registry/framework-specs/<id>.spec.yaml` — every framework spec sheet. Schema: `registry/schemas/framework-spec.schema.json`.
- `registry/INDEX.md` — auto-generated single discovery file (~3K tokens).
- `adapters/<ide>/` — small, idempotent lowering routines that emit the IDE-native file format.

Adapter responsibilities:

| Adapter | Output target | What it writes | What it does NOT write |
|---|---|---|---|
| `adapters/cursor/` | `.cursor/rules/<id>.mdc` + `.cursor/skills/<subagent-id>/SKILL.md` | Frontmatter + `summary` inline; full `content` via Cursor's `@rule:<id>` mention | Full rule bodies in always-on context |
| `adapters/copilot/` | `.github/copilot-instructions.md` (top-level INDEX only, ≤2K tokens) | Cross-references to `registry/INDEX.md` + existing `.github/copilot/*.md` | Anything under `.github/copilot/*` (preserves existing per-category files) |
| `adapters/agents-md/` | `AGENTS.md` glob-scoped sections in the consumer repo | `summary` inline per section | Full content (referenced via relative link) |

The single installer `adapters/install.sh` (Phase 3) auto-detects IDE markers (`.cursor/`, `.github/`, `AGENTS.md`) and lowers to every detected target. Re-running `install.sh` is **idempotent**: byte-identical output for the same registry state.

Claude Code and Windsurf adapters are deferred to Phase 8 M8 (per [`docs/MYTHOS.md`](../MYTHOS.md)) — the two-tier subagent contract (per ADR 0004) makes their addition mechanical.

## Consequences

### Positive

- **Single source of truth.** Drift is impossible by construction. A rule update lands in one file; every adapter picks it up.
- **Schema-enforced quality.** Required `summary` ≤300 chars, required `sources.primary`, required `mythos_alignment.substantiation` are CI-enforced. Cannot accidentally ship an unsourced rule.
- **Token-economy friendly.** The `summary`/`content` split is structural, not a convention. Adapters cannot accidentally inline `content`.
- **Cross-link integrity.** `extends:` and `references.rules` are validated by `registry-ci.yml` cross-link lint.
- **Cheap to add IDEs.** A new adapter is a ~200-line lowering routine; the canonical content is reused.
- **Cheap to remove IDEs.** Deleting an adapter does not touch any rule.

### Negative

- **Authoring overhead.** Contributors author in YAML + markdown (in the `content:` literal block), not pure markdown. Mitigated by IDE YAML schema awareness (most editors honour `$schema`) and the rule-author checklist in `CONTRIBUTING.md`.
- **YAML parsing in the SPA.** The static site needs a client-side YAML parser to render rule files. Phase 7 ships `js/yaml-loader.js` (lazy-loaded js-yaml v4).
- **No native IDE preview for raw rule files.** Cursor and Copilot understand their lowered formats, not the canonical YAML. Mitigated by the SPA + by the rule's lowered form being available immediately after `install.sh`.

### Neutral

- The Tier B chat-prompt fallback option is closed off (per ADR 0004); Copilot Chat users either read the lowered `SKILL.md` or invoke headless runners.
- A `registry/.integrity.json` is **not** shipped (git provides content integrity; no value in re-hashing in-tree).
- A separate `registry/skills/` tree is **not** shipped — subagents are the single source of truth; per-IDE skills are adapter output.

## Follow-up

- ADR 0002 — Manthan scan-gate contract (consumes subagent findings).
- ADR 0003 — Severity-thresholds policy (consumed by `hooks/config.yaml`).
- ADR 0004 — Claim hygiene and sourcing (motivates `sources.primary` required field).
- ADR 0005 — Token economy architecture (motivates `summary` field structure).
- Phase 6 `registry-ci.yml` ships the cross-link lint, schema validation, and INDEX regen.
- Phase 8 M8 ships Claude Code + Windsurf adapters under the same contract.

## References

- [`SPEC.md`](../../SPEC.md) §2 — Contracts.
- [`docs/AI-CONTROL-MAP.md`](../AI-CONTROL-MAP.md) — swim-lane.
- [`registry/schemas/rule.schema.json`](../../registry/schemas/rule.schema.json)
- [`registry/schemas/subagent.schema.json`](../../registry/schemas/subagent.schema.json)
- [`registry/schemas/framework-spec.schema.json`](../../registry/schemas/framework-spec.schema.json)
- [SCEC reference architecture](https://github.com/arvindiyu/SecureCodeEnterpriseControl) — original rule-shape inspiration.
- [Cursor Rules documentation](https://docs.cursor.com/context/rules-for-ai).
- [AGENTS.md convention](https://agents.md/).
