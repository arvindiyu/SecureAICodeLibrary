# Installation

> Per-IDE install matrix and pre-commit hook wiring patterns. Phase 3 ships the adapters under `adapters/<ide>/` and the single `adapters/install.sh` auto-detector. Phase 4 ships `hooks/pre-commit.sh` and `hooks/config.yaml`. This document is the user-facing wiring reference for both.

## Per-IDE install matrix

| IDE / surface | Adapter | Output target | What ships | Status |
|---|---|---|---|---|
| **Cursor** | `adapters/cursor/` | `.cursor/rules/<rule-id>.mdc` + `.cursor/skills/<subagent-id>/SKILL.md` | Frontmatter + `summary` inline; full `content` via `@rule:<id>` on demand. Subagents lowered to Cursor skills. | Phase 3 |
| **GitHub Copilot** | `adapters/copilot/` | `.github/copilot-instructions.md` (top-level INDEX only, ≤2K tokens) | Cross-references to `registry/INDEX.md` + existing `.github/copilot/*.md`. Does NOT overwrite existing per-category instruction files. | Phase 3 |
| **AGENTS.md-respecting agents** | `adapters/agents-md/` | `AGENTS.md` glob-scoped sections in consumer repo root | Summary inline; full content referenced. | Phase 3 |
| **Claude Code** | (deferred) | `CLAUDE.md` | Mechanical port from `adapters/agents-md/`. | M8 |
| **Windsurf** | (deferred) | `.windsurfrules` | Mechanical port from `adapters/agents-md/`. | M8 |

The single installer `adapters/install.sh` (Phase 3) auto-detects IDE markers (`.cursor/`, `.github/`, `AGENTS.md`) and lowers the canonical YAML into the right per-IDE format. Re-running `install.sh` is idempotent — byte-identical output for the same registry state.

### Cursor — install

```bash
# from your consumer project root
git clone https://github.com/arvindiyu/SecureAICodeLibrary .secure-ai-code-library
.secure-ai-code-library/adapters/install.sh --ide cursor --version v1.0.0
# Creates / updates: .cursor/rules/*.mdc and .cursor/skills/*/SKILL.md
```

Behaviour:
- `.cursor/rules/<rule-id>.mdc` — frontmatter (`alwaysApply: false` for non-Tier-0; `globs:` set) + `summary` inline. Full `content` resolved by Cursor's `@rule:<id>` mention when scope matches.
- `.cursor/skills/<subagent-id>/SKILL.md` — lowered subagent contract; Cursor's skill system reads this.
- Tier 0 rules (~5) ship with `alwaysApply: true`; everything else is scoped via `globs:`.

### GitHub Copilot — install

```bash
.secure-ai-code-library/adapters/install.sh --ide copilot --version v1.0.0
# Creates / updates: .github/copilot-instructions.md only.
# Does NOT touch your existing .github/copilot/*.md files.
```

Behaviour:
- `.github/copilot-instructions.md` is a ≤2K-token INDEX file. It points at `registry/INDEX.md` and the existing per-category instruction files under `.github/copilot/`.
- No inline rule bodies — Copilot loads rule content via the registry on demand.

### AGENTS.md — install

```bash
.secure-ai-code-library/adapters/install.sh --ide agents-md --version v1.0.0
# Creates / updates: AGENTS.md at your consumer repo root.
```

Behaviour:
- `AGENTS.md` carries glob-scoped sections — one section per rule scope (or rule group). Summary inline; full content referenced by relative link.
- Compatible with any agent that respects the [AGENTS.md convention](https://agents.md/).

### Auto-detect mode

```bash
.secure-ai-code-library/adapters/install.sh --auto --version v1.0.0
```

Behaviour:
- Detects `.cursor/`, `.github/`, `AGENTS.md` markers; lowers to every detected target.
- Safe to run on a project that uses multiple IDEs (Cursor + Copilot side-by-side).

### Pinning

Pass `--version <tag>` to pin to a release tag. Without `--version`, the installer pins to the current `main` (not recommended for production projects).

---

## Pre-commit hook wiring patterns

The library ships a **single hook script** `hooks/pre-commit.sh` (Phase 4). It runs in both pre-commit and CI contexts; it detects context via the `CI` environment variable. Three wiring patterns are supported:

### Pattern 1 — Raw `.git/hooks`

The simplest pattern. Symlink the library hook into the consumer repo's `.git/hooks/pre-commit`:

```bash
# from consumer project root
ln -s ../../.secure-ai-code-library/hooks/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Pros: zero extra dependencies. Cons: not version-controlled with the project; new clones must repeat the symlink.

### Pattern 2 — Husky

For projects already using [Husky](https://github.com/typicode/husky):

```bash
# in package.json
{
  "scripts": {
    "prepare": "husky install"
  }
}
```

```bash
# .husky/pre-commit
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"
exec ./.secure-ai-code-library/hooks/pre-commit.sh
```

Pros: version-controlled. Cons: requires npm / Node toolchain.

### Pattern 3 — `pre-commit` framework

For projects using the [pre-commit](https://pre-commit.com) framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secureaicodelibrary
        name: Secure AI Code Library — pre-commit
        entry: ./.secure-ai-code-library/hooks/pre-commit.sh
        language: system
        pass_filenames: false
        stages: [pre-commit]
```

Pros: works with the wider pre-commit ecosystem. Cons: requires pre-commit framework installation.

---

## Required dependencies for the hook

`hooks/pre-commit.sh` (Phase 4) requires the following on `PATH`:

| Tool | Why | Where |
|---|---|---|
| `git` | Diff and trailer parsing | Universal. |
| `rg` (ripgrep) | Fast rule-pattern matching | <https://github.com/BurntSushi/ripgrep> |
| `yq` | YAML parsing for rule files and config | <https://github.com/mikefarah/yq> |
| `jq` | JSON parsing for Manthan responses, schema validation | Universal package managers. |
| `curl` | Manthan endpoint calls | Universal. |
| `sha256sum` or `shasum -a 256` | Audit-log `inputs_hash` | Universal. |

Optional:

| Tool | Why |
|---|---|
| `tiktoken` (Python) | CI token-budget lint; not required at commit-time. |
| `syft` | CI SBOM regen; not required at commit-time. |
| `check-jsonschema` (Python) | CI schema validation. |

### Optional Ollama / vLLM endpoint for prose remediation

The hook respects an optional `SECUREAI_LLM_ENDPOINT` environment variable, set by the consumer:

```bash
# in ~/.zshrc or project .env
export SECUREAI_LLM_ENDPOINT="http://localhost:11434/v1/chat/completions"
```

Default behaviour without this variable: Tier C runners are fully deterministic, no LLM calls, no network beyond the Manthan loopback. With the variable set: the gate decision remains deterministic (rule-pattern matches in the runner), but **prose remediation explanations** are queried from the local LLM endpoint. This keeps zero cost the default while enabling richer feedback for teams that opt in.

The endpoint MUST be local (loopback or VPN) — do not point this at a public cloud endpoint without explicit consumer review. Documented in `hooks/config.yaml`:

```yaml
headless_llm_endpoint: null   # default; opt-in by uncommenting:
# headless_llm_endpoint: http://localhost:11434/v1/chat/completions
```

---

## Manthan integration

The pre-commit hook makes a `POST /v1/events/commit` call to a local Manthan instance by default. Configure the endpoint in `hooks/config.yaml`:

```yaml
manthan_endpoint: http://localhost:8080   # default
severity_threshold: high                  # critical | high | medium | low
freshness_window_commits: 5
```

If Manthan is unreachable, the hook fails closed with a clear message:

```
ERROR: Manthan endpoint http://localhost:8080/healthz unreachable (connect-timeout 3s).
       Set manthan_endpoint: null in hooks/config.yaml to disable the scan-gate locally.
```

Manthan is **not bundled** by this library; install it separately from <https://github.com/arvindiyu/manthan>. Endpoint contracts are documented in [`docs/MANTHAN-CONTRACT.md`](./MANTHAN-CONTRACT.md).

---

## Uninstall

### Cursor

```bash
rm -rf .cursor/rules/*.mdc .cursor/skills/<subagent-id>
# Or, to remove only library-installed entries:
.secure-ai-code-library/adapters/install.sh --ide cursor --uninstall
```

### Copilot

```bash
rm .github/copilot-instructions.md
# Preserves your existing .github/copilot/*.md files.
```

### AGENTS.md

```bash
# Strip library-managed sections from AGENTS.md
.secure-ai-code-library/adapters/install.sh --ide agents-md --uninstall
```

### Pre-commit

Depending on wiring pattern:
- Pattern 1: `rm .git/hooks/pre-commit`
- Pattern 2: edit `.husky/pre-commit` to remove the exec line.
- Pattern 3: remove the `secureaicodelibrary` entry from `.pre-commit-config.yaml`.

---

## CI wiring

For the equivalent server-side gate, see [`docs/MANTHAN-CONTRACT.md`](./MANTHAN-CONTRACT.md) and Phase 6's `merge-gate.yml`. The same `hooks/pre-commit.sh` runs server-side with `CI=1` set.

Recommended consumer workflow snippet (Phase 6 publishes the full workflow):

```yaml
# .github/workflows/secureai-merge-gate.yml
name: Secure AI Code Library — merge gate
on:
  pull_request:
    branches: [main]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run pre-commit hook in CI mode
        env:
          CI: "1"
        run: ./.secure-ai-code-library/hooks/pre-commit.sh
```

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| Pre-commit hook times out | Manthan endpoint unreachable | Run `curl -sf http://localhost:8080/healthz`; start Manthan or set `manthan_endpoint: null` in `hooks/config.yaml`. |
| `ai-attribution-check` blocks every commit | All commits flagged as AI-assisted but no Co-Authored-By trailer | Add the trailer to your commits, or configure your IDE's commit template; do NOT lower `severity_threshold`. |
| `summary > 300 chars` CI error on a new rule | Layer 1 budget exceeded | Trim `summary`; move detail to `content`. |
| Cursor doesn't pick up the new rules | Adapter not re-run after registry update | `adapters/install.sh --ide cursor` again; reload Cursor. |
| Copilot instructions truncated | Top-level INDEX exceeded ≤2K tokens | Check `registry/INDEX.md` size; trim `summary`s. |
