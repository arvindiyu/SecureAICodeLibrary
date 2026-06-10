# GitHub Copilot Adapter

Generates a single `.github/copilot-instructions.md` file for a consumer repository.

This adapter intentionally does **not** mirror every full rule. Copilot has tight always-on context budgets, so the generated file is a compact index: mission statement, Tier 0 summaries, one-line entries for scoped rules, and pointers back to the registry for on-demand expansion.

## Install

```bash
adapters/copilot/build.sh --consumer-repo /path/to/consumer-repo
```

Or use the unified installer:

```bash
adapters/install.sh --target copilot --consumer-repo /path/to/consumer-repo
```

## Generated Output

```text
.github/
  copilot-instructions.md
```

The generated file includes:

- A one-paragraph mission statement.
- Tier 0 rule summaries for `no-hardcoded-secrets`, `prompt-injection-prevention`, `agentic-human-approval`, `ai-audit-logging`, and `mcp-server-safety`.
- One-line summaries of all other rules with repo-relative YAML paths.
- A footer telling Copilot to load full registry rules on demand.

The adapter enforces a simple token budget heuristic: the emitted file must be at most 8,000 characters, approximating 2,000 tokens at four characters per token.

## Safety Modes

```bash
adapters/copilot/build.sh --consumer-repo /path/to/repo --dry-run
adapters/copilot/build.sh --consumer-repo /path/to/repo --check
```

`--dry-run` prints what would be written. `--check` exits non-zero if `.github/copilot-instructions.md` is missing or stale. Existing files whose first line is `# DO NOT REGENERATE` are never overwritten.
