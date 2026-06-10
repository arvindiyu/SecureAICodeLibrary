# Cursor Adapter

Generates Cursor-native rule files from `registry/rules/**/*.rule.yaml`.

## Install

From this library checkout:

```bash
adapters/cursor/build.sh --consumer-repo /path/to/consumer-repo
```

Or use the unified installer:

```bash
adapters/install.sh --target cursor --consumer-repo /path/to/consumer-repo
```

## Generated Layout

```text
.cursor/
  rules/
    <rule-id>.mdc
  commands/
    README.md
    <subagent-id>.md
```

Each `.mdc` file contains only Layer 1 rule guidance: the rule `summary` and a footer pointing back to the canonical YAML. Full `content` remains in `registry/rules/<category>/<id>.rule.yaml` for on-demand loading.

Tier 0 rules are always generated with `alwaysApply: true`:

- `no-hardcoded-secrets`
- `prompt-injection-prevention`
- `agentic-human-approval`
- `ai-audit-logging`
- `mcp-server-safety`

All other rules use `alwaysApply: false` and activate through their `scope.globs`.

Subagent command stubs are generated from `registry/subagents/<id>/subagent.yaml` when Wave 3b provides those files. Until then, `.cursor/commands/README.md` contains `## Subagents: (none registered yet)`.

## Safety Modes

```bash
adapters/cursor/build.sh --consumer-repo /path/to/repo --dry-run
adapters/cursor/build.sh --consumer-repo /path/to/repo --check
```

`--dry-run` prints the files that would be written. `--check` exits non-zero if generated files are missing or drift from the registry. Existing files whose first line is `# DO NOT REGENERATE` are never overwritten.
