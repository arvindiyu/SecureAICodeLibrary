# AGENTS.md Adapter

Generates a consumer repository `AGENTS.md` file from the canonical registry.

## Install

```bash
adapters/agents-md/build.sh --consumer-repo /path/to/consumer-repo
```

Or use the unified installer:

```bash
adapters/install.sh --target agents-md --consumer-repo /path/to/consumer-repo
```

If the library is vendored somewhere other than `.secure-ai-code-library`, pass the repo-relative path for the generated footer:

```bash
adapters/agents-md/build.sh \
  --consumer-repo /path/to/consumer-repo \
  --library-path-in-consumer vendor/SecureAICodeLibrary
```

## Generated Output

```text
AGENTS.md
```

The file contains:

- Header: `This project is governed by Secure AI Code Library v<version>.`
- Tier 0 always-on rule summaries.
- An activation map table: rule id, glob patterns, severity, and whether the rule is blocking.
- A subagent invocation section with Tier A native patterns from `registry/subagents/<id>/subagent.yaml`.
- Footer pointing to `<repo-relative path>/CONSTITUTION.md`.

Until Wave 3b adds `registry/subagents/<id>/subagent.yaml`, the generated subagent section says `## Subagents: (none registered yet)`.

## Safety Modes

```bash
adapters/agents-md/build.sh --consumer-repo /path/to/repo --dry-run
adapters/agents-md/build.sh --consumer-repo /path/to/repo --check
```

`--dry-run` prints what would be written. `--check` exits non-zero if the consumer `AGENTS.md` is missing or stale. Existing files whose first line is `# DO NOT REGENERATE` are never overwritten.
