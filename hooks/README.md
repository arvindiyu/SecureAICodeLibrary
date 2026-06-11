# hooks/ — Secure AI Code Library scan gate

> Pre-commit hook, Manthan ASOC client, installer, and configuration for the
> Secure AI Code Library scan-before-merge gate.
> Full wiring reference: [`docs/INSTALL.md`](../docs/INSTALL.md) |
> Endpoint contract: [`docs/MANTHAN-CONTRACT.md`](../docs/MANTHAN-CONTRACT.md)

## Contents

| File | Purpose |
|---|---|
| **`pre-commit.sh`** | Main runner — invoked as a Git hook, in CI, or manually. Runs compliance checks, Tier C subagent runners, assembles SARIF, calls Manthan, applies severity gating. |
| **`config.yaml`** | Hook configuration — severity floor, freshness windows, Manthan endpoint, subagent list, LLM endpoint opt-in, audit-log path, reporting paths. All defaults documented inline. |
| **`install.sh`** | Consumer helper — wires `pre-commit.sh` into `.git/hooks/pre-commit` (symlink), supports uninstall, check, and pre-commit-framework snippet modes. |
| **`manthan-client.sh`** | Thin `curl` wrapper — POSTs findings to the Manthan ASOC gateway, parses the response, maps verdict to Manthan-compatible exit codes. |
| **`README.md`** | This file. |

---

## Quick start

```bash
# 1. Clone the library alongside your project
git clone https://github.com/arvindiyu/SecureAICodeLibrary .secure-ai-code-library

# 2. Wire the hook
.secure-ai-code-library/hooks/install.sh

# 3. (Optional) Set your Manthan endpoint in hooks/config.yaml
#    manthan:
#      endpoint: "http://localhost:8080"

# 4. Verify
.secure-ai-code-library/hooks/install.sh --check
```

---

## Installation snippets

### Pattern 1 — Raw `.git/hooks` (zero dependencies)

```bash
# From your consumer project root:
ln -s ../../.secure-ai-code-library/hooks/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Or use the bundled installer (handles backups and relative symlinks):

```bash
.secure-ai-code-library/hooks/install.sh --install
.secure-ai-code-library/hooks/install.sh --check     # verify
.secure-ai-code-library/hooks/install.sh --uninstall # remove
```

**Limitation:** the symlink lives only in your local `.git/`; new clones must repeat the step. For team-wide enforcement use Pattern 2 or 3.

---

### Pattern 2 — Husky (Node.js projects)

```bash
npm install --save-dev husky
npx husky install
```

```sh
# .husky/pre-commit
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"
exec ./.secure-ai-code-library/hooks/pre-commit.sh
```

```json
// package.json
{
  "scripts": {
    "prepare": "husky install"
  }
}
```

---

### Pattern 3 — pre-commit framework

```bash
pip install pre-commit
```

Append to `.pre-commit-config.yaml` (or generate the snippet via the installer):

```bash
.secure-ai-code-library/hooks/install.sh --use-pre-commit-framework >> .pre-commit-config.yaml
pre-commit install
```

The emitted snippet:

```yaml
repos:
  - repo: local
    hooks:
      - id: secureaicodelibrary
        name: Secure AI Code Library — scan gate
        entry: ./.secure-ai-code-library/hooks/pre-commit.sh
        language: system
        pass_filenames: false
        stages: [pre-commit]
```

---

### Pattern 4 — GitHub Actions

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
        with:
          fetch-depth: 0       # full history required for freshness checks

      - name: Install dependencies
        run: |
          sudo apt-get install -y ripgrep jq
          pip install yq       # mikefarah/yq (Python wrapper)
          # Or: wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64

      - name: Run Secure AI Code Library scan gate
        env:
          CI: "1"
          MANTHAN_API_KEY: ${{ secrets.MANTHAN_API_KEY }}
          # SECUREAI_LLM_ENDPOINT: ""   # leave unset for zero-cost deterministic mode
        run: ./.secure-ai-code-library/hooks/pre-commit.sh --base origin/main
```

The same `pre-commit.sh` runs server-side with `CI=1`; no separate merge-gate script needed.
Wave 6 publishes the full opinionated `merge-gate.yml` for this library's own CI.

---

### Pattern 5 — GitLab CI

```yaml
# .gitlab-ci.yml (add to your existing pipeline)
secureai-merge-gate:
  stage: test
  image: ubuntu:22.04
  before_script:
    - apt-get update -qq && apt-get install -y -qq ripgrep jq git curl
    - pip install yq
  script:
    - CI=1 ./.secure-ai-code-library/hooks/pre-commit.sh --base origin/main
  only:
    - merge_requests
```

For additional GitLab CI patterns (DAST integration, scheduled full scans),
see [`prompts/`](../prompts/) in the library.

---

## Configuration reference (`hooks/config.yaml`)

All keys have inline documentation in the file. Key knobs:

| Key | Default | Description |
|---|---|---|
| `severity.block_floor` | `high` | Minimum severity that causes exit 1. Valid: `critical\|high\|medium\|low\|info`. |
| `severity.ai_assisted_raise_band` | `1` | Raise every finding by N bands when AI attribution detected. |
| `freshness.window_commits` | `10` | Warn when required artifact not touched in this many commits. |
| `manthan.endpoint` | `""` | Manthan base URL. Empty = Manthan disabled. |
| `manthan.on_unreachable` | `warn` | `warn` continues; `block` exits 3. |
| `subagents.enabled` | list | Tier C runners to invoke. `mcp-builder` and `secure-developer-mentor` auto-skip. |
| `headless_llm.endpoint_env` | `SECUREAI_LLM_ENDPOINT` | Env var for optional local LLM prose remediation (Ollama etc.). |

---

## Exit codes

| Code | Condition |
|---|---|
| `0` | Pass / warnings only |
| `1` | Blocking findings (local gate or Manthan `decision: block`) |
| `2` | Manthan internal error (5xx or `decision: error`) |
| `3` | Manthan unreachable (network error; configurable `on_unreachable: warn\|block`) |
| `4` | Schema mismatch (invalid config or unexpected Manthan response shape) |
| `64` | Bad CLI arguments |
| `65` | `hooks/config.yaml` missing, invalid, or required tool missing from `PATH` |
| `78` | Pre-Manthan compliance failure (missing artifact, stale artifact, Tier 0 audit gap) |

Full binding specification: [`docs/MANTHAN-CONTRACT.md § Exit-code mapping`](../docs/MANTHAN-CONTRACT.md).

---

## Required tools

| Tool | Purpose | Install |
|---|---|---|
| `git` | Diff, log, staged-file list | Universal |
| `rg` (ripgrep) | Fast pattern matching in Tier C runners | `brew install ripgrep` / `apt install ripgrep` |
| `yq` (mikefarah v4+) | YAML parsing for config and subagent YAML | `brew install yq` / [releases](https://github.com/mikefarah/yq/releases) |
| `jq` (1.6+) | JSON processing, SARIF aggregation | `brew install jq` / `apt install jq` |
| `curl` | Manthan HTTP calls | Universal |
| `sha256sum` or `shasum -a 256` | Audit-log `inputs_hash` | Built-in on Linux and macOS |

**Optional:**

| Tool | Purpose |
|---|---|
| `SECUREAI_LLM_ENDPOINT` env var | Enable prose remediation via Ollama / vLLM (gate decision stays deterministic) |
| `tiktoken` (Python) | CI token-budget lint (not required at commit time) |
| `syft` | SBOM regen (`make sbom`; not required at commit time) |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Exit 78: CONSTITUTION.md missing` | Required governance artifact not yet created | Run `make all` or manually create `CONSTITUTION.md`, `SPEC.md`, `THREAT_MODEL.md`. |
| `Exit 78: N compliance check(s) failed` | Missing artifact or stale freshness | Review errors above. Touch the stale artifact (`git commit --allow-empty -m "chore: touch SPEC.md"` is not sufficient — the file must change). |
| `Exit 78: Tier 0 coverage FAIL` | `ai-governance-auditor` not in `subagents.enabled` or `run.sh` missing | Ensure `ai-governance-auditor` is enabled in `hooks/config.yaml` and `registry/subagents/ai-governance-auditor/run.sh` exists. |
| Hook times out | Manthan endpoint unreachable | `curl -sf http://localhost:8080/healthz` — start Manthan, or set `manthan.endpoint: ""` in `hooks/config.yaml` to disable. |
| `ai-attribution-check` blocks every commit | All commits have AI Co-Authored-By but no explicit gate exception | Add the Co-Authored-By trailer to commits (per `AGENTS.md` hard-rule #1). Do NOT lower `severity_threshold`. |
| `yq: command not found` | yq not installed | `brew install yq` (macOS) or download from [mikefarah/yq releases](https://github.com/mikefarah/yq/releases). |
| `jq: walk function not found` | jq < 1.6 | Upgrade jq: `brew upgrade jq` / `apt install jq` (Ubuntu 20.04+ ships 1.6). |
| Subagent runner skipped with warning | `run.sh` missing or not executable | Ensure Wave 3b delivered `registry/subagents/<id>/run.sh` and it is `chmod +x`. |
| SARIF output empty | All subagents skipped | Check that at least one subagent in `subagents.enabled` has an executable `run.sh`. |
| Manthan returns HTTP 400 | Payload schema mismatch | Check `docs/MANTHAN-CONTRACT.md` for the expected request shape; verify `jq` is 1.6+. |
| Audit log missing after run | `.securecode/` directory not writable | `chmod 755 .securecode` or create it: `mkdir -p .securecode`. |

---

## Manual invocation examples

```bash
# Pre-commit mode (staged files only):
./hooks/pre-commit.sh

# Full-repo scan (use in CI or before a major release):
./hooks/pre-commit.sh --all

# Scan specific files:
./hooks/pre-commit.sh --scope "src/api.ts src/db.ts"

# CI mode with explicit base ref:
CI=1 ./hooks/pre-commit.sh --base origin/main

# Dry-run the Manthan client only (no actual POST):
./hooks/manthan-client.sh --dry-run

# Check install.sh wiring:
./hooks/install.sh --check
```

---

## Uninstall

```bash
# Remove the .git/hooks/pre-commit symlink (restores backup if present):
.secure-ai-code-library/hooks/install.sh --uninstall
```

For Husky: remove the exec line from `.husky/pre-commit`.
For pre-commit framework: remove the `secureaicodelibrary` entry from `.pre-commit-config.yaml` and run `pre-commit uninstall`.

---

## References

- [`docs/INSTALL.md`](../docs/INSTALL.md) — full wiring matrix, dependency list, Ollama opt-in
- [`docs/MANTHAN-CONTRACT.md`](../docs/MANTHAN-CONTRACT.md) — endpoint specs, payload schemas, exit-code map, severity matrix, freshness definition
- [`docs/adr/0002-manthan-scan-gate-contract.md`](../docs/adr/0002-manthan-scan-gate-contract.md) — architectural rationale
- [`docs/adr/0003-severity-thresholds-policy.md`](../docs/adr/0003-severity-thresholds-policy.md) — severity matrix + AI-floor rationale
- [`AGENTS.md`](../AGENTS.md) — Tier 0 rules, audit-log field spec, hard rules
- Manthan upstream: <https://github.com/arvindiyu/manthan>
