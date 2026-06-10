#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"

usage() {
  cat <<'EOF'
Usage: scripts/token-budget-lint.sh [--help] [--version]

Enforce rule summary and subagent system-prompt token budgets.
Warnings exit 0; blocking violations exit 1.
EOF
}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --version) printf '%s\n' "${VERSION}"; exit 0 ;;
  "") ;;
  *) printf 'token-budget-lint.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'token-budget-lint.sh: required tool not found: %s\n' "$1" >&2
    exit 1
  }
}

require_tool python3

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  python3 -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/python" - <<'PY'
import importlib.util
import subprocess
import sys

missing = []
if importlib.util.find_spec("yaml") is None:
    missing.append("PyYAML")
if importlib.util.find_spec("tiktoken") is None:
    missing.append("tiktoken")
if missing:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", *missing])
    except Exception:
        # tiktoken is optional at runtime; the linter falls back to 4 chars/token.
        if "PyYAML" in missing and importlib.util.find_spec("yaml") is None:
            raise
PY

cd "${REPO_ROOT}"

"${VENV_DIR}/bin/python" - <<'PY'
from pathlib import Path
import sys

import yaml

ROOT = Path.cwd()

try:
    import tiktoken
    ENCODING = tiktoken.get_encoding("cl100k_base")
except Exception:
    ENCODING = None

def token_count(text):
    text = str(text or "")
    if ENCODING is not None:
        return len(ENCODING.encode(text))
    return (len(text) + 3) // 4

rows = []
blocks = 0
warnings = 0

for path in sorted(ROOT.glob("registry/rules/**/*.rule.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = data.get("metadata") or {}
    summary = data.get("summary", "")
    chars = len(summary)
    status = "PASS"
    if chars > 300:
        status = "BLOCK"
        blocks += 1
    rows.append([
        "rule",
        metadata.get("id") or path.name.removesuffix(".rule.yaml"),
        str(chars),
        "300 chars",
        status,
        path.relative_to(ROOT).as_posix(),
    ])

for path in sorted(ROOT.glob("registry/subagents/*/subagent.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = data.get("metadata") or {}
    budget = data.get("token_budget") or {}
    budget_limit = int(budget.get("system_prompt") or budget.get("input_max") or 0)
    warn_at = float(budget.get("warn_at") or 0.8)
    prompt_path = path.parent / "prompts/system.md"
    prompt = prompt_path.read_text(encoding="utf-8", errors="ignore") if prompt_path.exists() else ""
    count = token_count(prompt)
    status = "PASS"
    if budget_limit and count >= budget_limit:
        status = "BLOCK"
        blocks += 1
    elif budget_limit and count >= int(budget_limit * warn_at):
        status = "WARN"
        warnings += 1
    rows.append([
        "subagent",
        metadata.get("id") or path.parent.name,
        str(count),
        f"{budget_limit} tokens",
        status,
        prompt_path.relative_to(ROOT).as_posix() if prompt_path.exists() else path.relative_to(ROOT).as_posix(),
    ])

widths = [max(len(row[i]) for row in ([["TYPE", "ID", "USED", "BUDGET", "STATUS", "PATH"]] + rows)) for i in range(6)]
fmt = "  ".join("{:<" + str(width) + "}" for width in widths)
print(fmt.format("TYPE", "ID", "USED", "BUDGET", "STATUS", "PATH"))
print(fmt.format(*["-" * width for width in widths]))
for row in rows:
    print(fmt.format(*row))

if ENCODING is None:
    print("WARN: tiktoken unavailable; used 4-chars-per-token heuristic.", file=sys.stderr)

if blocks:
    print(f"Token budget lint failed: {blocks} block(s), {warnings} warning(s).", file=sys.stderr)
    sys.exit(1)

print(f"Token budget lint passed: {warnings} warning(s).")
PY
