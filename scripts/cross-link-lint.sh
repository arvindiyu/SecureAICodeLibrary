#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"

usage() {
  cat <<'EOF'
Usage: scripts/cross-link-lint.sh [--help] [--version]

Validate intra-repository references:
  subagent references.rules[]
  rule/spec extends:
  framework applicable_rules[]
  markdown [text](path) links
EOF
}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --version) printf '%s\n' "${VERSION}"; exit 0 ;;
  "") ;;
  *) printf 'cross-link-lint.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'cross-link-lint.sh: required tool not found: %s\n' "$1" >&2
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

if importlib.util.find_spec("yaml") is None:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "PyYAML"])
PY

cd "${REPO_ROOT}"

"${VENV_DIR}/bin/python" - <<'PY'
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import unquote

import yaml

ROOT = Path.cwd()
failures = []

rule_ids = {}
for path in sorted(ROOT.glob("registry/rules/**/*.rule.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = data.get("metadata") or {}
    rule_id = metadata.get("id") or path.name.removesuffix(".rule.yaml")
    rule_ids[rule_id] = path.relative_to(ROOT).as_posix()

def fail(path, ref, reason):
    failures.append(f"{path}:{ref}:{reason}")

for path in sorted(ROOT.glob("registry/subagents/*/subagent.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    refs = ((data.get("references") or {}).get("rules") or [])
    for ref in refs:
        if ref not in rule_ids:
            fail(path.relative_to(ROOT).as_posix(), ref, "unknown rule id in references.rules[]")

for path in sorted(ROOT.glob("registry/rules/**/*.rule.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    parent = data.get("extends")
    if parent and parent not in rule_ids:
        fail(path.relative_to(ROOT).as_posix(), parent, "unknown parent rule id in extends")

for path in sorted(ROOT.glob("registry/framework-specs/*.spec.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    parent = data.get("extends")
    if parent and parent not in rule_ids:
        fail(path.relative_to(ROOT).as_posix(), parent, "unknown parent rule id in extends")
    for ref in data.get("applicable_rules") or []:
        if ref not in rule_ids:
            fail(path.relative_to(ROOT).as_posix(), ref, "unknown rule id in applicable_rules[]")

link_re = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
fence_re = re.compile(r"```.*?```", re.DOTALL)

def should_skip(target):
    if not target:
        return True
    if target.startswith(("#", "http://", "https://", "mailto:", "tel:")):
        return True
    return False

def resolve_link(source, target):
    target = target.strip()
    if " " in target:
        target = target.split()[0]
    target = target.split("#", 1)[0].split("?", 1)[0]
    target = unquote(target)
    if should_skip(target):
        return None
    if target.startswith("/"):
        return ROOT / target.lstrip("/")
    return (source.parent / target).resolve()

for path in sorted(ROOT.glob("**/*.md")):
    if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
        continue
    text = fence_re.sub("", path.read_text(encoding="utf-8", errors="ignore"))
    rel = path.relative_to(ROOT).as_posix()
    for match in link_re.finditer(text):
        raw = match.group(1)
        resolved = resolve_link(path, raw)
        if resolved is None:
            continue
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            fail(rel, raw, "markdown link escapes repository")
            continue
        if not resolved.exists():
            fail(rel, raw, "dead intra-repo markdown link")

if failures:
    for item in failures:
        print(item, file=sys.stderr)
    print(f"Cross-link lint failed: {len(failures)} dead reference(s).", file=sys.stderr)
    sys.exit(1)

print(f"Cross-link lint passed: {len(rule_ids)} rule id(s) indexed.")
PY
