#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"

usage() {
  cat <<'EOF'
Usage: scripts/build-search-index.sh [--help] [--version]

Emit js/search-index.json for Lunr.js. Includes rules, subagents,
framework specs, and top-level governance docs.
EOF
}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --version) printf '%s\n' "${VERSION}"; exit 0 ;;
  "") ;;
  *) printf 'build-search-index.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'build-search-index.sh: required tool not found: %s\n' "$1" >&2
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
from pathlib import Path
import json
import re

import yaml

ROOT = Path.cwd()
OUT = ROOT / "js/search-index.json"
DOCS = [
    "CONSTITUTION.md",
    "SPEC.md",
    "THREAT_MODEL.md",
    "AGENTS.md",
    "docs/AI-CONTROL-MAP.md",
    "docs/MYTHOS.md",
    "docs/MANTHAN-CONTRACT.md",
    "docs/SUBAGENT-FLOWS.md",
    "docs/TOKEN-ECONOMICS.md",
]

def compact(text, limit=300):
    value = " ".join(str(text or "").split())
    return value[:limit]

def first_heading(text):
    for line in text.splitlines():
        match = re.match(r"^#\s+(.+)", line)
        if match:
            return match.group(1).strip()
    return ""

items = []

for path in sorted(ROOT.glob("registry/rules/**/*.rule.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = data.get("metadata") or {}
    items.append({
        "id": metadata.get("id") or path.name.removesuffix(".rule.yaml"),
        "name": metadata.get("name") or metadata.get("id") or path.stem,
        "summary": data.get("summary", ""),
        "description": metadata.get("description", ""),
        "tags": metadata.get("tags", []),
        "globs": (data.get("scope") or {}).get("globs", []),
        "path": path.relative_to(ROOT).as_posix(),
        "category": data.get("category") or "rules",
        "body_preview": compact(path.read_text(encoding="utf-8"), 300),
    })

for path in sorted(ROOT.glob("registry/subagents/*/subagent.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = data.get("metadata") or {}
    items.append({
        "id": metadata.get("id") or path.parent.name,
        "name": metadata.get("name") or path.parent.name,
        "summary": metadata.get("description", ""),
        "description": metadata.get("description", ""),
        "tags": ["subagent"],
        "globs": [],
        "path": path.relative_to(ROOT).as_posix(),
        "category": "subagents",
        "body_preview": compact(path.read_text(encoding="utf-8"), 300),
    })

for path in sorted(ROOT.glob("registry/framework-specs/*.spec.yaml")):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = data.get("metadata") or {}
    items.append({
        "id": metadata.get("id") or path.name.removesuffix(".spec.yaml"),
        "name": metadata.get("name") or metadata.get("id") or path.stem,
        "summary": data.get("summary", ""),
        "description": metadata.get("description", ""),
        "tags": metadata.get("tags", []),
        "globs": data.get("globs", []),
        "path": path.relative_to(ROOT).as_posix(),
        "category": "framework-specs",
        "body_preview": compact(path.read_text(encoding="utf-8"), 300),
    })

for rel in DOCS:
    path = ROOT / rel
    if not path.exists():
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    doc_id = rel.removesuffix(".md").replace("/", "-").lower()
    items.append({
        "id": doc_id,
        "name": first_heading(text) or rel,
        "summary": compact(text, 180),
        "description": compact(text, 180),
        "tags": ["doc"],
        "globs": [],
        "path": rel,
        "category": "docs",
        "body_preview": compact(text, 300),
    })

items.sort(key=lambda item: (item["category"], item["id"]))
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(items, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"Wrote {OUT.relative_to(ROOT)} with {len(items)} item(s).")
PY
