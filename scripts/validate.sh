#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"

usage() {
  cat <<'EOF'
Usage: scripts/validate.sh [--help] [--version]

Validate registry YAML files against JSON Schemas:
  registry/rules/**/*.rule.yaml
  registry/subagents/*/subagent.yaml
  registry/framework-specs/*.spec.yaml
EOF
}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --version) printf '%s\n' "${VERSION}"; exit 0 ;;
  "") ;;
  *) printf 'validate.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'validate.sh: required tool not found: %s\n' "$1" >&2
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

missing = [pkg for pkg in ("jsonschema", "yaml") if importlib.util.find_spec(pkg) is None]
if missing:
    subprocess.check_call([
        sys.executable,
        "-m",
        "pip",
        "install",
        "--quiet",
        "jsonschema",
        "PyYAML",
    ])
PY

cd "${REPO_ROOT}"

"${VENV_DIR}/bin/python" - <<'PY'
from pathlib import Path
import json
import sys

import yaml
from jsonschema import Draft202012Validator

ROOT = Path.cwd()
SCHEMA_MAP = [
    ("registry/schemas/rule.schema.json", sorted(ROOT.glob("registry/rules/**/*.rule.yaml"))),
    ("registry/schemas/subagent.schema.json", sorted(ROOT.glob("registry/subagents/*/subagent.yaml"))),
    ("registry/schemas/framework-spec.schema.json", sorted(ROOT.glob("registry/framework-specs/*.spec.yaml"))),
]

def field_path(error):
    if not error.absolute_path:
        return "$"
    return "$." + ".".join(str(part) for part in error.absolute_path)

failures = 0
validated = 0

for schema_rel, files in SCHEMA_MAP:
    schema_path = ROOT / schema_rel
    with schema_path.open("r", encoding="utf-8") as fh:
        schema = json.load(fh)
    validator = Draft202012Validator(schema)

    for path in files:
        validated += 1
        rel = path.relative_to(ROOT)
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception as exc:  # YAML parser error
            print(f"{rel}:$:invalid YAML: {exc}", file=sys.stderr)
            failures += 1
            continue

        for error in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path)):
            print(f"{rel}:{field_path(error)}:{error.message}", file=sys.stderr)
            failures += 1

if failures:
    print(f"Schema validation failed: {failures} error(s) across {validated} file(s).", file=sys.stderr)
    sys.exit(1)

print(f"Schema validation passed: {validated} file(s).")
PY
