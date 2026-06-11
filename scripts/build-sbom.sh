#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/build-sbom.sh [--help] [--version]

Regenerate sbom.cdx.json as CycloneDX 1.5.
Uses syft when available; otherwise emits a minimal deterministic SBOM.
EOF
}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --version) printf '%s\n' "${VERSION}"; exit 0 ;;
  "") ;;
  *) printf 'build-sbom.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'build-sbom.sh: required tool not found: %s\n' "$1" >&2
    exit 1
  }
}

require_tool python3

cd "${REPO_ROOT}"

if command -v syft >/dev/null 2>&1; then
  syft . -o cyclonedx-json=sbom.cdx.json
  exit 0
fi

python3 - <<'PY'
from pathlib import Path
import hashlib
import json
import re
import subprocess

ROOT = Path.cwd()

def git_value(*args, default="unknown"):
    try:
        return subprocess.check_output(["git", *args], text=True).strip() or default
    except Exception:
        return default

def bom_ref(kind, name, version=""):
    raw = f"{kind}:{name}:{version}"
    return "pkg:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

components = []

components.append({
    "type": "application",
    "name": "SecureAICodeLibrary",
    "version": git_value("describe", "--tags", "--always", default="0.0.0"),
    "bom-ref": "pkg:secureaicodelibrary",
    "purl": "pkg:generic/SecureAICodeLibrary",
})

for package_json in sorted(ROOT.glob("**/package.json")):
    if ".git" in package_json.parts or "node_modules" in package_json.parts:
        continue
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except Exception:
        continue
    deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps.update(data.get(key) or {})
    for name, version in sorted(deps.items()):
        components.append({
            "type": "library",
            "name": name,
            "version": str(version),
            "bom-ref": bom_ref("npm", name, str(version)),
            "purl": f"pkg:npm/{name}@{version}",
            "properties": [{"name": "source", "value": package_json.relative_to(ROOT).as_posix()}],
        })

req_re = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)?\s*([^#;\s]+)?")
for req in sorted(ROOT.glob("**/requirements*.txt")):
    if ".git" in req.parts or ".venv" in req.parts:
        continue
    for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = req_re.match(line)
        if not match:
            continue
        name, version = match.group(1), match.group(2) or ""
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "bom-ref": bom_ref("pypi", name, version),
            "purl": f"pkg:pypi/{name}" + (f"@{version}" if version else ""),
            "properties": [{"name": "source", "value": req.relative_to(ROOT).as_posix()}],
        })

components.sort(key=lambda item: (item.get("type", ""), item.get("name", ""), item.get("version", "")))

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{hashlib.sha256(git_value('rev-parse', 'HEAD').encode()).hexdigest()[:32]}",
    "version": 1,
    "metadata": {
        "timestamp": git_value("show", "-s", "--format=%cI", "HEAD", default="1970-01-01T00:00:00Z"),
        "tools": [{
            "vendor": "SecureAICodeLibrary",
            "name": "scripts/build-sbom.sh fallback",
            "version": "1.0.0",
        }],
        "component": {
            "type": "application",
            "name": "SecureAICodeLibrary",
            "version": git_value("describe", "--tags", "--always", default="0.0.0"),
            "bom-ref": "pkg:secureaicodelibrary",
        },
    },
    "components": components,
}

(ROOT / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"Wrote sbom.cdx.json with {len(components)} component(s) using fallback emitter.")
PY
