#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/lint-js-size.sh [--help] [--version]

Check total local js/**/*.js plus estimated lazy-loaded vendor JS from
index.html CDN script tags. Limits:
  unminified/raw <= 200KB
  gzipped/estimated gzip <= 80KB
EOF
}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --version) printf '%s\n' "${VERSION}"; exit 0 ;;
  "") ;;
  *) printf 'lint-js-size.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'lint-js-size.sh: required tool not found: %s\n' "$1" >&2
    exit 1
  }
}

require_tool python3

cd "${REPO_ROOT}"

python3 - <<'PY'
from pathlib import Path
import gzip
import re
import sys

ROOT = Path.cwd()
RAW_LIMIT = 200 * 1024
GZIP_LIMIT = 80 * 1024

def estimate_vendor(url):
    lower = url.lower()
    # Conservative signatures for the intended lazy-loaded libraries.
    if "mermaid" in lower:
        return 120 * 1024, 42 * 1024
    if "js-yaml" in lower or "jsyaml" in lower:
        return 45 * 1024, 14 * 1024
    if "prism" in lower:
        return 55 * 1024, 18 * 1024
    if "lunr" in lower:
        return 70 * 1024, 24 * 1024
    return 50 * 1024, 18 * 1024

entries = []
raw_total = 0
gzip_total = 0

for path in sorted((ROOT / "js").glob("**/*.js")) if (ROOT / "js").exists() else []:
    data = path.read_bytes()
    gz = gzip.compress(data, compresslevel=9)
    raw_total += len(data)
    gzip_total += len(gz)
    entries.append((path.relative_to(ROOT).as_posix(), len(data), len(gz), "local"))

index = ROOT / "index.html"
if index.exists():
    html = index.read_text(encoding="utf-8", errors="ignore")
    for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE):
        if not src.startswith(("http://", "https://", "//")):
            continue
        raw, gz = estimate_vendor(src)
        raw_total += raw
        gzip_total += gz
        entries.append((src, raw, gz, "vendor-estimate"))

print("Asset                                    Raw KB  Gzip KB  Type")
print("---------------------------------------  ------  -------  ---------------")
for name, raw, gz, kind in entries:
    short = name if len(name) <= 39 else "..." + name[-36:]
    print(f"{short:<39}  {raw / 1024:6.1f}  {gz / 1024:7.1f}  {kind}")
print("---------------------------------------  ------  -------  ---------------")
print(f"{'TOTAL':<39}  {raw_total / 1024:6.1f}  {gzip_total / 1024:7.1f}")

failed = False
if raw_total > RAW_LIMIT:
    print(f"BLOCK: JS raw budget exceeded: {raw_total} > {RAW_LIMIT} bytes", file=sys.stderr)
    failed = True
if gzip_total > GZIP_LIMIT:
    print(f"BLOCK: JS gzip budget exceeded: {gzip_total} > {GZIP_LIMIT} bytes", file=sys.stderr)
    failed = True

sys.exit(1 if failed else 0)
PY
