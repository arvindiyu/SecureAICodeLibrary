#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"
MERMAID_ONLY="false"

usage() {
  cat <<'EOF'
Usage: scripts/source-hygiene-lint.sh [--mermaid-only] [--help] [--version]

Lint citation hygiene against docs/SOURCES.md and warn on Mermaid blocks
without accTitle/accDescr. Warnings exit 0; blocking hygiene failures exit 1.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mermaid-only) MERMAID_ONLY="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    --version) printf '%s\n' "${VERSION}"; exit 0 ;;
    *) printf 'source-hygiene-lint.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'source-hygiene-lint.sh: required tool not found: %s\n' "$1" >&2
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

"${VENV_DIR}/bin/python" - "${MERMAID_ONLY}" <<'PY'
from pathlib import Path
from urllib.parse import urlparse
import re
import sys

import yaml

ROOT = Path.cwd()
SOURCES = (ROOT / "docs/SOURCES.md").read_text(encoding="utf-8")
MERMAID_ONLY = sys.argv[1] == "true"

blocks = []
warnings = []

url_re = re.compile(r"https?://[^\s<>)\"']+")
allowed_urls = {u.rstrip(".,") for u in url_re.findall(SOURCES)}
allowed_hosts = {urlparse(u).netloc.lower() for u in allowed_urls}
allowed_domains_text = SOURCES.lower()

named_patterns = [
    # OWASP ASVS v5: accept both §1.1 and §V1.1 (Wave 2 rules use §V prefix)
    re.compile(r"^OWASP ASVS v5 §V?[0-9]+(\.[0-9]+)*(?:\s*\(.+\))?$"),
    re.compile(r"^OWASP Top 10 for LLM Applications \([0-9]{4}\) LLM[0-9]+"),
    re.compile(r"^ISO/IEC (27001:2022|42001:2023) A\.[0-9]+(\.[0-9]+)*$"),
    re.compile(r"^NIST (AI RMF (GOVERN|MAP|MEASURE|MANAGE)-[0-9]+(\.[0-9]+)*|AI 600-1 \([0-9]{4}\) §.+|SP 800-218 .+|CSF 2\.0 .+)$"),
    re.compile(r"^(CWE|CAPEC)-[0-9]+$"),
    re.compile(r"^AML\.T[0-9]+(\.[0-9]+)?$"),
    re.compile(r"^ATT&CK technique T[0-9]+.*$"),
    re.compile(r"^SLSA v1\.0 .+$"),
    re.compile(r"^CycloneDX 1\.5.*$"),
    re.compile(r"^SPDX [0-9]\.[0-9].*$"),
    # RFC: allow trailing parenthetical text (e.g. "RFC 8693 (OAuth 2.0 Token Exchange)")
    re.compile(r"^RFC [0-9]+.*$"),
    re.compile(r"^(EU AI Act Art\.|GDPR Art\.|HIPAA Privacy Rule §|PCI DSS v4 Req\.|SOX §).+$"),
    re.compile(r"^(Mandiant M-Trends|Verizon DBIR|CrowdStrike GTR|Microsoft DDR|ENISA Threat Landscape) [0-9]{4}.*$"),
    re.compile(r"^(Google TAG bulletin, [0-9]{4}-[0-9]{2}-[0-9]{2}|CISA AA[0-9]{2}-[0-9]{3}[A-Z]?).*$"),
    re.compile(r"^Anthropic Claude Mythos \(as of [0-9]{4}-[0-9]{2}-[0-9]{2}\)$"),
    # OpenSSF Scorecard checks (Wave 2: ai-code-provenance rule)
    re.compile(r"^OpenSSF Scorecard check: .+$"),
]

# Intra-repo path prefix: any source.primary that starts with a repo-relative path
# is an internal cross-reference, not an external citation; always allowed.
INTRA_REPO_PREFIXES = ("docs/", "registry/", "hooks/", "adapters/", "scripts/", "CONSTITUTION", "SPEC.md", "THREAT_MODEL")

# Files that are policy/meta documents discussing vendor names in a regulatory
# context — exempt from vendor-announcement proximity check to avoid false positives.
VENDOR_CHECK_EXEMPT = {
    "docs/SOURCES.md",
    "docs/adr/0004-claim-hygiene-and-sourcing.md",
    "docs/adr/0001-registry-and-adapter-architecture.md",
    # THREAT_MODEL.md discusses Glasswing in threat-context by definition (it IS the threat model)
    "THREAT_MODEL.md",
}

# Hosts that appear only in code-example, configuration-example, or
# development-endpoint contexts; never used as actual citations.
EXAMPLE_HOSTS = {
    "example.com", "subdomain.example.com", "www.example.com",
    "yourdomain.com", "your-app.com",
    "trusted-cdn.com",
    "secure.example.com",
    "api.yourdomain.com",
    "localhost",
    "elasticsearch",
    "elasticsearch:9200",
}

def warn(path, message):
    warnings.append(f"{path}:{message}")

def block(path, message):
    blocks.append(f"{path}:{message}")

def allowed_url(url):
    clean = url.rstrip(".,;`")
    parsed = urlparse(clean)
    host = parsed.netloc.lower()
    # Skip example/placeholder/development hosts entirely
    if host in EXAMPLE_HOSTS or host.endswith(".example.com"):
        return True
    # Skip localhost and private-network addresses (port variants like localhost:8080 included)
    bare_host = host.split(":")[0]
    if bare_host in ("localhost", "127.0.0.1", "0.0.0.0") or bare_host.startswith("192.168.") or bare_host.startswith("10."):
        return True
    if clean in allowed_urls:
        return True
    if any(clean.startswith(base.rstrip("/")) for base in allowed_urls):
        return True
    if host and host in allowed_hosts:
        return True
    return host and host in allowed_domains_text

def allowed_named(source):
    value = " ".join(str(source or "").split())
    if not value:
        return True
    # Intra-repo cross-reference (not an external citation)
    if any(value.startswith(prefix) for prefix in INTRA_REPO_PREFIXES):
        return True
    if value.startswith("http://") or value.startswith("https://"):
        return allowed_url(value)
    # Handle "Label — https://..." format (e.g. "MCP specification docs — https://...")
    if " — https://" in value or " - https://" in value:
        url_part = value.split("https://", 1)[1]
        return allowed_url("https://" + url_part)
    if any(pattern.match(value) for pattern in named_patterns):
        return True
    return value.lower() in SOURCES.lower()

def lint_mermaid(path, text):
    rel = path.relative_to(ROOT).as_posix()
    for idx, match in enumerate(re.finditer(r"```mermaid\n(.*?)```", text, flags=re.DOTALL), start=1):
        body = match.group(1)
        if "accTitle:" not in body or "accDescr:" not in body:
            warn(rel, f"mermaid block {idx} lacks accTitle or accDescr")

for path in sorted(ROOT.glob("**/*.md")):
    if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    lint_mermaid(path, text)

if MERMAID_ONLY:
    for item in warnings:
        print(f"WARN: {item}")
    print(f"Mermaid accessibility warnings: {len(warnings)}")
    sys.exit(0)

# Regex to strip fenced code blocks before URL checking; prevents example URLs
# embedded in code samples from being flagged as citation requirements.
all_fence_re = re.compile(r"```.*?```", re.DOTALL)

for path in sorted(ROOT.glob("**/*.md")):
    if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
        continue
    rel = path.relative_to(ROOT).as_posix()
    text = path.read_text(encoding="utf-8", errors="ignore")
    # Strip code fences for URL and prose checks; keeps narrative citations only.
    text_no_code = all_fence_re.sub("", text)

    for url in url_re.findall(text_no_code):
        clean = url.rstrip(".,;`")
        if not allowed_url(clean):
            block(rel, f"URL not in docs/SOURCES.md allowlist: {clean}")

    for para in re.split(r"\n\s*\n", text_no_code):
        # Skip markdown tables (policy/SLA tables are not threat statistics)
        stripped = para.strip()
        if stripped.startswith("|"):
            continue
        lower = para.lower()
        threatish = re.search(r"\b(vulnerability|vulnerabilities|cve|breach|attack|incident)\b", lower)
        statistic = re.search(r"\b\d{1,3}%\b|\b\d+\s+(days?|hours?|incidents?|breaches?|cves?)\b", lower)
        dated = re.search(r"\([0-9]{4}\)|as of [0-9]{4}-[0-9]{2}-[0-9]{2}|[A-Za-z][A-Za-z -]+,\s*[0-9]{4}", para)
        if threatish and statistic and not dated:
            excerpt = " ".join(para.split())[:160]
            block(rel, f"threat statistic lacks dated citation: {excerpt}")

    if rel in VENDOR_CHECK_EXEMPT:
        continue
    for vendor in re.finditer(r"Claude Mythos|GPT-5 release|Project Glasswing|OpenAI capability tier", text_no_code, flags=re.IGNORECASE):
        start = max(0, vendor.start() - 200)
        end = min(len(text_no_code), vendor.end() + 200)
        window = text_no_code[start:end].lower()
        if re.search(r"\b(vulnerability|cve|breach|attack|incident)\b", window):
            block(rel, "vendor announcement appears near threat-statistic keyword")

for path in sorted(ROOT.glob("registry/rules/**/*.rule.yaml")):
    rel = path.relative_to(ROOT).as_posix()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    primary = ((data.get("sources") or {}).get("primary") or [])
    for source in primary:
        if not allowed_named(source):
            block(rel, f"sources.primary entry not in docs/SOURCES.md allowlist: {source}")

for item in warnings:
    print(f"WARN: {item}")

if blocks:
    for item in blocks:
        print(f"BLOCK: {item}", file=sys.stderr)
    print(f"Source hygiene failed: {len(blocks)} block(s), {len(warnings)} warning(s).", file=sys.stderr)
    sys.exit(1)

print(f"Source hygiene passed: {len(warnings)} warning(s).")
PY
