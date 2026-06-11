#!/usr/bin/env bash
# shellcheck shell=bash
# hooks/manthan-client.sh — Thin curl wrapper for the Manthan ASOC gateway
#
# Reads hooks/config.yaml for defaults (endpoint, API key, timeouts).
# All config values are overridable via CLI flags.
# Called by pre-commit.sh for the scan-gate; also usable standalone.
#
# USAGE
#   hooks/manthan-client.sh [options]
#
# OPTIONS
#   --sarif <path>       SARIF findings file to POST (default: from config)
#   --endpoint <url>     Override manthan.endpoint from config
#   --timeout <secs>     Override manthan.timeout_seconds from config
#   --config <path>      Alternate hooks/config.yaml path (default: auto-detect)
#   --dry-run            Print payload and exit; do NOT send any HTTP request
#   --help               Print this message and exit
#
# OUTPUT
#   stdout: Manthan response JSON on success (exit 0 or 1)
#   stderr: all diagnostic / error messages (always visible)
#
# EXIT CODES  (binding — docs/MANTHAN-CONTRACT.md § Exit-code mapping)
#   0   decision: pass or decision: warn (no blocking findings)
#   1   decision: block (blocking findings detected by Manthan)
#   2   Manthan internal error (5xx HTTP status or decision: error)
#   3   Manthan unreachable (network error, connection refused, /healthz non-200)
#   4   schema mismatch (unexpected response shape or invalid SARIF input)
#
# DEPENDENCIES
#   Required: jq (1.6+), curl, yq (mikefarah/yq v4+), git
#   sha256sum (Linux) or shasum -a 256 (macOS)
#
# DOCS
#   docs/MANTHAN-CONTRACT.md — endpoint contracts, payload schema, exit-code map

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# ---------------------------------------------------------------------------
# Logging (all to stderr so stdout stays clean for JSON output)
# ---------------------------------------------------------------------------
_mlog() { printf '[manthan-client] %-6s %s\n' "$1" "$2" >&2; }
info()  { _mlog "INFO"  "$*"; }
warn()  { _mlog "WARN"  "$*"; }
error() { _mlog "ERROR" "$*"; }

die() {
  local code="$1"; shift
  error "$*"
  exit "${code}"
}

# Cross-platform SHA-256
sha256_of() {
  if command -v sha256sum &>/dev/null; then
    printf '%s' "$*" | sha256sum | awk '{print $1}'
  else
    printf '%s' "$*" | shasum -a 256 | awk '{print $1}'
  fi
}

now_iso8601() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# ---------------------------------------------------------------------------
# Parse CLI arguments
# ---------------------------------------------------------------------------
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
SARIF_OVERRIDE=""
ENDPOINT_OVERRIDE=""
TIMEOUT_OVERRIDE=""
DRY_RUN="false"

usage() {
  cat >&2 <<'EOF'
hooks/manthan-client.sh — Manthan ASOC gateway client

USAGE
  hooks/manthan-client.sh [--sarif <path>] [--endpoint <url>] [--dry-run]

OPTIONS
  --sarif <path>       SARIF findings file to POST (default: from config)
  --endpoint <url>     Override manthan.endpoint in hooks/config.yaml
  --timeout <secs>     Override manthan.timeout_seconds in hooks/config.yaml
  --config <path>      Alternate config file (default: auto-detect hooks/config.yaml)
  --dry-run            Print what would be sent; do not POST
  --help               Print this message

EXIT CODES
  0   pass / warn (no blocking findings)
  1   block (Manthan found blocking findings)
  2   Manthan internal error (5xx or decision:error)
  3   Manthan unreachable (network error or /healthz non-200)
  4   Schema mismatch (unexpected response shape)

DOCS
  docs/MANTHAN-CONTRACT.md
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sarif)
      [[ $# -ge 2 ]] || die 4 "--sarif requires a path argument."
      SARIF_OVERRIDE="$2"
      shift 2
      ;;
    --endpoint)
      [[ $# -ge 2 ]] || die 4 "--endpoint requires a URL argument."
      ENDPOINT_OVERRIDE="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die 4 "--timeout requires a seconds argument."
      TIMEOUT_OVERRIDE="$2"
      shift 2
      ;;
    --config)
      [[ $# -ge 2 ]] || die 4 "--config requires a file path argument."
      CONFIG_FILE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      die 4 "Unknown flag: '$1'. Run --help for usage."
      ;;
    *)
      die 4 "Unexpected argument: '$1'. Run --help for usage."
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Validate required tools
# ---------------------------------------------------------------------------
command -v jq   &>/dev/null || die 4 "Required tool 'jq' not found on PATH."
command -v curl &>/dev/null || die 4 "Required tool 'curl' not found on PATH."
command -v yq   &>/dev/null || die 4 "Required tool 'yq' not found on PATH."
command -v git  &>/dev/null || die 4 "Required tool 'git' not found on PATH."

# ---------------------------------------------------------------------------
# Load configuration (yq helper; returns empty string when key absent)
# ---------------------------------------------------------------------------
[[ -f "${CONFIG_FILE}" ]] \
  || die 4 "hooks/config.yaml not found at ${CONFIG_FILE}."

cfg() { yq e "${1} // \"\"" "${CONFIG_FILE}" 2>/dev/null || true; }

# Resolve values: CLI flag takes precedence over config file default
ENDPOINT="${ENDPOINT_OVERRIDE:-$(cfg '.manthan.endpoint')}"
TIMEOUT="${TIMEOUT_OVERRIDE:-$(cfg '.manthan.timeout_seconds')}"
TIMEOUT="${TIMEOUT:-60}"
API_KEY_ENV=$(cfg '.manthan.api_key_env')
API_KEY_ENV="${API_KEY_ENV:-MANTHAN_API_KEY}"
ON_UNREACHABLE=$(cfg '.manthan.on_unreachable')
ON_UNREACHABLE="${ON_UNREACHABLE:-warn}"
ON_INTERNAL_ERROR=$(cfg '.manthan.on_internal_error')
ON_INTERNAL_ERROR="${ON_INTERNAL_ERROR:-block}"

# Resolve SARIF path: CLI flag → config default → conventional path
SARIF_DEFAULT=$(cfg '.reporting.sarif_output_path')
SARIF_DEFAULT="${SARIF_DEFAULT:-.securecode/findings.sarif.json}"
LIBRARY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SARIF_FILE="${SARIF_OVERRIDE:-${LIBRARY_ROOT}/${SARIF_DEFAULT}}"

# ---------------------------------------------------------------------------
# Early exit when Manthan is not configured
# ---------------------------------------------------------------------------
if [[ -z "${ENDPOINT}" ]]; then
  info "manthan.endpoint is empty — nothing to do (Manthan scan-gate disabled)."
  exit 0
fi

# ---------------------------------------------------------------------------
# Validate SARIF input
# ---------------------------------------------------------------------------
[[ -f "${SARIF_FILE}" ]] \
  || die 4 "SARIF file not found: ${SARIF_FILE}. Run pre-commit.sh first to generate it."

jq empty "${SARIF_FILE}" 2>/dev/null \
  || die 4 "SARIF file is not valid JSON: ${SARIF_FILE}"

# ---------------------------------------------------------------------------
# Collect git context for the commit event payload
# (matches the POST /v1/events/commit schema in docs/MANTHAN-CONTRACT.md)
# ---------------------------------------------------------------------------
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
COMMIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
COMMIT_AUTHOR=$(git log -1 --format="%ae" 2>/dev/null || echo "unknown")

# Detect AI attribution from COMMIT_EDITMSG (pre-commit context) or last commit
IS_AI_ASSISTED="false"
COMMIT_MSG_FILE="${GIT_DIR:-.git}/COMMIT_EDITMSG"
if [[ -f "${COMMIT_MSG_FILE}" ]]; then
  grep -qi 'co-authored-by:.*\(claude\|copilot\|gpt\|gemini\|openai\|anthropic\|ai\|bot\)' \
    "${COMMIT_MSG_FILE}" 2>/dev/null && IS_AI_ASSISTED="true" || true
else
  git log -1 --format="%B" 2>/dev/null \
    | grep -qi 'co-authored-by:.*\(claude\|copilot\|gpt\|gemini\|openai\|anthropic\|ai\|bot\)' \
    && IS_AI_ASSISTED="true" || true
fi

# Count changed files from staged diff or last commit
FILES_CHANGED=$(git diff --staged --name-only 2>/dev/null | wc -l | tr -d ' ' \
  || git diff --name-only HEAD~1 2>/dev/null | wc -l | tr -d ' ' \
  || echo "0")

# Config values for the context block
SEVERITY_THRESHOLD=$(cfg '.severity.block_floor')
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-high}"
FRESHNESS_WINDOW=$(cfg '.freshness.window_commits')
FRESHNESS_WINDOW="${FRESHNESS_WINDOW:-10}"
REPO_NAME=$(basename "${LIBRARY_ROOT}")

# Convert IS_AI_ASSISTED string to JSON boolean
IS_AI_BOOL="false"
[[ "${IS_AI_ASSISTED}" == "true" ]] && IS_AI_BOOL="true"

# Extract Manthan-format subagent findings from the SARIF file
SUBAGENT_FINDINGS=$(jq '
  [
    .runs[]? |
    .tool.driver.name as $tool |
    .results[]? |
    {
      subagent_id: $tool,
      tier:        "C",
      findings: [{
        rule_id:  (.ruleId // "unknown"),
        severity: ((.properties.severity // .level // "medium") | ascii_downcase),
        path:     (.locations[0]?.physicalLocation?.artifactLocation?.uri // "unknown"),
        line:     (.locations[0]?.physicalLocation?.region?.startLine // 0),
        message:  (.message.text // "")
      }]
    }
  ]
' "${SARIF_FILE}" 2>/dev/null || echo "[]")

# Compute inputs hash for potential audit use
INPUTS_HASH=$(sha256_of "${SARIF_FILE}")

# ---------------------------------------------------------------------------
# Build POST payload (POST /v1/events/commit schema)
# ---------------------------------------------------------------------------
PAYLOAD=$(jq -n \
  --arg sha        "${COMMIT_SHA}" \
  --arg branch     "${COMMIT_BRANCH}" \
  --arg author     "${COMMIT_AUTHOR}" \
  --argjson ai     "${IS_AI_BOOL}" \
  --argjson nf     "${FILES_CHANGED}" \
  --arg repo       "${REPO_NAME}" \
  --arg ver        "1.0.0" \
  --arg floor      "${SEVERITY_THRESHOLD}" \
  --argjson fw     "${FRESHNESS_WINDOW}" \
  --argjson sf     "${SUBAGENT_FINDINGS}" \
  '{
    commit: {
      sha: $sha, branch: $branch, author: $author,
      is_ai_assisted: $ai, co_authored_by: []
    },
    diff: {
      files_changed: $nf, lines_added: 0, lines_removed: 0, paths: []
    },
    context: {
      repo: $repo, library_version: $ver,
      config_severity_threshold: $floor,
      config_freshness_window_commits: $fw
    },
    subagent_findings: $sf
  }')

# ---------------------------------------------------------------------------
# Dry-run mode — print what would be sent and exit
# ---------------------------------------------------------------------------
if [[ "${DRY_RUN}" == "true" ]]; then
  info "DRY RUN — would POST to: ${ENDPOINT%/}/v1/events/commit"
  info "DRY RUN — SARIF source: ${SARIF_FILE}"
  info "DRY RUN — commit context: sha=${COMMIT_SHA} branch=${COMMIT_BRANCH} ai=${IS_AI_BOOL}"
  info "DRY RUN — payload (pretty-printed):"
  echo "${PAYLOAD}" | jq . >&2
  info "DRY RUN — no HTTP request sent."
  exit 0
fi

# ---------------------------------------------------------------------------
# Health check (GET /healthz) — fail fast on network issues
# ---------------------------------------------------------------------------
HEALTHZ_URL="${ENDPOINT%/}/healthz"
info "Health check: ${HEALTHZ_URL}"

HEALTHZ_CODE="000"
HEALTHZ_CODE=$(curl -sS --connect-timeout 3 --max-time 5 \
  -o /dev/null -w "%{http_code}" "${HEALTHZ_URL}" 2>/dev/null) || true

if [[ "${HEALTHZ_CODE}" != "200" ]]; then
  warn "Manthan unreachable: ${HEALTHZ_URL} returned HTTP ${HEALTHZ_CODE}."
  # Always exit 3 to signal the caller; pre-commit.sh applies on_unreachable policy
  die 3 "Manthan endpoint unreachable (HTTP ${HEALTHZ_CODE}). Check that Manthan is running."
fi
info "Health check: OK (HTTP 200)"

# ---------------------------------------------------------------------------
# POST /v1/events/commit
# ---------------------------------------------------------------------------
POST_URL="${ENDPOINT%/}/v1/events/commit"
info "POST ${POST_URL} (timeout=${TIMEOUT}s)"

# Resolve API key (reads the env var named by api_key_env config key)
API_KEY=""
if [[ -n "${API_KEY_ENV}" ]]; then
  API_KEY="${!API_KEY_ENV:-}"
fi

CURL_ARGS=(-sS
  --max-time "${TIMEOUT}"
  -X POST
  -H "Content-Type: application/json"
  -d "${PAYLOAD}"
  -w "\n%{http_code}"
  "${POST_URL}")
[[ -n "${API_KEY}" ]] && CURL_ARGS+=(-H "Authorization: Bearer ${API_KEY}")

CURL_EXIT=0
RAW_RESPONSE=$(curl "${CURL_ARGS[@]}" 2>/dev/null) || CURL_EXIT=$?

# ---------------------------------------------------------------------------
# Handle transport errors
# ---------------------------------------------------------------------------
if [[ "${CURL_EXIT}" -ne 0 ]]; then
  warn "curl failed (exit code ${CURL_EXIT}): network error or timeout."
  die 3 "Manthan POST failed — network error (curl exit ${CURL_EXIT})."
fi

HTTP_STATUS=$(printf '%s' "${RAW_RESPONSE}" | tail -n1)
RESPONSE_BODY=$(printf '%s' "${RAW_RESPONSE}" | head -n -1)

# ---------------------------------------------------------------------------
# Handle HTTP error status codes
# ---------------------------------------------------------------------------
if [[ "${HTTP_STATUS}" =~ ^5 ]]; then
  warn "Manthan returned HTTP ${HTTP_STATUS} (internal server error)."
  die 2 "Manthan internal error HTTP ${HTTP_STATUS}."
fi

if [[ "${HTTP_STATUS}" =~ ^4 ]]; then
  warn "Manthan returned HTTP ${HTTP_STATUS} (client error)."
  warn "Response body: ${RESPONSE_BODY}"
  die 4 "Manthan returned HTTP ${HTTP_STATUS} — schema mismatch or bad request."
fi

if [[ "${HTTP_STATUS}" != "200" && "${HTTP_STATUS}" != "202" ]]; then
  warn "Manthan returned unexpected HTTP status: ${HTTP_STATUS}"
  die 4 "Unexpected HTTP status ${HTTP_STATUS} from Manthan."
fi

# ---------------------------------------------------------------------------
# Parse response — validate schema
# ---------------------------------------------------------------------------
if ! echo "${RESPONSE_BODY}" | jq -e '.quality_gate.decision' &>/dev/null; then
  warn "Manthan response is missing quality_gate.decision."
  warn "Response body: ${RESPONSE_BODY}"
  die 4 "Manthan response schema mismatch: quality_gate.decision not found."
fi

DECISION=$(echo "${RESPONSE_BODY}" | jq -r '.quality_gate.decision')
SCAN_ID=$(echo "${RESPONSE_BODY}" | jq -r '.scan_id // "unknown"')
RATIONALE=$(echo "${RESPONSE_BODY}" | jq -r '.quality_gate.rationale // ""')

info "Manthan decision: ${DECISION} (scan_id=${SCAN_ID})"
[[ -n "${RATIONALE}" ]] && info "Rationale: ${RATIONALE}"

# Emit response JSON to stdout for caller (pre-commit.sh or CI) to parse
echo "${RESPONSE_BODY}"

# ---------------------------------------------------------------------------
# Map decision to exit code (docs/MANTHAN-CONTRACT.md § Exit-code mapping)
# ---------------------------------------------------------------------------
case "${DECISION}" in
  pass|warn)
    # pass: no findings at or above threshold
    # warn: findings present but below threshold
    exit 0
    ;;
  block)
    # Blocking findings detected; caller should exit 1
    exit 1
    ;;
  error)
    # Manthan itself returned an error (scanners failed, etc.)
    warn "Manthan returned decision:error — internal Manthan failure."
    die 2 "Manthan decision:error (internal error in Manthan scanners)."
    ;;
  *)
    warn "Unexpected Manthan decision value: '${DECISION}'"
    die 4 "Schema mismatch: unexpected quality_gate.decision value '${DECISION}'."
    ;;
esac
