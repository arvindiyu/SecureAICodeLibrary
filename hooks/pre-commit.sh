#!/usr/bin/env bash
# shellcheck shell=bash
# hooks/pre-commit.sh — Secure AI Code Library pre-commit / CI scan gate
#
# INVOCATION MODES
#   Pre-commit hook:  git runs this automatically; staged files are the scope.
#   CI mode:          CI=1 ./hooks/pre-commit.sh [--base <ref>]
#   Full-repo scan:   ./hooks/pre-commit.sh --all
#   Explicit scope:   ./hooks/pre-commit.sh --scope "src/api.ts src/db.ts"
#
# EXIT CODES  (binding — docs/MANTHAN-CONTRACT.md § Exit-code mapping)
#   0   pass / warnings only
#   1   blocking findings detected (local gate or Manthan decision: block)
#   2   Manthan internal error (reachable, returns 5xx or decision:error)
#   3   Manthan unreachable (configurable: manthan.on_unreachable warn|block)
#   4   schema mismatch (response or config format invalid)
#   64  bad CLI arguments
#   65  hooks/config.yaml missing or invalid (including missing required tools)
#   78  pre-Manthan compliance failure (missing artifact, stale artifact,
#       missing Tier 0 audit entries, or gaps-risk check failure)
#
# DEPENDENCIES
#   Required: git, rg, yq (mikefarah/yq v4+), jq (1.6+), curl
#   sha256sum (Linux) or shasum -a 256 (macOS) — one must be on PATH
#   Optional: SECUREAI_LLM_ENDPOINT env var for Tier C prose remediation
#
# IDEMPOTENCY
#   Running twice on the same diff produces the same exit code and the same
#   audit-log delta (one entry per subagent + one scan-gate entry per run).
#   Machine output (.securecode/runtime/last-run.json) is overwritten each run.
#
# REFERENCE DOCS
#   docs/MANTHAN-CONTRACT.md  — endpoint contracts, exit codes, severity matrix
#   docs/INSTALL.md           — wiring patterns (git hook, Husky, pre-commit fw)
#   AGENTS.md                 — Tier 0 rules, audit-log field spec

set -euo pipefail

# ---------------------------------------------------------------------------
# Ensure bash 4+ associative-array support is available.
# On macOS the system /bin/bash is 3.2; Homebrew ships bash 5 at
# /opt/homebrew/bin/bash. Prepend Homebrew bin so that subagent run.sh scripts
# (which use `declare -A`) resolve `env bash` to bash 5. This is a no-op on
# Linux where system bash is already 4+. (Wave 4 fix — bash compat.)
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  export PATH="/opt/homebrew/bin:${PATH}"
fi

# ---------------------------------------------------------------------------
# Script location + library root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
LIBRARY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly LIBRARY_ROOT

readonly LIBRARY_VERSION="1.0.0"
readonly CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
readonly SUBAGENTS_DIR="${LIBRARY_ROOT}/registry/subagents"
readonly SARIF_SCHEMA="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# Subagent that covers all five Tier 0 rules (AGENTS.md § Tier 0 rules):
#   no-hardcoded-secrets, prompt-injection-prevention, agentic-human-approval,
#   ai-audit-logging, mcp-server-safety
readonly TIER0_SUBAGENT="ai-governance-auditor"

# ---------------------------------------------------------------------------
# Mutable runtime state (set by functions; read by main)
# ---------------------------------------------------------------------------
SCAN_MODE=""          # precommit | ci | manual
SCOPE_FILES=()        # files in scope for this run
SUBAGENT_FINDINGS_JSON="[]"   # Manthan-format findings array (built per subagent run)
SARIF_RUNS_JSON="[]"          # accumulated SARIF runs from all subagents
MANTHAN_DECISION="skipped"    # pass|warn|block|error|unreachable|skipped
MANTHAN_SCAN_ID=""
IS_AI_ASSISTED="false"        # "true" if Co-Authored-By AI trailer detected

# Config values (populated by load_config; defaults match hooks/config.yaml)
SEVERITY_BLOCK_FLOOR="high"
AI_RAISE_BAND="1"
AI_ATTRIBUTION_CHECK="blocking"
FRESHNESS_WINDOW_COMMITS="10"
FRESHNESS_WINDOW_DAYS="30"
MANTHAN_ENDPOINT=""
MANTHAN_API_KEY_ENV="MANTHAN_API_KEY"
MANTHAN_TIMEOUT="60"
MANTHAN_ON_UNREACHABLE="warn"
MANTHAN_ON_INTERNAL_ERROR="block"
AUDIT_LOG_PATH=""
SARIF_OUTPUT_PATH=""
MACHINE_OUTPUT_PATH=""
LLM_ENDPOINT_ENV="SECUREAI_LLM_ENDPOINT"
LLM_REMEDIATE_FLAG="--remediate"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
_log() { printf '[secureai] %-6s %s\n' "$1" "$2" >&2; }
info()    { _log "INFO"  "$*"; }
warn()    { _log "WARN"  "$*"; }
error()   { _log "ERROR" "$*"; }
success() { _log "OK"    "$*"; }

die() {
  local code="$1"; shift
  error "$*"
  exit "${code}"
}

# Cross-platform SHA-256 (macOS uses shasum; Linux uses sha256sum)
sha256_of() {
  if command -v sha256sum &>/dev/null; then
    printf '%s' "$*" | sha256sum | awk '{print $1}'
  else
    printf '%s' "$*" | shasum -a 256 | awk '{print $1}'
  fi
}

now_iso8601() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

require_tool() {
  command -v "$1" &>/dev/null \
    || die 65 "Required tool '$1' not found on PATH. See docs/INSTALL.md § Required dependencies."
}

# yq read helper — returns empty string when key is absent or config unreadable
cfg_get() {
  yq e "${1} // \"\"" "${CONFIG_FILE}" 2>/dev/null || true
}

# yq array helper — one value per line; empty when key absent
cfg_array() {
  yq e "${1}[]" "${CONFIG_FILE}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Usage / help
# ---------------------------------------------------------------------------
usage() {
  cat >&2 <<'EOF'
hooks/pre-commit.sh — Secure AI Code Library scan gate

USAGE
  ./hooks/pre-commit.sh                 auto-detect (staged files in pre-commit mode)
  ./hooks/pre-commit.sh --all           full-repo scan (all tracked files)
  ./hooks/pre-commit.sh --scope "f1 f2" explicit file scope (space-separated)
  CI=1 ./hooks/pre-commit.sh [--base <ref>]
                                        CI mode; diff from <ref>..HEAD (default: HEAD~1)
  ./hooks/pre-commit.sh --help

ENVIRONMENT
  CI=1                 Force CI mode
  SECUREAI_LLM_ENDPOINT   Optional local LLM for prose remediation (Ollama etc.)
  MANTHAN_API_KEY (or value of manthan.api_key_env in config)

EXIT CODES
  0   pass / warnings only
  1   blocking findings
  2   Manthan internal error
  3   Manthan unreachable
  4   schema mismatch
  64  bad CLI arguments
  65  config.yaml missing / invalid / required tool missing
  78  pre-Manthan compliance failure

DOCS
  docs/INSTALL.md  docs/MANTHAN-CONTRACT.md  hooks/README.md
EOF
}

# ---------------------------------------------------------------------------
# CLI argument parsing + scope determination
# ---------------------------------------------------------------------------
parse_args() {
  local all_flag="false"
  local explicit_scope=""
  local ci_base="HEAD~1"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all)
        all_flag="true"
        shift
        ;;
      --scope)
        [[ $# -ge 2 ]] || die 64 "--scope requires a space-separated file list argument."
        explicit_scope="$2"
        shift 2
        ;;
      --base)
        [[ $# -ge 2 ]] || die 64 "--base requires a git ref argument."
        ci_base="$2"
        shift 2
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
        die 64 "Unknown flag: '$1'. Run --help for usage."
        ;;
      *)
        die 64 "Unexpected positional argument: '$1'. Run --help for usage."
        ;;
    esac
  done

  if [[ "${all_flag}" == "true" ]]; then
    SCAN_MODE="manual"
    while IFS= read -r f; do
      [[ -n "${f}" ]] && SCOPE_FILES+=("${f}")
    done < <(cd "${LIBRARY_ROOT}" && git ls-files 2>/dev/null || true)

  elif [[ -n "${explicit_scope}" ]]; then
    SCAN_MODE="manual"
    read -ra SCOPE_FILES <<< "${explicit_scope}"

  elif [[ "${CI:-}" == "1" || "${CI:-}" == "true" ]]; then
    SCAN_MODE="ci"
    while IFS= read -r f; do
      [[ -n "${f}" ]] && SCOPE_FILES+=("${f}")
    done < <(cd "${LIBRARY_ROOT}" && \
      git diff --name-only "${ci_base}...HEAD" 2>/dev/null \
      || git diff --name-only HEAD~1 2>/dev/null \
      || true)

  else
    # Default: pre-commit mode (GIT_DIR may or may not be set)
    SCAN_MODE="precommit"
    while IFS= read -r f; do
      [[ -n "${f}" ]] && SCOPE_FILES+=("${f}")
    done < <(cd "${LIBRARY_ROOT}" && git diff --staged --name-only 2>/dev/null || true)
  fi

  info "Mode: ${SCAN_MODE} | Files in scope: ${#SCOPE_FILES[@]}"
}

# ---------------------------------------------------------------------------
# Config loading and validation
# ---------------------------------------------------------------------------
load_config() {
  [[ -f "${CONFIG_FILE}" ]] \
    || die 65 "hooks/config.yaml not found at ${CONFIG_FILE}. See docs/INSTALL.md."

  require_tool yq
  require_tool jq
  require_tool git
  require_tool curl

  local v
  v=$(cfg_get '.severity.block_floor'); SEVERITY_BLOCK_FLOOR="${v:-high}"
  case "${SEVERITY_BLOCK_FLOOR}" in
    critical|high|medium|low|info) ;;
    *) die 65 "severity.block_floor must be critical|high|medium|low|info; got '${SEVERITY_BLOCK_FLOOR}'." ;;
  esac

  v=$(cfg_get '.severity.ai_assisted_raise_band');  AI_RAISE_BAND="${v:-1}"
  v=$(cfg_get '.severity.ai_attribution_check');    AI_ATTRIBUTION_CHECK="${v:-blocking}"
  case "${AI_ATTRIBUTION_CHECK}" in
    blocking|warning|advisory) ;;
    *) die 65 "severity.ai_attribution_check must be blocking|warning|advisory; got '${AI_ATTRIBUTION_CHECK}'." ;;
  esac

  v=$(cfg_get '.freshness.window_commits');  FRESHNESS_WINDOW_COMMITS="${v:-10}"
  v=$(cfg_get '.freshness.window_days');     FRESHNESS_WINDOW_DAYS="${v:-30}"

  v=$(cfg_get '.manthan.endpoint');          MANTHAN_ENDPOINT="${v:-}"
  v=$(cfg_get '.manthan.api_key_env');       MANTHAN_API_KEY_ENV="${v:-MANTHAN_API_KEY}"
  v=$(cfg_get '.manthan.timeout_seconds');   MANTHAN_TIMEOUT="${v:-60}"
  v=$(cfg_get '.manthan.on_unreachable');    MANTHAN_ON_UNREACHABLE="${v:-warn}"
  v=$(cfg_get '.manthan.on_internal_error'); MANTHAN_ON_INTERNAL_ERROR="${v:-block}"

  v=$(cfg_get '.audit_log.path')
  AUDIT_LOG_PATH="${LIBRARY_ROOT}/${v:-.securecode/audit.log}"

  v=$(cfg_get '.reporting.sarif_output_path')
  SARIF_OUTPUT_PATH="${LIBRARY_ROOT}/${v:-.securecode/findings.sarif.json}"

  v=$(cfg_get '.reporting.machine_output_path')
  MACHINE_OUTPUT_PATH="${LIBRARY_ROOT}/${v:-.securecode/runtime/last-run.json}"

  v=$(cfg_get '.headless_llm.endpoint_env');  LLM_ENDPOINT_ENV="${v:-SECUREAI_LLM_ENDPOINT}"
  v=$(cfg_get '.headless_llm.remediate_flag'); LLM_REMEDIATE_FLAG="${v:---remediate}"

  # Ensure runtime output directories exist before anything writes to them
  mkdir -p "$(dirname "${AUDIT_LOG_PATH}")"
  mkdir -p "$(dirname "${SARIF_OUTPUT_PATH}")"
  mkdir -p "$(dirname "${MACHINE_OUTPUT_PATH}")"
}

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

# Numeric rank (higher = more severe); covers SARIF level names as well
severity_rank() {
  case "${1,,}" in
    critical|error)         echo 4 ;;
    high|warning)           echo 3 ;;
    medium|note)            echo 2 ;;
    low)                    echo 1 ;;
    *)                      echo 0 ;;  # info / none / unknown
  esac
}

# Returns 0 (true) when $1's severity rank >= block_floor rank
is_blocking_severity() {
  [[ "$(severity_rank "${1}")" -ge "$(severity_rank "${SEVERITY_BLOCK_FLOOR}")" ]]
}

# Raise a severity band by N; ceiling = critical
raise_severity() {
  local sev="${1,,}"
  local n="${2:-1}"
  local rank
  rank=$(severity_rank "${sev}")
  rank=$(( rank + n ))
  (( rank > 4 )) && rank=4
  case "${rank}" in
    4) echo "critical" ;;
    3) echo "high" ;;
    2) echo "medium" ;;
    1) echo "low" ;;
    *) echo "info" ;;
  esac
}

# ---------------------------------------------------------------------------
# AI-attribution detection
# ---------------------------------------------------------------------------
detect_ai_attribution() {
  local commit_msg_file="${GIT_DIR:-.git}/COMMIT_EDITMSG"

  if [[ "${SCAN_MODE}" == "precommit" && -f "${commit_msg_file}" ]]; then
    if grep -qi \
      'co-authored-by:.*\(claude\|copilot\|gpt\|gemini\|openai\|anthropic\|ai\|bot\)' \
      "${commit_msg_file}" 2>/dev/null; then
      IS_AI_ASSISTED="true"
    fi
  elif [[ "${SCAN_MODE}" == "ci" ]]; then
    if git log -1 --format="%B" 2>/dev/null \
        | grep -qi \
          'co-authored-by:.*\(claude\|copilot\|gpt\|gemini\|openai\|anthropic\|ai\|bot\)'; then
      IS_AI_ASSISTED="true"
    fi
  fi

  if [[ "${IS_AI_ASSISTED}" == "true" ]]; then
    info "AI-attribution: Co-Authored-By trailer detected (is_ai_assisted=true)."
    case "${AI_ATTRIBUTION_CHECK}" in
      blocking) info "AI floor raise: +${AI_RAISE_BAND} severity band(s) will be applied." ;;
      warning)  warn "AI-attribution detected; floor raise suppressed (ai_attribution_check=warning)." ;;
      advisory) info "AI-attribution detected; no gate effect (ai_attribution_check=advisory)." ;;
    esac
  fi
}

# ---------------------------------------------------------------------------
# Compliance checks — exit 78 on hard failure
# (docs/MANTHAN-CONTRACT.md § How the hook composes the request, step 3)
# ---------------------------------------------------------------------------

# Returns 1 (blocks) when artifact is beyond 2× window_commits; warns at 1× window.
_freshness_check_artifact() {
  local artifact="$1"

  local last_hash
  last_hash=$(cd "${LIBRARY_ROOT}" && git log -1 --format="%H" -- "${artifact}" 2>/dev/null || true)

  if [[ -z "${last_hash}" ]]; then
    warn "Freshness: '${artifact}' has no git history — skipping."
    return 0
  fi

  local commits_behind
  commits_behind=$(cd "${LIBRARY_ROOT}" \
    && git rev-list --count "${last_hash}..HEAD" 2>/dev/null \
    || echo "9999")

  local warn_at="${FRESHNESS_WINDOW_COMMITS}"
  local block_at=$(( FRESHNESS_WINDOW_COMMITS * 2 ))

  if [[ "${commits_behind}" -ge "${block_at}" ]]; then
    error "Freshness BLOCK: '${artifact}' not touched in ${commits_behind} commits (block threshold=${block_at})."
    return 1
  elif [[ "${commits_behind}" -ge "${warn_at}" ]]; then
    warn "Freshness WARN: '${artifact}' not touched in ${commits_behind} commits (warn threshold=${warn_at})."
  fi
  return 0
}

run_compliance_checks() {
  local failures=0
  info "Running pre-Manthan compliance checks (seven checks)..."

  # Check 1: CONSTITUTION.md present
  if [[ ! -f "${LIBRARY_ROOT}/CONSTITUTION.md" ]]; then
    error "Check 1 FAIL: CONSTITUTION.md missing."
    failures=$(( failures + 1 ))
  else
    success "Check 1 OK: CONSTITUTION.md present."
  fi

  # Check 2: SPEC.md present
  if [[ ! -f "${LIBRARY_ROOT}/SPEC.md" ]]; then
    error "Check 2 FAIL: SPEC.md missing."
    failures=$(( failures + 1 ))
  else
    success "Check 2 OK: SPEC.md present."
  fi

  # Check 3: sbom.cdx.json present + lockfile-change warning
  if [[ ! -f "${LIBRARY_ROOT}/sbom.cdx.json" ]]; then
    error "Check 3 FAIL: sbom.cdx.json missing — run 'make sbom' to regenerate."
    failures=$(( failures + 1 ))
  else
    success "Check 3 OK: sbom.cdx.json present."
    # Warn when a dependency lockfile is in scope but SBOM was not regenerated
    local lockfiles=("package-lock.json" "poetry.lock" "Cargo.lock" "go.sum" "yarn.lock")
    local lf
    for lf in "${lockfiles[@]}"; do
      if printf '%s\n' "${SCOPE_FILES[@]+"${SCOPE_FILES[@]}"}" | grep -qF "${lf}" 2>/dev/null; then
        if ! printf '%s\n' "${SCOPE_FILES[@]+"${SCOPE_FILES[@]}"}" | grep -qF "sbom.cdx.json" 2>/dev/null; then
          warn "Check 3 WARN: '${lf}' in scope but sbom.cdx.json not regenerated in this commit."
        fi
        break
      fi
    done
  fi

  # Check 4: docs/adr/ exists and contains at least one ADR
  if [[ ! -d "${LIBRARY_ROOT}/docs/adr" ]]; then
    error "Check 4 FAIL: docs/adr/ directory missing."
    failures=$(( failures + 1 ))
  else
    local adr_count
    adr_count=$(find "${LIBRARY_ROOT}/docs/adr" -maxdepth 1 -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${adr_count}" -eq 0 ]]; then
      error "Check 4 FAIL: docs/adr/ has no ADR (.md) files."
      failures=$(( failures + 1 ))
    else
      success "Check 4 OK: docs/adr/ has ${adr_count} ADR(s)."
    fi
  fi

  # Check 5: THREAT_MODEL.md present
  if [[ ! -f "${LIBRARY_ROOT}/THREAT_MODEL.md" ]]; then
    error "Check 5 FAIL: THREAT_MODEL.md missing."
    failures=$(( failures + 1 ))
  else
    success "Check 5 OK: THREAT_MODEL.md present."
  fi

  # Check 6: Freshness of required_artifacts (from config)
  info "Check 6: Artifact freshness..."
  local artifact
  while IFS= read -r artifact; do
    [[ -z "${artifact}" ]] && continue
    if ! _freshness_check_artifact "${artifact}"; then
      failures=$(( failures + 1 ))
    fi
  done < <(cfg_array '.freshness.required_artifacts')

  # Check 7: Tier 0 audit-log coverage (pre-run check — warns only)
  # A hard failure is raised AFTER subagents run (verify_tier0_coverage) if the
  # Tier 0 subagent could not be invoked. Here we warn if the log looks empty.
  info "Check 7: Tier 0 audit-log pre-check..."
  if [[ "${#SCOPE_FILES[@]}" -gt 0 && -f "${AUDIT_LOG_PATH}" ]]; then
    if ! grep -q "\"subagent_id\":\"${TIER0_SUBAGENT}\"" "${AUDIT_LOG_PATH}" 2>/dev/null; then
      warn "Check 7 WARN: No prior ${TIER0_SUBAGENT} entries in audit.log (first run or log cleared)."
    else
      success "Check 7 OK: ${TIER0_SUBAGENT} entries found in audit.log."
    fi
  else
    info "Check 7: No audit.log yet — will be created this run."
  fi

  if [[ "${failures}" -gt 0 ]]; then
    die 78 "${failures} compliance check(s) failed before Manthan scan-gate. Fix and re-commit."
  fi

  success "All compliance checks passed."
}

# ---------------------------------------------------------------------------
# Tier C subagent runners
# (docs/SUBAGENT-FLOWS.md; AGENTS.md § How to invoke subagents)
# ---------------------------------------------------------------------------

# Returns 0 (applicable) unless subagent.yaml declares tiers.headless: not_applicable
_subagent_headless_applicable() {
  local id="$1"
  local yaml="${SUBAGENTS_DIR}/${id}/subagent.yaml"
  [[ -f "${yaml}" ]] || return 0  # no yaml → assume applicable (fail later at run.sh)
  local val
  val=$(yq e '.tiers.headless // ""' "${yaml}" 2>/dev/null || true)
  [[ "${val}" != "not_applicable" ]]
}

run_subagents() {
  info "Running Tier C subagent runners..."

  # Build scope string for run.sh --scope argument
  local scope_str=""
  if [[ "${#SCOPE_FILES[@]}" -gt 0 ]]; then
    scope_str=$(printf '%s\n' "${SCOPE_FILES[@]}" | tr '\n' ' ')
    scope_str="${scope_str% }"  # strip trailing space
  fi

  # Resolve LLM endpoint env var (opt-in prose remediation)
  local llm_endpoint=""
  if [[ -n "${LLM_ENDPOINT_ENV}" ]]; then
    # Bash indirect variable reference; safe under set -u because we guard with -n
    llm_endpoint="${!LLM_ENDPOINT_ENV:-}"
  fi

  # Read enabled / disabled subagent lists from config
  local enabled_ids=()
  while IFS= read -r sid; do
    [[ -n "${sid}" ]] && enabled_ids+=("${sid}")
  done < <(cfg_array '.subagents.enabled' 2>/dev/null || true)

  local disabled_ids=()
  while IFS= read -r sid; do
    [[ -n "${sid}" ]] && disabled_ids+=("${sid}")
  done < <(cfg_array '.subagents.disabled' 2>/dev/null || true)

  local subagent_id
  for subagent_id in "${enabled_ids[@]+"${enabled_ids[@]}"}"; do
    # Skip if explicitly disabled
    local is_disabled="false"
    local d
    for d in "${disabled_ids[@]+"${disabled_ids[@]}"}"; do
      [[ "${d}" == "${subagent_id}" ]] && is_disabled="true" && break
    done
    if [[ "${is_disabled}" == "true" ]]; then
      info "Subagent '${subagent_id}': in disabled list — skipping."
      continue
    fi

    # Skip if Tier C is not_applicable for this subagent
    if ! _subagent_headless_applicable "${subagent_id}"; then
      info "Subagent '${subagent_id}': tiers.headless=not_applicable — skipping."
      continue
    fi

    local runner="${SUBAGENTS_DIR}/${subagent_id}/run.sh"
    if [[ ! -f "${runner}" ]]; then
      warn "Subagent '${subagent_id}': run.sh not found at ${runner} — skipping (non-fatal)."
      continue
    fi
    if [[ ! -x "${runner}" ]]; then
      warn "Subagent '${subagent_id}': run.sh not executable — skipping (non-fatal)."
      continue
    fi

    info "Running '${subagent_id}'..."

    # Build runner argument list.
    # Contract assumption (Wave 3b): run.sh accepts --scope "<files>" and emits SARIF to stdout.
    # Optional: --remediate flag when LLM endpoint is set (prose explanation only).
    local runner_args=()
    [[ -n "${scope_str}" ]] && runner_args+=(--scope "${scope_str}")
    [[ -n "${llm_endpoint}" ]] && runner_args+=("${LLM_REMEDIATE_FLAG}")

    local sarif_out=""
    local runner_exit=0
    sarif_out=$("${runner}" "${runner_args[@]+"${runner_args[@]}"}" 2>/tmp/secureai_run_stderr_$$) \
      || runner_exit=$?

    if [[ "${runner_exit}" -ne 0 ]]; then
      warn "Subagent '${subagent_id}' exited ${runner_exit} — findings may be partial."
    fi

    # Validate SARIF output and accumulate into SARIF_RUNS_JSON
    local finding_count=0
    local decision="pass"

    if [[ -n "${sarif_out}" ]] && echo "${sarif_out}" | jq empty 2>/dev/null; then
      # Count all results across runs (handles both run-object and full SARIF doc)
      finding_count=$(echo "${sarif_out}" | \
        jq '[.. | .results? // empty | .[]] | length' 2>/dev/null || echo 0)
      [[ "${finding_count}" -gt 0 ]] && decision="block"

      # Normalise to a JSON array of runs
      local runs_fragment
      if echo "${sarif_out}" | jq -e '.runs' &>/dev/null; then
        runs_fragment=$(echo "${sarif_out}" | jq '.runs')
      else
        # Single run object — wrap in array
        runs_fragment=$(echo "${sarif_out}" | jq '[.]')
      fi
      SARIF_RUNS_JSON=$(echo "${SARIF_RUNS_JSON}" | \
        jq --argjson r "${runs_fragment}" '. + $r')

      # Extract per-finding data for the Manthan subagent_findings payload
      local manthan_findings
      manthan_findings=$(echo "${sarif_out}" | jq '
        [.. | .results? // empty | .[] |
          {
            rule_id:  (.ruleId // "unknown"),
            severity: ((.properties.severity // .level // "medium") | ascii_downcase),
            path:     (.locations[0]?.physicalLocation?.artifactLocation?.uri // "unknown"),
            line:     (.locations[0]?.physicalLocation?.region?.startLine // 0),
            message:  (.message.text // "")
          }
        ]
      ' 2>/dev/null || echo "[]")

      SUBAGENT_FINDINGS_JSON=$(echo "${SUBAGENT_FINDINGS_JSON}" | jq \
        --arg sid "${subagent_id}" \
        --argjson findings "${manthan_findings}" \
        '. + [{"subagent_id": $sid, "tier": "C", "findings": $findings}]')
    else
      warn "Subagent '${subagent_id}': no valid SARIF output — recording empty run."
      SARIF_RUNS_JSON=$(echo "${SARIF_RUNS_JSON}" | jq \
        --arg n "${subagent_id}" \
        '. + [{"tool":{"driver":{"name":$n,"version":"1.0.0","rules":[]}},"results":[]}]')
    fi

    # Append audit-log entry (10 required fields per AGENTS.md § ai-audit-logging)
    local inputs_hash
    inputs_hash=$(sha256_of "${scope_str}")
    jq -n \
      --arg ts      "$(now_iso8601)" \
      --arg sid     "${subagent_id}" \
      --arg user    "${USER:-unknown}" \
      --arg ihash   "${inputs_hash}" \
      --arg dec     "${decision}" \
      --argjson fc  "${finding_count}" \
      '{
        timestamp:     $ts,
        subagent_id:   $sid,
        tier:          "C",
        user:          $user,
        inputs_hash:   $ihash,
        model:         null,
        token_in:      0,
        token_out:     0,
        decision:      $dec,
        finding_count: $fc
      }' >> "${AUDIT_LOG_PATH}"

    success "Subagent '${subagent_id}' done. Findings: ${finding_count} (decision=${decision})."
  done

  # Clean up per-run stderr temp file
  rm -f /tmp/secureai_run_stderr_$$ 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# SARIF aggregation
# ---------------------------------------------------------------------------
aggregate_sarif() {
  info "Aggregating SARIF output to ${SARIF_OUTPUT_PATH}"
  jq -n \
    --arg schema "${SARIF_SCHEMA}" \
    --argjson runs "${SARIF_RUNS_JSON}" \
    '{"$schema": $schema, "version": "2.1.0", "runs": $runs}' \
    > "${SARIF_OUTPUT_PATH}"
  success "SARIF written: ${SARIF_OUTPUT_PATH}"
}

# ---------------------------------------------------------------------------
# AI-assistance severity floor raise
# Applied in-place to the SARIF file after aggregation.
# ---------------------------------------------------------------------------
apply_ai_floor() {
  [[ "${IS_AI_ASSISTED}" == "true" ]] || return 0
  [[ "${AI_ATTRIBUTION_CHECK}" == "advisory" ]] && return 0
  if [[ "${AI_ATTRIBUTION_CHECK}" == "warning" ]]; then
    warn "AI-attributed code: floor raise suppressed (ai_attribution_check=warning)."
    return 0
  fi
  [[ "${AI_RAISE_BAND}" -ge 1 ]] || return 0

  info "Applying AI-assistance floor raise (+${AI_RAISE_BAND} band) to SARIF findings..."

  # jq walk() requires jq 1.6+; documented in docs/INSTALL.md § Required dependencies
  local raised
  raised=$(jq --argjson n "${AI_RAISE_BAND}" '
    def rank(s):
      if s == "critical" or s == "error" then 4
      elif s == "high" or s == "warning" then 3
      elif s == "medium" or s == "note" then 2
      elif s == "low" then 1
      else 0 end;
    def unrank(r):
      if r >= 4 then "critical"
      elif r == 3 then "high"
      elif r == 2 then "medium"
      elif r == 1 then "low"
      else "info" end;
    def raise_sev(s): unrank([rank(s) + $n, 4] | min);
    walk(
      if type == "object" then
        if (has("properties") and (.properties | type == "object") and (.properties | has("severity")))
          then .properties.severity |= raise_sev(.)
        elif has("level")
          then .level |= raise_sev(.)
        else .
        end
      else .
      end
    )
  ' "${SARIF_OUTPUT_PATH}" 2>/dev/null) || raised=$(cat "${SARIF_OUTPUT_PATH}")

  printf '%s\n' "${raised}" > "${SARIF_OUTPUT_PATH}"
  info "Floor raise applied."
}

# ---------------------------------------------------------------------------
# Severity gate — counts findings at or above block_floor
# ---------------------------------------------------------------------------
count_blocking_findings() {
  jq --arg floor "${SEVERITY_BLOCK_FLOOR}" '
    def rank(s):
      if s == "critical" or s == "error" then 4
      elif s == "high" or s == "warning" then 3
      elif s == "medium" or s == "note" then 2
      elif s == "low" then 1
      else 0 end;
    [
      .. | .results? // empty | .[] |
      select(rank(.properties.severity // .level // "info") >= rank($floor))
    ] | length
  ' "${SARIF_OUTPUT_PATH}" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# Tier 0 rule coverage verification (post-subagent-run)
# Exits 78 if the Tier 0 subagent did not produce an audit entry this run.
# ---------------------------------------------------------------------------
verify_tier0_coverage() {
  info "Verifying Tier 0 rule coverage (${TIER0_SUBAGENT})..."

  if [[ ! -f "${AUDIT_LOG_PATH}" ]]; then
    warn "Tier 0 coverage: audit.log not found — cannot verify."
    return 0
  fi

  if grep -q "\"subagent_id\":\"${TIER0_SUBAGENT}\"" "${AUDIT_LOG_PATH}" 2>/dev/null; then
    success "Tier 0 coverage: ${TIER0_SUBAGENT} audit entries present."
    return 0
  fi

  error "Tier 0 coverage FAIL: ${TIER0_SUBAGENT} has not run on this scope."
  error "  Tier 0 rules require coverage: no-hardcoded-secrets, prompt-injection-prevention,"
  error "  agentic-human-approval, ai-audit-logging, mcp-server-safety."
  error "  Ensure '${TIER0_SUBAGENT}' is in subagents.enabled in hooks/config.yaml"
  error "  and that ${SUBAGENTS_DIR}/${TIER0_SUBAGENT}/run.sh is present and executable."
  return 1
}

# ---------------------------------------------------------------------------
# Manthan ASOC scan-gate call
# Delegates to manthan-client.sh when present; falls back to inline HTTP call.
# ---------------------------------------------------------------------------
call_manthan() {
  if [[ -z "${MANTHAN_ENDPOINT}" ]]; then
    info "manthan.endpoint is empty — Manthan scan-gate disabled."
    MANTHAN_DECISION="skipped"
    return 0
  fi

  local client="${SCRIPT_DIR}/manthan-client.sh"
  if [[ -f "${client}" && -x "${client}" ]]; then
    local client_exit=0
    local client_stdout=""
    # Capture stdout (JSON response); stderr from client flows to user's stderr
    client_stdout=$(bash "${client}" \
      --sarif "${SARIF_OUTPUT_PATH}" \
      --timeout "${MANTHAN_TIMEOUT}" \
      2>&1 1>/tmp/manthan_response_$$) || client_exit=$?

    # Read stdout from temp file (avoids bash subshell stderr-capture dance)
    local manthan_resp=""
    [[ -f /tmp/manthan_response_$$ ]] && manthan_resp=$(cat /tmp/manthan_response_$$ || true)
    rm -f /tmp/manthan_response_$$ 2>/dev/null || true

    if echo "${manthan_resp}" | jq -e '.quality_gate.decision' &>/dev/null; then
      MANTHAN_DECISION=$(echo "${manthan_resp}" | jq -r '.quality_gate.decision')
      MANTHAN_SCAN_ID=$(echo "${manthan_resp}" | jq -r '.scan_id // ""')
    fi

    case "${client_exit}" in
      0) MANTHAN_DECISION="${MANTHAN_DECISION:-pass}" ;;
      1) MANTHAN_DECISION="block" ;;
      2)
        if [[ "${MANTHAN_ON_INTERNAL_ERROR}" == "block" ]]; then
          die 2 "Manthan internal error (client exit 2)."
        fi
        warn "Manthan internal error (on_internal_error=warn)."
        MANTHAN_DECISION="error"
        ;;
      3)
        if [[ "${MANTHAN_ON_UNREACHABLE}" == "block" ]]; then
          die 3 "Manthan unreachable (client exit 3)."
        fi
        warn "Manthan unreachable (on_unreachable=warn)."
        MANTHAN_DECISION="unreachable"
        ;;
      4) die 4 "Manthan schema mismatch (client exit 4)." ;;
      *)
        warn "manthan-client.sh returned unexpected exit code ${client_exit}."
        MANTHAN_DECISION="error"
        ;;
    esac
  else
    warn "manthan-client.sh not available — using inline HTTP call."
    _inline_manthan_call
  fi

  info "Manthan decision: ${MANTHAN_DECISION} (scan_id=${MANTHAN_SCAN_ID:-n/a})"
}

# Inline fallback Manthan call used when manthan-client.sh is absent.
_inline_manthan_call() {
  local healthz="${MANTHAN_ENDPOINT%/}/healthz"
  local http_code="000"
  http_code=$(curl -sS --connect-timeout 3 --max-time 5 \
    -o /dev/null -w "%{http_code}" "${healthz}" 2>/dev/null) || true

  if [[ "${http_code}" != "200" ]]; then
    warn "Manthan ${healthz} unreachable (HTTP ${http_code})."
    if [[ "${MANTHAN_ON_UNREACHABLE}" == "block" ]]; then
      die 3 "Manthan unreachable (on_unreachable=block). Set manthan.on_unreachable: warn to continue without Manthan."
    fi
    MANTHAN_DECISION="unreachable"
    return 0
  fi

  # Collect git context for the commit event payload
  local sha branch author
  sha=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
  branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
  author=$(git log -1 --format="%ae" 2>/dev/null || echo "${USER:-unknown}")

  local api_key=""
  if [[ -n "${MANTHAN_API_KEY_ENV}" ]]; then
    api_key="${!MANTHAN_API_KEY_ENV:-}"
  fi

  # Convert IS_AI_ASSISTED to a proper JSON boolean for jq
  local is_ai_bool
  [[ "${IS_AI_ASSISTED}" == "true" ]] && is_ai_bool="true" || is_ai_bool="false"

  local n_files="${#SCOPE_FILES[@]}"

  local payload
  payload=$(jq -n \
    --arg sha     "${sha}" \
    --arg branch  "${branch}" \
    --arg author  "${author}" \
    --argjson ai  "${is_ai_bool}" \
    --argjson nf  "${n_files}" \
    --arg repo    "$(basename "${LIBRARY_ROOT}")" \
    --arg ver     "${LIBRARY_VERSION}" \
    --arg floor   "${SEVERITY_BLOCK_FLOOR}" \
    --argjson fw  "${FRESHNESS_WINDOW_COMMITS}" \
    --argjson sf  "${SUBAGENT_FINDINGS_JSON}" \
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

  local curl_args=(-sS --max-time "${MANTHAN_TIMEOUT}"
    -X POST
    -H "Content-Type: application/json"
    -d "${payload}"
    -w "\n%{http_code}"
    "${MANTHAN_ENDPOINT%/}/v1/events/commit")
  [[ -n "${api_key}" ]] && curl_args+=(-H "Authorization: Bearer ${api_key}")

  local curl_exit=0
  local raw_resp
  raw_resp=$(curl "${curl_args[@]}" 2>/dev/null) || curl_exit=$?

  if [[ "${curl_exit}" -ne 0 ]]; then
    warn "Manthan POST failed (curl exit ${curl_exit})."
    if [[ "${MANTHAN_ON_UNREACHABLE}" == "block" ]]; then
      die 3 "Manthan POST failed (on_unreachable=block)."
    fi
    MANTHAN_DECISION="unreachable"
    return 0
  fi

  local http_status
  http_status=$(printf '%s' "${raw_resp}" | tail -n1)
  local body
  body=$(printf '%s' "${raw_resp}" | head -n -1)

  if [[ "${http_status}" =~ ^5 ]]; then
    warn "Manthan returned HTTP ${http_status} (internal error)."
    if [[ "${MANTHAN_ON_INTERNAL_ERROR}" == "block" ]]; then
      die 2 "Manthan internal error HTTP ${http_status} (on_internal_error=block)."
    fi
    MANTHAN_DECISION="error"
    return 0
  fi

  [[ "${http_status}" =~ ^4 ]] \
    && die 4 "Manthan returned HTTP ${http_status} (schema mismatch / bad request)."

  if ! echo "${body}" | jq -e '.quality_gate.decision' &>/dev/null; then
    die 4 "Manthan response missing quality_gate.decision (schema mismatch)."
  fi

  MANTHAN_DECISION=$(echo "${body}" | jq -r '.quality_gate.decision')
  MANTHAN_SCAN_ID=$(echo "${body}" | jq -r '.scan_id // ""')
}

# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

# Append the scan-gate audit-log entry (10 required fields + Manthan extras)
_write_audit_gate_entry() {
  local final_decision="$1"
  local finding_count="$2"
  local scope_str=""
  [[ "${#SCOPE_FILES[@]}" -gt 0 ]] && scope_str=$(printf '%s ' "${SCOPE_FILES[@]}")
  local ihash
  ihash=$(sha256_of "${scope_str}")

  jq -n \
    --arg ts     "$(now_iso8601)" \
    --arg user   "${USER:-unknown}" \
    --arg ihash  "${ihash}" \
    --arg dec    "${final_decision}" \
    --argjson fc "${finding_count}" \
    --arg sid    "${MANTHAN_SCAN_ID:-null}" \
    '{
      timestamp:       $ts,
      subagent_id:     "scan-gate",
      tier:            "C",
      user:            $user,
      inputs_hash:     $ihash,
      model:           null,
      token_in:        0,
      token_out:       0,
      decision:        $dec,
      finding_count:   $fc,
      manthan_scan_id: $sid,
      engines_run:     []
    }' >> "${AUDIT_LOG_PATH}"
}

# Write machine-readable last-run summary (overwritten each run; not committed)
_write_last_run() {
  local exit_code="$1"
  local blocking="$2"
  local is_ai_bool
  [[ "${IS_AI_ASSISTED}" == "true" ]] && is_ai_bool="true" || is_ai_bool="false"

  jq -n \
    --arg  ts       "$(now_iso8601)" \
    --arg  mode     "${SCAN_MODE}" \
    --argjson nf    "${#SCOPE_FILES[@]}" \
    --argjson ec    "${exit_code}" \
    --argjson blk   "${blocking}" \
    --arg  decision "${MANTHAN_DECISION:-skipped}" \
    --arg  floor    "${SEVERITY_BLOCK_FLOOR}" \
    --argjson ai    "${is_ai_bool}" \
    '{
      timestamp:            $ts,
      scan_mode:            $mode,
      files_scanned:        $nf,
      exit_code:            $ec,
      blocking_findings:    $blk,
      manthan_decision:     $decision,
      severity_block_floor: $floor,
      is_ai_assisted:       $ai
    }' > "${MACHINE_OUTPUT_PATH}"
}

# Human-readable summary to stderr
_print_summary() {
  local exit_code="$1"
  local blocking="$2"
  {
    echo ""
    echo "┌──────────────────────────────────────────────────────────────────┐"
    echo "│  Secure AI Code Library — Scan Gate Summary                      │"
    echo "├──────────────────────────────────────────────────────────────────┤"
    printf "│  %-30s %-35s│\n" "Mode:"              "${SCAN_MODE}"
    printf "│  %-30s %-35s│\n" "Files scanned:"     "${#SCOPE_FILES[@]}"
    printf "│  %-30s %-35s│\n" "Severity floor:"    "${SEVERITY_BLOCK_FLOOR}"
    printf "│  %-30s %-35s│\n" "AI-assisted:"       "${IS_AI_ASSISTED}"
    printf "│  %-30s %-35s│\n" "Manthan:"           "${MANTHAN_DECISION:-skipped}"
    printf "│  %-30s %-35s│\n" "Blocking findings:" "${blocking}"
    printf "│  %-30s %-35s│\n" "Exit code:"         "${exit_code}"
    if [[ "${exit_code}" -eq 0 ]]; then
      echo "│  Result:    PASS                                                  │"
    else
      echo "│  Result:    FAIL  (review errors above)                           │"
    fi
    echo "└──────────────────────────────────────────────────────────────────┘"
    echo ""
  } >&2
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  load_config
  detect_ai_attribution

  # Step 3 (MANTHAN-CONTRACT.md): pre-Manthan compliance checks
  run_compliance_checks

  # Step 4: Tier C subagent runners
  run_subagents

  # Step 5a: write aggregated SARIF
  aggregate_sarif

  # Step 5b: apply AI-assistance severity floor raise
  apply_ai_floor

  # Verify Tier 0 coverage was achieved by the subagent runs above
  if ! verify_tier0_coverage; then
    die 78 "Tier 0 rule coverage unsatisfied — see errors above. Exit 78."
  fi

  # Count blocking findings from local analysis
  local blocking_count
  blocking_count=$(count_blocking_findings)

  # Step 5 (MANTHAN-CONTRACT.md): POST to Manthan and integrate verdict
  call_manthan

  # Determine final exit code
  local final_exit=0

  if [[ "${blocking_count}" -gt 0 ]]; then
    final_exit=1
    error "Severity gate: ${blocking_count} blocking finding(s) at or above '${SEVERITY_BLOCK_FLOOR}'."
  fi

  if [[ "${MANTHAN_DECISION:-}" == "block" ]]; then
    final_exit=1
    error "Manthan gate decision: BLOCK."
  fi

  # Write outputs
  local final_decision="pass"
  [[ "${final_exit}" -ne 0 ]] && final_decision="block"

  _write_audit_gate_entry "${final_decision}" "${blocking_count}"
  _write_last_run "${final_exit}" "${blocking_count}"
  _print_summary "${final_exit}" "${blocking_count}"

  exit "${final_exit}"
}

main "$@"
