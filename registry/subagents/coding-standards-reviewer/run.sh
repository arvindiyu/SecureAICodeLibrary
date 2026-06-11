#!/usr/bin/env bash
# shellcheck shell=bash
#
# coding-standards-reviewer Tier C headless runner.
#
# Walks staged (or HEAD~1..HEAD) changes, detects language by extension, and
# runs deterministic rule-pattern checks for each cross-language coding-standards
# rule whose scope.globs match a changed file. Emits SARIF 2.1.0 to stdout by
# default. Zero LLM calls unless $SECUREAI_LLM_ENDPOINT is set AND --remediate
# is passed.
#
# Install: `chmod +x registry/subagents/coding-standards-reviewer/run.sh`.
# Invoked by hooks/pre-commit.sh and merge-gate.yml.
#
# Contract: docs/MANTHAN-CONTRACT.md, docs/SUBAGENT-FLOWS.md §4, AGENTS.md.

set -euo pipefail

SUBAGENT_ID="coding-standards-reviewer"
LIB_VERSION="1.0.0"
AUDIT_LOG="${SECUREAI_AUDIT_LOG:-.securecode/audit.log}"
OUTPUT_FORMAT="sarif"
REMEDIATE=0
LANG_HINT=""
TIER="C"

usage() {
  cat <<'USAGE'
coding-standards-reviewer Tier C runner

Usage:
  registry/subagents/coding-standards-reviewer/run.sh
        [--output-format sarif|jsonl|markdown]
        [--lang <typescript|javascript|python|java|go|rust|csharp|ruby|php|kotlin>]
        [--remediate]
        [--help] [--version]

Behaviour:
  - Walks files in the staged diff (or HEAD~1..HEAD).
  - Detects language by extension; loads cross-language rules via rg patterns.
  - Findings classified by severity. Critical/high block the gate.

Exit codes:
  0 = pass or warnings only
  1 = blocking findings
  2 = internal error
  3 = missing dependency
USAGE
}

version() {
  printf '%s subagent-version=%s library-version=%s\n' "$SUBAGENT_ID" "$LIB_VERSION" "$LIB_VERSION"
}

SCOPE_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --version|-V) version; exit 0 ;;
    --output-format) shift; OUTPUT_FORMAT="${1:-sarif}" ;;
    --lang) shift; LANG_HINT="${1:-}" ;;
    --remediate) REMEDIATE=1 ;;
    --scope) shift; SCOPE_OVERRIDE="${1:-}" ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
  shift || true
done

case "$OUTPUT_FORMAT" in
  sarif|jsonl|markdown) ;;
  *) printf 'invalid --output-format: %s\n' "$OUTPUT_FORMAT" >&2; exit 64 ;;
esac

for dep in git rg jq yq; do
  command -v "$dep" >/dev/null 2>&1 || { printf 'missing dependency: %s\n' "$dep" >&2; exit 3; }
done

mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

detect_diff_range() {
  if [[ -n "${GIT_DIR:-}" && -f "${GIT_DIR}/MERGE_MSG" ]]; then
    printf -- '--staged'; return
  fi
  if git diff --staged --quiet 2>/dev/null; then
    printf 'HEAD~1..HEAD'
  else
    printf -- '--staged'
  fi
}

DIFF_RANGE="$(detect_diff_range)"
# shellcheck disable=SC2086
CHANGED_FILES="$(git diff --name-only $DIFF_RANGE 2>/dev/null || true)"
# --scope override: space-separated file list supplied by pre-commit.sh in --all mode
[[ -n "${SCOPE_OVERRIDE}" ]] && CHANGED_FILES="${SCOPE_OVERRIDE}"

# Each rule has: severity, anti-pattern (presence == finding), language-globs.
# Patterns are conservative; absence of a match means the rule is satisfied or
# inapplicable to this file.
declare -A SEV ANTI GLOBS HINT
SEV[no-hardcoded-secrets]="critical"
ANTI[no-hardcoded-secrets]='(api[_-]?key|secret|password|token)\s*[:=]\s*"[A-Za-z0-9_\-]{16,}"'
GLOBS[no-hardcoded-secrets]='\.(ts|tsx|js|jsx|py|java|go|rs|cs|rb|php|kt)$'
HINT[no-hardcoded-secrets]="Likely hardcoded secret. Move to environment / vault."

SEV[sql-injection-prevention]="critical"
ANTI[sql-injection-prevention]='(execute|query|raw)\s*\(\s*[`"][^"`]*\$\{|f"[^"]*SELECT|f"[^"]*INSERT'
GLOBS[sql-injection-prevention]='\.(ts|js|py|java|go|rs|cs|rb|php|kt)$'
HINT[sql-injection-prevention]="String-interpolated SQL detected. Use parameterized queries."

SEV[output-encoding]="high"
ANTI[output-encoding]='dangerouslySetInnerHTML|innerHTML\s*=|Mark::Safe|HtmlString\('
GLOBS[output-encoding]='\.(ts|tsx|js|jsx|py|java|cs|rb|kt)$'
HINT[output-encoding]="Unsafe HTML interpolation. Use templating with autoescape."

SEV[input-validation]="high"
ANTI[input-validation]='request\.(body|query|params|GET|POST)\b(?![^\n]*(validate|schema|pydantic|zod|joi|yup))'
GLOBS[input-validation]='\.(ts|js|py|java|go|cs|rb|php)$'
HINT[input-validation]="Untrusted input used without visible validator."

SEV[secure-deserialization]="high"
ANTI[secure-deserialization]='\bpickle\.load|\byaml\.load\(|ObjectInputStream|Marshal\.load|unserialize\('
GLOBS[secure-deserialization]='\.(py|java|rb|php|kt)$'
HINT[secure-deserialization]="Insecure deserializer. Use SafeLoader / JSON / explicit allowlists."

SEV[cryptography-standards]="high"
ANTI[cryptography-standards]='\b(MD5|SHA1|DES|RC4|ECB)\b'
GLOBS[cryptography-standards]='\.(ts|js|py|java|go|rs|cs|rb|php|kt)$'
HINT[cryptography-standards]="Weak/legacy crypto primitive. Use SHA-256+, AES-GCM/ChaCha20-Poly1305."

SEV[secure-headers]="medium"
ANTI[secure-headers]='Access-Control-Allow-Origin:\s*\*'
GLOBS[secure-headers]='\.(ts|js|py|java|go|cs|rb|php|kt|conf|yaml|yml)$'
HINT[secure-headers]="Wildcard CORS or missing CSP. Tighten headers."

SEV[cors-security]="high"
ANTI[cors-security]='cors\(\s*\{\s*origin\s*:\s*"?\*'
GLOBS[cors-security]='\.(ts|js|py|java|go|cs)$'
HINT[cors-security]="Wildcard CORS origin. Allow-list specific origins."

SEV[auth-patterns]="high"
ANTI[auth-patterns]='\bjwt\.decode\(|verify\s*=\s*false|VerifySignature\s*=\s*false'
GLOBS[auth-patterns]='\.(ts|js|py|java|go|cs|rb|php|kt)$'
HINT[auth-patterns]="JWT decoded without signature verification."

SEV[session-management]="medium"
ANTI[session-management]='Set-Cookie:[^;]*(?!.*Secure)|cookie\.set\([^)]*secure\s*=\s*false'
GLOBS[session-management]='\.(ts|js|py|java|go|cs|rb|php|kt)$'
HINT[session-management]="Session cookie missing Secure / HttpOnly / SameSite."

SEV[access-control]="high"
ANTI[access-control]='@PreAuthorize\("permitAll"\)|@AllowAnonymous|app\.(get|post|put|delete)\([^)]*\)\s*\{[^}]*\}\s*//\s*TODO\s*auth'
GLOBS[access-control]='\.(java|cs|ts|js|py|kt)$'
HINT[access-control]="Endpoint missing or weakened authorization."

SEV[file-upload-security]="high"
ANTI[file-upload-security]='multipart|formidable|Multer.*limits\s*:\s*\{\s*\}'
GLOBS[file-upload-security]='\.(ts|js|py|java|go|cs|rb|php|kt)$'
HINT[file-upload-security]="File upload without explicit size / type limits."

SEV[error-handling-logging]="medium"
ANTI[error-handling-logging]='catch\s*\([^)]*\)\s*\{\s*\}|except[^:]*:\s*pass'
GLOBS[error-handling-logging]='\.(ts|js|py|java|go|cs|rb|php|kt)$'
HINT[error-handling-logging]="Empty catch / except. Log + rethrow or handle explicitly."

SEV[dependency-management]="medium"
ANTI[dependency-management]='\^[0-9]+\.[0-9]+\.[0-9]+|~[0-9]+\.[0-9]+\.[0-9]+|"latest"'
GLOBS[dependency-management]='(package\.json|requirements\.txt|go\.mod|Cargo\.toml|pom\.xml|build\.gradle)$'
HINT[dependency-management]="Floating version range. Pin or use a lockfile."

RULES=( no-hardcoded-secrets sql-injection-prevention output-encoding input-validation \
        secure-deserialization cryptography-standards secure-headers cors-security \
        auth-patterns session-management access-control file-upload-security \
        error-handling-logging dependency-management )

inputs_hash() {
  printf '%s' "$CHANGED_FILES" | shasum -a 256 2>/dev/null | awk '{print "sha256:"$1}' || printf 'sha256:unknown'
}

run_rule() {
  local rule="$1"
  local sev="${SEV[$rule]}"
  local anti="${ANTI[$rule]}"
  local globs="${GLOBS[$rule]}"
  local hint="${HINT[$rule]}"

  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    [[ ! -f "$f" ]] && continue
    [[ ! "$f" =~ $globs ]] && continue
    while IFS=: read -r path lineno _; do
      [[ -z "$path" ]] && continue
      jq -nc \
        --arg rid "$rule" \
        --arg sev "$sev" \
        --arg msg "$hint" \
        --arg path "$path" \
        --argjson line "${lineno:-1}" \
        '{rule_id:$rid, severity:$sev, path:$path, line:$line, message:$msg}'
    done < <(rg --no-heading -nP "$anti" "$f" 2>/dev/null || true)
  done <<<"$CHANGED_FILES"
}

main() {
  local all_findings=()
  local rule
  for rule in "${RULES[@]}"; do
    while IFS= read -r f; do
      [[ -n "$f" ]] && all_findings+=("$f")
    done < <(run_rule "$rule")
  done

  local finding_count="${#all_findings[@]}"
  local blocking=0
  local f
  for f in "${all_findings[@]}"; do
    case "$(printf '%s' "$f" | jq -r .severity)" in
      critical|high) blocking=$((blocking+1)) ;;
    esac
  done

  case "$OUTPUT_FORMAT" in
    sarif)
      local results_json="[]"
      if [[ "$finding_count" -gt 0 ]]; then
        results_json=$(printf '%s\n' "${all_findings[@]}" | jq -s '
          map({
            ruleId: .rule_id,
            level: (if .severity == "critical" or .severity == "high" then "error" else "warning" end),
            message: { text: .message },
            locations: [{ physicalLocation: { artifactLocation: { uri: .path }, region: { startLine: .line } } }],
            properties: { severity: .severity }
          })')
      fi
      jq -n --argjson results "$results_json" --arg lh "$LANG_HINT" '
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          version: "2.1.0",
          runs: [{
            tool: { driver: { name: "coding-standards-reviewer", version: "1.0.0",
                              informationUri: "https://github.com/arvindiyu/SecureAICodeLibrary",
                              properties: { lang_hint: $lh } } },
            results: $results
          }]
        }'
      ;;
    jsonl)
      printf '%s\n' "${all_findings[@]}"
      ;;
    markdown)
      if [[ "$finding_count" -eq 0 ]]; then
        printf '# coding-standards-reviewer\n\nNo coding-standards findings.\n'
      else
        printf '# coding-standards-reviewer\n\n%d findings (%d blocking).\n\n| Rule | Severity | Path | Line | Message |\n|---|---|---|---|---|\n' \
          "$finding_count" "$blocking"
        for f in "${all_findings[@]}"; do
          printf '| %s | %s | %s | %s | %s |\n' \
            "$(printf '%s' "$f" | jq -r .rule_id)" \
            "$(printf '%s' "$f" | jq -r .severity)" \
            "$(printf '%s' "$f" | jq -r .path)" \
            "$(printf '%s' "$f" | jq -r .line)" \
            "$(printf '%s' "$f" | jq -r .message)"
        done
      fi
      ;;
  esac

  local decision="pass"
  [[ "$blocking" -gt 0 ]] && decision="block"

  jq -nc \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg id "$SUBAGENT_ID" \
    --arg tier "$TIER" \
    --arg user "${USER:-unknown}" \
    --arg ih "$(inputs_hash)" \
    --arg dec "$decision" \
    --argjson fc "$finding_count" \
    '{
      timestamp:$ts, subagent_id:$id, tier:$tier, user:$user,
      inputs_hash:$ih, model:null, token_in:0, token_out:0,
      decision:$dec, finding_count:$fc
    }' >> "$AUDIT_LOG" 2>/dev/null || true

  if [[ "$REMEDIATE" -eq 1 && -n "${SECUREAI_LLM_ENDPOINT:-}" && "$finding_count" -gt 0 ]]; then
    : # opt-in LLM prose remediation; gate decision unchanged.
  fi

  [[ "$blocking" -gt 0 ]] && exit 1 || exit 0
}

main "$@"
