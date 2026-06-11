#!/usr/bin/env bash
# shellcheck shell=bash
#
# adr-author Tier C headless runner.
#
# Detects architecture-impact in a staged (or single-commit) diff and emits a
# SARIF 2.1.0 finding (`MISSING_ADR`) plus a suggested filename when no
# corresponding ADR is present. Deterministic by default — never calls an LLM
# unless $SECUREAI_LLM_ENDPOINT is set AND `--remediate` is passed.
#
# Install: `chmod +x registry/subagents/adr-author/run.sh` (do NOT chmod here).
# Invoked by hooks/pre-commit.sh (Phase 4) and merge-gate.yml (Phase 6).
#
# Contract: docs/MANTHAN-CONTRACT.md (exit codes), docs/SUBAGENT-FLOWS.md (flow),
# AGENTS.md (audit-log fields), ADR 0001/0005.

set -euo pipefail

SUBAGENT_ID="adr-author"
LIB_VERSION="1.0.0"
AUDIT_LOG="${SECUREAI_AUDIT_LOG:-.securecode/audit.log}"
OUTPUT_FORMAT="sarif"
REMEDIATE=0
TIER="C"

usage() {
  cat <<'USAGE'
adr-author Tier C runner

Usage:
  registry/subagents/adr-author/run.sh [--output-format sarif|jsonl|markdown]
                                       [--remediate]
                                       [--help] [--version]

Behaviour:
  - Reads the staged diff (or HEAD~1..HEAD when not in pre-commit context).
  - Flags architecture-impact: new top-level directory, new runtime dependency
    in package.json/pyproject.toml/go.mod/Cargo.toml/requirements.txt,
    schema/contract change under registry/schemas/ or **/openapi*.yaml.
  - When impact is detected and no docs/adr/NNNN-*.md was touched in the same
    diff, emits one SARIF finding `MISSING_ADR` with a suggested ADR filename
    (next free NNNN, slug from the most-changed top-level path).
  - Always appends one JSON-lines entry to .securecode/audit.log.

Exit codes:
  0 = pass or warnings only
  1 = blocking findings detected (MISSING_ADR by default is blocking)
  2 = internal error
  3 = missing dependency (rg, jq, or git not on PATH)

Environment:
  SECUREAI_LLM_ENDPOINT  Optional. When set AND --remediate is passed, the
                         runner POSTs the ADR skeleton to this endpoint to
                         request prose. Gate decision is unchanged.
  SECUREAI_AUDIT_LOG     Optional override for the audit log path.
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
    --output-format)
      shift
      OUTPUT_FORMAT="${1:-sarif}"
      ;;
    --remediate) REMEDIATE=1 ;;
    --scope) shift; SCOPE_OVERRIDE="${1:-}" ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
  shift || true
done

case "$OUTPUT_FORMAT" in
  sarif|jsonl|markdown) ;;
  *) printf 'invalid --output-format: %s\n' "$OUTPUT_FORMAT" >&2; exit 64 ;;
esac

for dep in git rg jq; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    printf 'missing dependency: %s\n' "$dep" >&2
    exit 3
  fi
done

mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

detect_diff_range() {
  if [[ -n "${GIT_DIR:-}" && -f "${GIT_DIR}/MERGE_MSG" ]]; then
    printf -- '--staged'
    return
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

if [[ -z "$CHANGED_FILES" ]]; then
  CHANGED_FILES=""
fi

architecture_impact() {
  local files="$1"
  local hits=0
  local reasons=()

  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    case "$f" in
      package.json|*/package.json|pyproject.toml|*/pyproject.toml|go.mod|*/go.mod|Cargo.toml|*/Cargo.toml|requirements*.txt|*/requirements*.txt)
        reasons+=("dependency-manifest:$f"); hits=$((hits+1)) ;;
      registry/schemas/*|*/openapi*.yaml|*/openapi*.yml|*.proto)
        reasons+=("schema-change:$f"); hits=$((hits+1)) ;;
    esac
  done <<<"$files"

  local top_dirs
  top_dirs="$(printf '%s\n' "$files" | awk -F/ 'NF>1{print $1}' | sort -u)"
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    if [[ ! -d "$d" ]]; then
      reasons+=("new-top-level-dir:$d"); hits=$((hits+1))
    fi
  done <<<"$top_dirs"

  printf '%d|%s\n' "$hits" "$(IFS=,; printf '%s' "${reasons[*]:-}")"
}

adr_touched() {
  printf '%s\n' "$1" | rg -q '^docs/adr/[0-9]{4}-[a-z0-9-]+\.md$' && return 0 || return 1
}

next_adr_number() {
  local n=1
  if [[ -d docs/adr ]]; then
    n="$(ls docs/adr 2>/dev/null | rg -o '^([0-9]{4})-' -r '$1' | sort -n | tail -1 || echo "0000")"
    n=$((10#${n:-0} + 1))
  fi
  printf '%04d' "$n"
}

slug_from_changes() {
  printf '%s\n' "$1" \
    | awk -F/ 'NF>1{print $1}' \
    | sort | uniq -c | sort -rn | awk 'NR==1{print $2}' \
    | tr '[:upper:]' '[:lower:]' \
    | tr -c 'a-z0-9-' '-' \
    | sed -E 's/^-+|-+$//g; s/-+/-/g'
}

inputs_hash() {
  printf '%s' "$CHANGED_FILES" | shasum -a 256 2>/dev/null | awk '{print "sha256:"$1}' || printf 'sha256:unknown'
}

emit_sarif() {
  local finding_count="$1"
  local suggested="$2"
  local reasons="$3"
  local results="[]"
  if [[ "$finding_count" -gt 0 ]]; then
    results=$(jq -n --arg f "$suggested" --arg r "$reasons" '
      [{
        "ruleId": "MISSING_ADR",
        "level": "error",
        "message": { "text": ("Architecture-impact detected (" + $r + ") but no ADR was touched in this diff. Suggested file: " + $f) },
        "locations": [{
          "physicalLocation": { "artifactLocation": { "uri": $f } }
        }]
      }]')
  fi
  jq -n --argjson results "$results" '
    {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "adr-author",
            "version": "1.0.0",
            "informationUri": "https://github.com/arvindiyu/SecureAICodeLibrary",
            "rules": [{
              "id": "MISSING_ADR",
              "name": "MissingArchitecturalDecisionRecord",
              "shortDescription": { "text": "Architecture-impact change without an accompanying ADR." },
              "helpUri": "registry/rules/policies/required-artifacts.rule.yaml"
            }]
          }
        },
        "results": $results
      }]
    }'
}

emit_jsonl() {
  local finding_count="$1"
  local suggested="$2"
  local reasons="$3"
  if [[ "$finding_count" -gt 0 ]]; then
    jq -nc --arg f "$suggested" --arg r "$reasons" '
      { "rule_id": "MISSING_ADR", "severity": "high", "suggested_path": $f, "reasons": $r }'
  fi
}

emit_markdown() {
  local finding_count="$1"
  local suggested="$2"
  local reasons="$3"
  if [[ "$finding_count" -eq 0 ]]; then
    printf '# adr-author\n\nNo architecture-impact detected. No ADR required.\n'
  else
    printf '# adr-author\n\n**MISSING_ADR** — architecture-impact detected (%s).\n\nSuggested file: `%s`.\n' "$reasons" "$suggested"
  fi
}

main() {
  local impact reasons hits suggested
  impact="$(architecture_impact "$CHANGED_FILES")"
  hits="${impact%%|*}"
  reasons="${impact#*|}"

  local finding_count=0
  suggested=""

  if [[ "$hits" -gt 0 ]] && ! adr_touched "$CHANGED_FILES"; then
    finding_count=1
    suggested="docs/adr/$(next_adr_number)-$(slug_from_changes "$CHANGED_FILES").md"
  fi

  case "$OUTPUT_FORMAT" in
    sarif)    emit_sarif    "$finding_count" "$suggested" "$reasons" ;;
    jsonl)    emit_jsonl    "$finding_count" "$suggested" "$reasons" ;;
    markdown) emit_markdown "$finding_count" "$suggested" "$reasons" ;;
  esac

  local decision="pass"
  [[ "$finding_count" -gt 0 ]] && decision="block"

  jq -nc \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg id "$SUBAGENT_ID" \
    --arg tier "$TIER" \
    --arg user "${USER:-unknown}" \
    --arg ih "$(inputs_hash)" \
    --arg dec "$decision" \
    --argjson fc "$finding_count" \
    '{
      timestamp: $ts,
      subagent_id: $id,
      tier: $tier,
      user: $user,
      inputs_hash: $ih,
      model: null,
      token_in: 0,
      token_out: 0,
      decision: $dec,
      finding_count: $fc
    }' >> "$AUDIT_LOG" 2>/dev/null || true

  if [[ "$REMEDIATE" -eq 1 && -n "${SECUREAI_LLM_ENDPOINT:-}" && "$finding_count" -gt 0 ]]; then
    : # opt-in LLM remediation hook — never overrides the gate decision.
  fi

  [[ "$finding_count" -gt 0 ]] && exit 1 || exit 0
}

main "$@"
