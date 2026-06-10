#!/usr/bin/env bash
# shellcheck shell=bash
#
# threat-modeler Tier C headless runner.
#
# Detects trust-boundary changes (new HTTP endpoints, new MCP/auth paths, new
# persistence layers, new IPC) in a staged (or single-commit) diff. Emits a
# SARIF 2.1.0 finding `MISSING_THREAT_MODEL` plus suggested STRIDE entries when
# THREAT_MODEL.md was not touched in the same diff. Deterministic by default —
# never calls an LLM unless $SECUREAI_LLM_ENDPOINT is set AND --remediate is
# passed.
#
# Install: `chmod +x registry/subagents/threat-modeler/run.sh`.
# Invoked by hooks/pre-commit.sh and merge-gate.yml.
#
# Contract: docs/MANTHAN-CONTRACT.md, docs/SUBAGENT-FLOWS.md §2, AGENTS.md.

set -euo pipefail

SUBAGENT_ID="threat-modeler"
LIB_VERSION="1.0.0"
AUDIT_LOG="${SECUREAI_AUDIT_LOG:-.securecode/audit.log}"
OUTPUT_FORMAT="sarif"
REMEDIATE=0
TIER="C"

usage() {
  cat <<'USAGE'
threat-modeler Tier C runner

Usage:
  registry/subagents/threat-modeler/run.sh [--output-format sarif|jsonl|markdown]
                                           [--remediate]
                                           [--help] [--version]

Behaviour:
  - Reads the staged diff (or HEAD~1..HEAD when not in pre-commit context).
  - Flags trust-boundary changes:
      * New HTTP route handlers (Express, FastAPI, Flask, Spring, ASP.NET, Gin).
      * New MCP server stubs (server.tool, registerTool, MCP class definitions).
      * New auth code paths (login, oauth, OBO, token exchange, JWT verify).
      * New persistence layers (sqlite, postgres, redis, mongo, S3 client init).
      * New IPC entry points (gRPC service def, message-queue consumer).
  - When boundary change is detected and THREAT_MODEL.md was not touched in the
    same diff, emits SARIF `MISSING_THREAT_MODEL` plus a Mermaid DFD skeleton
    (in `properties.suggested_diagram`).

Exit codes:
  0 = pass or warnings only
  1 = blocking findings detected
  2 = internal error
  3 = missing dependency (rg, jq, git)

Environment:
  SECUREAI_LLM_ENDPOINT  Optional. Enables opt-in LLM prose remediation when
                         combined with --remediate. Gate decision unchanged.
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
    --output-format) shift; OUTPUT_FORMAT="${1:-sarif}" ;;
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

for dep in git rg jq; do
  command -v "$dep" >/dev/null 2>&1 || { printf 'missing dependency: %s\n' "$dep" >&2; exit 3; }
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
# shellcheck disable=SC2086
DIFF_BODY="$(git diff $DIFF_RANGE 2>/dev/null || true)"

# Patterns are deliberately conservative; better to miss than to over-fire.
HTTP_ROUTE_PAT='@(app|router|api)\.(get|post|put|delete|patch)|@(RestController|GetMapping|PostMapping|PutMapping|DeleteMapping)|@app\.route|app\.MapGet|app\.MapPost|router\.(GET|POST|PUT|DELETE|PATCH)'
MCP_PAT='server\.tool\(|registerTool\(|McpServer|@mcp\.tool|class\s+\w+\s*\(\s*MCPServer'
AUTH_PAT='\b(login|signin|oauth|oidc|obo|on-behalf-of|token_exchange|jwt\.verify|verifyAccessToken|authenticate)\b'
PERSIST_PAT='\b(sqlite3|psycopg|pg\.Pool|redis\.createClient|MongoClient|S3Client|aioboto3|@Entity|sqlalchemy\.create_engine)\b'
IPC_PAT='\b(grpc\.|@GrpcService|ServerStreamingMethodHandler|kafka\.|consume\(|@KafkaListener|amqplib|nats\.connect)\b'

scan_boundaries() {
  local body="$1"
  local hits=0
  local reasons=()
  if printf '%s' "$body" | rg -q "$HTTP_ROUTE_PAT"; then reasons+=("new-http-endpoint"); hits=$((hits+1)); fi
  if printf '%s' "$body" | rg -q "$MCP_PAT";        then reasons+=("new-mcp-tool");      hits=$((hits+1)); fi
  if printf '%s' "$body" | rg -q "$AUTH_PAT";       then reasons+=("new-auth-path");     hits=$((hits+1)); fi
  if printf '%s' "$body" | rg -q "$PERSIST_PAT";    then reasons+=("new-persistence");   hits=$((hits+1)); fi
  if printf '%s' "$body" | rg -q "$IPC_PAT";        then reasons+=("new-ipc-entry");     hits=$((hits+1)); fi
  printf '%d|%s\n' "$hits" "$(IFS=,; printf '%s' "${reasons[*]:-}")"
}

threat_model_touched() {
  printf '%s\n' "$1" | rg -q '^THREAT_MODEL\.md$' && return 0 || return 1
}

inputs_hash() {
  printf '%s' "$CHANGED_FILES" | shasum -a 256 2>/dev/null | awk '{print "sha256:"$1}' || printf 'sha256:unknown'
}

mermaid_skeleton() {
  local reasons="$1"
  cat <<'MERMAID'
flowchart LR
  accTitle: Proposed data-flow for new trust boundary
  accDescr: Skeleton DFD generated by threat-modeler. Replace placeholders before merging into THREAT_MODEL.md.
  Client["Client"] -->|"request"| Boundary["NEW boundary"]
  Boundary -->|"data"| Persistence[("Persistence")]
  Boundary -.->|"audit"| Log[("Audit log")]
MERMAID
}

stride_table() {
  cat <<'TABLE'
| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | Caller identity unverified at new boundary. | Require auth (see `agentic-obo-auth`). |
| Tampering | Request body not validated. | Schema-validate; cite `coding-standards/input-validation`. |
| Repudiation | No audit log on the new boundary. | Emit `.securecode/audit.log` per `ai-audit-logging`. |
| Information disclosure | New persistence may leak PII. | Classify per `ai-data-classification`. |
| Denial of service | No rate limit. | Add per `ai-rate-limiting`. |
| Elevation of privilege | New tool exposes broad scope. | Tighten `tool_scope.allowed` per `agentic-tool-scoping`. |
TABLE
}

emit_sarif() {
  local finding_count="$1"
  local reasons="$2"
  local results="[]"
  if [[ "$finding_count" -gt 0 ]]; then
    results=$(jq -n \
      --arg r "$reasons" \
      --arg diagram "$(mermaid_skeleton "$reasons")" \
      --arg stride "$(stride_table)" \
      '
      [{
        "ruleId": "MISSING_THREAT_MODEL",
        "level": "error",
        "message": { "text": ("Trust-boundary change detected (" + $r + ") but THREAT_MODEL.md was not touched in this diff.") },
        "locations": [{
          "physicalLocation": { "artifactLocation": { "uri": "THREAT_MODEL.md" } }
        }],
        "properties": {
          "suggested_diagram": $diagram,
          "suggested_stride_entries": $stride
        }
      }]')
  fi
  jq -n --argjson results "$results" '
    {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "threat-modeler",
            "version": "1.0.0",
            "informationUri": "https://github.com/arvindiyu/SecureAICodeLibrary",
            "rules": [{
              "id": "MISSING_THREAT_MODEL",
              "name": "MissingThreatModelUpdate",
              "shortDescription": { "text": "Trust-boundary change without an accompanying THREAT_MODEL.md update." },
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
  local reasons="$2"
  if [[ "$finding_count" -gt 0 ]]; then
    jq -nc --arg r "$reasons" '
      { "rule_id": "MISSING_THREAT_MODEL", "severity": "high", "reasons": $r }'
  fi
}

emit_markdown() {
  local finding_count="$1"
  local reasons="$2"
  if [[ "$finding_count" -eq 0 ]]; then
    printf '# threat-modeler\n\nNo trust-boundary change detected. THREAT_MODEL.md update not required.\n'
  else
    printf '# threat-modeler\n\n**MISSING_THREAT_MODEL** — trust-boundary change detected (%s).\n\n' "$reasons"
    printf '## Suggested DFD\n\n```mermaid\n%s\n```\n\n' "$(mermaid_skeleton "$reasons")"
    printf '## Suggested STRIDE entries\n\n%s\n' "$(stride_table)"
  fi
}

main() {
  local impact reasons hits
  impact="$(scan_boundaries "$DIFF_BODY")"
  hits="${impact%%|*}"
  reasons="${impact#*|}"

  local finding_count=0
  if [[ "$hits" -gt 0 ]] && ! threat_model_touched "$CHANGED_FILES"; then
    finding_count=1
  fi

  case "$OUTPUT_FORMAT" in
    sarif)    emit_sarif    "$finding_count" "$reasons" ;;
    jsonl)    emit_jsonl    "$finding_count" "$reasons" ;;
    markdown) emit_markdown "$finding_count" "$reasons" ;;
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
    : # opt-in LLM prose remediation — gate decision unchanged.
  fi

  [[ "$finding_count" -gt 0 ]] && exit 1 || exit 0
}

main "$@"
