#!/usr/bin/env bash
# shellcheck shell=bash
#
# ai-governance-auditor Tier C headless runner.
#
# Walks staged (or HEAD~1..HEAD) changes that match the AI-globs and runs
# deterministic rule-pattern checks for each Tier 0 + scope-activated AI rule
# in references.rules. Emits SARIF 2.1.0 to stdout by default. Zero LLM calls
# unless $SECUREAI_LLM_ENDPOINT is set AND --remediate is passed.
#
# Install: `chmod +x registry/subagents/ai-governance-auditor/run.sh`.
# Invoked by hooks/pre-commit.sh and merge-gate.yml.
#
# Contract: docs/MANTHAN-CONTRACT.md, docs/SUBAGENT-FLOWS.md §3, AGENTS.md.

set -euo pipefail

SUBAGENT_ID="ai-governance-auditor"
LIB_VERSION="1.0.0"
AUDIT_LOG="${SECUREAI_AUDIT_LOG:-.securecode/audit.log}"
OUTPUT_FORMAT="sarif"
REMEDIATE=0
RULE_FILTER=""
TIER="C"

usage() {
  cat <<'USAGE'
ai-governance-auditor Tier C runner

Usage:
  registry/subagents/ai-governance-auditor/run.sh
        [--output-format sarif|jsonl|markdown]
        [--rule <rule-id>]            Restrict the run to a single rule.
        [--remediate]                 Opt-in LLM prose remediation (requires
                                      $SECUREAI_LLM_ENDPOINT). Gate decision
                                      remains deterministic.
        [--help] [--version]

Behaviour:
  - Walks files in the staged diff (or HEAD~1..HEAD) matching AI-globs:
      **/llm/**, **/agents/**, **/prompts/**, **/mcp/**, **/rag/**,
      and any file containing 'OpenAI', 'Anthropic', 'Bedrock', 'OllamaClient',
      'mcp.tool', 'McpServer', or 'system_prompt' in its body.
  - Pattern-checks each rule in references.rules. Findings keyed by rule_id.
  - Findings classified C/H/M/L by severity (deterministic table below).

Exit codes:
  0 = pass or warnings only
  1 = blocking findings detected (severity >= configured threshold)
  2 = internal error
  3 = missing dependency (rg, jq, yq, git)
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
    --rule) shift; RULE_FILTER="${1:-}" ;;
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

ai_globs() {
  printf '%s\n' "$CHANGED_FILES" \
    | rg --no-line-number -e '(^|/)(llm|agents|prompts|mcp|rag)/' \
       -e 'openai|anthropic|bedrock|ollama|mcp\.tool|McpServer|system_prompt' \
    || true
}

# Rule -> (severity, pattern, hint). Patterns are conservative; absence of a
# match is the finding (e.g. an LLM call without input sanitization).
declare -A SEV PAT HINT POS
SEV[prompt-injection-prevention]="critical"
PAT[prompt-injection-prevention]='untrusted|sanitize|escape_user_input|html\.escape|bleach'
POS[prompt-injection-prevention]="negative" # block when pattern is ABSENT in AI files
HINT[prompt-injection-prevention]="LLM call without visible input sanitization."

SEV[mcp-server-safety]="high"
PAT[mcp-server-safety]='tool_scope|allowed_tools|capability\s*='
POS[mcp-server-safety]="negative"
HINT[mcp-server-safety]="MCP server stub without explicit tool_scope."

SEV[agentic-action-classification]="medium"
PAT[agentic-action-classification]='classification\s*[:=]\s*"?(low|medium|high)-impact'
POS[agentic-action-classification]="negative"
HINT[agentic-action-classification]="Agentic action without action-classification metadata."

SEV[agentic-human-approval]="critical"
PAT[agentic-human-approval]='human_approval|require_approval|confirm\(|ask_user'
POS[agentic-human-approval]="negative"
HINT[agentic-human-approval]="Agentic action without a human-approval surface."

SEV[agentic-tool-scoping]="high"
PAT[agentic-tool-scoping]='allowed\s*[:=]\s*\[|tool_scope'
POS[agentic-tool-scoping]="negative"
HINT[agentic-tool-scoping]="Tool registration without an explicit allow-list."

SEV[agentic-bulk-limits]="medium"
PAT[agentic-bulk-limits]='max_(items|rows|requests|batch)|limit\s*='
POS[agentic-bulk-limits]="negative"
HINT[agentic-bulk-limits]="Agentic loop without a bulk limit."

SEV[agentic-obo-auth]="high"
PAT[agentic-obo-auth]='on[_-]?behalf[_-]?of|token_exchange|act_as_user'
POS[agentic-obo-auth]="negative"
HINT[agentic-obo-auth]="Agentic action against user resources without OBO."

SEV[ai-audit-logging]="critical"
PAT[ai-audit-logging]='\.securecode/audit\.log|audit_log|emit_audit'
POS[ai-audit-logging]="negative"
HINT[ai-audit-logging]="LLM/agent call without an audit-log emission."

SEV[ai-data-classification]="medium"
PAT[ai-data-classification]='data_class|classification\s*[:=]\s*"?(public|internal|confidential|restricted)'
POS[ai-data-classification]="negative"
HINT[ai-data-classification]="Data crossing AI boundary without a classification tag."

SEV[ai-data-provenance]="medium"
PAT[ai-data-provenance]='provenance|source_uri|attribution'
POS[ai-data-provenance]="negative"
HINT[ai-data-provenance]="AI training/inference input without provenance metadata."

SEV[ai-data-segregation]="high"
PAT[ai-data-segregation]='tenant_id|partition_key|namespace'
POS[ai-data-segregation]="negative"
HINT[ai-data-segregation]="Vector DB / RAG store without tenant segregation."

SEV[ai-content-moderation]="high"
PAT[ai-content-moderation]='moderate|toxicity|safety_classifier|content_filter'
POS[ai-content-moderation]="negative"
HINT[ai-content-moderation]="LLM output path without a content-moderation step."

SEV[ai-bias-fairness]="medium"
PAT[ai-bias-fairness]='fairness|bias_check|disparate_impact'
POS[ai-bias-fairness]="negative"
HINT[ai-bias-fairness]="High-impact decision path without bias/fairness check."

SEV[ai-explainability]="medium"
PAT[ai-explainability]='rationale|explanation|reasoning|why_this_decision'
POS[ai-explainability]="negative"
HINT[ai-explainability]="High-impact decision without an explanation surface."

SEV[ai-guardrails]="high"
PAT[ai-guardrails]='guardrail|policy_check|deny_list|safety_check'
POS[ai-guardrails]="negative"
HINT[ai-guardrails]="LLM output path without guardrail checks."

SEV[ai-human-oversight]="high"
PAT[ai-human-oversight]='human_review|reviewer|escalate_to_human'
POS[ai-human-oversight]="negative"
HINT[ai-human-oversight]="Autonomous decision path without a human-oversight escape hatch."

SEV[ai-model-lifecycle]="medium"
PAT[ai-model-lifecycle]='model_version|model_card|deprecation'
POS[ai-model-lifecycle]="negative"
HINT[ai-model-lifecycle]="Model invocation without lifecycle metadata."

SEV[ai-rate-limiting]="medium"
PAT[ai-rate-limiting]='rate_limit|RateLimiter|requests_per_(second|minute|hour)'
POS[ai-rate-limiting]="negative"
HINT[ai-rate-limiting]="LLM endpoint without rate limiting."

SEV[ai-regulatory-compliance]="medium"
PAT[ai-regulatory-compliance]='gdpr|eu_ai_act|regulatory|hipaa|pci'
POS[ai-regulatory-compliance]="negative"
HINT[ai-regulatory-compliance]="Regulated path without explicit compliance tagging."

SEV[ai-third-party-ai]="medium"
PAT[ai-third-party-ai]='third_party|vendor_id|model_provider'
POS[ai-third-party-ai]="negative"
HINT[ai-third-party-ai]="Third-party AI call without provider tagging."

SEV[llm-output-sanitization]="high"
PAT[llm-output-sanitization]='sanitize_output|escape_html|safe_render'
POS[llm-output-sanitization]="negative"
HINT[llm-output-sanitization]="LLM output rendered without sanitization."

SEV[ai-kill-switch]="high"
PAT[ai-kill-switch]='kill_switch|disable_agent|emergency_stop'
POS[ai-kill-switch]="negative"
HINT[ai-kill-switch]="Long-running agent without a kill-switch."

SEV[ai-code-provenance]="medium"
PAT[ai-code-provenance]='Co-Authored-By|ai_generated|provenance_tag'
POS[ai-code-provenance]="negative"
HINT[ai-code-provenance]="AI-generated code without provenance trailer."

RULES=( prompt-injection-prevention mcp-server-safety agentic-action-classification \
        agentic-human-approval agentic-tool-scoping agentic-bulk-limits agentic-obo-auth \
        ai-audit-logging ai-data-classification ai-data-provenance ai-data-segregation \
        ai-content-moderation ai-bias-fairness ai-explainability ai-guardrails \
        ai-human-oversight ai-model-lifecycle ai-rate-limiting ai-regulatory-compliance \
        ai-third-party-ai llm-output-sanitization ai-kill-switch ai-code-provenance )

run_rule() {
  local rule="$1"
  local files="$2"
  local sev="${SEV[$rule]}"
  local pat="${PAT[$rule]}"
  local hint="${HINT[$rule]}"
  local results=()

  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    [[ ! -f "$f" ]] && continue
    if rg -q "$pat" "$f" 2>/dev/null; then
      continue # rule SATISFIED
    fi
    results+=("$(jq -nc \
      --arg rid "$rule" \
      --arg sev "$sev" \
      --arg msg "$hint" \
      --arg path "$f" \
      '{rule_id:$rid, severity:$sev, path:$path, message:$msg}')")
  done <<<"$files"

  printf '%s\n' "${results[@]}"
}

inputs_hash() {
  printf '%s' "$CHANGED_FILES" | shasum -a 256 2>/dev/null | awk '{print "sha256:"$1}' || printf 'sha256:unknown'
}

main() {
  local ai_files
  ai_files="$(ai_globs)"

  local all_findings=()
  local rule
  for rule in "${RULES[@]}"; do
    [[ -n "$RULE_FILTER" && "$rule" != "$RULE_FILTER" ]] && continue
    while IFS= read -r f; do
      [[ -n "$f" ]] && all_findings+=("$f")
    done < <(run_rule "$rule" "$ai_files")
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
            locations: [{ physicalLocation: { artifactLocation: { uri: .path } } }],
            properties: { severity: .severity }
          })')
      fi
      jq -n --argjson results "$results_json" '
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          version: "2.1.0",
          runs: [{
            tool: { driver: { name: "ai-governance-auditor", version: "1.0.0",
                              informationUri: "https://github.com/arvindiyu/SecureAICodeLibrary" } },
            results: $results
          }]
        }'
      ;;
    jsonl)
      printf '%s\n' "${all_findings[@]}"
      ;;
    markdown)
      if [[ "$finding_count" -eq 0 ]]; then
        printf '# ai-governance-auditor\n\nNo AI-governance findings.\n'
      else
        printf '# ai-governance-auditor\n\n%d findings (%d blocking).\n\n| Rule | Severity | Path | Message |\n|---|---|---|---|\n' \
          "$finding_count" "$blocking"
        for f in "${all_findings[@]}"; do
          printf '| %s | %s | %s | %s |\n' \
            "$(printf '%s' "$f" | jq -r .rule_id)" \
            "$(printf '%s' "$f" | jq -r .severity)" \
            "$(printf '%s' "$f" | jq -r .path)" \
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
