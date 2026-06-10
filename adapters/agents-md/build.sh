#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
LIB_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)
RULES_ROOT="$LIB_ROOT/registry/rules"
SUBAGENTS_ROOT="$LIB_ROOT/registry/subagents"
CONSUMER_REPO=${CONSUMER_REPO:-$(pwd)}
ADAPTER_MODE=${ADAPTER_MODE:-write}
LIBRARY_PATH_IN_CONSUMER=${SECUREAI_LIBRARY_PATH_IN_CONSUMER:-.secure-ai-code-library}

# shellcheck source=../common.sh
. "$LIB_ROOT/adapters/common.sh"

usage() {
  cat <<'USAGE'
Usage: adapters/agents-md/build.sh --consumer-repo /path/to/repo [--dry-run|--check] [--version vX.Y.Z] [--library-path-in-consumer .secure-ai-code-library]

Generates:
  AGENTS.md
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --consumer-repo)
      [ "$#" -ge 2 ] || die "--consumer-repo requires a path"
      CONSUMER_REPO=$2
      shift 2
      ;;
    --dry-run)
      ADAPTER_MODE=dry-run
      shift
      ;;
    --check)
      ADAPTER_MODE=check
      shift
      ;;
    --version)
      [ "$#" -ge 2 ] || die "--version requires a value"
      SECUREAI_LIBRARY_VERSION=$2
      export SECUREAI_LIBRARY_VERSION
      shift 2
      ;;
    --library-path-in-consumer)
      [ "$#" -ge 2 ] || die "--library-path-in-consumer requires a path"
      LIBRARY_PATH_IN_CONSUMER=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

require_yaml_reader
[ -d "$CONSUMER_REPO" ] || die "Consumer repo does not exist: $CONSUMER_REPO"

records_file=$(mktemp)
output_file=$(mktemp)
trap 'rm -f "$records_file" "$output_file"' EXIT
collect_rule_records "$RULES_ROOT" "$records_file"
validate_tier0_present "$records_file"

{
  generated_header
  printf '\nThis project is governed by Secure AI Code Library %s.\n\n' "$(adapter_version)"
  printf 'Only Layer 1 rule summaries are inlined here. Load full guidance from the registry YAML when scope globs match or a user references a rule by id.\n\n'

  printf '## Tier 0 Always-On Rules\n\n'
  for tier0_id in $TIER0_RULE_IDS; do
    awk -F '\t' -v id="$tier0_id" '$2 == id { print $3 }' "$records_file" | while IFS= read -r rule_file; do
      summary=$(yaml_scalar "$rule_file" '.summary')
      printf -- '- `%s` — %s\n' "$tier0_id" "$summary"
    done
  done

  printf '\n## Activation Map\n\n'
  printf '| Rule id | Glob patterns | Severity | Blocking? |\n'
  printf '|---|---|---|---|\n'
  while IFS="$(printf '\t')" read -r category id rule_file; do
    globs=$(yaml_array_lines "$rule_file" '.scope.globs' | join_lines_csv)
    [ -n "$globs" ] || globs='(global)'
    severity=$(yaml_scalar "$rule_file" '.severity')
    [ -n "$severity" ] || severity='info'
    mode=$(yaml_scalar "$rule_file" '.enforcement.mode')
    if [ "$mode" = "blocking" ]; then
      blocking='yes'
    else
      blocking='no'
    fi
    printf '| `%s` | %s | `%s` | `%s` |\n' \
      "$(escape_table_cell "$id")" \
      "$(escape_table_cell "$globs")" \
      "$(escape_table_cell "$severity")" \
      "$blocking"
  done < "$records_file"

  printf '\n## Subagent Invocation\n\n'
  if emit_subagents_none_if_absent "$SUBAGENTS_ROOT"; then
    :
  else
    printf '| Subagent | Cursor | AGENTS.md | Copilot Coding Agent |\n'
    printf '|---|---|---|---|\n'
    find "$SUBAGENTS_ROOT" -type f -name subagent.yaml | sort | while IFS= read -r subagent_file; do
      subagent_id=$(yaml_scalar "$subagent_file" '.id')
      [ -n "$subagent_id" ] || subagent_id=$(basename "$(dirname "$subagent_file")")
      native_cursor=$(yaml_scalar "$subagent_file" '.tiers.native.cursor')
      native_agents=$(yaml_scalar "$subagent_file" '.tiers.native.agents_md')
      native_copilot=$(yaml_scalar "$subagent_file" '.tiers.native.copilot_coding_agent')
      [ -n "$native_cursor" ] || native_cursor='n/a'
      [ -n "$native_agents" ] || native_agents='n/a'
      [ -n "$native_copilot" ] || native_copilot='n/a'
      printf '| `%s` | `%s` | `%s` | `%s` |\n' \
        "$(escape_table_cell "$subagent_id")" \
        "$(escape_table_cell "$native_cursor")" \
        "$(escape_table_cell "$native_agents")" \
        "$(escape_table_cell "$native_copilot")"
    done
  fi

  printf '\nSee %s/CONSTITUTION.md for control mapping.\n' "$LIBRARY_PATH_IN_CONSUMER"
} > "$output_file"

write_generated_file "$CONSUMER_REPO/AGENTS.md" "$output_file"
