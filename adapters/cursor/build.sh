#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
LIB_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)
RULES_ROOT="$LIB_ROOT/registry/rules"
SUBAGENTS_ROOT="$LIB_ROOT/registry/subagents"
CONSUMER_REPO=${CONSUMER_REPO:-$(pwd)}
ADAPTER_MODE=${ADAPTER_MODE:-write}

# shellcheck source=../common.sh
. "$LIB_ROOT/adapters/common.sh"

usage() {
  cat <<'USAGE'
Usage: adapters/cursor/build.sh --consumer-repo /path/to/repo [--dry-run|--check] [--version vX.Y.Z]

Generates:
  .cursor/rules/<rule-id>.mdc
  .cursor/commands/README.md
  .cursor/commands/<subagent-id>.md when registry/subagents/*/subagent.yaml exists
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
trap 'rm -f "$records_file"' EXIT
collect_rule_records "$RULES_ROOT" "$records_file"
validate_tier0_present "$records_file"

while IFS="$(printf '\t')" read -r category id rule_file; do
  summary=$(yaml_scalar "$rule_file" '.summary')
  [ -n "$summary" ] || die "Rule missing summary: $rule_file"
  relpath=$(rule_relpath_for_file "$rule_file")
  output_file=$(mktemp)

  {
    generated_header
    printf -- '---\n'
    printf 'description: |-\n'
    printf '  %s\n' "$summary"
    if yaml_array_lines "$rule_file" '.scope.globs' | grep -q .; then
      printf 'globs:\n'
      yaml_array_lines "$rule_file" '.scope.globs' | while IFS= read -r glob; do
        printf '  - "%s"\n' "$glob"
      done
    else
      printf 'globs: []\n'
    fi
    if is_tier0_rule "$id"; then
      printf 'alwaysApply: true\n'
    else
      printf 'alwaysApply: false\n'
    fi
    printf -- '---\n\n'
    printf '%s\n\n' "$summary"
    printf '> Full guidance: see %s\n' "$relpath"
  } > "$output_file"

  write_generated_file "$CONSUMER_REPO/.cursor/rules/$id.mdc" "$output_file"
  rm -f "$output_file"
done < "$records_file"

commands_index=$(mktemp)
{
  generated_header
  printf '\n# Secure AI Code Library Cursor Commands\n\n'
  if emit_subagents_none_if_absent "$SUBAGENTS_ROOT"; then
    :
  else
    printf '## Subagents\n\n'
    find "$SUBAGENTS_ROOT" -type f -name subagent.yaml | sort | while IFS= read -r subagent_file; do
      subagent_id=$(yaml_scalar "$subagent_file" '.id')
      [ -n "$subagent_id" ] || subagent_id=$(basename "$(dirname "$subagent_file")")
      subagent_name=$(yaml_scalar "$subagent_file" '.name')
      [ -n "$subagent_name" ] || subagent_name=$subagent_id
      native_cursor=$(yaml_scalar "$subagent_file" '.tiers.native.cursor')
      [ -n "$native_cursor" ] || native_cursor="@$subagent_id"
      printf -- '- `%s` — %s (`%s`)\n' "$subagent_id" "$subagent_name" "$native_cursor"

      command_file=$(mktemp)
      {
        generated_header
        printf '\n# %s\n\n' "$subagent_name"
        printf 'Invoke `%s` when this repository needs the `%s` subagent.\n\n' "$native_cursor" "$subagent_id"
        printf 'Full subagent contract: `%s`.\n' "$(rule_relpath_for_file "$subagent_file")"
      } > "$command_file"
      write_generated_file "$CONSUMER_REPO/.cursor/commands/$subagent_id.md" "$command_file"
      rm -f "$command_file"
    done
  fi
} > "$commands_index"
write_generated_file "$CONSUMER_REPO/.cursor/commands/README.md" "$commands_index"
rm -f "$commands_index"
