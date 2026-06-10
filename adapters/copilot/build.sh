#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
LIB_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)
RULES_ROOT="$LIB_ROOT/registry/rules"
CONSUMER_REPO=${CONSUMER_REPO:-$(pwd)}
ADAPTER_MODE=${ADAPTER_MODE:-write}
MAX_CHARS=${SECUREAI_COPILOT_MAX_CHARS:-8000}

# shellcheck source=../common.sh
. "$LIB_ROOT/adapters/common.sh"

usage() {
  cat <<'USAGE'
Usage: adapters/copilot/build.sh --consumer-repo /path/to/repo [--dry-run|--check] [--version vX.Y.Z]

Generates:
  .github/copilot-instructions.md
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
output_file=$(mktemp)
trap 'rm -f "$records_file" "$output_file"' EXIT
collect_rule_records "$RULES_ROOT" "$records_file"
validate_tier0_present "$records_file"

{
  generated_header
  printf '\n# Secure AI Code Library Instructions\n\n'
  printf 'This project uses the Secure AI Code Library as a secure-by-design AI control plane: keep Tier 0 controls always in force, use this file as a compact rule index, and load full registry YAML only when a rule path or matching scope is relevant.\n\n'
  printf '## Tier 0 Always-On Rules\n\n'
  for tier0_id in $TIER0_RULE_IDS; do
    awk -F '\t' -v id="$tier0_id" '$2 == id { print $3 }' "$records_file" | while IFS= read -r rule_file; do
      summary=$(yaml_scalar "$rule_file" '.summary')
      printf -- '- `%s` — %s\n' "$tier0_id" "$summary"
    done
  done

  printf '\n## Scoped Rule Index\n\n'
  while IFS="$(printf '\t')" read -r category id rule_file; do
    if is_tier0_rule "$id"; then
      continue
    fi
    summary=$(yaml_scalar "$rule_file" '.summary')
    relpath=$(rule_relpath_for_file "$rule_file")
    printf -- '- `%s` — %s (`%s`)\n' "$id" "$summary" "$relpath"
  done < "$records_file"

  printf '\n## Full Guidance\n\n'
  printf 'Load full rule content on demand from `registry/rules/<category>/<id>.rule.yaml`; start discovery with `registry/INDEX.md`. Do not inline full rule bodies into Copilot instructions.\n'
} > "$output_file"

char_count=$(wc -c < "$output_file" | tr -d ' ')
if [ "$char_count" -gt "$MAX_CHARS" ]; then
  die ".github/copilot-instructions.md would be ${char_count} chars, exceeding ${MAX_CHARS} chars (~2000 tokens)"
fi

write_generated_file "$CONSUMER_REPO/.github/copilot-instructions.md" "$output_file"
