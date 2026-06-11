#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
LIB_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)

# shellcheck source=common.sh
. "$SCRIPT_DIR/common.sh"

TARGET=${TARGET:-}
CONSUMER_REPO=${CONSUMER_REPO:-}
ADAPTER_MODE=${ADAPTER_MODE:-write}
VERSION_ARG=
LIBRARY_PATH_IN_CONSUMER=

usage() {
  cat <<'USAGE'
Usage: adapters/install.sh --target cursor|copilot|agents-md|all --consumer-repo /path/to/repo [--dry-run|--check]

Options:
  --target, --ide       Adapter to run: cursor, copilot, agents-md, all.
  --consumer-repo       Consumer repository root.
  --dry-run             Print generated targets without writing.
  --check               Verify generated files match current registry output.
  --version             Override generated adapter version string.
  --library-path-in-consumer
                        Repo-relative library path for AGENTS.md footer.
  --auto                Alias for --target all.

Examples:
  ./install.sh --target cursor --consumer-repo /path/to/repo
  ./install.sh --target copilot --consumer-repo /path/to/repo
  ./install.sh --target agents-md --consumer-repo /path/to/repo
  ./install.sh --target all --consumer-repo /path/to/repo --dry-run
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target|--ide)
      [ "$#" -ge 2 ] || die "$1 requires a value"
      TARGET=$2
      shift 2
      ;;
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
      VERSION_ARG=$2
      shift 2
      ;;
    --library-path-in-consumer)
      [ "$#" -ge 2 ] || die "--library-path-in-consumer requires a path"
      LIBRARY_PATH_IN_CONSUMER=$2
      shift 2
      ;;
    --auto)
      TARGET=all
      shift
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

if [ -z "$TARGET" ]; then
  printf 'Adapter target (cursor, copilot, agents-md, all): '
  IFS= read -r TARGET
fi

if [ -z "$CONSUMER_REPO" ]; then
  printf 'Consumer repo path: '
  IFS= read -r CONSUMER_REPO
fi

[ -n "$CONSUMER_REPO" ] || die "Consumer repo is required"
[ -d "$CONSUMER_REPO" ] || die "Consumer repo does not exist: $CONSUMER_REPO"

run_adapter() {
  adapter=$1
  build_script="$SCRIPT_DIR/$adapter/build.sh"
  [ -x "$build_script" ] || die "Adapter build script is not executable: $build_script"

  args=(--consumer-repo "$CONSUMER_REPO")
  case "$ADAPTER_MODE" in
    dry-run) args+=(--dry-run) ;;
    check) args+=(--check) ;;
    write) ;;
    *) die "Unknown adapter mode: $ADAPTER_MODE" ;;
  esac
  if [ -n "$VERSION_ARG" ]; then
    args+=(--version "$VERSION_ARG")
  fi
  if [ "$adapter" = "agents-md" ] && [ -n "$LIBRARY_PATH_IN_CONSUMER" ]; then
    args+=(--library-path-in-consumer "$LIBRARY_PATH_IN_CONSUMER")
  fi

  "$build_script" "${args[@]}"
}

case "$TARGET" in
  cursor)
    run_adapter cursor
    ;;
  copilot)
    run_adapter copilot
    ;;
  agents-md)
    run_adapter agents-md
    ;;
  all)
    run_adapter cursor
    run_adapter copilot
    run_adapter agents-md
    ;;
  *)
    die "Unsupported target: $TARGET"
    ;;
esac
