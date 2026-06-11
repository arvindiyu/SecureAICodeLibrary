#!/usr/bin/env bash
# shellcheck shell=bash
# hooks/install.sh — Wire hooks/pre-commit.sh into a consumer repository
#
# Supports four actions:
#   --install  (default)  Symlink .git/hooks/pre-commit → hooks/pre-commit.sh
#   --uninstall           Remove the symlink (restores any backup)
#   --check               Verify the symlink is in place and points correctly
#   --use-pre-commit-framework   Print a .pre-commit-config.yaml snippet
#
# USAGE
#   # From consumer project root (after cloning the library):
#   .secure-ai-code-library/hooks/install.sh
#   .secure-ai-code-library/hooks/install.sh --check
#   .secure-ai-code-library/hooks/install.sh --uninstall
#   .secure-ai-code-library/hooks/install.sh --use-pre-commit-framework
#   .secure-ai-code-library/hooks/install.sh --consumer-root /path/to/repo
#
# EXIT CODES
#   0   success
#   1   operation failed
#   64  bad CLI arguments

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
LIBRARY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly LIBRARY_ROOT

readonly PRE_COMMIT_SH="${SCRIPT_DIR}/pre-commit.sh"

# Mutable state
CONSUMER_ROOT="${PWD}"
ACTION="install"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
info()  { printf '[install.sh] INFO:  %s\n' "$*"; }
warn()  { printf '[install.sh] WARN:  %s\n' "$*" >&2; }
error() { printf '[install.sh] ERROR: %s\n' "$*" >&2; }
ok()    { printf '[install.sh] OK:    %s\n' "$*"; }

die() {
  local code="$1"; shift
  error "$*"
  exit "${code}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
  cat <<'EOF'
hooks/install.sh — Wire hooks/pre-commit.sh into a consumer repo

ACTIONS (mutually exclusive; default: --install)
  --install                 Symlink .git/hooks/pre-commit → hooks/pre-commit.sh
  --uninstall               Remove the symlink (restores backup if present)
  --check                   Verify symlink is present and points at the right script
  --use-pre-commit-framework  Print a .pre-commit-config.yaml snippet to stdout

OPTIONS
  --consumer-root <path>    Target repo root (default: current working directory)
  --help                    Print this message and exit

EXAMPLES
  # Wire the hook (run from consumer project root):
  .secure-ai-code-library/hooks/install.sh

  # Verify installation:
  .secure-ai-code-library/hooks/install.sh --check

  # Emit pre-commit framework snippet:
  .secure-ai-code-library/hooks/install.sh --use-pre-commit-framework \
    >> .pre-commit-config.yaml

  # Remove hook:
  .secure-ai-code-library/hooks/install.sh --uninstall
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)
      ACTION="install"
      shift
      ;;
    --uninstall)
      ACTION="uninstall"
      shift
      ;;
    --check)
      ACTION="check"
      shift
      ;;
    --use-pre-commit-framework)
      ACTION="framework"
      shift
      ;;
    --consumer-root)
      [[ $# -ge 2 ]] || die 64 "--consumer-root requires a path argument."
      CONSUMER_ROOT="$2"
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
      die 64 "Unexpected argument: '$1'. Run --help for usage."
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Resolve consumer root
# ---------------------------------------------------------------------------
CONSUMER_ROOT="$(cd "${CONSUMER_ROOT}" 2>/dev/null && pwd)" \
  || die 1 "Cannot resolve consumer root: ${CONSUMER_ROOT}"

readonly GIT_HOOKS_DIR="${CONSUMER_ROOT}/.git/hooks"
readonly TARGET_LINK="${GIT_HOOKS_DIR}/pre-commit"
readonly BACKUP_FILE="${TARGET_LINK}.bak"

# ---------------------------------------------------------------------------
# Helper: compute the best link target (relative when possible, absolute fallback)
# A relative symlink survives when the library directory is renamed.
# ---------------------------------------------------------------------------
_compute_link_target() {
  # GNU coreutils realpath --relative-to is available on Linux; not on macOS.
  if command -v realpath &>/dev/null \
      && realpath --relative-to="${GIT_HOOKS_DIR}" "${PRE_COMMIT_SH}" &>/dev/null; then
    realpath --relative-to="${GIT_HOOKS_DIR}" "${PRE_COMMIT_SH}"
  else
    # Absolute path fallback
    echo "${PRE_COMMIT_SH}"
  fi
}

# ---------------------------------------------------------------------------
# Helper: resolve the canonical real path of a file (macOS / Linux portable)
# ---------------------------------------------------------------------------
_realpath() {
  if command -v realpath &>/dev/null; then
    realpath "$1" 2>/dev/null || echo "$1"
  else
    # POSIX fallback via pwd
    local dir
    dir=$(cd "$(dirname "$1")" 2>/dev/null && pwd)
    echo "${dir}/$(basename "$1")"
  fi
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

do_install() {
  # Validate prerequisites
  [[ -d "${GIT_HOOKS_DIR}" ]] \
    || die 1 "${GIT_HOOKS_DIR} not found. Run inside a Git repository, or use --consumer-root."

  [[ -f "${PRE_COMMIT_SH}" ]] \
    || die 1 "pre-commit.sh not found at ${PRE_COMMIT_SH}. Library installation may be incomplete."

  chmod +x "${PRE_COMMIT_SH}" \
    || warn "Could not chmod +x ${PRE_COMMIT_SH}. You may need to do this manually."

  # Back up any existing non-symlink hook
  if [[ -e "${TARGET_LINK}" && ! -L "${TARGET_LINK}" ]]; then
    warn "${TARGET_LINK} exists and is a regular file (existing hook)."
    warn "Backing up to ${BACKUP_FILE}"
    mv "${TARGET_LINK}" "${BACKUP_FILE}"
    ok "Backup created: ${BACKUP_FILE}"
  fi

  local link_target
  link_target="$(_compute_link_target)"

  ln -sf "${link_target}" "${TARGET_LINK}"
  ok "Installed: ${TARGET_LINK} -> ${link_target}"

  # Verify immediately
  if do_check &>/dev/null; then
    ok "Verification passed. The hook is active for your next commit."
  else
    warn "Verification failed after install — check manually with --check."
  fi
}

do_uninstall() {
  if [[ -L "${TARGET_LINK}" ]]; then
    rm "${TARGET_LINK}"
    ok "Removed symlink: ${TARGET_LINK}"
    if [[ -f "${BACKUP_FILE}" ]]; then
      mv "${BACKUP_FILE}" "${TARGET_LINK}"
      ok "Restored backup: ${BACKUP_FILE} -> ${TARGET_LINK}"
    fi
  elif [[ -e "${TARGET_LINK}" ]]; then
    warn "${TARGET_LINK} exists but is not a symlink (was not installed by this script)."
    warn "Remove it manually if you no longer need it."
    exit 1
  else
    info "${TARGET_LINK} does not exist — nothing to uninstall."
  fi
}

do_check() {
  if [[ ! -L "${TARGET_LINK}" ]]; then
    error "NOT INSTALLED: ${TARGET_LINK} is not a symlink."
    info "  Run: hooks/install.sh --install"
    exit 1
  fi

  local resolved_link
  resolved_link=$(_realpath "${TARGET_LINK}")
  local expected
  expected=$(_realpath "${PRE_COMMIT_SH}")

  if [[ "${resolved_link}" == "${expected}" ]]; then
    ok "Installed: ${TARGET_LINK} -> ${resolved_link}"
  else
    error "MISMATCH: ${TARGET_LINK} -> ${resolved_link}"
    error "  Expected:  -> ${expected}"
    info "  Re-run: hooks/install.sh --install"
    exit 1
  fi
}

do_framework() {
  # Emit a .pre-commit-config.yaml snippet to stdout.
  # The caller can redirect (>>) into their existing .pre-commit-config.yaml.
  cat <<'YAML'
# ---------------------------------------------------------------------------
# Secure AI Code Library — pre-commit framework hook snippet
# Source: https://github.com/arvindiyu/SecureAICodeLibrary
#
# Add this block to your .pre-commit-config.yaml (or create that file).
# Requires: https://pre-commit.com  (pip install pre-commit)
# ---------------------------------------------------------------------------
repos:
  - repo: local
    hooks:
      - id: secureaicodelibrary
        name: Secure AI Code Library — scan gate
        entry: ./.secure-ai-code-library/hooks/pre-commit.sh
        language: system
        pass_filenames: false
        stages: [pre-commit]
        # Pass --all to scan all tracked files (slow; use in CI only):
        # args: [--all]
YAML
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "${ACTION}" in
  install)   do_install ;;
  uninstall) do_uninstall ;;
  check)     do_check ;;
  framework) do_framework ;;
esac
