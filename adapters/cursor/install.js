#!/usr/bin/env bash
set -euo pipefail

# Node-free compatibility entrypoint. The .js name is intentional for
# environments that look for adapter install.js files; the implementation is
# pure Bash and delegates to the canonical Cursor build script.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "$SCRIPT_DIR/build.sh" "$@"
