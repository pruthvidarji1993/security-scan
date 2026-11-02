#!/usr/bin/env bash
# Security-scan one project. Usage: run.sh [project-path]   (default: current directory)
# Works from a clone of this repo, or copied/downloaded on its own: if scan.py is not
# next to this script it clones the repo to $SECURITY_SCAN_HOME (default ~/.cache/security-scan)
# and updates it on each run.
set -euo pipefail
REPO="https://github.com/pruthvidarji1993/security-scan.git"
DIR="${SECURITY_SCAN_HOME:-$HOME/.cache/security-scan}"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || true)"

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "$SELF/scan.py" ] && [ -d "$SELF/skill" ]; then
  DIR="$SELF"
elif [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull -q --ff-only || echo "warning: could not update $DIR, using the existing copy" >&2
else
  git clone -q --depth 1 "$REPO" "$DIR"
fi

exec python3 "$DIR/scan.py" "${1:-.}"
