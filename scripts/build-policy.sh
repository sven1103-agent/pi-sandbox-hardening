#!/usr/bin/env bash
# Render the effective pi sandbox policy for a given workdir.
#
# Mirrors ~/.config/sandbox-exec/run-sandboxed.sh exactly, so probes measure the
# real thing. WORK_DIR must be a realistic workdir ($HOME over-grants, see
# EVIDENCE.md E8).
#
# Usage: build-policy.sh [workdir] [outfile]
set -euo pipefail

POLICY_DIR="$HOME/.config/sandbox-exec"
BASE_POLICY="$POLICY_DIR/agent.sb"
GRANTS_FILE="$POLICY_DIR/grants.sb"
TMUX_PROFILE="$HOME/.safehouse-tmux.sb"

workdir="${1:-$PWD}"
out="${2:-/tmp/pi-effective-policy.sb}"

[[ -d "$workdir" ]] || { echo "workdir not found: $workdir" >&2; exit 1; }
workdir="$(cd "$workdir" && pwd -P)"

[[ -f "$BASE_POLICY" ]] || { echo "missing base policy: $BASE_POLICY" >&2; exit 1; }

sed "s|__SAFEHOUSE_REPLACE_ME_WITH_WORK_DIR_DEFINE__|(define WORK_DIR \"$workdir\")|g" \
    "$BASE_POLICY" > "$out"

cat >> "$out" <<WORKDIR_PROFILE

;; --- dynamic workdir grant (workdir: $workdir) ---
(allow file-read* file-write*
    (subpath "$workdir")
)
WORKDIR_PROFILE

if [[ -f "$GRANTS_FILE" ]]; then
  printf '\n;; --- grants.sb ---\n' >> "$out"
  cat "$GRANTS_FILE" >> "$out"
fi

if [[ -f "$TMUX_PROFILE" ]]; then
  printf '\n;; --- tmux/nvim ---\n' >> "$out"
  cat "$TMUX_PROFILE" >> "$out"
fi

echo "$out"
