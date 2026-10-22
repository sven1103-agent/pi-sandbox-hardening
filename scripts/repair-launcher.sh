#!/usr/bin/env bash
# Repair a launcher broken by the Step 2 patch (apply-step-02.sh before the fix).
#
# The original patch inserted `#` comment lines INSIDE a backslash-continued
# `env` call. Bash treats `#` as the start of a comment, so the command ended at
# `env TMUX="${TMUX:-}"` — `env` then ran with no command, dumped the environment
# and pi never started. (Also: that dump printed secrets to the terminal.)
#
# This script rewrites the launcher block so the comments precede the `env` call.
# Idempotent. Backs up first. Verifies functionally before declaring success.
#
# Usage: scripts/repair-launcher.sh [--dry-run]
set -euo pipefail

LAUNCHER="${SANDBOX_LAUNCHER:-$HOME/.config/sandbox-exec/run-sandboxed.sh}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

[[ -f "$LAUNCHER" ]] || { echo "ERROR: no launcher at $LAUNCHER" >&2; exit 1; }

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: run this from an UNCONFINED terminal." >&2
  exit 3
fi

echo "launcher: $LAUNCHER"
echo "backup:   $LAUNCHER.bak-$STAMP"
echo

if (( DRY )); then
  echo "[dry-run] would move comments out of the env continuation and re-verify"
  exit 0
fi

cp -p "$LAUNCHER" "$LAUNCHER.bak-$STAMP"

python3 - "$LAUNCHER" <<'PY'
import sys, os, stat
path = sys.argv[1]
src = open(path).read()

# Correct: comments BEFORE the exec line (never inside a continuation).
good = ('# Agent-scoped identity (Step 2): own gh token file + own gitconfig.\n'
        '# GIT_CONFIG_GLOBAL closes the ambient-keychain route via the host\n'
        '# global gitconfig (FINDINGS F12).\n'
        'exec sandbox-exec -f "$tmp_policy" \\\n'
        '  env \\\n'
        '    TMUX="${TMUX:-}" \\\n'
        '    GH_CONFIG_DIR="$HOME/.agent/gh" \\\n'
        '    GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \\\n'
        '    GIT_CONFIG_SYSTEM=/dev/null \\\n')

# Broken shapes we may encounter (comments inside the continuation).
broken_variants = [
    ('exec sandbox-exec -f "$tmp_policy" \\\n'
     '  env \\\n'
     '    TMUX="${TMUX:-}" \\\n'
     '    # agent-scoped identity (Step 2): own gh token file + own gitconfig.\n'
     '    # GIT_CONFIG_GLOBAL closes the ambient-keychain route via the host\n'
     '    # global gitconfig (FINDINGS F12).\n'
     '    GH_CONFIG_DIR="$HOME/.agent/gh" \\\n'
     '    GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \\\n'
     '    GIT_CONFIG_SYSTEM=/dev/null \\\n'),
    ('exec sandbox-exec -f "$tmp_policy" \\\n'
     '  # agent-scoped identity (Step 2): own gh token file + own gitconfig.\n'
     '  # GIT_CONFIG_GLOBAL closes the ambient-keychain route via the host\n'
     '  # global gitconfig (FINDINGS F12).\n'
     '  env \\\n'
     '    TMUX="${TMUX:-}" \\\n'
     '    GH_CONFIG_DIR="$HOME/.agent/gh" \\\n'
     '    GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \\\n'
     '    GIT_CONFIG_SYSTEM=/dev/null \\\n'),
]

mode = stat.S_IMODE(os.stat(path).st_mode)

if good in src:
    print("already correct (nothing to do)")
    sys.exit(0)

for bad in broken_variants:
    if bad in src:
        open(path, "w").write(src.replace(bad, good, 1))
        os.chmod(path, mode)
        print("repaired: moved comments out of the env continuation")
        sys.exit(0)

# Fall back: comment-out nothing, just report very loudly.
sys.exit("ERROR: could not find the patched block to repair. "
         "Restore from your backup manually.")
PY

echo
echo "functional verification:"
if "$SCRIPT_DIR/verify-launcher.sh" "$LAUNCHER" | sed 's/^/  /'; then
  echo
  echo "REPAIRED OK — open a NEW terminal before starting pi."
else
  echo
  echo "STILL BROKEN — restore the backup:" >&2
  echo "  cp -p $LAUNCHER.bak-$STAMP $LAUNCHER" >&2
  exit 1
fi
