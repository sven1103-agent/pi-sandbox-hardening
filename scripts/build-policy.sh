#!/usr/bin/env bash
# Render the effective pi sandbox policy for a given workdir.
#
# Mirrors ~/.config/sandbox-exec/run-sandboxed.sh exactly, so probes measure the
# real thing. WORK_DIR must be a realistic workdir ($HOME over-grants, see
# EVIDENCE.md E8).
#
# Usage: build-policy.sh [workdir] [outfile]
set -euo pipefail

# POLICY_DIR is overridable so tests can render a REPLICA policy dir instead of
# the live one (apply-step-*.sh verification needs the patched copy, otherwise it
# silently verifies the unpatched policy).
POLICY_DIR="${SANDBOX_POLICY_DIR:-$HOME/.config/sandbox-exec}"
BASE_POLICY="$POLICY_DIR/agent.sb"
GRANTS_FILE="${SANDBOX_GRANTS:-$POLICY_DIR/grants.sb}"
TMUX_PROFILE="${SANDBOX_TMUX_PROFILE:-$HOME/.safehouse-tmux.sb}"

workdir="${1:-$PWD}"
out="${2:-/tmp/pi-effective-policy.sb}"

[[ -d "$workdir" ]] || { echo "workdir not found: $workdir" >&2; exit 1; }
workdir="$(cd "$workdir" && pwd -P)"

# Guard against the F1/F11 artifact: a workdir of $HOME (or an ancestor of it)
# appends `(allow file-read* file-write* (subpath "$HOME"))`, which exposes
# ~/.ssh, ~/.zshrc and the keychain — producing false "LEAK" results.
if [[ "$workdir" == "$HOME" ]]; then
  cat >&2 <<'EOF'
ERROR: refusing to build a policy with workdir=$HOME.

That appends a whole-home read/write grant, which hides the very paths this
repo exists to protect (~/.ssh, ~/.zshrc, ~/Library/Keychains) and makes
probes report false leaks. This was the cause of the retracted F1 finding.

Re-run from a real repository/workdir, e.g.:
  cd ~/git/<some-repo> && scripts/selftest.sh
EOF
  exit 2
fi

# Fail loudly if we are already inside a sandbox (nested sandbox-exec is refused),
# so probes are not misread as "denied".
if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "WARNING: nested sandbox-exec is refused — are you already inside a sandbox?" >&2
  echo "         Run build-policy.sh/selftest.sh from an UNCONFINED terminal (see P0.3)." >&2
fi

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
