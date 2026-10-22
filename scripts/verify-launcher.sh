#!/usr/bin/env bash
# Verify that a sandbox launcher still actually INVOKES pi with the intended
# agent-scoped env after patching.
#
# Why this exists: a `#` comment inside a backslash-continued `env` call silently
# truncates the command, so the launcher runs `env` with no arguments — it dumps
# the environment and NEVER starts pi. `bash -n` does NOT catch this (it is not a
# syntax error), and grepping for the vars does not either. Only executing the
# launcher with a stub sandbox-exec reveals it.
#
# SAFE: runs with a sanitized environment (env -i) and a stub sandbox-exec that
# only prints its argv. No real sandbox is created and no secrets are printed.
#
# Usage: scripts/verify-launcher.sh [launcher-path]
# Exit: 0 ok · 1 broken · 2 usage
set -uo pipefail

LAUNCHER="${1:-$HOME/.config/sandbox-exec/run-sandboxed.sh}"
[[ -f "$LAUNCHER" ]] || { echo "usage: verify-launcher.sh <launcher>" >&2; exit 2; }

stub="$(mktemp -d)"
trap 'rm -rf "$stub"' EXIT

# Stub sandbox-exec: print argv and stop (never exec anything).
cat > "$stub/sandbox-exec" <<'EOF'
#!/bin/sh
printf 'ARGV:'
for a in "$@"; do printf ' [%s]' "$a"; done
printf '\n'
exit 0
EOF
chmod +x "$stub/sandbox-exec"

# Run with an EMPTY environment so nothing sensitive is ever printed or inherited.
out="$(env -i PATH="$stub:/usr/bin:/bin" HOME="${HOME:-/tmp}" TMUX="" \
        /bin/bash "$LAUNCHER" 2>&1)"
rc=$?

echo "$out" | sed 's/^/  /'
echo

fail=0
if ! printf '%s' "$out" | grep -q 'ARGV:'; then
  echo "FAIL: launcher did not reach sandbox-exec at all (rc=$rc)"; exit 1
fi

argv="$(printf '%s\n' "$out" | grep '^ARGV:' | head -1)"

# 1) pi must still be the command passed to sandbox-exec
if printf '%s' "$argv" | grep -q '/opt/homebrew/bin/pi'; then
  echo "ok   pi is still invoked"
else
  echo "FAIL: pi is NOT in the argv — the env call is truncated (bare 'env' runs"
  echo "      with no command, dumps the environment, and pi never starts)"
  fail=1
fi

# 2) the agent identity must be in the child env
for v in GH_CONFIG_DIR GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM; do
  if printf '%s' "$argv" | grep -q "$v="; then
    echo "ok   $v present"
  else
    echo "FAIL: $v missing from the child env"
    fail=1
  fi
done

# 3) the launcher must not have clobbered the user-wide keychain search list.
# The launcher runs to completion here (stub sandbox-exec), so any list change
# it makes would be observable — catch that, and restore if needed.
if ! security list-keychains 2>/dev/null | grep -qF "login.keychain-db"; then
  echo "FAIL: launcher removed the login keychain from the search list"
  security list-keychains -s "$HOME/Library/Keychains/login.keychain-db" \
      /Library/Keychains/System.keychain >/dev/null 2>&1 || true
  echo "      (restored)"
  fail=1
else
  echo "ok   login keychain still in the search list"
fi

exit "$fail"
