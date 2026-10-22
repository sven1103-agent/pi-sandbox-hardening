#!/usr/bin/env bash
# Step 5 — environment sanitization.
#
# Replaces the launcher's inherited environment with an explicit allowlist
# (env -i), so secrets exported in ~/.zshrc can no longer reach pi or any
# subagent. Closes FINDINGS F5.
#
# Why this matters beyond pi itself: pi-subagents spawns each subagent as a new
# pi process with
#     runnerEnv = { ...omitGitRoutingEnv(omitExtensionBindingsEnv(process.env)), ... }
# i.e. it strips git/extension routing but NOT secrets. Sanitizing at the
# launcher therefore fixes pi AND every subagent at once, since they inherit
# from the parent pi process.
#
# Measured before writing this (see STEP-05-env-sanitization.md):
#   - env -i with this allowlist still resolves node/git/gh
#   - git-over-SSH authenticates as sven1103-agent with NO SSH_AUTH_SOCK
#     (agent ssh config sets IdentitiesOnly yes + explicit IdentityFile)
#   - gh api user -> sven1103-agent under the sanitized env
#   - keychain provider lookups work with no env at all inside the sandbox
#     (SECURITYSESSIONID is NOT needed)
#
# Idempotent, backs up, refuses to run confined, gates on verify-launcher.sh.
#
# Usage: scripts/apply-step-05.sh [--dry-run]
set -euo pipefail

LAUNCHER="${SANDBOX_LAUNCHER:-$HOME/.config/sandbox-exec/run-sandboxed.sh}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARK="pi-sandbox-hardening step-05"

DRY=0
if [[ "${1:-}" == "--dry-run" ]]; then DRY=1; fi

say() { printf '%s\n' "$*"; }

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: run this from an UNCONFINED terminal." >&2
  exit 3
fi
[[ -f "$LAUNCHER" ]] || { echo "ERROR: launcher not found: $LAUNCHER" >&2; exit 1; }

say "launcher: $LAUNCHER"
say "backup  : $LAUNCHER.bak-$STAMP"
say

if grep -q "step-05" "$LAUNCHER"; then
  say "step-05 already applied to this launcher, nothing to do."
  say "To re-apply, restore the backup first."
  exit 0
fi

if ! grep -q '^exec sandbox-exec' "$LAUNCHER"; then
  echo "ERROR: no 'exec sandbox-exec' line found — unexpected launcher layout." >&2
  exit 1
fi

NEW_BLOCK="$(cat <<'BLOCK'
# --- pi-sandbox-hardening step-05: sanitized environment --------------------
# Started from an EMPTY environment. 'env' without -i only ADDS variables, so
# secrets exported in ~/.zshrc (SSH_AUTH_SOCK, *_TOKEN) used to reach pi AND
# every subagent, regardless of the sandbox: environment variables are not a
# filesystem concept, so no SBPL grant or deny can constrain them (FINDINGS F5).
#
# Every variable below was measured as needed; everything else is dropped.
# Notably dropped: SSH_AUTH_SOCK (git-over-SSH uses the agent key with
# IdentitiesOnly, verified working without it) and any *_TOKEN.
#
# Comments MUST stay above the exec line: a '#' inside the backslash-continued
# command truncates it and pi never starts (see STEP-02 incident).
env_args=(
  PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  HOME="$HOME"
  USER="${USER:-$(id -un)}"
  LOGNAME="${LOGNAME:-$(id -un)}"
  SHELL="${SHELL:-/bin/zsh}"
  TMPDIR="${TMPDIR:-/tmp}"
  TERM="${TERM:-xterm-256color}"
  COLORTERM="${COLORTERM:-}"
  LANG="${LANG:-en_US.UTF-8}"
  EDITOR="${EDITOR:-}"
  VISUAL="${VISUAL:-}"
  TMUX="${TMUX:-}"
  GH_CONFIG_DIR="$HOME/.agent/gh"
  GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig"
  GIT_CONFIG_SYSTEM=/dev/null
)

# Pass through only pi configuration vars that are already set.
for _opt in PI_OFFLINE PI_SKIP_VERSION_CHECK PI_TIMING PI_CODING_AGENT_DIR PI_PACKAGE_DIR PI_SUBAGENT_PI_BINARY; do
  if [[ -n "${!_opt:-}" ]]; then
    env_args+=("$_opt=${!_opt}")
  fi
done
unset _opt

# Loudly report anything sensitive we are dropping, so the change is visible.
for _bad in SSH_AUTH_SOCK SSH_AGENT_PID; do
  if [[ -n "${!_bad:-}" ]]; then
    printf 'step-05: dropping inherited %s from the sandboxed environment\n' "$_bad" >&2
  fi
done
unset _bad

exec sandbox-exec -f "$tmp_policy" env -i "${env_args[@]}" /opt/homebrew/bin/pi ${passthrough_args[@]+"${passthrough_args[@]}"}
BLOCK
)"

if (( DRY )); then
  say "[dry-run] would replace the current exec block:"
  say "--- from ---"
  sed -n '/^exec sandbox-exec/,$p' "$LAUNCHER" | sed 's/^/  /'
  say "--- to ---"
  printf '%s\n' "$NEW_BLOCK" | sed 's/^/  /'
  exit 0
fi

# --- apply ------------------------------------------------------------------

cp -p "$LAUNCHER" "$LAUNCHER.bak-$STAMP"
say "1. backup written"

python3 - "$LAUNCHER" "$NEW_BLOCK" <<'PY'
import sys, os, stat
path, new_block = sys.argv[1], sys.argv[2]
src = open(path).read()
marker = "\nexec sandbox-exec"
idx = src.find(marker)
if idx == -1:
    sys.exit("ERROR: exec line not found")
head = src[:idx].rstrip("\n")
mode = stat.S_IMODE(os.stat(path).st_mode)
open(path, "w").write(head + "\n\n" + new_block)
os.chmod(path, mode)
print("   replaced exec block")
PY

bash -n "$LAUNCHER" || { echo "ERROR: launcher syntax error; restoring" >&2; cp -p "$LAUNCHER.bak-$STAMP" "$LAUNCHER"; exit 1; }
say "   launcher syntax ok"

# --- gate -------------------------------------------------------------------

say
say "2. verify-launcher.sh gate"
if "$SCRIPT_DIR/verify-launcher.sh" "$LAUNCHER" > /tmp/vl5.out 2>&1; then
  sed 's/^/   /' /tmp/vl5.out
else
  sed 's/^/   /' /tmp/vl5.out
  echo
  echo "ERROR: launcher no longer starts pi correctly. Restoring backup." >&2
  cp -p "$LAUNCHER.bak-$STAMP" "$LAUNCHER"
  echo "  restored: $LAUNCHER" >&2
  exit 1
fi
rm -f /tmp/vl5.out

# --- behavioural proof ------------------------------------------------------

say
say "3. behavioural proof"
stub="$(mktemp -d)"
trap 'rm -rf "$stub"' EXIT
cat > "$stub/sandbox-exec" <<'EOF'
#!/bin/sh
printf 'ARGV:'
for a in "$@"; do printf ' [%s]' "$a"; done
printf '\n'
exit 0
EOF
chmod +x "$stub/sandbox-exec"
out="$(env -i PATH="$stub:/usr/bin:/bin" HOME="$HOME" \
        SSH_AUTH_SOCK="/tmp/fake-agent.sock" HF_TOKEN_STRICT="sentinel-value" \
        /bin/bash "$LAUNCHER" 2>&1)"
argv="$(printf '%s\n' "$out" | grep '^ARGV:' | head -1)"

chk() { # label  present|absent  var
  # Match the bracketed argv token, not a substring: PATH contains ".../bin:"
  # and would otherwise make "/opt/homebrew/bin/pi" appear always-present.
  if printf '%s' "$argv" | grep -q "\[$3="; then have=present; else have=absent; fi
  if [[ "$2" == "$have" ]]; then printf '   ok   %-22s %s\n' "$1" "$have"
  else printf '   FAIL %-22s %s (expected %s)\n' "$1" "$have" "$2"; return 1; fi
}
fail=0
if printf '%s' "$argv" | grep -q '\[/opt/homebrew/bin/pi\]$'; then
  printf '   ok   %-22s present\n' "pi invoked (last argv)"
else
  printf '   FAIL %-22s absent — env call truncated?\n' "pi invoked (last argv)"; fail=1
fi
chk "HOME"            present  HOME            || fail=1
chk "PATH"            present  PATH            || fail=1
chk "GH_CONFIG_DIR"   present  GH_CONFIG_DIR   || fail=1
chk "GIT_CONFIG_GLOBAL" present GIT_CONFIG_GLOBAL || fail=1
chk "GIT_CONFIG_SYSTEM" present GIT_CONFIG_SYSTEM || fail=1
chk "SSH_AUTH_SOCK"   absent   SSH_AUTH_SOCK   || fail=1
chk "HF_TOKEN_STRICT" absent   HF_TOKEN_STRICT || fail=1

if (( fail )); then
  echo
  echo "ERROR: sanitization did not behave as expected. Restoring backup." >&2
  cp -p "$LAUNCHER.bak-$STAMP" "$LAUNCHER"
  exit 1
fi

cat <<EOF

DONE. Step 5 applied.

Verify in a NEW terminal (policy + env are bound at launch):
  ~/.config/sandbox-exec/run-sandboxed.sh

Then inside that session:
  printenv SSH_AUTH_SOCK           # must print nothing
  ssh-add -l                       # must fail to connect to the agent
  gh api user --jq .login          # must print sven1103-agent
  git ls-remote git@github.com:example-org/example-app HEAD   # SSH must work
  security find-generic-password -ws litellm | head -c4       # providers must work
  # and a subagent must still reach its model

Record + diff:
  scripts/selftest.sh --record baseline-step5.tsv
  scripts/selftest.sh --diff baseline-step3b.tsv

ROLLBACK:
  cp -p $LAUNCHER.bak-$STAMP $LAUNCHER
EOF
