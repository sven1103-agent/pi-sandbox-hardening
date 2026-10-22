#!/usr/bin/env bash
# Assert that the effective policy blocks all credential access.
# Exits non-zero if ANY probe leaks. Never prints secret values.
#
# Usage: selftest.sh [policy-file]
#
# Run from an UNCONFINED context (see probe.sh note).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
policy="${1:-$("$HERE/build-policy.sh" "$PWD")}"

[[ -f "$policy" ]] || { echo "policy not found: $policy" >&2; exit 2; }

fail=0
leaked=()

chk() { # name, shell-command
  local name="$1" cmd="$2" out rc
  out="$(sandbox-exec -f "$policy" -- /bin/sh -c "$cmd" 2>&1)"; rc=$?
  printf '%-34s ' "$name"
  if [[ $rc -eq 0 ]]; then
    echo "LEAK"; leaked+=("$name"); fail=1
  elif [[ "$out" == *"sandbox_apply: Operation not permitted"* ]]; then
    echo "INCONCLUSIVE (already sandboxed)"; fail=1
  else
    echo "ok"
  fi
}

echo "policy: $policy"
echo

# --- credential material ---
chk "keychain-db"        'head -c1 "$HOME/Library/Keychains/login.keychain-db"'
chk "security: gh token" '/usr/bin/security find-generic-password -s gh:github.com -w'
chk "security: personal" '/usr/bin/security find-generic-password -s gh:github.com -a sven1103 -w'
chk "gh auth token"      '/opt/homebrew/bin/gh auth token'
chk "gh hosts.yml"       'cat "$HOME/.config/gh/hosts.yml"'
chk "pi auth.json"       'cat "$HOME/.pi/agent/auth.json"'

# --- ssh material ---
chk "ssh-agent (ssh-add -l)" '/usr/bin/ssh-add -l'
chk "ssh id_rsa"         'head -c1 "$HOME/.ssh/id_rsa"'
chk "ssh id_ed25519"     'head -c1 "$HOME/.ssh/id_ed25519"'
chk "ssh id_human_ed25519"        'head -c1 "$HOME/.ssh/id_human_ed25519"'
chk "agent-github-key"   'head -c1 "$HOME/.agent/ssh/agent-github-key"'

# --- ambient secrets ---
chk "env HF_TOKEN_STRICT" '[ -n "${HF_TOKEN_STRICT:-}" ]'
chk "zshrc"              'cat "$HOME/.zshrc"'
chk "git-credentials"    'cat "$HOME/.git-credentials"'

echo
if [[ $fail -eq 0 ]]; then
  echo "PASS: no credential leaks detected"
else
  echo "FAIL: leaked -> ${leaked[*]}"
fi
exit "$fail"
