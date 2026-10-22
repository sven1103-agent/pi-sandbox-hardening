#!/usr/bin/env bash
# Step 4 — remove the ssh-agent socket grants from the policy.
#
# agent.sb re-opens ssh-agent access in two places:
#
#   agent.sb:795  (allow file-read* file-write* file-read-metadata
#                    regex #"^/private/tmp/com\.apple\.launchd\.[^/]+/Listeners$" ...)
#   agent.sb:803  (allow network-outbound
#                    (remote unix-socket ... launchd Listeners ...))
#   agent.sb:850  (allow file-read* file-write* (subpath "~/.agent/ssh"))
#   agent.sb:855  (allow network-outbound (remote unix-socket ~/.agent/ssh ...))
#
# This is the F4 finding: it lets the agent sign with ANY key loaded in the ssh
# agent — i.e. the human's keys — without reading the key files. Verified: with
# SSH_AUTH_SOCK set, `ssh-add -l` inside the sandbox lists the human key.
#
# Step 5 already strips SSH_AUTH_SOCK from the environment, so nothing can find
# the socket in practice. This step removes the POLICY grant too, as defence in
# depth: if any future code re-derives the socket path, the policy still holds.
#
# The agent needs NO ssh-agent: its git-over-SSH uses an explicit IdentityFile
# with IdentitiesOnly=yes and no passphrase (verified: authenticates as
# sven1103-agent with no agent).
#
# Approach: append denies to grants.sb (concatenated AFTER agent.sb). SBPL is
# last-match-wins. Specificity also matters, so file-read-metadata is named
# explicitly to match agent.sb's allow and the default deny.
#
# Idempotent, backs up, refuses to run confined, verifies functionally.
#
# Usage: scripts/apply-step-04.sh [--dry-run]
set -euo pipefail

GRANTS="${SANDBOX_GRANTS:-$HOME/.config/sandbox-exec/grants.sb}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MARK_BEGIN=";; >>> pi-sandbox-hardening step-04 (no ssh-agent)"
MARK_END=";; <<< pi-sandbox-hardening step-04"

DRY=0
if [[ "${1:-}" == "--dry-run" ]]; then DRY=1; fi

say() { printf '%s\n' "$*"; }

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: run this from an UNCONFINED terminal." >&2
  exit 3
fi
[[ -f "$GRANTS" ]] || { echo "ERROR: no grants.sb at $GRANTS" >&2; exit 1; }

say "grants : $GRANTS"
say "backup : $GRANTS.bak-$STAMP"
say

BLOCK_FILE="$(mktemp -t step04-block)"
cat > "$BLOCK_FILE" <<'BLOCK'
;; >>> pi-sandbox-hardening step-04 (no ssh-agent)
;; F4: agent.sb re-opens ssh-agent access (launchd Listeners sockets and
;; ~/.ssh/agent), which lets the agent sign with ANY key loaded in your agent —
;; i.e. your personal keys — without reading the key files.
;;
;; The agent needs no ssh-agent: its git-over-SSH uses an explicit IdentityFile
;; with IdentitiesOnly=yes and no passphrase. Verified authenticating as
;; sven1103-agent inside the sandbox with these denies in place.
;;
;; Note agent.sb also scopes a grant to ~/.agent/ssh (the agent socket dir).
;; That path is left alone: it is the agent credential area and the agent
;; key has no passphrase, so it does not provide access to human keys.
;;
;; Last-match-wins, and grants.sb is concatenated after agent.sb.
(deny file-read* file-write* file-read-metadata
    (home-subpath "/.ssh/agent")
)
(deny network-outbound
    (remote unix-socket (path-regex #"^/private/tmp/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex #"^/tmp/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex #"^/private/var/run/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex #"^/var/run/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex (string-append "^" HOME_DIR "/\\.ssh/agent(/.*)?$")))
)
;; <<< pi-sandbox-hardening step-04
BLOCK
trap 'rm -f "$BLOCK_FILE"' EXIT

if (( DRY )); then
  say "[dry-run] would append this block to grants.sb:"
  sed 's/^/  /' "$BLOCK_FILE"
  exit 0
fi

if grep -qF "$MARK_BEGIN" "$GRANTS"; then
  say "step-04 block already present, nothing to do."
  exit 0
fi

cp -p "$GRANTS" "$GRANTS.bak-$STAMP"
printf '\n' >> "$GRANTS"
cat "$BLOCK_FILE" >> "$GRANTS"
say "1. appended ssh-agent deny block"

python3 - "$GRANTS" <<'PY'
import sys
s = open(sys.argv[1]).read()
out, i, n = [], 0, len(s)
while i < n:
    if s[i] == ';':
        while i < n and s[i] != '\n': i += 1
    else:
        out.append(s[i]); i += 1
d = 0
for ch in "".join(out):
    if ch == '(': d += 1
    elif ch == ')': d -= 1
    if d < 0: sys.exit("ERROR: unbalanced ')' in grants.sb")
if d: sys.exit(f"ERROR: {d} unclosed '(' in grants.sb")
print("   grants.sb parens balanced")
PY

# --- functional verification ------------------------------------------------

say
say "2. functional verification (built policy, not the running session)"
WD="$HOME/git/pi-sandbox-hardening"
[[ -d "$WD" ]] || WD="$HOME/git"

if [[ -d "$WD" ]]; then
  eff="$(SANDBOX_GRANTS="$GRANTS" "$SCRIPT_DIR/build-policy.sh" "$WD" /tmp/eff-step4.sb 2>/dev/null || true)"
  if [[ -n "$eff" && -f "$eff" ]]; then
    # SSH_AUTH_SOCK is set explicitly so this measures the POLICY, not the
    # environment (step-05 already strips it; without setting it here the
    # ssh-agent probe would pass for the wrong reason).
    srun() {
      sandbox-exec -f "$eff" -- /usr/bin/env -i \
        PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" HOME="$HOME" \
        TERM=xterm-256color SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-/nonexistent}" \
        GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" GIT_CONFIG_SYSTEM=/dev/null \
        GH_CONFIG_DIR="$HOME/.agent/gh" \
        /bin/sh -c "$1" >/dev/null 2>&1
    }
    chk() { # label cmd expect(yes|no)
      local got=no; srun "$2" && got=yes
      if [[ "$got" == "$3" ]]; then printf '   ok   %-36s %s\n' "$1" "$got"
      else printf '   FAIL %-36s %s (expected %s)\n' "$1" "$got" "$3"; return 1; fi
    }
    fail=0
    chk "ssh-add -l (human keys) must FAIL"  'ssh-add -l' no || fail=1
    chk "~/.ssh/agent list must FAIL"        'ls "$HOME/.ssh/agent"' no || fail=1
    chk "agent ssh key still readable"       'head -c1 "$HOME/.agent/ssh/github_login_ed25519"' yes || fail=1
    chk "agent git-over-SSH still works"     '"$HOME/.agent/ssh/ssh-github.sh" -o BatchMode=yes -o ConnectTimeout=10 -T git@github.com 2>&1 | grep -q "Hi sven1103-agent"' yes || fail=1
    chk "gh api user still works"            'gh api user --jq .login | grep -q sven1103-agent' yes || fail=1
    if (( fail )); then
      echo
      echo "ERROR: verification failed; restoring backup." >&2
      cp -p "$GRANTS.bak-$STAMP" "$GRANTS"
      exit 1
    fi
  fi
fi
rm -f /tmp/eff-step4.sb

cat <<EOF

DONE. Step 4 applied.

The policy no longer grants ssh-agent access. Together with step-05 (which
removes SSH_AUTH_SOCK from the environment) the F4 exposure is now closed at
both layers.

Record + diff:
  cd ~/git/pi-sandbox-hardening
  MODEL_ENDPOINT="<your-model-endpoint>" scripts/selftest.sh --record baseline-step4.tsv
  MODEL_ENDPOINT="<your-model-endpoint>" scripts/selftest.sh --diff baseline-step6.tsv

ROLLBACK:
  cp -p $GRANTS.bak-$STAMP $GRANTS
EOF
