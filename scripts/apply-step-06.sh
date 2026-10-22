#!/usr/bin/env bash
# Step 6 — close the personal gh config read/write grant.
#
# agent.sb carries the Safehouse core SCM grant:
#
#   agent.sb:740  (allow file-read* file-write*
#   agent.sb:741      (home-subpath "/.config/gh")   ;; gh auth tokens/config
#
# That is the PERSONAL gh config. Step 2 gave the agent its own
# (~/.agent/gh via GH_CONFIG_DIR), so the personal one is no longer needed.
#
# Measured before writing this:
#   - ~/.config/gh/hosts.yml holds NO oauth_token (96 bytes, metadata only);
#     the real personal token is in the login keychain as gh:github.com /
#     acct sven1103, which Step 3b already denies. So this is a metadata +
#     write-surface leak, not a credential leak.
#   - the grant also allows WRITE to ~/.config/gh (a config-tampering surface).
#   - the agent's own config is at ~/.agent/gh, a different path, and still
#     works (gh api user -> sven1103-agent) with this deny in place.
#
# Chosen approach: append a deny to grants.sb, which the launcher concatenates
# AFTER agent.sb. SBPL is last-match-wins, so the deny wins without editing the
# upstream-generated base policy (which a Safehouse upgrade may replace).
#
# Idempotent, backs up, refuses to run confined, verifies functionally.
#
# Usage: scripts/apply-step-06.sh [--dry-run]
set -euo pipefail

GRANTS="${SANDBOX_GRANTS:-$HOME/.config/sandbox-exec/grants.sb}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MARK_BEGIN=";; >>> pi-sandbox-hardening step-06 (personal gh config)"
MARK_END=";; <<< pi-sandbox-hardening step-06"

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

BLOCK="$(cat <<'BLOCK'
;; >>> pi-sandbox-hardening step-06 (personal gh config)
;; Deny the PERSONAL gh config. agent.sb's core SCM grant allows
;; file-read* AND file-write* on ~/.config/gh; Step 2 gave the agent its own
;; config at ~/.agent/gh (via GH_CONFIG_DIR), so the personal path is redundant.
;;
;; Verified: ~/.config/gh/hosts.yml contains no oauth_token (the real personal
;; token lives in the login keychain, denied by step-03b), so this is a metadata
;; and write-surface reduction rather than a credential fix. The write grant in
;; particular was a config-tampering surface.
;;
;; Last-match-wins: this must sit after agent.sb's allow. grants.sb is
;; concatenated after agent.sb by the launcher, so appending here is correct.
(deny file-read* file-write*
    (home-subpath "/.config/gh")
)
;; Keep directory traversal for tool discovery (mise, gh, git probe ~/.config).
(allow file-read-metadata
    (home-literal "/.config")
)
;; <<< pi-sandbox-hardening step-06
BLOCK
)"

if (( DRY )); then
  say "[dry-run] would append this block to grants.sb:"
  printf '%s\n' "$BLOCK" | sed 's/^/  /'
  exit 0
fi

if grep -qF "$MARK_BEGIN" "$GRANTS"; then
  say "step-06 block already present, nothing to do."
  exit 0
fi

cp -p "$GRANTS" "$GRANTS.bak-$STAMP"
printf '\n%s\n' "$BLOCK" >> "$GRANTS"
say "1. appended deny block"

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
  # MUST render the PATCHED grants.sb: build-policy.sh defaults to the live file,
  # which would verify the unpatched policy and report false failures.
  eff="$(SANDBOX_GRANTS="$GRANTS" "$SCRIPT_DIR/build-policy.sh" "$WD" /tmp/eff-step6.sb 2>/dev/null || true)"
  if [[ -n "$eff" && -f "$eff" ]]; then
    probe() { # label cmd expect_reachable(yes|no)
      local out
      if sandbox-exec -f "$eff" -- /usr/bin/env -i \
           PATH="/opt/homebrew/bin:/usr/bin:/bin" HOME="$HOME" TERM=xterm-256color \
           GH_CONFIG_DIR="$HOME/.agent/gh" /bin/sh -c "$2" >/dev/null 2>&1; then
        out=yes
      else
        out=no
      fi
      if [[ "$out" == "$3" ]]; then printf '   ok   %-34s %s\n' "$1" "$out"
      else printf '   FAIL %-34s %s (expected %s)\n' "$1" "$out" "$3"; return 1; fi
    }
    fail=0
    probe "personal gh hosts.yml (block)" 'head -c1 "$HOME/.config/gh/hosts.yml"' no || fail=1
    probe "personal gh config.yml (block)" 'head -c1 "$HOME/.config/gh/config.yml"' no || fail=1
    probe "personal gh dir list (block)"   'ls "$HOME/.config/gh"' no || fail=1
    probe "personal gh write (block)"      'touch "$HOME/.config/gh/.probe"' no || fail=1
    probe "~/.config traversal (allow)"    'ls "$HOME/.config"' yes || fail=1
    probe "agent gh config (allow)"        'head -c1 "$HOME/.agent/gh/hosts.yml"' yes || fail=1
    probe "agent gh api (allow)"           '/opt/homebrew/bin/gh api user --jq .login' yes || fail=1
    rm -f "$HOME/.config/gh/.probe" 2>/dev/null || true
    if (( fail )); then
      echo
      echo "ERROR: verification failed; restoring backup." >&2
      cp -p "$GRANTS.bak-$STAMP" "$GRANTS"
      exit 1
    fi
  fi
fi
rm -f /tmp/eff-step6.sb

cat <<EOF

DONE. Step 6 applied.

Record + diff:
  cd ~/git/pi-sandbox-hardening
  MODEL_ENDPOINT="<your-model-endpoint>" scripts/selftest.sh --record baseline-step6.tsv
  MODEL_ENDPOINT="<your-model-endpoint>" scripts/selftest.sh --diff baseline-step5.tsv

Expected: "human gh hosts.yml" REACHABLE/LEAK -> DENIED/ok. Everything else unchanged.

ROLLBACK:
  cp -p $GRANTS.bak-$STAMP $GRANTS
EOF
