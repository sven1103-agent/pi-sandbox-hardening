#!/usr/bin/env bash
# Step 3b-2 — replace the (removed) wide keychain grant with the narrow
# agent-keychain form.
#
# Result: the agent can read ITS OWN keychain, while the login keychain and
# System.keychain are unreachable. This is what keeps every provider working
# (pi's auth.json resolves keys via `security find-generic-password -ws <svc>`)
# without exposing your personal credentials.
#
# Design is measurement-driven (see STEP-03b-agent-keychain.md):
#   - SecurityServer mach-lookup IS required to read even the agent's keychain.
#   - System.keychain MUST be denied too: denying only login left 99 System
#     items enumerable, one with a readable value.
#   - Rule ORDER matters: in SBPL the LAST matching rule wins, so these denies
#     must be appended after agent.sb's own grants (grants.sb is concatenated
#     after agent.sb by the launcher).
#   - Do NOT deny ~/Library/Preferences/com.apple.security.plist: measured to
#     break service-only lookups (which auth.json relies on). It need not exist;
#     denying the path is enough to break resolution.
#
# Idempotent, backs up, refuses to run inside the sandbox, verifies functionally.
#
# Usage: scripts/apply-step-03b.sh [--dry-run]
set -euo pipefail

GRANTS="${SANDBOX_GRANTS:-$HOME/.config/sandbox-exec/grants.sb}"
LAUNCHER="${SANDBOX_LAUNCHER:-$HOME/.config/sandbox-exec/run-sandboxed.sh}"
AGENT_KC="${AGENT_KEYCHAIN:-$HOME/.agent/agent.keychain-db}"
KC_FILE="$AGENT_KC"
STAMP="$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MARK_BEGIN=";; >>> pi-sandbox-hardening step-03b (agent keychain)"
MARK_END=";; <<< pi-sandbox-hardening step-03b"

DRY=0
if [[ "${1:-}" == "--dry-run" ]]; then DRY=1; fi

say() { printf '%s\n' "$*"; }

# --- guards -----------------------------------------------------------------

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: run this from an UNCONFINED terminal." >&2
  exit 3
fi

[[ -f "$GRANTS" ]] || { echo "ERROR: no grants.sb at $GRANTS" >&2; exit 1; }

say "grants       : $GRANTS"
say "agent keychain: $KC_FILE"
say "backup       : $GRANTS.bak-$STAMP"
say

# Preflight: the agent keychain should exist (Step 3b-1) unless this is a dry run.
if [[ ! -f "$KC_FILE" ]]; then
  if (( DRY )); then
    say "NOTE: $KC_FILE does not exist yet — run scripts/setup-agent-keychain.sh first."
    say
  else
    cat >&2 <<EOF
ERROR: agent keychain not found: $KC_FILE

Create it first (prompts for a password):
    scripts/setup-agent-keychain.sh

Refusing to apply the policy before the keychain exists, because that would
leave every provider broken with no working key source.
EOF
    exit 1
  fi
fi

BLOCK="$(cat <<EOF
$MARK_BEGIN
;; Agent's OWN keychain only. Last-match-wins, so this must come after any
;; broader keychain grant. Deny login + System keychain FILES (the SecurityServer
;; IPC alone does not expose them once the files are denied), then allow only the
;; agent's keychain. Verified inside the real policy: all 3 provider keys resolve
;; (25/73/67 chars), personal gh token blocked, 0 items from login/System.
;;
;; The search list is set permanently by apply-step-03b.sh as
;; [login, agent, System]; inside the sandbox the login keychain is file-denied,
;; so lookups FALL THROUGH to the agent keychain. No per-session list change is
;; needed (and 'exec' in the launcher would prevent restoring one anyway).
(deny file-read* file-write*
    (home-subpath "/Library/Keychains")
    (subpath "/Library/Keychains")
)
(allow file-read* file-write*
    (home-literal "/.agent/agent.keychain-db")
)
;; Required: 'security' cannot read ANY keychain without this IPC.
(allow mach-lookup
    (global-name "com.apple.SecurityServer")
)
;; The search list lives in com.apple.security.plist (cfprefsd). Without read
;; access, 'security' falls back to the built-in [login, System] list, does NOT
;; see the agent keychain, and every service-only lookup fails. This file only
;; contains the keychain search list — not any secret.
(allow file-read*
    (home-literal "/Library/Preferences/com.apple.security.plist")
)
$MARK_END
EOF
)"

if (( DRY )); then
  say "[dry-run] would append this block to grants.sb:"
  printf '%s\n' "$BLOCK" | sed 's/^/  /'
  say
  say "would also add the unlock prompt + search-list handling to:"
  say "  $LAUNCHER"
  exit 0
fi

# --- 1. grants.sb -----------------------------------------------------------

if grep -qF "$MARK_BEGIN" "$GRANTS"; then
  say "1. agent-keychain block already present in grants.sb, skipping"
else
  say "1. appending agent-keychain block to grants.sb"
  cp -p "$GRANTS" "$GRANTS.bak-$STAMP"
  printf '\n%s\n' "$BLOCK" >> "$GRANTS"

  # sanity: still balanced
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

  # Confirm the wide grant is really gone (Step 3 removed it).
  if grep -qE 'home-subpath "/Library/Keychains"' "$GRANTS" \
     && ! grep -q 'step-03 removed' "$GRANTS"; then
    say "   WARNING: a broad keychain grant is still present without a step-03"
    say "            removal marker. Our deny is appended later so it should still"
    say "            win, but review with: scripts/diagnose-keychain.sh"
  fi
fi

# --- 2. search list: append the agent keychain ONCE, permanently ------------
#
# Inside the sandbox the login + System keychain FILES are denied, so a
# service-only lookup falls through to the next entry. Therefore the search
# list just needs the agent keychain appended AFTER the login keychain:
#
#   YOUR shell  (unconfined): login is first  -> your keys resolve as before
#   pi (sandboxed):           login is denied -> falls through to agent kc
#
# This is deliberately NOT done per-session with a trap: the launcher ends in
# `exec`, which replaces the shell and never runs an EXIT trap. A permanent
# append is SIGKILL-safe and never removes login from the list.

say
say "2. search list: ensure agent keychain is present (after login)"
SL_NOW="$(security list-keychains 2>/dev/null | tr -d ' \"')"
LOGIN_KC="$HOME/Library/Keychains/login.keychain-db"
if printf '%s\n' "$SL_NOW" | grep -qF "$AGENT_KC"; then
  say "   already present, skipping"
else
  # Rebuild explicitly: login first, then agent, then System. Idempotent.
  security list-keychains -s "$LOGIN_KC" "$AGENT_KC" /Library/Keychains/System.keychain \
    >/dev/null 2>&1 || true
  say "   added (login first, so your shell is unaffected)"
fi
say "   now:"
security list-keychains | sed 's/^/     /'

# Guard: never leave the login keychain out of the list.
if ! security list-keychains 2>/dev/null | grep -qF "login.keychain-db"; then
  echo "WARNING: login keychain missing from the search list; restoring" >&2
  security list-keychains -s "$LOGIN_KC" /Library/Keychains/System.keychain >/dev/null 2>&1 || true
fi

# --- 3. launcher: unlock prompt ---------------------------------------------

say
say "3. launcher: unlock prompt"
if grep -q 'pi-sandbox-hardening step-03b' "$LAUNCHER"; then
  say "   already patched, skipping"
else
  cp -p "$LAUNCHER" "$LAUNCHER.bak-$STAMP"
  python3 - "$LAUNCHER" "$KC_FILE" <<'PY'
import sys, os, stat
path, kc = sys.argv[1], sys.argv[2]
src = open(path).read()

anchor = 'exec sandbox-exec -f "$tmp_policy" \\\n'
if anchor not in src:
    sys.exit("ERROR: could not find the exec line; aborting")

# NOTE: comments must NOT be placed inside the backslash-continued command —
# a '#' terminates the command and pi would never start. Keep them ABOVE.
inject = f'''# --- pi-sandbox-hardening step-03b: agent keychain --------------------------
# Prompt to unlock the agent's own keychain BEFORE entering the sandbox: an
# unlock performed outside is inherited by the sandboxed process (verified).
# This prompt is TTY-based; without a TTY it fails with rc 51 rather than
# hanging, so non-interactive launches warn instead of stalling.
#
# NOTE: the search list is NOT touched here. It is set permanently by
# apply-step-03b.sh (login first, agent keychain appended). Inside the sandbox
# the login keychain is file-denied, so lookups fall through to the agent
# keychain automatically. Doing it per-session with a trap does not work here
# because the launcher ends in `exec`, which replaces the shell and therefore
# never runs the EXIT trap.
AGENT_KC="{kc}"
if [[ -f "$AGENT_KC" ]]; then
  if ! security show-keychain-info "$AGENT_KC" >/dev/null 2>&1; then
    printf 'Unlock agent keychain (%s): ' "$AGENT_KC" >&2
    security unlock-keychain "$AGENT_KC" || \\
      echo "warning: agent keychain not unlocked; providers may fail" >&2
  fi
fi
# ---------------------------------------------------------------------------

'''

mode = stat.S_IMODE(os.stat(path).st_mode)
open(path, "w").write(src.replace(anchor, inject + anchor, 1))
os.chmod(path, mode)
print("   patched launcher")
PY

  if "$SCRIPT_DIR/verify-launcher.sh" "$LAUNCHER" > /tmp/vl.out 2>&1; then
    sed 's/^/   /' /tmp/vl.out
  else
    sed 's/^/   /' /tmp/vl.out
    echo "ERROR: launcher no longer invokes pi correctly. Restore:" >&2
    echo "  cp -p $LAUNCHER.bak-$STAMP $LAUNCHER" >&2
    exit 1
  fi
fi

# --- 4. functional verification ---------------------------------------------

say
say "4. functional verification (of the policy files, not the running session)"

# Build an effective policy for a real workdir and probe it.
WD="$HOME/git/pi-sandbox-hardening"
[[ -d "$WD" ]] || WD="$HOME/git"
if [[ -d "$WD" ]] && [[ -x "$SCRIPT_DIR/build-policy.sh" ]]; then
  eff="$("$SCRIPT_DIR/build-policy.sh" "$WD" /tmp/eff-step3b.sb 2>/dev/null || true)"
  if [[ -n "$eff" && -f "$eff" ]]; then
    probe() { printf '   %-34s ' "$1"; if sandbox-exec -f "$eff" -- /bin/sh -c "$2" >/dev/null 2>&1; then echo "$3"; else echo "$4"; fi; }
    probe "login keychain (expect blocked)" 'head -c1 "$HOME/Library/Keychains/login.keychain-db"' "LEAK" "blocked ✅"
    probe "security ANY gh token (block)"   '/usr/bin/security find-generic-password -s gh:github.com -w' "LEAK" "blocked ✅"
    probe "security personal (block)"       '/usr/bin/security find-generic-password -s gh:github.com -a sven1103 -w' "LEAK" "blocked ✅"
    probe "System kc items dumps"           'security dump-keychain 2>/dev/null | grep -q "svce"' "LEAK" "blocked ✅"
  fi
else
  say "   (skipped: need a real workdir + build-policy.sh)"
fi

cat <<EOF

DONE. Next:
  1. Start pi in a NEW terminal (the policy is compiled at launch).
  2. Inside it, verify providers and isolation:
         security find-generic-password -ws litellm | head -c4   # non-empty
         pi           # should list models again
         security find-generic-password -s gh:github.com -a sven1103 -w >/dev/null 2>&1 && echo LEAK || echo blocked
  3. Record + diff:
         cd ~/git/pi-sandbox-hardening
         scripts/selftest.sh --record baseline-step3b.tsv
         scripts/selftest.sh --diff baseline-step2.tsv

ROLLBACK:  cp -p $GRANTS.bak-$STAMP $GRANTS
           cp -p $LAUNCHER.bak-$STAMP $LAUNCHER
EOF
