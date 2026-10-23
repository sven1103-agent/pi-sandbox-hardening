#!/usr/bin/env bash
# Step 1b — move the AGENT gh token from a plaintext file into the AGENT keychain.
#
# Why: Step 1 installed the agent token as a FILE (`gh auth login
# --insecure-storage`) so the human login keychain could stay denied. That works,
# but leaves the token in plaintext on disk. gh can ALSO read it from the agent
# keychain — which the sandbox already allows, and which the sandbox cannot write.
#
# Measured mechanics (see STEP-01b-gh-token-in-agent-keychain.md):
#
#   read  : `security find-generic-password` (NO keychain argument) searches the
#           user-wide SEARCH LIST. Inside the sandbox `login.keychain-db` is
#           file-denied, so the lookup FALLS THROUGH to
#           ~/.agent/agent.keychain-db. Verified by placing a bogus token there
#           and observing gh fail with "The token in keyring is invalid".
#
#   write : `security add-generic-password -U -s %s -a %s -w %s` carries NO
#           keychain argument, so it targets the DEFAULT keychain — which is
#           `login.keychain-db`, the one the sandbox denies. So gh can never
#           store its own token from inside the sandbox (rc=161, "Operation not
#           permitted"); the migration must happen here, unconfined, with an
#           explicit keychain path.
#
#   format: gh stores values as "go-keyring-base64:<base64(token)>". A raw value
#           also reads back correctly, but the prefixed form matches gh itself.
#
# Never prints secret values. Verifies by authenticating, and compares hashes only.
#
# Usage:
#   scripts/migrate-gh-token-to-keychain.sh --dry-run
#   scripts/migrate-gh-token-to-keychain.sh
#   scripts/migrate-gh-token-to-keychain.sh --purge-login-copy
#
# --purge-login-copy additionally removes the redundant bot item from the LOGIN
# keychain. Read the warning it prints before using it: your unconfined `gh`
# resolves through that item today.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

HOSTS="${GH_AGENT_HOSTS:-$HOME/.agent/gh/hosts.yml}"
AGENT_KC="${AGENT_KEYCHAIN:-$HOME/.agent/agent.keychain-db}"
LOGIN_KC="$HOME/Library/Keychains/login.keychain-db"
SERVICE="gh:github.com"

DRY=0
PURGE=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --purge-login-copy) PURGE=1 ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }   # pre-backup: nothing to undo yet

# --- guards -----------------------------------------------------------------

# Keychain writes need an unconfined shell. This is the same guard the
# apply-step-*.sh scripts use.
if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  die "run this from an UNCONFINED terminal (keychain writes are denied in the sandbox)."
fi

command -v security >/dev/null || die "'security' not found"
command -v base64   >/dev/null || die "'base64' not found"

[[ -f "$HOSTS" ]]     || die "no gh hosts.yml at $HOSTS (run Step 1 first)"
[[ -f "$AGENT_KC" ]]  || die "no agent keychain at $AGENT_KC (run scripts/setup-agent-keychain.sh first)"

# --- preflight: what are we working with? -----------------------------------

# Pull the token and the account out of hosts.yml. awk, not python: bash 3.2
# miscounts parentheses inside $(...) when a heredoc body contains them.
tok="$(awk -F'oauth_token:' '/oauth_token:/{v=$2; gsub(/^[ \t]+|[ \t]+$/,"",v); print v; exit}' "$HOSTS")"
account="$(awk -F'user:' '/^[[:space:]]+user:/{v=$2; gsub(/^[ \t]+|[ \t]+$/,"",v); print v; exit}' "$HOSTS")"
[[ -n "$account" ]] || die "could not determine the account from $HOSTS"

say "hosts.yml    : $HOSTS"
say "agent keychain: $AGENT_KC"
say "service      : $SERVICE"
say "account      : $account"
say

if [[ -z "$tok" ]]; then
  say "hosts.yml has NO oauth_token (already migrated?)."
  if security find-generic-password -s "$SERVICE" -a "$account" "$AGENT_KC" >/dev/null 2>&1; then
    say "the agent keychain already holds $SERVICE/$account — nothing to do."
    exit 0
  fi
  die "no token in the file and none in the agent keychain."
fi

# Sanity-check the shape so a parsing slip cannot write garbage into the keychain.
case "$tok" in
  gho_*|ghp_*|github_pat_*) : ;;
  *) die "the oauth_token in hosts.yml does not look like a GitHub token" ;;
esac

# Is it valid, and as whom? HTTP status / login name only — never the value.
api_login="$(curl -sS -H "Authorization: Bearer $tok" https://api.github.com/user 2>/dev/null \
             | awk -F'"' '/"login"/{print $4; exit}')"
say "token authenticates as: ${api_login:-<could not verify>}"
[[ "$api_login" == "$account" ]] || die "token identity ($api_login) does not match config account ($account)"

say
say "plan:"
say "  1. store the token in the agent keychain as $SERVICE / $account"
say "  2. remove oauth_token from $HOSTS (keychain becomes authoritative)"
[[ "$PURGE" == 1 ]] && say "  3. remove the redundant $SERVICE/$account item from the LOGIN keychain"
say "  4. verify: sandboxed gh authenticates; unconfined gh still authenticates"

if [[ "$DRY" == 1 ]]; then
  say
  say "--dry-run: no changes made."
  exit 0
fi

# --- backup + apply ---------------------------------------------------------

STAMP="$(date +%Y%m%d-%H%M%S)"
BAK="$HOSTS.bak-$STAMP"

# Keep the original in memory so rollback can restore it exactly.
# It is deliberately NOT written to disk: a plaintext copy of the token on disk is
# the very exposure this step removes, and at a path no cleanup step knows about.
orig_hosts="$(cat "$HOSTS")"

# The on-disk backup is REDACTED. It keeps the file's shape so a diff still shows
# what changed, without preserving the secret. The token stays recoverable from
# the agent keychain (and, unless --purge-login-copy is used, the login keychain),
# so this is not a loss of recovery ability.
sed 's/^\([[:space:]]*oauth_token:[[:space:]]*\).*/\1<REDACTED-BY-STEP-01b>/' "$HOSTS" > "$BAK"
chmod 600 "$BAK"
say
say "backup (redacted): $BAK"

HAD_KC_ITEM=0
security find-generic-password -s "$SERVICE" -a "$account" "$AGENT_KC" >/dev/null 2>&1 && HAD_KC_ITEM=1

rollback() {
  printf '\nrolling back...\n' >&2
  # Restore from memory (exact original), not from the redacted backup.
  umask 077
  printf '%s\n' "$orig_hosts" > "$HOSTS" 2>/dev/null || cp -p "$BAK" "$HOSTS" 2>/dev/null || true
  [[ "$HAD_KC_ITEM" == 0 ]] && \
    security delete-generic-password -s "$SERVICE" -a "$account" "$AGENT_KC" >/dev/null 2>&1 || true
  printf 'restored %s (token re-inserted; on-disk copy is redacted)\n' "$HOSTS" >&2
}

# 'die' calls exit, which does NOT raise ERR, so wire rollback in explicitly.
die() { printf 'ERROR: %s\n' "$*" >&2; rollback; exit 1; }
trap 'rollback' ERR

# NOTE: `-w <value>` is briefly visible in `ps`. The interactive prompt form
# needs a real TTY, and `security` cannot read the value from stdin, so this is
# unavoidable for scripted use. Same trade-off as setup-agent-keychain.sh; it is
# an attended, unconfined setup step. The value passed here is base64 of the
# token, so it is not directly usable as a credential if observed.
b64="$(printf '%s' "$tok" | base64 | tr -d '\n')"
security add-generic-password -U -s "$SERVICE" -a "$account" \
  -w "go-keyring-base64:$b64" "$AGENT_KC" >/dev/null
say "stored in agent keychain ✅"

# Drop the plaintext copy. hosts.yml keeps git_protocol/user; gh then resolves the
# token from the keyring.
tmp="$(mktemp -t gh-hosts)"
grep -v '^[[:space:]]*oauth_token:' "$HOSTS" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$HOSTS"
say "removed oauth_token from hosts.yml ✅"

# --- verify -----------------------------------------------------------------

say
say "verification:"

hash_of() { printf '%s' "$1" | shasum -a 256 | cut -c1-16; }

raw="$(security find-generic-password -s "$SERVICE" -a "$account" -w "$AGENT_KC" 2>/dev/null || true)"
stored="${raw#go-keyring-base64:}"
if [[ -n "$stored" ]]; then stored="$(printf '%s' "$stored" | base64 -d 2>/dev/null || true)"; fi
printf '  keychain value matches file token : '
if [[ "$(hash_of "$stored")" == "$(hash_of "$tok")" ]]; then echo "yes ✅"; else die "MISMATCH"; fi

# Sandboxed gh must now authenticate via the keyring, not the (now token-free) file.
eff="$(cd "$REPO_DIR" && ./scripts/build-policy.sh "$REPO_DIR" /tmp/pi-step01b.sb >/dev/null 2>&1; echo /tmp/pi-step01b.sb)"
printf '  sandboxed gh api user            : '
sb_login="$(sandbox-exec -f "$eff" -- /usr/bin/env -i \
  PATH="/opt/homebrew/bin:/usr/bin:/bin" HOME="$HOME" \
  GH_CONFIG_DIR="$(dirname "$HOSTS")" \
  /bin/sh -c 'gh api user -q .login' 2>&1 | head -1)"
printf '%s\n' "$sb_login"
[[ "$sb_login" == "$account" ]] || die "sandboxed gh failed after migration"
rm -f "$eff"

# The label gh prints tells us WHICH source it used. '(keyring)' here proves the
# agent keychain is doing the work, not the (now token-free) file.
printf '  sandboxed gh source              : '
printf '%s\n' "$(sandbox-exec -f "$(cd "$REPO_DIR" && ./scripts/build-policy.sh "$REPO_DIR" /tmp/pi-step01b2.sb >/dev/null 2>&1; echo /tmp/pi-step01b2.sb)" \
  -- /usr/bin/env -i PATH="/opt/homebrew/bin:/usr/bin:/bin" HOME="$HOME" \
  GH_CONFIG_DIR="$(dirname "$HOSTS")" \
  /bin/sh -c 'gh auth status 2>&1 | grep -oE "\\(keyring\\)|\\(/[^)]*\\)" | head -1')"
rm -f /tmp/pi-step01b2.sb

printf '  hosts.yml has no oauth_token      : '
if grep -q 'oauth_token' "$HOSTS"; then echo "STILL PRESENT ⚠️"; else echo "yes ✅"; fi

if [[ "$PURGE" == 1 ]]; then
  say
  say "WARNING: removing the login-keychain copy."
  say "  Your UNCONFINED gh (via ~/.config/gh) resolves through that item today."
  say "  After removal it should fall through to the agent keychain — the search"
  say "  list still contains it — but re-check with:  gh api user -q .login"
  security delete-generic-password -s "$SERVICE" -a "$account" "$LOGIN_KC" >/dev/null 2>&1 || true
  printf '  login-keychain copy removed      : '
  security find-generic-password -s "$SERVICE" -a "$account" "$LOGIN_KC" >/dev/null 2>&1 \
    && echo "STILL PRESENT ⚠️" || echo "yes ✅"
  printf '  unconfined gh api user           : '
  gh api user -q .login 2>&1 | head -1
fi

trap - ERR
unset tok b64 stored raw orig_hosts

say
say "done."
say "Note: the on-disk backup $BAK is REDACTED by design (no token in it)."
say "To roll back, re-run with the token, or copy the value back from the agent"
say "keychain:  security find-generic-password -s $SERVICE -a $account -w $AGENT_KC"
