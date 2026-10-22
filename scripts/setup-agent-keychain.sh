#!/usr/bin/env bash
# Step 3b-1 — create the AGENT's own keychain and migrate provider keys into it.
#
# Why: pi's auth.json resolves every provider key via
#   !security find-generic-password -ws '<service>'
# so removing keychain access entirely breaks ALL providers. Instead we give the
# agent a keychain of its own and deny the login/System keychains (Step 3b-2).
#
# Run from an UNCONFINED terminal, BEFORE applying the policy change:
#   - it READS the login keychain (which Step 3b-2 will deny)
#   - it prompts for a password via SecurityAgent (interactive)
#
# Never prints secret values; verifies each key against its endpoint instead.
#
# Usage:
#   scripts/setup-agent-keychain.sh              # create/migrate (prompts)
#   scripts/setup-agent-keychain.sh --dry-run    # show plan, no changes
#   scripts/setup-agent-keychain.sh --add NAME   # add/update one service
set -uo pipefail

AGENT_KC="${AGENT_KEYCHAIN:-$HOME/.agent/agent.keychain-db}"
SERVICES=(litellm openrouter opencode-go-private)

DRY=0; ADD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --add) ADD="${2:?--add needs a service name}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
[[ -n "$ADD" ]] && SERVICES=("$ADD")

# Endpoint used to verify the litellm key. Override for your own provider; the
# default is a placeholder so this example stays generic.
LITELLM_MODELS_URL="${LITELLM_MODELS_URL:-https://llm.internal.example.com/v1/models}"

SL_BAK="$(mktemp -t kc-searchlist)"

# Restore the user-wide keychain search list, ensuring the login keychain is
# present. 'create-keychain' appends the new keychain to this list and has been
# observed to drop login.keychain-db from it, which breaks YOUR shell's keychain
# access — so always restore, and always re-add the login keychain.
restore_searchlist() {
  if [[ -s "$SL_BAK" ]]; then
    # shellcheck disable=SC2046
    xargs -n1 security list-keychains -s < "$SL_BAK" >/dev/null 2>&1 || true
  fi
  local cur login="$HOME/Library/Keychains/login.keychain-db"
  cur="$(security list-keychains 2>/dev/null | tr -d ' "')"
  if ! printf '%s\n' "$cur" | grep -qF "$login"; then
    security list-keychains -s "$login" /Library/Keychains/System.keychain >/dev/null 2>&1 || true
    say "restored login keychain to the search list"
  fi
  rm -f "$SL_BAK"
}
trap 'rm -f "$SL_BAK"' EXIT

# --- guards -----------------------------------------------------------------

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: already inside a sandbox. Run this from an UNCONFINED terminal." >&2
  exit 3
fi

command -v security >/dev/null || { echo "ERROR: 'security' not found" >&2; exit 1; }

say "agent keychain: $AGENT_KC"
say "services      : ${SERVICES[*]}"
say

# --- preflight --------------------------------------------------------------

missing=()
for s in "${SERVICES[@]}"; do
  security find-generic-password -s "$s" >/dev/null 2>&1 || missing+=("$s")
done
if (( ${#missing[@]} )); then
  say "WARNING: not found in the login keychain: ${missing[*]}"
  say "         (these will be skipped; use --add later if they appear)"
  say
fi

if (( DRY )); then
  say "[dry-run] would:"
  say "  1. create $AGENT_KC with a prompted password (SecurityAgent)"
  say "  2. copy these items from the login keychain: ${SERVICES[*]}"
  say "  3. restore the global search list (create-keychain appends to it)"
  say "  4. verify each key against its provider endpoint"
  say
  say "search list before:"
  security list-keychains | sed 's/^/  /'
  exit 0
fi

# --- create ----------------------------------------------------------------

if [[ -f "$AGENT_KC" ]]; then
  say "keychain already exists, reusing: $AGENT_KC"
  restore_searchlist
else
  say "creating $AGENT_KC (you will be prompted for a password)"
  # -P prompts via SecurityAgent. NOTE: create-keychain APPENDS the new keychain
  # to the user-wide search list, and has been observed to drop the login
  # keychain from it. Save beforehand and restore afterwards, no matter what.
  security list-keychains > "$SL_BAK" 2>/dev/null || true
  security create-keychain -P "$AGENT_KC" || { echo "ERROR: create failed" >&2; exit 1; }
  restore_searchlist
fi

# --- migrate ---------------------------------------------------------------

say
migrated=0; skipped=0
for s in "${SERVICES[@]}"; do
  printf '  %-24s ' "$s"
  if ! security find-generic-password -s "$s" >/dev/null 2>&1; then
    echo "skip (not in login keychain)"; skipped=$((skipped+1)); continue
  fi

  # Read value from login keychain without echoing it.
  val="$(security find-generic-password -ws "$s" 2>/dev/null)"
  if [[ -z "$val" ]]; then echo "skip (could not read)"; skipped=$((skipped+1)); continue; fi

  # -U updates in place, so re-running is idempotent.
  if security add-generic-password -U -a "$USER" -s "$s" -w "$val" "$AGENT_KC" >/dev/null 2>&1; then
    echo "migrated"; migrated=$((migrated+1))
  else
    echo "FAILED"; skipped=$((skipped+1))
  fi
  unset val
done

say
say "migrated: $migrated   skipped: $skipped"

# --- verify (endpoint checks, no secrets printed) ---------------------------

say
say "verification:"
kcval() { security find-generic-password -ws "$1" "$AGENT_KC" 2>/dev/null; }

check() { # name url
  local name="$1" url="$2" k
  k="$(kcval "$name")"
  printf '  %-22s ' "$name"
  if [[ -z "$k" ]]; then echo "no key in agent keychain"; return; fi
  local code
  code="$(curl -s --max-time 12 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $k" "$url")"
  case "$code" in
    200) echo "HTTP 200 ok" ;;
    401) echo "HTTP 401 — key invalid/expired (refresh needed)" ;;
    *)   echo "HTTP $code" ;;
  esac
  unset k
}

check litellm             "$LITELLM_MODELS_URL"
check openrouter          "https://openrouter.ai/api/v1/models"
check opencode-go-private "https://opencode.ai/zen/go/v1/models"

cat <<EOF

NEXT
  1. Lock it to confirm the prompt path works later:
         security lock-keychain "$AGENT_KC"
  2. Apply the policy:   scripts/apply-step-03b.sh
  3. Add the unlock prompt + search-list handling to the launcher.
  4. IMPORTANT: the login keychain items are NOT deleted. Keep them until the
     agent keychain is proven working in a sandboxed session, then remove:
         security delete-generic-password -s litellm
EOF
