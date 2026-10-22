#!/usr/bin/env bash
# Install a GitHub token for the AGENT into a file (not the keychain).
#
# Run from an UNCONFINED terminal. The sandbox denies writes to ~/.agent, so
# this cannot be run from inside pi.
#
# The token is read from an environment variable, never from an argument, so it
# does not land in shell history or the process table. It is never echoed.
#
# Usage:
#   TOKEN=github_pat_xxx scripts/install-agent-gh-auth.sh
#   scripts/install-agent-gh-auth.sh --from-existing   # reuse the keychain token
#
# --from-existing is provided for convenience/testing ONLY. The current keychain
# token is a classic OAuth token (gho_) with the `workflow` scope, which is the
# F3 risk we are removing. Prefer a fine-grained PAT (see STEP-01).
set -euo pipefail

DIR="${AGENT_GH_DIR:-$HOME/.agent/gh}"
HOST="${GH_HOST:-github.com}"
ACCOUNT="${GH_ACCOUNT:-sven1103-agent}"

die() { echo "error: $*" >&2; exit 1; }

case "${1:-}" in
  --from-existing)
    command -v gh >/dev/null || die "gh not found"
    TOKEN="$(gh auth token 2>/dev/null || true)"
    [[ -n "$TOKEN" ]] || die "could not read a token via 'gh auth token'"
    ;;
  "")
    [[ -n "${TOKEN:-}" ]] || die "set TOKEN=... or pass --from-existing"
    ;;
  *) die "unknown argument: $1" ;;
esac

# --- guard: refuse a token we know is too broad, unless explicitly allowed ----
if [[ "$TOKEN" != github_pat_* && "${ALLOW_BROAD_TOKEN:-0}" != "1" ]]; then
  case "$TOKEN" in
    gho_*|ghp_*)
      cat >&2 <<'EOF'
error: this is a CLASSIC token (gho_/ghp_), not a fine-grained PAT.

Classic tokens cannot be scoped down and this one carries `workflow`, which
means "edit .github/workflows/**" = arbitrary code in CI with repo/org secrets.
That is the exposure we are removing (F3), so installing it would defeat the
point.

If you understand the trade-off and want to proceed anyway (e.g. to test the
mechanism before rotating), re-run with:
    ALLOW_BROAD_TOKEN=1 scripts/install-agent-gh-auth.sh --from-existing

Otherwise create a fine-grained PAT (STEP-01) and pass it via TOKEN=...
EOF
      exit 1 ;;
  esac
fi

# --- write ------------------------------------------------------------------
umask 077
mkdir -p "$DIR"
chmod 700 "$DIR"

# Write atomically; never print the token.
tmp="$(mktemp "${DIR}/.hosts.yml.XXXXXX")"
cat > "$tmp" <<EOF
${HOST}:
    git_protocol: ssh
    users:
        ${ACCOUNT}:
            oauth_token: ${TOKEN}
    user: ${ACCOUNT}
EOF
chmod 600 "$tmp"
mv -f "$tmp" "$DIR/hosts.yml"

echo "wrote $DIR/hosts.yml (mode 600, git_protocol=ssh)"

# --- verify without leaking --------------------------------------------------
# NOTE: while a working keychain entry exists, gh IGNORES hosts.yml, so a naive
# "auth status ok" here would actually be verifying the KEYCHAIN, not our file.
# Detect that case and say so, rather than reporting a false pass.
echo
echo "verifying (no token printed):"

keychain_present=0
if command -v security >/dev/null 2>&1; then
  if security find-generic-password -s "gh:${HOST}" >/dev/null 2>&1; then
    keychain_present=1
  fi
fi

# Compare the token gh would actually use against the one we just wrote.
used="$(GH_CONFIG_DIR="$DIR" gh auth token 2>/dev/null || true)"
if [[ -n "$used" && "$used" == "$TOKEN" ]]; then
  echo "  token source: hosts.yml (file) — gh is using our token"
elif [[ $keychain_present -eq 1 && -n "$used" ]]; then
  echo "  token source: KEYCHAIN — gh is overriding hosts.yml"
  echo "                expected until Step 3 makes the keychain unreachable;"
  echo "                file-token verification is INCONCLUSIVE right now"
else
  echo "  token source: unknown / no token in use"
fi

login="$(GH_CONFIG_DIR="$DIR" gh api user --jq .login 2>/dev/null || true)"
if [[ "$login" == "$ACCOUNT" ]]; then
  echo "  api user    : $login  (agent identity)"
else
  echo "  api user    : ${login:-failed}  <-- expected $ACCOUNT"
fi

scopes="$(GH_CONFIG_DIR="$DIR" gh api -i user 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="x-oauth-scopes"{print $2}')"
[[ -n "$scopes" ]] && echo "  scopes      : $scopes  <-- classic token; consider rotating"

cat <<'EOF'

IMPORTANT: gh prefers the login keychain over hosts.yml. This file only takes
effect once the keychain is unreachable (Step 3). The harness check
`agent: gh api(own)` proves the fallback works after that change.
EOF
