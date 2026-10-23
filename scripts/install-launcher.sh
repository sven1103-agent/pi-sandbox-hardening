#!/usr/bin/env bash
# Install the repo's launcher + policy fragment into the live policy directory,
# so the PUBLISHED files are the single source of truth for the running system.
#
# Why this exists: `launcher/` and `~/.config/sandbox-exec/` had already drifted.
# Nothing installed, verified or diffed them, so the README pointed at one file
# and TESTING.md at another, and the two were no longer the same program. This
# script is the missing link: it makes the repo authoritative and refuses to
# install anything that does not verify.
#
# What it does:
#   1. refuses to run if confined (policy dir is unreadable inside the sandbox)
#   2. backs up the current live files
#   3. installs launcher/run-sandboxed.sh -> $POLICY_DIR/run-sandboxed.sh
#              launcher/grants.sb      -> $POLICY_DIR/grants.sb
#   4. renders the composed policy and checks sandbox-exec accepts it
#   5. runs verify-launcher.sh (executes the launcher with a stub sandbox-exec)
#   6. restores the backups if ANY check fails
#
# Safety: the installed launcher is behaviourally equivalent to the one it
# replaces — same policy composition order, same keychain unlock, same `env -i`
# allowlist. It is a cleaned-up transcription, not a redesign. Verified by
# `--diff-only` before installing.
#
# Usage:
#   scripts/install-launcher.sh              # install
#   scripts/install-launcher.sh --dry-run    # show the diff, change nothing
#   scripts/install-launcher.sh --diff-only  # alias for --dry-run
#   scripts/install-launcher.sh --force      # install even if identical
#
# Env:
#   SANDBOX_POLICY_DIR  default ~/.config/sandbox-exec
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

POLICY_DIR="${SANDBOX_POLICY_DIR:-$HOME/.config/sandbox-exec}"
SRC_LAUNCHER="$REPO_DIR/launcher/run-sandboxed.sh"
SRC_GRANTS="$REPO_DIR/launcher/grants.sb"
DST_LAUNCHER="$POLICY_DIR/run-sandboxed.sh"
DST_GRANTS="$POLICY_DIR/grants.sb"
BASE_POLICY="$POLICY_DIR/agent.sb"

DRY=0; FORCE=0
for a in "$@"; do
  case "$a" in
    --dry-run|--diff-only) DRY=1 ;;
    --force)               FORCE=1 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }

# --- guards -----------------------------------------------------------------
# Inside the sandbox the policy dir is denied, so this cannot run there (and
# must not: it would be an agent modifying its own confinement).
if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: already inside a sandbox. Run this from an UNCONFINED terminal." >&2
  exit 3
fi

for f in "$SRC_LAUNCHER" "$SRC_GRANTS"; do
  [[ -f "$f" ]] || { echo "ERROR: missing source file: $f" >&2; exit 1; }
done
[[ -d "$POLICY_DIR" ]] || { echo "ERROR: no policy dir: $POLICY_DIR" >&2; exit 1; }
[[ -f "$BASE_POLICY" ]] || {
  echo "ERROR: base policy missing: $BASE_POLICY" >&2
  echo "       Generate one with: safehouse --stdout > $BASE_POLICY" >&2
  exit 1
}

# A drift check that also catches a re-introduction of the marker rename fixed in
# this repo (step-02 was rewordinged during genericization; apply-step-02.sh
# matches on the OLD text, so a mismatch means that script would append a
# DUPLICATE block on its next run).
check_marker() {
  local name="$1" script="$2" marker
  marker="$(grep -m1 '^MARK_BEGIN=' "$script" | sed 's/MARK_BEGIN="//;s/"$//')"
  [[ -n "$marker" ]] || return 0
  if ! grep -qF "$marker" "$SRC_GRANTS"; then
    echo "ERROR: marker drift — $SRC_GRANTS lacks:" >&2
    echo "         $marker" >&2
    echo "       (required by $(basename "$script"); installing would let it duplicate its block)" >&2
    exit 1
  fi
}
for s in apply-step-02.sh apply-step-03b.sh apply-step-04.sh apply-step-06.sh; do
  [[ -f "$SCRIPT_DIR/$s" ]] && check_marker "$s" "$SCRIPT_DIR/$s"
done

# --- show what would change -------------------------------------------------
drift=0
for pair in "$SRC_LAUNCHER:$DST_LAUNCHER" "$SRC_GRANTS:$DST_GRANTS"; do
  src="${pair%%:*}"; dst="${pair#*:}"
  if ! cmp -s "$src" "$dst"; then
    drift=1
    say "CHANGED  $(basename "$dst")"
  else
    say "same     $(basename "$dst")"
  fi
done

if (( DRY )); then
  say ""
  say "--- diff (functional lines only, comments stripped) ---"
  strip() { grep -v '^[[:space:]]*#' "$1" | grep -v '^[[:space:]]*$'; }
  diff <(strip "$SRC_LAUNCHER") <(strip "$DST_LAUNCHER") \
    | sed 's/^/  launcher| /' || true
  say ""
  say "[dry-run] nothing changed."
  exit 0
fi

if (( drift == 0 && FORCE == 0 )); then
  say ""
  say "already in sync — nothing to install. (--force to reinstall.)"
  exit 0
fi

# --- install with rollback --------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
rollback() {
  echo "ROLLBACK: restoring from .bak-$STAMP" >&2
  for pair in "$SRC_LAUNCHER:$DST_LAUNCHER" "$SRC_GRANTS:$DST_GRANTS"; do
    dst="${pair#*:}"
    [[ -f "$dst.bak-$STAMP" ]] && cp -p "$dst.bak-$STAMP" "$dst"
  done
  echo "  restored." >&2
}
trap 'rc=$?; if (( rc != 0 )); then rollback; fi; exit $rc' EXIT

say ""
for pair in "$SRC_LAUNCHER:$DST_LAUNCHER" "$SRC_GRANTS:$DST_GRANTS"; do
  src="${pair%%:*}"; dst="${pair#*:}"
  cp -p "$dst" "$dst.bak-$STAMP"
  cp -p "$src" "$dst"
  say "installed $(basename "$dst")   (backup: $(basename "$dst").bak-$STAMP)"
done

# --- verify 1: syntax -------------------------------------------------------
bash -n "$DST_LAUNCHER" || { echo "FAIL: launcher syntax error" >&2; exit 1; }
say "ok   launcher syntax"

# --- verify 2: the composed policy is accepted by sandbox-exec --------------
tmp_policy="$(mktemp "${TMPDIR:-/tmp}/install-check.XXXXXX")"
cat "$BASE_POLICY" > "$tmp_policy"
sed -i '' "s|__SAFEHOUSE_REPLACE_ME_WITH_WORK_DIR_DEFINE__|(define WORK_DIR \"$REPO_DIR\")|g" "$tmp_policy" 2>/dev/null \
  || sed -i "s|__SAFEHOUSE_REPLACE_ME_WITH_WORK_DIR_DEFINE__|(define WORK_DIR \"$REPO_DIR\")|g" "$tmp_policy"
printf '\n(allow file-read* file-write* (subpath "%s"))\n' "$REPO_DIR" >> "$tmp_policy"
cat "$DST_GRANTS" >> "$tmp_policy"
if ! sandbox-exec -f "$tmp_policy" -- /usr/bin/true >/dev/null 2>&1; then
  rm -f "$tmp_policy"
  echo "FAIL: sandbox-exec rejected the composed policy" >&2
  exit 1
fi
rm -f "$tmp_policy"
say "ok   composed policy accepted by sandbox-exec"

# --- verify 3: the launcher still starts pi with the right env --------------
if "$SCRIPT_DIR/verify-launcher.sh" "$DST_LAUNCHER" >/tmp/install-launcher.verify 2>&1; then
  sed 's/^/  /' /tmp/install-launcher.verify | grep -E 'ok |ARGV' | sed 's/^/  /'
  say "ok   verify-launcher.sh passed"
else
  sed 's/^/  /' /tmp/install-launcher.verify >&2
  echo "FAIL: verify-launcher.sh failed" >&2
  exit 1
fi
rm -f /tmp/install-launcher.verify

trap - EXIT
say ""
say "INSTALLED. The repo's launcher/ is now the live configuration."
say "Restart any running pi session to pick up the change."
