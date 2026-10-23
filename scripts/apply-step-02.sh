#!/usr/bin/env bash
# Step 2 — wire the agent's OWN GitHub identity into the sandbox.
#
# Applies three changes (additive; nothing is removed):
#   1. ~/.agent/gitconfig      agent git identity: bot name/email, agent SSH key,
#                              NO credential helper. Pointing GIT_CONFIG_GLOBAL at
#                              this also closes F12 (ambient keychain route).
#   2. grants.sb managed block read access to ~/.agent/gh + ~/.agent/gitconfig,
#                              read/write gh cache/state. Replaces keychain use.
#   3. run-sandboxed.sh        sets GH_CONFIG_DIR / GIT_CONFIG_GLOBAL /
#                              GIT_CONFIG_SYSTEM for agent sessions.
#
# Idempotent. Backs up before editing. Never prints secret values.
# MUST be run from an UNCONFINED terminal (policy dir is denied inside the sandbox).
#
# Usage: scripts/apply-step-02.sh [--dry-run] [--force]
set -euo pipefail

POLICY_DIR="${SANDBOX_POLICY_DIR:-$HOME/.config/sandbox-exec}"
LAUNCHER="$POLICY_DIR/run-sandboxed.sh"
GRANTS="$POLICY_DIR/grants.sb"
AGENT_DIR="$HOME/.agent"
GITCONFIG="$AGENT_DIR/gitconfig"
SSH_WRAPPER="$AGENT_DIR/ssh/ssh-github.sh"
STAMP="$(date +%Y%m%d-%H%M%S)"

MARK_BEGIN=";; >>> pi-sandbox-hardening step-02 (agent identity)"
MARK_END=";; <<< pi-sandbox-hardening step-02"
# Legacy marker. This block was originally labelled "(managed block)" and was
# renamed to "(agent identity)" to match the naming of the other step blocks.
# Accept the old text too, otherwise re-running this script against an installed
# file would append a SECOND, duplicate copy of the same grants.
MARK_BEGIN_LEGACY=";; >>> pi-sandbox-hardening step-02 (managed block)"
grants_has_block() {
  grep -qF "$MARK_BEGIN" "$GRANTS" || grep -qF "$MARK_BEGIN_LEGACY" "$GRANTS"
}

DRY=0; FORCE=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --force)   FORCE=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
run() { if (( DRY )); then say "  [dry-run] $*"; else "$@"; fi; }
backup() { local f="$1"; run cp -p "$f" "$f.bak-$STAMP"; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- guards -----------------------------------------------------------------

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: already inside a sandbox. Run this from an UNCONFINED terminal." >&2
  exit 3
fi

for f in "$LAUNCHER" "$GRANTS"; do
  [[ -f "$f" ]] || { echo "ERROR: missing $f" >&2; exit 1; }
done

[[ -f "$HOME/.agent/gh/hosts.yml" ]] \
  || echo "WARN: ~/.agent/gh/hosts.yml is missing — run Step 1 first." >&2
[[ -x "$SSH_WRAPPER" ]] \
  || echo "WARN: $SSH_WRAPPER not executable — git-over-SSH may fail." >&2

say "policy dir : $POLICY_DIR"
say "backup tag : .bak-$STAMP"
say

# --- 1. agent git identity --------------------------------------------------

if [[ -f "$GITCONFIG" && $FORCE -eq 0 ]]; then
  say "1. gitconfig exists, keeping it: $GITCONFIG  (use --force to overwrite)"
else
  say "1. writing $GITCONFIG"
  if (( DRY )); then
    say "  [dry-run] would write agent gitconfig (bot identity, sshCommand=$SSH_WRAPPER)"
  else
    umask 077
    mkdir -p "$AGENT_DIR"
    cat > "$GITCONFIG" <<EOF
[user]
	name = sven1103-agent
	email = sven1103-agent@users.noreply.github.com
[core]
	sshCommand = $SSH_WRAPPER
[credential]
	helper =
[commit]
	gpgsign = false
[tag]
	gpgsign = false
EOF
    chmod 600 "$GITCONFIG"
  fi
fi

# --- 2. launcher: agent-scoped env ------------------------------------------

say
say "2. patching $LAUNCHER"
if grep -q 'GH_CONFIG_DIR' "$LAUNCHER"; then
  say "   already patched, skipping"
else
  backup "$LAUNCHER"
  if (( DRY )); then
    say "  [dry-run] would set GH_CONFIG_DIR / GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM"
  else
    python3 - "$LAUNCHER" <<'PY'
import sys, shutil, stat, re
path = sys.argv[1]
src = open(path).read()

# NOTE: a '#' comment is only safe BEFORE the command. Inside a
# backslash-continued command it terminates the command, so `env` would run with
# no arguments (dumping the environment, never starting pi). `bash -n` does not
# catch this — only executing the launcher does (see verify-launcher.sh).
old = ('exec sandbox-exec -f "$tmp_policy" \\\n'
       '  env TMUX="${TMUX:-}" \\\n')
new = ('# Agent-scoped identity (Step 2): own gh token file + own gitconfig.\n'
       '# GIT_CONFIG_GLOBAL closes the ambient-keychain route via the host\n'
       '# global gitconfig (FINDINGS F12).\n'
       'exec sandbox-exec -f "$tmp_policy" \\\n'
       '  env \\\n'
       '    TMUX="${TMUX:-}" \\\n'
       '    GH_CONFIG_DIR="$HOME/.agent/gh" \\\n'
       '    GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \\\n'
       '    GIT_CONFIG_SYSTEM=/dev/null \\\n')

if old not in src:
    sys.exit("ERROR: could not locate the 'env TMUX=' launch line; aborting")

mode = stat.S_IMODE(__import__("os").stat(path).st_mode)
open(path, "w").write(src.replace(old, new, 1))
__import__("os").chmod(path, mode)
print("   patched launch env")
PY
    say "   diff:"
    diff -u "$LAUNCHER.bak-$STAMP" "$LAUNCHER" | sed 's/^/     /' || true
  fi
fi

# --- 3. grants.sb: agent credential paths -----------------------------------

say
say "3. adding managed grants block to $GRANTS"
if grants_has_block; then
  say "   already present, skipping"
else
  backup "$GRANTS"
  if (( DRY )); then
    say "  [dry-run] would append managed grants block"
  else
    cat >> "$GRANTS" <<EOF

$MARK_BEGIN
;; Agent's own, keychain-free credentials. Read-only for the token/identity;
;; read/write only for gh's cache/state dirs.
(allow file-read*
    (home-literal "/.agent/gitconfig")
    (home-subpath "/.agent/gh")
)
(allow file-read* file-write*
    (home-subpath "/.cache/gh")
    (home-subpath "/.local/state/gh")
)
$MARK_END
EOF
    say "   appended"
  fi
fi

# --- verify -----------------------------------------------------------------

say
say "verification:"
if (( DRY )); then
  say "  (dry run — no changes made)"
  exit 0
fi

grep -q 'GH_CONFIG_DIR' "$LAUNCHER" && say "  launcher: GH_CONFIG_DIR present" || say "  launcher: MISSING GH_CONFIG_DIR"
grants_has_block && say "  grants:   managed block present"  || say "  grants:   MISSING block"
[[ -f "$GITCONFIG" ]] && say "  identity: $GITCONFIG present" || say "  identity: MISSING"

# Functional check: a grep can pass while the launcher is broken (a '#' inside the
# env continuation truncates the command, so pi never starts). Execute the
# launcher against a stub sandbox-exec to prove pi is still invoked.
say "  functional: verifying the launcher still invokes pi"
if "$SCRIPT_DIR/verify-launcher.sh" "$LAUNCHER" > /tmp/verify-launcher.out 2>&1; then
  sed 's/^/    /' /tmp/verify-launcher.out
else
  say ""
  sed 's/^/    /' /tmp/verify-launcher.out
  cat >&2 <<'BROKEN'

ERROR: the patched launcher does NOT correctly invoke pi.
Restore the backup and re-run:
    cp -p <launcher>.bak-<tag> <launcher>
BROKEN
  exit 1
fi

cat <<'EOF'

NEXT
  1. Open a NEW terminal and start pi via the sandbox launcher; confirm pi boots,
     then inside it run:
         gh api user --jq .login          # expect sven1103-agent
         git status                       # works, no identity prompt
  2. Re-run the harness from a real workdir:
         scripts/selftest.sh --diff baseline-before.tsv
     Expected: agent: gh config / agent: gh api(own)  ->  REACHABLE/ok
               all DENY checks unchanged (9 leaks remain until Step 3).
  3. If pi fails to start, restore:
         cp -p <file>.bak-<tag> <file>
EOF
