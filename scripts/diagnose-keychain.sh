#!/usr/bin/env bash
# Diagnose why keychain access is (still) reachable after Step 3.
#
# Checks each policy layer for keychain grants, because the effective policy is
# composed in this order (later layers override earlier ones):
#   1) agent.sb            2) dynamic workdir grant
#   3) grants.sb           4) ~/.safehouse-tmux.sb   <-- appended LAST
# If a later layer re-grants the keychain, removing it from grants.sb alone is
# ineffective.
#
# Run from an UNCONFINED terminal. Prints no secrets.
set -uo pipefail

PD="$HOME/.config/sandbox-exec"
PAT='Keychains|SecurityServer|com\.apple\.security\.agent|db/mds|security\.plist'

hdr() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

hdr "policy files"
for f in "$PD/agent.sb" "$PD/grants.sb" "$HOME/.safehouse-tmux.sb"; do
  if [[ -f "$f" ]]; then
    printf '  %-52s %s bytes\n' "$f" "$(wc -c < "$f" | tr -d ' ')"
  else
    printf '  %-52s (absent)\n' "$f"
  fi
done

hdr "keychain references per layer (these must be gone from every layer)"
for f in "$PD/agent.sb" "$PD/grants.sb" "$HOME/.safehouse-tmux.sb"; do
  [[ -f "$f" ]] || continue
  n=$(grep -cE "$PAT" "$f" 2>/dev/null || echo 0)
  printf '  %-52s %s hit(s)\n' "$(basename "$f")" "$n"
  if [[ "$n" != "0" ]]; then
    grep -nE "$PAT" "$f" | sed 's/^/      /' | head -20
  fi
done

hdr "step-03 removal markers (proves the script edited grants.sb)"
grep -n 'step-03 removed' "$PD/grants.sb" | sed 's/^/  /' || echo "  none found — did apply-step-03.sh run?"

hdr "backups present"
ls -1 "$PD"/grants.sb.bak-* 2>/dev/null | sed 's/^/  /' | tail -5 || echo "  no grants.sb backups"

hdr "effective policy (what the launcher actually builds)"
if [[ -x "$HOME/git/pi-sandbox-hardening/scripts/build-policy.sh" ]]; then
  eff="$("$HOME/git/pi-sandbox-hardening/scripts/build-policy.sh" "$PWD" /tmp/effective-now.sb 2>/dev/null || true)"
  if [[ -n "$eff" && -f "$eff" ]]; then
    n=$(grep -cE "$PAT" "$eff" 2>/dev/null || echo 0)
    printf '  %-52s %s hit(s)\n' "$(basename "$eff")" "$n"
    if [[ "$n" != "0" ]]; then
      echo "  -> keychain is still granted by SOME layer:"
      grep -nE "$PAT" "$eff" | sed 's/^/      /' | head -20
    else
      echo "  -> effective policy grants NO keychain access ✅"
      echo "     => the running pi process is STALE. Restart pi (new terminal)."
    fi
  else
    echo "  could not build effective policy (run from a real workdir)"
  fi
else
  echo "  build-policy.sh not found; skipping"
fi

cat <<'EOF'

INTERPRETATION
  - If a layer still shows keychain hits -> that layer re-grants it; remove it there.
    (~/.safehouse-tmux.sb is appended LAST and overrides grants.sb.)
  - If NO layer shows hits but the sandboxed session still reaches the keychain
    -> the running pi process was started before Step 3. Restart pi in a NEW
       terminal (the policy is compiled at launch and never reloaded).
EOF
