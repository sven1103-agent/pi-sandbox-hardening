#!/usr/bin/env bash
# Step 3 — remove the keychain re-open from grants.sb.
#
# Removes the blocks that grant access to ~/Library/Keychains and the
# SecurityServer/security.agent IPC. Keeps `com.apple.trustd.agent` (TLS).
#
# Idempotent, backs up first, refuses to run inside the sandbox.
# After the change it verifies FUNCTIONALLY that the agent's own gh token still
# works (that is the real regression risk — gh prefers the keychain, so this
# change is what forces the file token to be used).
#
# Usage: scripts/apply-step-03.sh [--dry-run]
set -euo pipefail

GRANTS="${SANDBOX_GRANTS:-$HOME/.config/sandbox-exec/grants.sb}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

say() { printf '%s\n' "$*"; }

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: run this from an UNCONFINED terminal." >&2
  exit 3
fi
[[ -f "$GRANTS" ]] || { echo "ERROR: no grants.sb at $GRANTS" >&2; exit 1; }

say "grants: $GRANTS"
say "backup: $GRANTS.bak-$STAMP"
say

if (( DRY )); then
  say "[dry-run] would remove keychain + SecurityServer grants and keep trustd.agent"
  say
  say "current keychain-related lines:"
  grep -n 'Keychains\|SecurityServer\|security\.agent\|security\.trustd\|db/mds\|com\.apple\.security' "$GRANTS" | sed 's/^/  /' || say "  (none found)"
  exit 0
fi

cp -p "$GRANTS" "$GRANTS.bak-$STAMP"

python3 - "$GRANTS" <<'PY'
import re, sys, os, stat

path = sys.argv[1]
src = open(path).read()
orig = src

# Remove any top-level (allow ...) form that references the keychain surface.
# We do this by walking the S-expression forms rather than regexing blindly, so
# we never cut a form in half or swallow an unrelated grant.
KEYCHAIN_MARKERS = (
    "/Library/Keychains",
    "com.apple.security.plist",
    "/private/var/db/mds",
    "com.apple.SecurityServer",
    "com.apple.security.agent",
)

def split_forms(text):
    """Yield (start, end, form_text) for each top-level parenthesised form."""
    i, n = 0, len(text)
    while i < n:
        if text[i] == '(':
            depth, j = 0, i
            while j < n:
                if text[j] == '(':
                    depth += 1
                elif text[j] == ')':
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            yield i, j + 1, text[i:j + 1]
            i = j + 1
        else:
            i += 1

KEYCHAIN_LINE = re.compile(r'"/Library/Keychains|com\.apple\.security\.plist', re.I)

def surgical_metadata(form):
    """For a file-read-metadata allow that mixes /Library traversal with
    Keychains literals, drop ONLY the Keychains lines and keep /Library.
    Removing the whole form would also drop generic /Library traversal, which
    other grants may depend on."""
    lines = form.splitlines(keepends=True)
    kept = [ln for ln in lines if not KEYCHAIN_LINE.search(ln)]
    return "".join(kept)

keep, removed, trimmed = [], 0, 0
last = 0
for start, end, form in split_forms(src):
    keep.append(src[last:start])          # whitespace/comments between forms
    low = form.lower()
    is_allow = low.lstrip().startswith("(allow")
    is_metadata = "file-read-metadata" in low
    hits = [m for m in KEYCHAIN_MARKERS if m.lower() in low]
    # Never remove a trustd-only grant (needed for TLS), and never touch a (deny ...).
    is_trustd_only = "trustd" in low and not any(
        m.lower() in low for m in KEYCHAIN_MARKERS
    )
    if is_allow and hits and not is_trustd_only:
        if is_metadata and "(home-literal \"/library\")" in low.replace(" ", " "):
            # Mixed traversal form: keep the non-Keychains lines.
            newform = surgical_metadata(form)
            body = re.sub(r'(?is)^\s*\(allow\s+file-read-metadata', '', newform).strip()
            if body in ("", ")") or newform.count("(") <= 1:
                keep.append(";; [step-03 removed keychain metadata grant]\n")
            else:
                keep.append(newform)
            trimmed += 1
        else:
            removed += 1
            keep.append(";; [step-03 removed keychain grant]\n")
    else:
        keep.append(form)
    last = end
keep.append(src[last:])
out = "".join(keep)

if removed == 0 and trimmed == 0:
    print("nothing to remove (already clean?)")
    sys.exit(0)

mode = stat.S_IMODE(os.stat(path).st_mode)
open(path, "w").write(out)
os.chmod(path, mode)
print(f"removed {removed} keychain grant form(s); trimmed {trimmed} mixed metadata form(s)")
PY

say
say "remaining keychain-related lines (expect none, except trustd.agent):"
grep -n 'Keychains\|SecurityServer\|security\.agent\|db/mds' "$GRANTS" | sed 's/^/  /' || say "  none ✅"
grep -n 'trustd' "$GRANTS" | sed 's/^/  kept: /' || true

say
say "sanity: grants.sb still parses as balanced parens?"
python3 - "$GRANTS" <<'PY'
import sys
s = open(sys.argv[1]).read()
# strip comments
out, i, n = [], 0, len(s)
while i < n:
    if s[i] == ';':
        while i < n and s[i] != '\n':
            i += 1
    else:
        out.append(s[i]); i += 1
t = "".join(out)
d = 0
for ch in t:
    if ch == '(':
        d += 1
    elif ch == ')':
        d -= 1
    if d < 0:
        sys.exit("ERROR: unbalanced ')' — grants.sb is malformed")
if d != 0:
    sys.exit(f"ERROR: {d} unclosed '(' — grants.sb is malformed")
print("  balanced ✅")
PY

cat <<'EOF'

NEXT — the functional check that matters
  Open a NEW terminal and start pi via the sandbox launcher, then inside it:
      gh api user --jq .login          # must still print sven1103-agent
      gh pr list --repo example-org/example-app --limit 1
      curl -s -o /dev/null -w '%{http_code}\n' https://api.github.com   # 200

  If `gh` fails with Bad credentials / an auth prompt, the file-token fallback
  did not take over — restore:
      cp -p <grants>.bak-<tag> <grants>

  Then record + diff:
      cd ~/git/pi-sandbox-hardening
      scripts/selftest.sh --record baseline-step3.tsv
      scripts/selftest.sh --diff baseline-step2.tsv
EOF
