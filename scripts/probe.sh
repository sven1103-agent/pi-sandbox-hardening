#!/usr/bin/env bash
# Probe a single path/reachability question under an effective policy.
#
# Always uses exit status only: never prints secret material.
#
# Usage: probe.sh <policy-file> <command...>
#   probe.sh /tmp/pi-effective-policy.sb /usr/bin/security find-generic-password -s gh:github.com -w
#
# NOTE: run this from an UNCONFINED context. If you are already inside a
# sandbox, nested sandbox-exec fails and every probe misreports.
set -uo pipefail

policy="${1:?usage: probe.sh <policy-file> <command...>}"; shift
[[ -f "$policy" ]] || { echo "policy not found: $policy" >&2; exit 2; }

# If nested sandbox-exec is refused we are already confined, and every probe
# would be misread (see EVIDENCE.md E7 and the retracted FINDINGS F1).
if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "INCONCLUSIVE (already inside a sandbox — run from an unconfined shell)"
  exit 3
fi

out="$(sandbox-exec -f "$policy" -- "$@" 2>&1)"
rc=$?

if [[ $rc -eq 0 ]]; then
  echo "ALLOWED"
  exit 0
fi

case "$out" in
  *"sandbox_apply: Operation not permitted"*)
    echo "INCONCLUSIVE (nested sandbox refused — run from an unconfined shell)"
    exit 3
    ;;
  *)
    echo "denied"
    exit 1
    ;;
esac
