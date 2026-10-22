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
