#!/usr/bin/env bash
# Install this repo's git hooks (kept under scripts/hooks/ so they are versioned).
set -euo pipefail
root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
for h in "$root"/scripts/hooks/*; do
  name="$(basename "$h")"
  cp -p "$h" "$root/.git/hooks/$name"
  chmod +x "$root/.git/hooks/$name"
  echo "installed $name"
done
