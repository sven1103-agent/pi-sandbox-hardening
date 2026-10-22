# Mitigation Plan

Ordered so that **irreversible/account-level actions are separated from local
policy edits**. Do the account hygiene (P5/P7) first if there is any chance the
host is already compromised; otherwise P1–P4 give the biggest gain per effort.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked/needs user

---

## Phase 0 — Pre-flight

- [ ] **P0.1** Confirm assumptions still hold:
      `gh auth status`, `ls -la ~/.config/sandbox-exec/`,
      `./scripts/selftest.sh` (see `EVIDENCE.md`).
- [ ] **P0.2** Back up policy files before touching anything:
      ```bash
      cd ~/.config/sandbox-exec
      for f in agent.sb grants.sb run-sandboxed.sh; do
        cp -p "$f" "$f.bak-$(date +%Y%m%d-%H%M%S)"
      done
      ```
- [ ] **P0.3** Do all edits from an **unconfined** terminal (not from inside pi),
      so a broken policy cannot lock you out of fixing it.
- [ ] **P0.4** `[!]` Ask user before doing anything irreversible (P5, P7) —
      token revocation and key passphrases affect other machines/CI.

---

## Phase 1 — Make the sandbox non-bypassable

### P1 — Sandbox the session, not the `pi` invocation  [fixes F1]
- [ ] **P1.1** Create a launcher for a **confined tmux server** so every child
      (`pi`, `pi-native`, subshells, MCP servers, extensions) is inside one
      boundary. Sketch: `scripts/agent-tmux.sh`
      ```bash
      #!/usr/bin/env bash
      # Launch a tmux server whose entire process tree is under the policy.
      set -euo pipefail
      SOCK="/tmp/agent-tmux-$$"
      exec sandbox-exec -f "$(scripts/build-policy.sh "$PWD")" \
        /usr/bin/env -i PATH=/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin \
          HOME="$HOME" TERM="${TERM:-xterm-256color}" TMPDIR="${TMPDIR:-/tmp}" \
        /opt/homebrew/bin/tmux -S "$SOCK" new-session -A -s agent
      ```
- [ ] **P1.2** Keep **one unconfined terminal** for admin/git-push work. Do not
      try to sandbox the shell you use to fix the sandbox.
- [ ] **P1.3** Change the zsh alias to be a *convenience*, not the boundary:
      keep `alias pi=...` but document that `pi-native` must not be used for
      untrusted work. Consider shadowing `pi-native` to print a warning.
- [ ] **P1.4** Note: nested `sandbox-exec` intentionally fails. Do **not**
      "fix" that; the outer policy is the boundary.

### P2 — Remove the keychain hole  [fixes F2]
- [ ] **P2.1** In `~/.config/sandbox-exec/grants.sb`, **delete lines 31–58**
      (the entire `Integration: Keychain (GitHub-Auth via gh CLI)` block,
      including the `mach-lookup` on `SecurityServer` / `security.agent` /
      `trustd`).
- [ ] **P2.2** Keep `com.apple.trustd.agent` — it is already allowed at
      `agent.sb:209` and is needed for TLS. Removing the `grants.sb` trustd
      allow must not break HTTPS; verify in P2.5.
- [ ] **P2.3** `[!]` Decide the credential strategy **before** removing, or `gh`
      and `git push` will break inside the sandbox:
      - **Option A (recommended):** dedicated agent keychain
        (`security create-keychain agent.keychain-db`) unlocked only for agent
        sessions, holding only the bot token.
      - **Option B:** no GitHub auth inside the sandbox at all — do pushes in
        the unconfined terminal.
- [ ] **P2.4** Replace any keychain `file-read*` with `file-read-metadata` if a
      path-resolution need is discovered later. Never grant `file-write*` on the
      keychain.
- [ ] **P2.5** Verify (from a confined process):
      ```bash
      security find-generic-password -s gh:github.com -w >/dev/null 2>&1 && echo LEAK || echo blocked
      curl -s --max-time 10 -o /dev/null -w '%{http_code}\n' https://api.github.com   # expect 200
      ```

### P3 — Remove ssh-agent access  [fixes F4]
- [ ] **P3.1** In `agent.sb`, delete lines ~787–809:
      - `(allow file-read-metadata (home-literal "/.ssh/agent"))`
      - the `file-read* file-write* file-read-metadata` block on the
        `Listeners` regexes and `(home-subpath "/.ssh/agent")`
      - the `(allow network-outbound (remote unix-socket …))` block for those
        sockets
- [ ] **P3.2** Keep the existing `(deny file-read* file-write* (home-subpath "/.ssh"))`
      at ~line 760 and keep the specific *file* allows for `known_hosts`,
      `config`, `config.d`, `allowed_signers` — those are needed for git SSH
      and commit signing without exposing keys.
- [ ] **P3.3** Verify: `ssh-add -l` inside the sandbox must fail; commit signing
      must still work via `allowed_signers` + an unconfined signer, or be
      documented as intentionally unavailable.

### P4 — Stop environment inheritance  [fixes F7]
- [ ] **P4.1** In `run-sandboxed.sh`, replace the `env TMUX=...` form with an
      explicit allowlist:
      ```bash
      exec sandbox-exec -f "$tmp_policy" \
        /usr/bin/env -i \
          PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
          HOME="$HOME" \
          TERM="${TERM:-xterm-256color}" \
          TMPDIR="${TMPDIR:-/tmp}" \
          LANG="${LANG:-en_US.UTF-8}" \
          TMUX="${TMUX:-}" \
          /opt/homebrew/bin/pi ${passthrough_args[@]+"${passthrough_args[@]}"}
      ```
- [ ] **P4.2** `[!]` **Rotate `HF_TOKEN_STRICT`** — it was disclosed in plaintext
      in a prior session log. Also remove it from `~/.zshrc`; load it from a
      keychain/secret store or set it only in the shell that needs it.
- [ ] **P4.3** Add a repo-level check to prevent regressions: grep the wrapper
      for `env ` without `-i` in CI/review.

---

## Phase 2 — Account and key hygiene (irreversible — confirm with user)

### P5 — Retire the personal GitHub token from the keychain  [fixes F3]
- [ ] **P5.1** `[!]` Revoke the personal-account OAuth token at
      github.com/settings/applications, then remove the `sven1103` item:
      ```bash
      security delete-generic-password -s "gh:github.com" -a "sven1103"
      ```
- [ ] **P5.2** `[!]` Audit and revoke stale `gho_` tokens for both accounts.
- [ ] **P5.3** Reduce the bot token: replace the classic OAuth token with a
      **fine-grained PAT** (specific repos, `contents:write` only where needed)
      or a **GitHub App** installation token (1h TTL). **Do not grant
      `workflow`** unless a task truly requires it — it is equivalent to running
      code in CI with repo/org secrets.
- [ ] **P5.4** Reduce org exposure: prefer **per-repo collaborator grants** over
      org-wide membership for `sven1103-agent`.
- [ ] **P5.5** Add branch protection / required review on `.github/workflows/**`
      and on default branches, so a stolen token cannot self-escalate via CI.
- [ ] **P5.6** Consider pointing repo/org secrets at a separate CI identity so
      token theft ≠ secret theft.

### P6 — Remove the extra agent key path  [fixes F5]
- [ ] **P6.1** In `agent.sb`, remove the wizard-generated grant for
      `/Users/sven1103/.agent/ssh` (line ~851) unless a concrete workflow needs
      it; if needed, narrow to an exact `literal` file and mark it read-only.
- [ ] **P6.2** Review `~/.agent/ssh/agent-github-key` — decide whether it should
      exist, and protect it with a passphrase if it stays.

### P7 — Protect on-disk SSH keys  [fixes F6]
- [ ] **P7.1** `[!]` Add passphrases to `~/.ssh/id_rsa`, `~/.ssh/jenkins`,
      `~/.ssh/id_ed25519` (all currently usable with an empty passphrase), or
      move them into a dedicated keychain/agent.
- [ ] **P7.2** Keep `sven1103-agent-strongbox` passphrase-protected and do not
      leave `ssh-agent` unlocked during agent sessions.
- [ ] **P7.3** Prefer per-repo read-only **deploy keys** over broad account keys.

---

## Phase 3 — Defense in depth

### P8 — Constrain network egress  [fixes F8]
- [ ] **P8.1** Replace `(allow network-outbound (remote ip))` with an allowlist
      of required hosts (model API, package registries, GitHub) if feasible.
- [ ] **P8.2** If host filtering is impractical, add outbound telemetry/alerts
      instead of pretending egress is controlled.

### P9 — Remove ambient git auth  [fixes F10]
- [ ] **P9.1** Remove global `credential.helper=gh` from `~/.gitconfig`; set it
      per-repo, or use a helper that returns credentials only for allow-listed
      repos.
- [ ] **P9.2** Wash out `credential.https://github.com.helper` duplicates.

### P10 — Regression guard
- [ ] **P10.1** Add `scripts/selftest.sh` (see `EVIDENCE.md`) and call it from
      the launcher; **fail the launch** if any credential probe succeeds.
- [ ] **P10.2** Record the expected results in this repo so future agents can
      diff behaviour.

---

## Verification checklist (run after each phase)

```bash
# 1. Keychain not reachable from a confined process
security find-generic-password -s gh:github.com -w >/dev/null 2>&1 && echo LEAK || echo blocked

# 2. No personal token left in the keychain
security find-generic-password -s gh:github.com -a sven1103 -w >/dev/null 2>&1 && echo STILL-THERE || echo removed

# 3. ssh-agent not usable
ssh-add -l >/dev/null 2>&1 && echo LEAK || echo blocked

# 4. Env not inherited
printenv HF_TOKEN_STRICT   # inside the sandbox: expect empty / non-zero exit

# 5. Policy still functional
curl -s --max-time 10 -o /dev/null -w '%{http_code}\n' https://api.github.com   # 200
cd <workdir> && git status   # works
```

## Rollback

Each edited file has a `*.bak-<timestamp>` sibling from P0.2. Restore with
`cp -p <file>.bak-<ts> <file>`. If the session sandbox locks you out, fix from a
fresh unconfined terminal (e.g. Terminal.app, not the confined tmux).
