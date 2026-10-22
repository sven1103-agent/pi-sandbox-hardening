# Mitigation Plan

> **Status: historical planning document — kept for traceability.**
>
> This was the plan written *before* any change was made. It is **not** a
> description of what was ultimately done: the implementation diverged in two
> important ways, and the step documents are authoritative.
>
> | Plan item | What actually happened |
> |---|---|
> | P2 — remove the keychain hole | Superseded by **Step 3b**: rather than removing keychain access (which broke every provider, since `auth.json` resolves keys via `security find-generic-password`), the agent got its **own** keychain. See `STEP-03b-agent-keychain.md`. |
> | P3 — remove ssh-agent access | Implemented as **Step 4** (`STEP-04-ssh-agent-deny.md`), plus **Step 5** which removes `SSH_AUTH_SOCK` from the environment. |
> | P4 — stop environment inheritance | Implemented as **Step 5** (`STEP-05-env-sanitization.md`). |
> | P5–P8, P10, P11 | Not done. `P5` (retire the personal token) is now **unnecessary**: Step 3b denies the login keychain entirely. P8 (egress) and P11 (stop forking upstream) remain open. |
> | — | **Added:** Step 1/2 (agent identity), Step 6 (personal `gh` config deny). |
>
> Checkbox counts below are therefore misleading and are left as-written.
> See `README.md` for the actual outcome and `STEP-*.md` for the implementations.

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

### P1 — Sandbox the session, not the `pi` invocation  [F1 retracted; still worth doing]

> **F1 was a measurement artifact, not a sandbox bypass.** The earlier session ran
> from the home folder, so `WORK_DIR=$HOME` and the wrapper appended
> `(allow file-read* file-write* (subpath "$HOME"))`, exposing `~/.ssh`,
> `~/.zshrc` and the keychain. Re-verified (F11): with a real workdir the sandbox
> holds. The residual issue is only that a *direct* `pi`/`pi-native` invocation
> is unconfined — an invocation problem, not a policy hole.

- [ ] **P1.0** Always start agent sessions from a real workdir, never `$HOME`.
      `scripts/build-policy.sh` and `scripts/selftest.sh` now refuse `$PWD=$HOME`
      so this mistake cannot silently recur.
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

> Context: keychain access is an upstream **opt-in** (`--enable=keychain`,
> auto-injected only for agent profiles that declare it; `60-agents/pi.sb` does
> **not**). The `grants.sb` blocks are a trimmed copy of upstream's
> `55-integrations-optional/keychain.sb`, except upstream's docs advise making it
> **read-only** while the local copy grants `file-write*`. Upstream treats this as
> by-design, so there is no upstream fix to wait for — it is a local deviation.
> See `UPSTREAM_STANCE.md` §3.
>
> Note also: removing the keychain grant does **not** hide the `gh` token if it is
> stored in `~/.config/gh/hosts.yml`, because core `scm-clis.sb` grants that path
> by default. Prefer the least-privilege token approach (P5).
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

### P3 — Remove ssh-agent access  [fixes F4; restores upstream default]

> Context: this is **not** a novel finding. Upstream reported it as issue #36 and
> fixed it in v0.4.0 by adding a core, always-loaded deny profile
> `50-integrations-core/ssh-agent-default-deny.sb`. The local policy omits that
> profile and instead bakes in the optional `--enable=ssh` allows. So this task is
> best framed as **reverting a local deviation to upstream's documented default**
> (`default-assumptions`: ssh agent sockets denied "unless `ssh` is enabled").
> See `UPSTREAM_STANCE.md` §2.
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

### P4 — Stop environment inheritance  [fixes F7; use upstream's sanitized mode]

> Context: upstream warns that `--env` "forwards the entire inherited host
> environment, including cloud credentials, API keys, and other secrets", and
> ships **sanitized env by default** with `--env-pass=NAMES` for opt-ins. The local
> wrapper's bare `env TMUX=…` reproduces the dangerous `--env` behaviour. Prefer
> upstream's sanitized mode + `--env-pass` over a hand-rolled allowlist.
> See `UPSTREAM_STANCE.md` §5.
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
- [ ] **P6.2** Review `~/.agent/ssh/github_login_ed25519` (mode `0600`) — decide
      whether it should exist, and protect it with a passphrase if it stays.
      (Earlier drafts named a non-existent `agent-github-key`; see F5/F11.)

### P7 — Protect on-disk SSH keys  [fixes F6]
- [ ] **P7.1** `[!]` Add passphrases to `~/.ssh/id_rsa`, `~/.ssh/jenkins`,
      `~/.ssh/id_ed25519` (all currently usable with an empty passphrase), or
      move them into a dedicated keychain/agent.
- [ ] **P7.2** Keep `sven1103-agent-strongbox` passphrase-protected and do not
      leave `ssh-agent` unlocked during agent sessions.
- [ ] **P7.3** Prefer per-repo read-only **deploy keys** over broad account keys.

---

## Phase 3 — Defense in depth

### P8 — Constrain network egress  [accepts or mitigates F8; upstream won't fix]

> Context: upstream lists "Data exfiltration over network from files the sandbox
> is allowed to read" as an explicit **non-goal**, and `scm-clis.sb` states
> "preventing exfiltration/C2 is NOT a goal". Expect no upstream change; decide
> whether to accept the risk or add your own controls.
- [ ] **P8.1** Replace `(allow network-outbound (remote ip))` with an allowlist
      of required hosts (model API, package registries, GitHub) if feasible.
- [ ] **P8.2** If host filtering is impractical, add outbound telemetry/alerts
      instead of pretending egress is controlled.

### P9 — Remove ambient git auth  [fixes F10, F12 — now load-bearing]

> **F12:** your global gitconfig is an independent route to the login keychain.
> Its host-scoped `credential.https://github.com.helper = !gh auth git-credential`
> answers for github.com, so `git credential fill` returns a token from inside the
> sandbox even if the keychain DB grant is removed. Pointing the agent at its own
> `GIT_CONFIG_GLOBAL` closes this (verified) — so P9 is required for P2 to actually
> hold, not cosmetic. The system `credential.helper=osxkeychain` is latent
> (no github.com item) and is *not* the leaker. See FINDINGS F12.

- [ ] **P9.1** Remove global `credential.helper=gh` from `~/.gitconfig`; set it
      per-repo, or use a helper that returns credentials only for allow-listed
      repos. **Also remove the host-scoped
      `credential.https://github.com.helper = !gh auth git-credential` line** —
      that is the one that actually answers.
- [ ] **P9.2** Wash out `credential.https://github.com.helper` duplicates.

### P10 — Regression guard
- [ ] **P10.1** Add `scripts/selftest.sh` (see `EVIDENCE.md`) and call it from
      the launcher; **fail the launch** if any credential probe succeeds.
- [ ] **P10.2** Record the expected results in this repo so future agents can
      diff behaviour.

---

### P11 — Stop forking upstream; use generated policy + final-deny overlay

> Rationale: the local `agent.sb`/`grants.sb` drifted into a *less* safe
> combination than upstream defaults (P2/P3/P4, `UPSTREAM_STANCE.md` §6). Upstream
> explicitly supports layering: "Final-deny overlays should always remain possible
> (`--append-profile`)."

- [x] **P11.1** ~~Consider upgrading safehouse~~ **Done** — installed version is
      now **v0.12.0** (upstream latest; verified with `safehouse --version`).
      Re-verify the generated policy after switching to it (issue #102
      write-grant/persistence class may be affected). Note: the hand-edited
      `agent.sb`/`grants.sb` fork is still what the wrapper loads, so the upgrade
      alone changes nothing until P11.2 is done.
- [ ] **P11.2** Prefer letting `safehouse` generate the policy from flags, then
      add only a small `--append-profile` overlay for local needs, instead of
      maintaining a full hand-edited profile.
- [ ] **P11.3** Use `safehouse --explain` / `--stdout` to diff effective grants
      against expectations and against the local `agent.sb`.
- [ ] **P11.4** Optional: use `<workdir>/.safehouse` (`add-dirs-ro=`, `add-dirs=`,
      `enable=`, `append-profile=`) with `--trust-workdir-config` for per-project
      grants instead of editing the global profile.
- [ ] **P11.5** Do **not** enable `--enable=ssh` casually; it is the upstream gate
      for ssh-agent credential use.
- [ ] **P11.6** Avoid `--enable=launch-services` (`open` starts processes OUTSIDE
      the sandbox with full user permissions) unless required.

---

## Verification checklist (run after each phase)

```bash
# 0. Run from a REAL workdir, never $HOME (see F1/F11) — scripts enforce this
cd "$HOME/git/<some-repo>"

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
