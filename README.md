# Pi Sandbox Hardening — Handoff

**Status:** investigation complete, no changes applied yet
**Created:** 2026-10-22
**Owner:** sven1103
**Goal:** Keep running the pi coding agent as the normal user `sven1103` (no second
account, no account switching), while preventing the agent from reaching macOS
keychain credentials, SSH keys, ambient tokens, and GitHub auth.

This directory is a **self-contained handoff**. A fresh agent should be able to
read `FINDINGS.md` + `MITIGATION_PLAN.md` and continue without re-investigating.

## Read in this order

| File | Purpose |
|---|---|
| `FINDINGS.md` | Verified current state: what is exposed, with evidence |
| `MITIGATION_PLAN.md` | Ordered, actionable fixes with checkboxes and exact edits |
| `TESTING.md` | **Regression harness: DENY/ALLOW suites, baseline + diff workflow** |
| `EVIDENCE.md` | Raw file excerpts, line numbers, reproduction commands |
| `UPSTREAM_STANCE.md` | What Safehouse authors say; local vs upstream defaults |
| `OPEN_QUESTIONS.md` | Unresolved items / decisions needed from the user |

## TL;DR

1. **The alias is not a boundary** — `pi-native` and any direct `pi` launch run
   unconfined, so sandbox the *session* (tmux), not the `pi` invocation.
   **Corrected:** an earlier draft called the alias sandbox "bypassable" because
   pi was seen reading `~/.ssh` and the keychain. That was a `WORK_DIR=$HOME`
   artifact: running from the home folder appends a whole-home grant. With a
   realistic workdir the sandbox holds (`~/.ssh/id_rsa` and home writes denied).
   See `FINDINGS.md` F1/F11. The live holes are keychain (F2) and ssh-agent (F4).
2. **`grants.sb` deliberately re-opens the keychain** (`file-read* file-write*`
   on `~/Library/Keychains`) with `mach-lookup` to `SecurityServer`. This is the
   main keyring hole and it also grants *write*.
3. **`agent.sb` re-opens ssh-agent access**, so the agent can sign with any
   loaded key without reading it.
4. **`run-sandboxed.sh` inherits the full environment** via `env`, so secrets
   exported in `~/.zshrc` (e.g. `HF_TOKEN_STRICT`) reach even a correctly
   sandboxed pi.
5. **A personal-account GitHub OAuth token (`sven1103`) sits in the login
   keychain next to the bot token** and is readable by any unconfined process
   under this UID.

### Upstream context (see `UPSTREAM_STANCE.md`)

- Safehouse **documents** that it does not protect against "abuse through
  already-allowed IPC/credential channels" or "leakage from explicitly allowed
  paths", and that "preventing exfiltration/C2 is NOT a goal". Keychain is an
  **intentional opt-in**, not a bug.
- The **ssh-agent** exposure *was* reported (#36) and fixed by deny-by-default in
  v0.4.0. The local policy **dropped that core deny** and baked in the
  `--enable=ssh` allow → local setup is *less* safe than upstream defaults.
- Upstream exposes `gh`/`glab` tokens **by default** via core `scm-clis.sb`. The
  local fork was written against **v0.10.1**; safehouse is now **v0.12.0**
  (P11.1 done), but the hand-edited policy is still what the wrapper loads.
- Implication: prefer upstream generation + a small `--append-profile` final-deny
  overlay over a hand-maintained fork, and make the bot token least-privilege
  rather than relying on hiding it.

## Ground rules for the next agent

- **Test before you change.** Record a baseline (`TESTING.md`) then apply one
  step, then diff. A step is only done when the diff is understood.
- **The invariant is "human creds unreachable, agent still works"** — not "any
  readable credential is bad". The agent's own creds (`~/.pi/agent/auth.json`,
  `~/.agent/**`) are supposed to be reachable.
- **Run tests from an unconfined terminal, in a real workdir.** Never `$HOME`
  (see F1/F11). The scripts enforce both.
- **Do not print secret values into the transcript or these files.** Verify
  reachability with exit-status tests (see `EVIDENCE.md`), never by printing
  tokens.
- **Rotate, don't just hide.** `HF_TOKEN_STRICT` was printed in plaintext in a
  prior session log and must be considered compromised.
- Back up any policy file before editing (`*.bak-<date>`).
- Changes to `~/.config/sandbox-exec/*` affect the user's daily workflow; make
  them opt-in/incremental and verify pi still starts.
