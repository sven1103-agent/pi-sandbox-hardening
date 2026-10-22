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
| `EVIDENCE.md` | Raw file excerpts, line numbers, reproduction commands |
| `OPEN_QUESTIONS.md` | Unresolved items / decisions needed from the user |

## TL;DR

1. **The pi alias sandbox is bypassable** — `pi-native` and any non-aliased
   launch run unconfined. To change this, sandbox the *session* (tmux), not the
   `pi` invocation.
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

## Ground rules for the next agent

- **Do not print secret values into the transcript or these files.** Verify
  reachability with exit-status tests (see `EVIDENCE.md`), never by printing
  tokens.
- **Rotate, don't just hide.** `HF_TOKEN_STRICT` was printed in plaintext in a
  prior session log and must be considered compromised.
- Back up any policy file before editing (`*.bak-<date>`).
- Changes to `~/.config/sandbox-exec/*` affect the user's daily workflow; make
  them opt-in/incremental and verify pi still starts.
