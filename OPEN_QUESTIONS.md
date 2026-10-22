# Open questions / decisions needed

Answer these to unblock implementation. Each maps to a plan item.

## Q1 — GitHub auth inside the sandbox (blocks P2.3)
The `grants.sb` keychain block exists so `gh` works inside the sandbox.
If it is removed, what should happen?

- [ ] **A** Dedicated agent keychain (`agent.keychain-db`), unlocked per session,
      containing **only** the `sven1103-agent` bot token. *(recommended)*
- [ ] **B** No GitHub auth inside the sandbox at all — do all pushes in the
      unconfined terminal.
- [ ] **C** Something else: ______

## Q2 — Commit signing (affects P3)
`~/.gitconfig` sets `commit.gpgsign=true` with SSH signing and
`gpg.ssh.program=/usr/bin/ssh-keygen`. If ssh-agent access is removed, signing
inside the sandbox will need a different route.

- [ ] Accept unsigned commits inside the sandbox, sign on push/amend outside
- [ ] Keep a narrowly scoped ssh-agent allow (document why)
- [ ] Other: ______

## Q3 — Session sandbox scope (P1)
A confined tmux server restricts everything in that pane.

- Which workdirs do you need in a confined session? ______
- Do you need `docker`, browsers/Playwright, Xcode, or `open` inside it?
  (each needs its own optional profile)
- Is one unconfined terminal acceptable for admin work? *(recommended)*

## Q4 — Token revocation (blocks P5, needs user action)
- [ ] Approve revoking the personal-account `gho_` token and deleting the
      `sven1103` keychain item?
- [ ] Approve replacing the bot token with a fine-grained PAT / GitHub App token
      **without** `workflow` scope? Any workflow that genuinely needs it? ______

## Q5 — SSH keys (P7)
- [ ] Add passphrases to `id_rsa`, `jenkins`, `id_ed25519`, or relocate them?
- Are any of these used by automation that cannot supply a passphrase? ______

## Q6 — `HF_TOKEN_STRICT` (blocks P4.2)
Must be rotated (disclosed in plaintext in a prior session log).

- [ ] Confirm rotation done: ______
- Where should it live instead? (keychain / secret store / per-shell export) ______

## Q7 — Network egress (P8)
- [ ] Is an outbound host allowlist feasible, or should we rely on
      detection/alerting instead?

## Q8 — Upstream alignment (new; see `UPSTREAM_STANCE.md`)

- [ ] **Q8.1** Upgrade safehouse v0.10.1 → v0.12.0, then regenerate instead of
      hand-editing? *(recommended)*
- [ ] **Q8.2** Adopt "generate policy + small `--append-profile` final-deny
      overlay" instead of maintaining `agent.sb`/`grants.sb`?
- [ ] **Q8.3** Do you actually need `--enable=ssh` (ssh-agent) inside the sandbox,
      or can git remotes use HTTPS + token? Blocking it is upstream's documented
      default (and was fixed upstream in #36 / v0.4.0).
- [ ] **Q8.4** Optional upstream report: the wizard-generated output can bake in
      `--enable=ssh` + keychain while omitting the core
      `ssh-agent-default-deny.sb`. Related upstream items: #71, #102, #118.
      File it?

## Q9 — Pending user preference
- [ ] Apply P1–P4 locally now (reversible, with backups), or wait until the
      decisions above are made?
