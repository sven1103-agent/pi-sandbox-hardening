# Step 2 — Wire the agent's own GitHub identity into the sandbox

**STATUS: ✅ APPLIED AND VERIFIED (2026-10-22)** — see "Verification results" below.

**Depends on:** Step 1 (agent `gh` token installed at `~/.agent/gh/hosts.yml`)
**Toward:** makes Steps 3–4 safe (removing keychain/ssh-agent must not break work).

## Verification results (measured live, inside the sandboxed session)

| Check | Result |
|---|---|
| env reaches session (`GH_CONFIG_DIR`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`) | ✅ all set |
| `gh api user` | ✅ `sven1103-agent` |
| `gh pr list` / `gh issue list` / `gh search repos` / `--json statusCheckRollup` | ✅ all work |
| git-over-SSH with `SSH_AUTH_SOCK` unset | ✅ works (agent key, no ssh-agent) |
| **file token present + gh authenticates** | ✅ (but see caveat) |
| F12 ambient keychain route (`git credential fill`) | ✅ **blocked** |
| agent creds reachable (`~/.agent/gh`, `~/.agent/gitconfig`, `~/.agent/ssh`) | ✅ reachable |
| DENY leaks (keychain/ssh-agent/env) | unchanged — 9 open, Step 3+ pending |

### CORRECTION: the "file token is in use" claim was wrong

An earlier version of this file claimed the file token was proven in use because
`sha256(gh auth token) == sha256(oauth_token in hosts.yml)`. **That proved
nothing** — the file and the keychain hold the *same* token value (Step 1 was
Option 2, reusing the existing token), so both sources hash identically.

Precedence, measured properly with a **bogus account name** so the keyring lookup
*misses* (this is the case that matters — it is what Step 3 creates):

| hosts.yml token | keyring | `gh api user` |
|---|---|---|
| valid | miss | ✅ authenticates — **file is authoritative** |
| invalid | miss | ❌ `Bad credentials` — **file is authoritative** |
| invalid | hit (real account) | ✅ authenticates — **keyring wins** |

So: while the keychain entry is reachable, `gh` uses it and `hosts.yml` is
ignored. Once the keychain is *unreachable* (Step 3), `gh` falls back to
`hosts.yml` correctly — verified directly. **Step 3 is therefore viable**, and the
correct regression signal is not a hash comparison but the invalid-token test
above.

## Post-mortem: the launcher-breaking patch (must-read before editing this file)

The first version of `apply-step-02.sh` inserted `#` comment lines **inside** the
backslash-continued `env` command:

```bash
  exec sandbox-exec -f "$tmp_policy" \
  env \
    TMUX="${TMUX:-}" \
    # agent-scoped identity (Step 2)      <-- FATAL
    GH_CONFIG_DIR="$HOME/.agent/gh" \
```

Bash treats `#` as the start of a comment, so the command ended at
`env TMUX="${TMUX:-}"`. `env` then ran **with no command**: it dumped the
environment and pi **never started**. Confirm:

```
ARGV: [-f] [/dev/null] [env] [TMUX=]      # pi is gone
```

Two lessons, both now enforced by tooling:

1. **`bash -n` does NOT catch this** — it is not a syntax error. Neither does
   grepping for the variables. Only *executing* the launcher reveals it.
   → `scripts/verify-launcher.sh` stub-executes the launcher and fails if pi is
   missing from argv. `apply-step-02.sh` now runs it and aborts on failure.
2. **Comments are only safe *before* the command.** Putting them between
   `exec … \` and `env \` is equally broken. The correct form has the comments
   above the `exec` line.

> Incident note: diagnosing this, one test executed `env` with no arguments in a
> non-sanitised shell and **printed `HF_TOKEN_STRICT` to the terminal**. The test
> helper now always runs under `env -i`. The token must be rotated regardless
> (see `OPEN_QUESTIONS.md` Q6).

If the launcher is already broken, run `scripts/repair-launcher.sh`.

## Original plan (for reference)

## What changes

Three things, all **additive or narrowing** — no capability is removed:

1. **Grant the agent's own credential paths** to the sandbox: `~/.agent/gh`
   (read) plus the `gh` cache/state dirs it writes.
2. **Give the agent its own git identity** (name/email) so it never commits as
   `you@example.com`.
3. **Neutralise the host git credential helpers** for agent sessions
   (`GIT_CONFIG_SYSTEM=/dev/null`) — see F12: the *system* gitconfig's
   `credential.helper=osxkeychain` is a second route to the login keychain.

## Prerequisite check

From an unconfined terminal:

```bash
ls -l "$HOME/.agent/gh/hosts.yml"        # exists, mode 600 (Step 1)
GH_CONFIG_DIR="$HOME/.agent/gh" gh api user --jq .login   # sven1103-agent
```

## 2.1 — Agent git identity file

Create `~/.agent/gitconfig` so the agent commits as the bot and uses the agent's
SSH key for git, with **no** credential helper:

```bash
cat > "$HOME/.agent/gitconfig" <<'EOF'
[user]
	name = sven1103-agent
	email = sven1103-agent@users.noreply.github.com
[core]
	sshCommand = "~/.agent/ssh/ssh-github.sh"
[credential]
	helper =
[commit]
	gpgsign = false
[tag]
	gpgsign = false
EOF
chmod 600 "$HOME/.agent/gitconfig"
```

> `gpgsign = false` because signing uses your passphrase-protected `id_human_ed25519`
> (the human key). The agent cannot sign without it — that is intended. Unsigned
> agent commits are fine; you can amend/sign them from an unconfined terminal.
> If you later want agent-signed commits, add the agent's *own* key to
> `allowed_signers` and set `gpg.format=ssh` + `user.signingkey` to the agent key.

Replace the email with the **numeric** bot address if you prefer privacy
(`gh api user --jq .id` under the agent config, then `<id>+sven1103-agent@users.noreply.github.com`).

## 2.2 — Policy changes (back up first)

```bash
cd "$HOME/.config/sandbox-exec"
for f in agent.sb grants.sb run-sandboxed.sh; do
  cp -p "$f" "$f.bak-$(date +%Y%m%d-%H%M%S)"
done
```

**a) Narrow the `~/.agent/ssh` grant (P6, F5).** The grant is currently
`(subpath "/Users/sven1103/.agent/ssh")` on the whole dir. Narrow it to the files
git actually needs, read-only:

```scheme
;; Agent's own GitHub identity (read-only, no other files in the dir)
(allow file-read*
    (literal "/Users/sven1103/.agent/ssh/config")
    (literal "/Users/sven1103/.agent/ssh/github_login_ed25519")
    (literal "/Users/sven1103/.agent/ssh/github_login_ed25519.pub")
    (literal "/Users/sven1103/.agent/ssh/known_hosts")
    (literal "/Users/sven1103/.agent/ssh/ssh-github.sh")
)
```

**b) Grant the agent's `gh` config (read-only) and cache (rw).** Add to
`grants.sb` — this is the file-based replacement for the keychain grant:

```scheme
;; === Agent's own GitHub credentials (keychain-free) ===
(allow file-read*
    (home-subpath "/.agent/gh")
    (home-literal "/.agent/gitconfig")
    (home-literal "/.agent/ssh"))
(allow file-read* file-write*
    (home-subpath "/.cache/gh")            ;; gh API cache
    (home-subpath "/.local/state/gh")      ;; gh runtime state
)
```

**c) Do NOT yet remove the keychain block.** That is Step 3. This step only adds
the replacement, so if something breaks you still have a working path.

## 2.3 — Session environment

The agent session must use its own identity. Add to the launcher
(`run-sandboxed.sh`, in the `env -i` allowlist from P4 — or as the first change
if P4 is not done yet):

```bash
GH_CONFIG_DIR="$HOME/.agent/gh" \
GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \
GIT_CONFIG_SYSTEM=/dev/null \
```

`GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig"` is required — see F12. Your global
gitconfig's host-scoped `!gh auth git-credential` helper is an independent route
to the login keychain; pointing the agent at its own gitconfig closes it
(verified). `GIT_CONFIG_SYSTEM=/dev/null` adds belt-and-braces isolation and is
optional for this leak.

## 2.4 — Verify

```bash
cd ~/git/pi-sandbox-hardening
scripts/selftest.sh --diff baseline-before.tsv
```

Expected diff for this step:

```
CHANGED  agent: gh config   MISSING/NOTYET  -> REACHABLE/ok
CHANGED  agent: gh api(own) MISSING/NOTYET  -> REACHABLE/ok
```

DENY checks must be **unchanged** (the 9 leaks remain until Steps 3–5) — Step 2
adds a capability, it does not yet close the keychain.

From **inside** the agent session, confirm real work:

```bash
gh api user --jq .login                                   # sven1103-agent
gh pr view --repo example-org/example-app --json number   # API works
git -C ~/git/<repo> status                                 # git works
printf 'protocol=https\nhost=github.com\n\n' | git credential fill   # should NOT return a password
```

## Exit criteria

- [ ] `agent: gh config` and `agent: gh api(own)` → `ok` in the harness
- [ ] DENY suite unchanged (still 9 leaks; no new leaks introduced)
- [ ] `gh pr view` / `gh issue list` work inside the agent session as `sven1103-agent`
- [ ] `git status`/`commit` inside a repo use `sven1103-agent`, not your identity
- [ ] `git credential fill` does **not** return a credential (F12 closed for the agent)
- [ ] agent commits are **not** signed with your key (and don't fail)

## Rollback

```bash
cd "$HOME/.config/sandbox-exec"
mv agent.sb.bak-<ts> agent.sb && mv grants.sb.bak-<ts> grants.sb
mv run-sandboxed.sh.bak-<ts> run-sandboxed.sh
rm -f "$HOME/.agent/gitconfig"
```

## Caveat to keep in mind

`gh` prefers the **keychain** over `hosts.yml`. Until Step 3 makes the keychain
unreachable, `gh` may still authenticate via the keychain and this step's
fallback is not truly exercised. The `agent: gh api(own)` check proves the wiring
is *reachable*; Step 3 is what proves the file token is *used*. Verify the token
source explicitly after Step 3 (`gh auth token` under `GH_CONFIG_DIR` should equal
the file's token).
