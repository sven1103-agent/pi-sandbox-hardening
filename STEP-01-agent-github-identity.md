# Step 1 — Give the agent its own GitHub identity (SSH for git, token for the API)

**Status:** ready to run (user, unconfined) · **Reversible:** yes (additive only)
**Toward:** F3 (personal token exposure), F7 (env inheritance), and the
dependency for P2/P3 (removing keychain + ssh-agent must not break GitHub work).

## Why this comes first

Today the agent reaches GitHub using **your** credentials: the login keychain
(`grants.sb`, bot + personal tokens) and the ssh-agent holding your keys. Before
we can remove those channels (Steps 3–4) the agent needs its **own** credentials,
so removing them doesn't break work. This step only **adds**; it changes **no**
policy, so it cannot reduce current capability.

## Design — why two mechanisms

`git` and `gh` authenticate differently, so the agent gets one credential for each:

| Need | Mechanism | Why |
|---|---|---|
| `git clone/fetch/push` | **SSH** with `~/.agent/ssh/github_login_ed25519` | No token, no keychain, no ssh-agent. **Already works** (verified below). |
| `gh pr/issue/api/search` | **Fine-grained PAT** in a file | `gh` is token-only — it has no SSH path. |

Verified in the current sandbox:

```
$ env -u SSH_AUTH_SOCK GIT_SSH_COMMAND=~/.agent/ssh/ssh-github.sh \
    git ls-remote git@github.com:example-org/example-app HEAD
179830b0ebceb70013b3ca28f277696022ef1e51  HEAD          # rc=0, no ssh-agent, no PAT
$ ~/.agent/ssh/ssh-github.sh -T git@github.com
Hi sven1103-agent!                                       # authenticates as the BOT, not you
```

Fingerprint: `SHA256:JJQXyblBNxHbTXTrQY3yH3CL+Ww2Uo2bxZvUHK0LMSc  pi-agent@local`
(no passphrase ⇒ usable as a plain file, independent of ssh-agent — which is what
makes Step 4 safe).

## Token scope (least privilege)

Fine-grained PAT, owned by / authorised for **`sven1103-agent`**:

- **Repository access:** only the repos the agent needs (start minimal).
- **Repository permissions:**
  - `Metadata: Read` (mandatory, auto)
  - `Contents: Read` — file/diff views
  - `Issues: Read` — `gh issue list/view`
  - `Pull requests: Read` — `gh pr list/view`
  - `Checks: Read` — `gh pr view --json statusCheckRollup,checks`
  - `Commit statuses: Read` — classic status contexts
- **Do NOT grant `Workflow`.** Read-only PR/issue queries never need it. That
  scope means "edit `.github/workflows/**`" = arbitrary code in CI with repo/org
  secrets — the single most dangerous thing the old token had (F3).
- **Expiration:** set one (e.g. 90 days).

## Do this (unconfined terminal — Terminal.app, NOT inside pi)

### 1. Create the PAT (browser)

github.com → Settings → Developer settings → Fine-grained tokens → Generate.
Generate it for **`sven1103-agent`**, with the permissions above.

### 2. Install it as a FILE, not in the keychain

`gh` stores tokens in the macOS keychain by default — which is exactly what we
are trying to close. Use `--insecure-storage` so the token lives in a file the
sandbox can grant explicitly:

```bash
install -d -m 700 "$HOME/.agent/gh"

GH_CONFIG_DIR="$HOME/.agent/gh" /opt/homebrew/bin/gh auth login \
  --hostname github.com \
  --git-protocol ssh \
  --with-token \
  --insecure-storage
# paste the fine-grained PAT, then Ctrl-D

chmod 600 "$HOME/.agent/gh/hosts.yml"
```

> On `--insecure-storage`: the token is `0600` in your home dir rather than in
> the login keychain. That is the deliberate trade — it is the agent's **own**
> token, it keeps the human keychain closed, and it is not your personal token.
> `--git-protocol ssh` ensures `gh` also uses SSH for git ops.

### 3. Verify identity and scope

```bash
export GH_CONFIG_DIR="$HOME/.agent/gh"
gh auth status                                   # expect sven1103-agent, NO 'workflow'
gh api user --jq '{login,type}'                  # expect sven1103-agent
gh api user --jq .login                          # must NOT print sven1103
gh pr view --repo example-org/example-app --json number >/dev/null && echo "API ok"
```

### 4. Confirm git-over-SSH still needs nothing else

```bash
env -u SSH_AUTH_SOCK GIT_SSH_COMMAND="$HOME/.agent/ssh/ssh-github.sh" \
  git ls-remote git@github.com:example-org/example-app HEAD
```

### 5. Confirm you did not disturb your human config

```bash
ls -l "$HOME/.config/gh/hosts.yml"     # unchanged, still yours
gh auth status                         # (no GH_CONFIG_DIR) still shows your account
```

### 6. Re-run the harness

```bash
cd ~/git/pi-sandbox-hardening
scripts/selftest.sh --diff baseline-before.tsv
```

**Expect no change yet.** `agent: gh config` / `agent: gh api(own)` will still
read `MISSING`/`NOTYET`, because the sandbox does not yet grant `~/.agent/gh`
(only `~/.agent/ssh` is). Wiring is Step 2. What must hold: **all 9 DENY leaks
unchanged, ALLOW green.**

## Exit criteria

- [ ] `GH_CONFIG_DIR=~/.agent/gh gh auth status` → `sven1103-agent`, **no `workflow`**
- [ ] `gh api user` under that config → `sven1103-agent`, **not** `sven1103`
- [ ] `~/.agent/gh/hosts.yml` exists, mode `600`, stored in a **file** (not keychain)
- [ ] `env -u SSH_AUTH_SOCK` git-over-SSH to a private repo succeeds
- [ ] human `~/.config/gh/hosts.yml` unchanged
- [ ] `selftest.sh --diff` shows no unexpected change; ALLOW green

## Rollback

```bash
rm -rf "$HOME/.agent/gh"        # git-over-SSH keeps working regardless
```

Nothing else was modified. (Revoke the PAT at github.com if retiring it.)

## Notes

- **Never** export this token in `~/.zshrc` — env vars are inherited into the
  sandbox (F7) and would undo Step 5. The file is the point.
- Git identity (author/email) is handled separately by a `~/.agent/gitconfig`, so
  the agent doesn't commit under `you@example.com`. That is
  Step 2's wiring; it needs no new credential.
- GitHub noreply address for the bot: the agent should commit as
  `sven1103-agent` with a `<id>+sven1103-agent@users.noreply.github.com` address.
  Get the numeric id with `gh api user --jq .id` (under the agent config) when
  wiring Step 2.
- Say "step 1 done" once the exit criteria pass; Step 2 grants `~/.agent/gh` and
  sets `GH_CONFIG_DIR` for agent sessions.
