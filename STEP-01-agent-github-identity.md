# Step 1 — Give the agent its own GitHub identity (SSH for git, token for the API)

**Status: APPLIED** (agent identity in place; `~/.agent/ssh/github_login_ed25519` exists).
**Reversible:** yes (additive only)
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
| `gh pr/issue/api/search` | **Fine-grained PAT** in the **agent's own keychain** | `gh` is token-only — it has no SSH path. See Step 1b. |

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

## Procedure (historical — unconfined terminal, not inside pi)

### 1. Create the PAT (browser)

github.com → Settings → Developer settings → Fine-grained tokens → Generate.
Generate it for **`sven1103-agent`**, with the permissions above.

### 2. Install the token — in the agent's keychain

The goal is not to avoid *a* keychain, it is to avoid the **human's** keychain. The
token belongs in the agent's **own** keychain (`~/.agent/agent.keychain-db`, created
by Step 3b), where the sandbox can reach it and the login keychain stays closed.

**`gh auth login` cannot do this — and this is the non-obvious part.** `gh` writes
through `zalando/go-keyring`, whose write call carries **no keychain argument**:

```
security add-generic-password -U -s %s -a %s -w %s
```

With no keychain named, `security` targets the **default** keychain — which is
`login.keychain-db` and is *not* changed by Step 3b (Step 3b sets the **search
list**, which governs **reads**). So the two mechanisms differ:

| | governed by | effect for the agent keychain |
|---|---|---|
| **read** | search list | falls through to the agent keychain ✅ |
| **write** | default keychain (`login`) | cannot reach the agent keychain ❌ |

Adding `--insecure-storage` does not help either — it sends the token to a plaintext
file. **So the token must be written with an explicit keychain path.** Do it directly:

```bash
install -d -m 700 "$HOME/.agent/gh"

# 0. Read the PAT without echoing it to the terminal or shell history.
read -rsp 'Paste the fine-grained PAT: ' PAT; echo

# 1. Put it in the agent keychain, explicitly. gh reads it back from here via the
#    search list; nothing else is needed.
b64="$(printf '%s' "$PAT" | base64 | tr -d '\n')"
security add-generic-password -U -s gh:github.com -a sven1103-agent \
  -w "go-keyring-base64:$b64" "$HOME/.agent/agent.keychain-db"
unset PAT b64

# 2. hosts.yml needs only the metadata: git protocol + which account is active.
cat > "$HOME/.agent/gh/hosts.yml" <<'YAML'
github.com:
    git_protocol: ssh
    users:
        sven1103-agent:
    user: sven1103-agent
YAML
chmod 600 "$HOME/.agent/gh/hosts.yml"
```

> The value format `go-keyring-base64:<base64>` is what `gh` itself writes. A raw
> value also reads back, but matching `gh` avoids surprises.
>
> **Run this unconfined** — keychain writes are denied inside the sandbox (measured
> `rc=161`), and this is a deliberate, attended setup step.
> `scripts/migrate-gh-token-to-keychain.sh` automates exactly these two steps,
> including verification and rollback — prefer it over hand-running the above.

**If you would rather let `gh` hold the token first** (e.g. you want `gh auth login`
to validate it interactively), that is the *interim* path this step originally
took — and it is what Step 1b migrates away from:

```bash
GH_CONFIG_DIR="$HOME/.agent/gh" gh auth login --hostname github.com \
  --git-protocol ssh --with-token --insecure-storage
# then move it into the agent keychain:
scripts/migrate-gh-token-to-keychain.sh
```

> **Superseded: the file is no longer the destination.** Step 1 originally said
> *"Install it as a FILE, not in the keychain"* — correct **at the time**, because
> the only keychain available was the human's. Step 3b gave the agent its own, so
> the plaintext-file workaround outlived its reason. **The keychain is now the
> target.** See [`STEP-01b-gh-token-in-agent-keychain.md`](STEP-01b-gh-token-in-agent-keychain.md)
> for the measured mechanics.

### 3. Verify identity and scope

```bash
export GH_CONFIG_DIR="$HOME/.agent/gh"
gh auth status                                   # expect sven1103-agent, NO 'workflow'
                                                 # and '(keyring)' — not '(default)'
gh api user --jq '{login,type}'                  # expect sven1103-agent
gh api user --jq .login                          # must NOT print sven1103
gh pr view --repo example-org/example-app --json number >/dev/null && echo "API ok"
```

`gh auth status` labels which storage the token came from: **`(keyring)`** means a
keychain item was located (the agent keychain, via the search list); **`(default)`**
means none was found — i.e. you are still on an interim file token. See Step 1b.

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

- [ ] `GH_CONFIG_DIR=~/.agent/gh gh auth status` → `sven1103-agent`, **no `workflow`**,
      and **`(keyring)`** — read from the agent keychain, not a plaintext file
- [ ] `gh api user` under that config → `sven1103-agent`, **not** `sven1103`
- [ ] `~/.agent/gh/hosts.yml` exists, mode `600`, and holds **no `oauth_token`**
      (metadata only — the token is in the keychain; see Step 1b)
- [ ] `env -u SSH_AUTH_SOCK` git-over-SSH to a private repo succeeds
- [ ] human `~/.config/gh/hosts.yml` unchanged
- [ ] `selftest.sh --diff` shows no unexpected change; ALLOW green

## Rollback

```bash
rm -rf "$HOME/.agent/gh"        # git-over-SSH keeps working regardless

# If the token went into the agent keychain (the intended path), remove it there
# too — deleting the config dir alone leaves it behind:
security delete-generic-password -s gh:github.com -a sven1103-agent \
  "$HOME/.agent/agent.keychain-db" 2>/dev/null || true
```

Nothing else was modified. (Revoke the PAT at github.com if retiring it.)

## Notes

- **Never** export this token in `~/.zshrc` — env vars are inherited into the
  sandbox (F7) and would undo Step 5. Keeping it in the agent keychain is the point.
- Git identity (author/email) is handled separately by a `~/.agent/gitconfig`, so
  the agent doesn't commit under `you@example.com`. That is
  Step 2's wiring; it needs no new credential.
- The agent's GitHub noreply address is the bot's: commits are authored as
  `sven1103-agent` with an `<id>+sven1103-agent@users.noreply.github.com` address.
  The numeric id comes from `gh api user --jq .id` under the agent config.
- Step 2 wires this identity into agent sessions: it grants `~/.agent/gh` and
  sets `GH_CONFIG_DIR`.
