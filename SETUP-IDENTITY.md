# Give your agent its own git identity (do this after cloning)

`user.name`, `signingkey` and `sshCommand` live in `.git/config`, which is **not**
part of a repository — git creates it on clone. So a fresh clone of this repo
falls back to whatever you have configured globally: **your** identity.

Two things then go wrong, and only one of them is loud:

| | what happens | loud? |
|---|---|---|
| `git push` | offers *your* key, GitHub sees *you*, the agent's repo rejects it | yes — `Permission denied` |
| `git commit` | **succeeds**, but is authored by *you* and signed with *your* key | **no — silent** |

The second is the one to care about. This repo's entire premise is that the
agent acts as itself; a commit silently attributed to you undoes that, and
nothing warns you.

This page is the fix. The steps are the same whether you are working in a clone
of this repo or giving your own agent an identity in your own repo.

---

## 1. Decide your agent's values

```bash
AGENT_ID="<your-agent-github-username>"               # e.g. my-agent-bot
AGENT_SSH_DIR="$HOME/<where-your-agent-ssh-lives>"    # e.g. ~/.agent/ssh

# Derive the author email from the account id. GitHub's noreply form is what
# attributes AND links the commit to the account.
AGENT_EMAIL="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')"
```

> Run the `gh` call as your **agent** account (e.g. with its own
> `GH_CONFIG_DIR`), so `.id`/`.login` are the agent's, not yours.

Check it before using it:

```bash
echo "$AGENT_EMAIL"     # want: 1234+my-agent-bot@users.noreply.github.com
```

> **Two noreply forms both work.** GitHub accepts both the older
> `login@users.noreply.github.com` and the current `id+login@users.noreply.github.com`.
> They behave the same for attribution; the `id+` form also survives a
> username change. This repo's own commits use the older `login@` form, so if you
> are adding to an existing history, match whatever is already there rather than
> mixing the two.

## 2. Give the agent a dedicated SSH wrapper

A tiny wrapper that pins the config file, the identity file and
`IdentitiesOnly=yes` is worth generating. Without it you are relying on the
ordering in your `~/.ssh/config`, and any personal `Host github.com` entry there
will win.

```bash
#!/bin/bash
# <AGENT_SSH_DIR>/ssh-github.sh
SSH_DIR="$(cd "$(dirname "$0")" && pwd)"
exec ssh \
  -F "${SSH_DIR}/config" \
  -o "IdentityFile=${SSH_DIR}/<agent-signing-key>" \
  -o "UserKnownHostsFile=${SSH_DIR}/known_hosts" \
  "$@"
```

## 3. Point the repository at the agent

```bash
git config --local core.sshCommand "$AGENT_SSH_DIR/ssh-github.sh"
git config --local user.name      "$AGENT_ID"
git config --local user.email     "$AGENT_EMAIL"
```

## 4. Sign commits as the agent, not as you

```bash
git config --local user.signingkey "$AGENT_SSH_DIR/<agent-signing-key>"
git config --local gpg.format      ssh
git config --local commit.gpgsign  true
git config --local tag.gpgsign     true
git config --local gpg.ssh.program /usr/bin/ssh-keygen

# Optional. Only affects LOCAL `git verify-commit`; GitHub ignores this file.
git config --local gpg.ssh.allowedSignersFile "$AGENT_SSH_DIR/allowed_signers"
```

`--local` writes to this repo's `.git/config` only.

## 5. Register the key on the agent's GitHub account

**This is the step people miss.** GitHub verifies a signature against keys on the
**account** — not against `allowedSignersFile`, which is local-only. Add the
agent's public key at *Settings → SSH and GPG keys → New SSH key* and set the key
type to **Signing Key**.

The same key can be registered twice — once for authentication and once for
signing. Check what is already registered (public API, no auth needed):

```bash
curl -s "https://api.github.com/users/<AGENT_ID>/ssh_signing_keys" | grep -c ssh-ed25519
```

If the signing key is absent, pushes still work but commits are not shown as
**Verified**.

## 6. Verify — do not assume

```bash
git log --format='%h %G? %an <%ae>' -1
```

You want `G` (good signature) with the agent's name and address:

```
b7f6610 G my-agent-bot <1234+my-agent-bot@users.noreply.github.com>
```

`%G?` is `G` good, `N` no signature (signing is off), `U`/`B` untrusted/bad. And
check the push identity without pushing anything:

```bash
git push --dry-run
```

---

## Two traps

**`--dry-run` and `ls-remote` do not prove the push identity.** A no-op push never
opens a connection, and on a *public* repo `ls-remote` succeeds without
authenticating as anyone. Both look green while the problem is still present.
To actually inspect which key is offered:

```bash
GIT_SSH_COMMAND="$AGENT_SSH_DIR/ssh-github.sh -v" \
  git push --dry-run 2>&1 | grep 'Offering public key'
```

If that line names *your* personal key, the configuration did not take.

**Never `--global`.** Setting these globally applies your agent's identity to
every repository on the machine, including your personal ones. Scope them with
`--local`. That is the whole difference between a fix and a mess.

---

## Why there is no script for this

A script would have to guess three identity-bearing values — the agent's name,
its email, and where its key lives. Guessing wrong means silently configuring a
repository to commit as the wrong identity, which is the exact failure this page
exists to prevent. These are decisions worth making deliberately, once, per
clone.

For the same reason this repo does **not** ship a helper that edits
`~/.ssh/config` or `~/.gitconfig`: those are the human's files, and the point of
the whole exercise is that the agent does not reach them.
