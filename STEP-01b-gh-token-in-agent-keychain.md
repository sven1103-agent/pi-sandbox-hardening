# Step 1b — Move the agent's gh token into its own keychain

**Status: APPLIED and verified.** Ran `scripts/migrate-gh-token-to-keychain.sh` on
2026-10-23. Token now lives in the agent keychain; `hosts.yml` carries no token.
**Depends on:** Step 1 (agent gh token), Step 3b (agent keychain).
**Closes:** the last plaintext secret belonging to the agent's *own* credentials.

## Why this is now the right thing to do

Step 1 deliberately stored the agent token as a **file**:

> `gh` stores tokens in the macOS keychain by default — which is exactly what we
> are trying to close. Use `--insecure-storage` so the token lives in a file.
> — `STEP-01-agent-github-identity.md`

That was correct **at the time**: the only keychain available was the login
keychain, which we were trying to close. But Step 3b later gave the agent **its
own** keychain, and the sandbox already allows it. The workaround outlived its
reason.

Migrating removes the last plaintext credential of the agent's own, and makes the
agent's storage consistent: all four of its secrets (three provider keys, one
`gh` token) in one encrypted keychain.

## Measured mechanics

I tested all of this rather than assuming it, because `gh`'s keyring behaviour is
not documented in the places you would expect.

### Read path — works, via search-list fall-through

`gh` reads through the keyring helper (`zalando/go-keyring`), which shells out to:

```
security find-generic-password -s gh:github.com -a <account> -w
```

**No keychain argument.** The lookup therefore searches the user-wide **search
list**. Inside the sandbox `login.keychain-db` is file-denied (Step 3b), so the
lookup **falls through** to `~/.agent/agent.keychain-db` — the same mechanism
that already makes the provider keys work.

Proven by placing a **bogus** token in the agent keychain and observing `gh`
find it:

```
config without oauth_token + bogus item in agent keychain
  -> "Failed to log in ... (keyring) - The token in keyring is invalid"
```

That is the smoking gun: `(keyring)` means a keychain item was located, and the
only reachable one was the agent's.

The label distinguishes the paths, which makes verification easy:

| situation | label |
|---|---|
| no keychain item found | `(default)` |
| keychain item found | `(keyring)` |

### Write path — targets the WRONG keychain (important)

`gh`'s write template carries no keychain argument either:

```
security add-generic-password -U -s %s -a %s -w %s
```

`security` documents: *"If no keychain is specified, the password is added to the
default keychain."* Measured — the default is `login.keychain-db`, which the
sandbox **denies**:

```
add-generic-password (no keychain arg)   -> default = login  -> operation not permitted
add-generic-password ~/.agent/...keychain-db (positional)    -> works
```

(Note: the keychain is a **positional** argument to `add-generic-password`.
There is no `-k` flag — passing one makes `security` print usage. This matters
because a naive `-k` invocation silently does nothing useful.)

**Consequence:** `gh auth login` can never store a token from inside the sandbox.
Migration must be a deliberate, unconfined step. If the token later expires, the
agent cannot self-heal — re-run the migration script. This is the price of the
design, and worth knowing before the token expires at an awkward moment.

### Value format

`gh` stores values as `go-keyring-base64:<base64(token)>`. A raw value also reads
back correctly, but the script writes the prefixed form to match `gh` itself.

### Ordinary authentication still needs no keychain

The `security` lookup above is only because `gh` uses *its* keyring. Note that
**`git` over SSH needs none of this** — Step 1 gave it an explicit
`IdentityFile` with `IdentitiesOnly yes`. So the token is only for `gh`'s API
calls, which narrows the blast radius.

## What changes

| | before | after |
|---|---|---|
| token at rest | plaintext `~/.agent/gh/hosts.yml` (0600) | `~/.agent/agent.keychain-db` (encrypted) |
| `hosts.yml` | contains `oauth_token` | metadata only |
| sandboxed `gh api` | works (reads file) | works (reads keychain) |
| sandboxed `gh auth login` | fails | fails (unchanged — default is login) |
| unconfined `gh` | works (file) | works (falls through to agent keychain) |

## Harness impact — the probes must be re-scoped

This is the part worth reading twice. Today the harness asserts:

```
deny "security:any gh token"  required 'security find-generic-password -s gh:github.com -w'
deny "security:bot"           required 'security find-generic-password -s gh:github.com -a sven1103-agent -w'
```

After migration, that exact path **finds the agent's own token** — correctly, by
design. Left unchanged, the harness would report a `LEAK` for a state we
deliberately created. So the expectations move:

| probe | before | after |
|---|---|---|
| `security:personal` (`-a sven1103`) | DENY | DENY (unchanged — still only in login) |
| `security:bot` (`-a sven1103-agent`) | DENY | **ALLOW** — the agent's own credential |
| `security:any gh token` (no account) | DENY | **retired** — it can no longer be a blanket deny |

`security:any gh token` has to go: with no account it resolves to whatever the
search list finds first, which after migration is the agent's own token. A
blanket "no gh token is reachable" assertion stops being true, and keeping it
would only teach us to ignore the harness.

The invariant is unchanged and still holds: **the personal token (`-a
sven1103`) must be unreachable, the agent's own must work.**

## Applied — measured result

```
token at rest              : agent keychain (gh:github.com / sven1103-agent)
~/.agent/gh/hosts.yml      : 0 oauth_token lines (metadata only)
agent keychain items       : 4  (3 provider keys + gh token)
plaintext copies on disk   : 0

sandboxed gh api user      : sven1103-agent
sandboxed gh source        : (keyring)          <- the keychain, not a file
sandboxed scopes           : gist, read:org, repo, workflow
unconfined gh api user     : sven1103-agent
unconfined gh source       : (keyring)
harness                    : PASS (DENY 16/16, ALLOW 14/14)
```

### A flaw in the first version of the script (fixed)

The original wrote the backup with `cp -p "$HOSTS" "$BAK"` — preserving the
**plaintext token** on disk at a path no cleanup step knows about. That recreates
the exact exposure the step exists to remove, so the step would have *looked*
clean while leaving a plaintext copy behind.

Fixed: the on-disk backup is now **redacted** (token replaced with a placeholder,
file shape preserved), and rollback restores the original from memory rather than
from the backup file. The existing plaintext backup was redacted in place, and the
tree was swept to confirm no copy of the token remains under `~/.agent`.

Worth generalising: **a backup is a copy of the secret.** Any step that migrates a
credential must decide what its backup contains.

### The keychain token wins over a file token

Tested, because it decides whether a stale `hosts.yml` is dangerous: with a bogus
`oauth_token` inserted into `hosts.yml` (well-formed YAML), sandboxed `gh` still
authenticated as `sven1103-agent` — the keychain value took precedence. So leaving
a stale file token behind would not silently override the keychain. (An earlier
apparent failure of this test was malformed YAML from a crude append, not
precedence — worth noting because the wrong conclusion was the alarming one.)

## Rollback

The on-disk backup is **redacted by design** (see above), so it cannot restore the
secret by itself. Two options:

```bash
# a) copy the value back out of the keychain
TOK="$(security find-generic-password -s gh:github.com -a sven1103-agent -w \
        ~/.agent/agent.keychain-db | sed 's/^go-keyring-base64://' | base64 -d)"
# insert it into ~/.agent/gh/hosts.yml as an oauth_token line, then:
security delete-generic-password -s gh:github.com -a sven1103-agent ~/.agent/agent.keychain-db

# b) or simply re-run the migration in reverse:
#    gh auth login --with-token --insecure-storage   (with GH_CONFIG_DIR set)
```

The script also rolls back automatically if any verification step fails.

## Residual exposure (unchanged by this)

The **personal** `gh:github.com` token still sits in the login keychain. It is
unreachable from the sandbox (Step 3b denies the keychain files), so it is not a
sandbox problem — but an unconfined process running as you can still read it.

The *agent's* token also still exists in the login keychain (same value); this is
what the unconfined `gh` resolved through before the migration, and it is harmless
residue. `--purge-login-copy` removes it. That was **not** run: it is the step most
likely to surprise the user's own shell, so it is deliberately left as a separate,
explicit action. Removing the *personal* token is a rotation decision, not a
sandbox one.
