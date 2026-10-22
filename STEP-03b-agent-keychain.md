# Step 3 (REVISED) — Dedicated agent keychain with prompted unlock

**Status:** ready to implement · **Reversible:** yes
**Supersedes:** the "remove keychain access entirely" version of Step 3
**Fixes:** F2/F3 (login + System keychain unreachable) **while keeping all
providers working**

## Why the revision

The first Step 3 removed keychain access wholesale. That broke **every provider**,
because `~/.pi/agent/auth.json` resolves all three keys from the keychain:

```json
"litellm":             { "key": "!security find-generic-password -ws 'litellm'" }
"openrouter":          { "key": "!security find-generic-password -ws 'openrouter'" }
"opencode-go-private": { "key": "!security find-generic-password -ws 'opencode-go-private'" }
```

(`!` = "run this command to obtain the key", per pi's `docs/providers.md`.)

Rather than fight that, give the agent a **keychain of its own**, unlocked by
prompt at session start, and deny the login + System keychains.

## Design (all points measured, not assumed)

```scheme
;; agent's own keychain only
(deny file-read* file-write*
    (home-subpath "/Library/Keychains")      ;; login.keychain-db
    (subpath "/Library/Keychains"))          ;; System.keychain
(allow file-read* file-write*
    (home-literal "/.agent/agent.keychain-db")
    ;; required: 'security' reads the search list from this file
    (home-literal "/Library/Preferences/com.apple.security.plist")
(allow mach-lookup
    (global-name "com.apple.SecurityServer"))
```

Measured behaviour:

| Check | Result |
|---|---|
| agent keychain item read | ✅ works |
| login `litellm` key | ✅ blocked |
| login `gh:github.com` personal token | ✅ blocked |
| login DB direct read | ✅ blocked |
| System keychain items enumerable | ✅ 0 (99 without the System deny) |
| agent keychain **without** `SecurityServer` | ❌ fails — IPC is required |
| agent keychain with `SecurityServer` | ✅ works |

**Two non-obvious requirements:**

1. **`SecurityServer` mach-lookup must be allowed.** Without it the agent's own
   keychain is unreadable. It does **not** re-open the login keychain, because
   the file deny is enforced — measured.
2. **You must deny `System.keychain` too** (`/Library/Keychains`). Denying only
   the login keychain left 99 System items enumerable, one with a readable value.

## The search-list trap (important)

`auth.json` uses **service-only** lookups (`-ws 'litellm'`, no keychain path).
Those consult the **search list**, whose contents live in
`~/Library/Preferences/com.apple.security.plist`. Measured:

| Lookup | prefs readable | prefs denied |
|---|---|---|
| service-only (`-ws svc`) | ✅ finds item | ❌ **not found** |
| explicit path (`-ws svc /path/kc`) | ✅ | ✅ works |

So with the prefs file denied, service-only lookups fail **even if the agent
keychain is in the search list**. We therefore keep the prefs file readable.

> The search list is **user-wide state** — changing it with
> `security list-keychains -s` also affects your interactive shell, so the
> launcher saves and restores it (see below).

## Unlock at session start (your choice: prompted)

Measured:

- `security unlock-keychain <kc>` **prompts on a TTY** (verified — you saw the prompt).
- `security unlock-keychain -p <pw> <kc>` unlocks without a prompt.
- `unlock-keychain` with **no `-p`** and **no TTY** fails with rc 51 (does not hang).
- An unlock performed **outside** the sandbox **is inherited** by the sandboxed
  process — verified. This is what makes a launcher-side prompt work.

### Recommended: prompt before entering the sandbox

In `run-sandboxed.sh`, before the `exec sandbox-exec` line:

```bash
# --- Agent keychain: prompt to unlock before entering the sandbox ---
AGENT_KC="$HOME/.agent/agent.keychain-db"
if [[ -f "$AGENT_KC" ]]; then
  if ! security show-keychain-info "$AGENT_KC" >/dev/null 2>&1; then
    printf 'Unlock agent keychain (%s): ' "$AGENT_KC" >&2
    if ! security unlock-keychain "$AGENT_KC"; then
      echo "warning: agent keychain not unlocked; providers may fail" >&2
    fi
  fi
fi
```

Notes:
- `security show-keychain-info` succeeds only when unlocked, so this is
  idempotent and never double-prompts within a session.
- **Prompting must happen OUTSIDE the sandbox** — otherwise the GUI/TTY
  SecurityAgent prompt is itself sandboxed and can fail. Verified that an
  out-of-sandbox unlock is visible inside.
- The prompt is TTY-based. If pi is launched non-interactively (cron, CI), it
  fails with rc 51 rather than hanging — acceptable, and it warns.

### Search list handling

Set the search list to **only** the agent keychain for the session, and restore
it afterwards. Measured result inside the sandbox:

| Check (search list = agent kc only) | Result |
|---|---|
| service-only lookup `-ws litellm` | ✅ resolves |
| login `gh:github.com` token | ✅ blocked |
| `security dump-keychain` item count | ✅ **1** (only the agent's) |

```bash
security list-keychains > /tmp/kc-searchlist.bak
security list-keychains -s "$HOME/.agent/agent.keychain-db"
# ... exec sandbox-exec ...
trap 'xargs -n1 security list-keychains -s < /tmp/kc-searchlist.bak >/dev/null 2>&1; rm -f /tmp/kc-searchlist.bak' EXIT INT TERM
```

Because the login keychain *file* is denied inside the sandbox, leaving it in the
list would be harmless — but scoping to the agent keychain alone is cleaner and
shrinks enumeration.

> **Gotcha:** `security create-keychain` *also* appends the new keychain to the
> global search list. `setup-agent-keychain.sh` saves and restores it around
> creation for this reason.

## Implementation

### 3a — create and populate the agent keychain

```bash
scripts/setup-agent-keychain.sh
```

It will:
1. `security create-keychain -p "" ~/.agent/agent.keychain-db` — **no** password
   at creation (the file-prompt password is set interactively afterwards), or
   prompt you for one.
2. Migrate `litellm`, `openrouter`, `opencode-go-private` from the login keychain.
3. Set a strong unlock password (prompted).
4. Verify each key against its endpoint.

> **Migration reads the login keychain**, so run it **before** applying the
> policy change, or from an unconfined shell.

### 3b — apply the policy

`scripts/apply-step-03b.sh` edits `grants.sb`:
- replaces the wide keychain block with the narrow form above,
- keeps `SecurityServer` but drops `security.agent` and `security.trustd`,
- **keeps** `com.apple.security.plist` readable (required for service-only lookup).

### 3c — launcher

Add the unlock prompt + search-list save/restore (above), then verify with
`scripts/verify-launcher.sh`.

## Verification

```bash
# unconfined
cd ~/git/pi-sandbox-hardening
scripts/selftest.sh --record baseline-step3.tsv
scripts/selftest.sh --diff baseline-step2.tsv
```

Expected: login-keychain checks `LEAK -> ok`; **new** ALLOW checks for the agent
keychain `ok`.

Inside a **new** sandboxed session:

```bash
# providers must work
gh api user --jq .login                                     # sven1103-agent
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $(security find-generic-password -ws litellm)" \
  https://llm.internal.example.com/v1/models            # 200

# login keychain must not
security find-generic-password -s gh:github.com -a sven1103 -w >/dev/null 2>&1 && echo LEAK || echo blocked
security dump-keychain 2>/dev/null | grep -c '"svce"<blob>' # expect 0
```

## Exit criteria

- [ ] All 3 providers resolve keys and authenticate
- [ ] `pi` starts and can list models
- [ ] login keychain: `litellm`, `openrouter`, `gh:github.com` (both accounts) → blocked
- [ ] `security dump-keychain` shows 0 items
- [ ] login DB direct read → denied
- [ ] unlock prompt works and does not appear twice
- [ ] interactive shell's search list is unchanged after pi exits

## Rollback

```bash
cd ~/.config/sandbox-exec
cp -p grants.sb.bak-<timestamp> grants.sb
security delete-keychain "$HOME/.agent/agent.keychain-db"
```

## Open items

- `opencode-go-private` returns **401 even from the keychain** — pre-existing,
  unrelated to this change. Refresh that key.
- Decide whether `security.agent` / `security.trustd` are needed for anything
  else; currently dropped. If a provider auth flow needs a GUI prompt, re-add
  `security.agent` explicitly and document why.

---

## Corrections found while building `apply-step-03b.sh`

Three measurement errors in the earlier notes are corrected here.

### 1. SBPL rule order: LAST match wins

Tested directly:

| Policy | Login keychain read |
|---|---|
| `deny` then `allow` (same scope) | **ALLOWED** |
| `allow` then `deny` (same scope) | denied |

So the deny must be appended **after** any broad grant. `grants.sb` is
concatenated after `agent.sb` by the launcher, so appending the block at the end
of `grants.sb` is correct. `apply-step-03b.sh` warns if a broad grant survives
without a `step-03 removed` marker.

### 2. The `com.apple.security.plist` claim was wrong in mechanism (right in effect)

`~/Library/Preferences/com.apple.security.plist` **does not exist** on this
machine. A test that "denied" it therefore denied a nonexistent path — which is
not a no-op. Re-measured:

| Variant | Service-only lookup |
|---|---|
| no prefs rule at all | ✅ resolves |
| `deny (literal ".../com.apple.security.plist")` | ❌ **FAIL** |
| `deny (literal ".../com.apple.other.plist")` | ✅ resolves |
| `deny` then `allow` the same path | ✅ resolves |

Conclusion is unchanged (**do not deny that path**), but the reason is that
denying that *specific* name breaks `securityd`'s lookup — not that a file is
being read. Keep the path out of the policy entirely; do not add an allow for it
either, since it is already permitted by default in the base policy.

### 3. `create-keychain` can DROP the login keychain from the search list

`--dry-run`-verified then observed live: after `security create-keychain`, the
user-wide search list was

```
"/Users/sven1103/.agent/agent.keychain-db"
"/Library/Keychains/System.keychain"      # <- login.keychain-db GONE
```

This breaks **your** shell's keychain access, not just the agent's.
`setup-agent-keychain.sh` now has a `restore_searchlist()` that restores the
saved list *and* re-adds the login keychain if it is missing. It is called on
both the create and the reuse path.

### Also: `add-generic-password` argv exposure

`add-generic-password -w <value>` puts the secret in `argv` for the duration of
the call (visible to same-user processes via `ps`). The prompt form
(`-w` as the final argument) requires a real TTY. For an unconfined, attended
setup step the transient argv exposure is accepted; `-U` keeps re-runs
idempotent. Documented rather than hidden.

---

## `apply-step-03b.sh` — what it does

1. **Appends** the narrow block to `grants.sb` (paren-balance checked, backup
   taken, idempotent via markers).
2. **Patches the launcher**: unlock prompt + search-list scoping with a `trap`
   restore. Comments are kept **above** the backslash-continued `exec` — putting
   a `#` inside caused the earlier launcher incident.
3. **Gates on `verify-launcher.sh`** — a stub-executes-the-launcher check. If pi
   would no longer be invoked correctly, it restores the backup and exits
   non-zero.
4. **Probes the built policy** with a real workdir (login keychain blocked, `gh`
   token blocked, personal token blocked, System items blocked).

Refuses to apply if the agent keychain does not exist, since that would leave
every provider broken with no working key source.

---

## APPLIED — and two more corrections found during application

### 4. `exec` defeats the EXIT trap (the search-list bug)

The first version of the launcher patch scoped the search list per session and
restored it with `trap ... EXIT INT TERM`. **That silently never ran**, because
the launcher's final line is `exec sandbox-exec ...` — `exec` *replaces* the
shell, so no EXIT trap fires. Measured:

```bash
bash -c 'trap "echo FIRED" EXIT INT TERM; exec /usr/bin/true'   # nothing printed
bash -c 'trap "echo FIRED" EXIT INT TERM;        /usr/bin/true' # FIRED
```

Consequence: the search list was left scoped to the agent keychain, **dropping
your login keychain** from it. This is what broke the search list twice.

Worse, `verify-launcher.sh` *stub-executes* the launcher, so the guard itself
triggered the side effect.

**Fixed by removing the per-session list change entirely** and relying on
fall-through instead (below). `verify-launcher.sh` now also asserts that the
login keychain is still in the search list after executing the launcher, and
restores it if not.

### 5. Fall-through: the search list does not need to change at all

Measured: if an earlier keychain in the search list is **file-denied**, a
service-only lookup falls through to the next entry.

| Search list | Environment | `litellm` resolves from |
|---|---|---|
| `[login, agent, System]` | your shell | login (login first) |
| `[login, agent, System]` | sandboxed | **agent** (login file-denied → fall-through) |

So the search list is simply set **once, permanently, as `[login, agent,
System]`**. Your shell is unaffected (login is first); pi is unaffected (login is
denied, so it falls through). No trap, no `exec` problem, SIGKILL-safe, and the
login keychain never leaves the list.

### 6. The prefs file DOES matter — I had this backwards twice

Earlier I wrote that `~/Library/Preferences/com.apple.security.plist` "does not
exist" and that denying it breaks lookups for an unrelated reason. Both were
wrong. The file **did not exist until we first customized the search list**, at
which point `cfprefsd` created it (12:58) to store the list.

Measured against the **real** policy, appending one grant at a time:

| Added grant | `-ws litellm` |
|---|---|
| (nothing) | 0 chars ❌ |
| `cfprefsd.agent` mach-lookup | 0 chars ❌ |
| `~/Library/Preferences` read | **25 chars** ✅ |
| `/Library/Preferences` plist | 0 chars ❌ |

Without read access to that one file, `security` falls back to the built-in
`[login, System]` list, never sees the agent keychain, and **every provider
fails**. The final block therefore allows exactly:

```scheme
(allow file-read*
    (home-literal "/Library/Preferences/com.apple.security.plist")
)
```

That file contains only the search list — no secret.

## Final verified state (inside the real built policy)

```
providers:  litellm 25 · openrouter 73 · opencode-go-private 67 chars
isolation:  personal gh token blocked · any gh token blocked
            login kc file blocked · System kc file blocked
            ~/.ssh/id_human_ed25519 blocked
            items visible via dump-keychain: 3   (was 381 unconfined)
```

`selftest.sh` DENY suite: all keychain checks `DENIED`/`FAILED` (no LEAK).
ALLOW suite: 0 BROKEN.

---

## CONFIRMED WORKING (live session)

A real sandboxed pi session was launched via
`~/.config/sandbox-exec/run-sandboxed.sh` and worked: the agent keychain unlock
prompt appeared once, and models/providers loaded normally.

Post-session checks (nothing left behind):

| Check | Result |
|---|---|
| search list | `[login, agent, System]`, login first ✅ |
| your shell resolves `litellm` | from **login** keychain ✅ (unaffected) |
| agent keychain state | unlocked (inherited by the session) ✅ |
| `/tmp/kc-searchlist*` leftovers | none ✅ |

**Step 3b is done.** The agent now reads only its own keychain; the login and
System keychains are unreachable from inside the sandbox; your shell is
unchanged.
