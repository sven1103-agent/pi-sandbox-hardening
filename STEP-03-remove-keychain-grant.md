# Step 3 — Remove the keychain grant (the first real exposure removal)

**Status:** ready to run · **Reversible:** yes (backup + restore documented)
**Fixes:** F2, F3 (5 of the 9 DENY leaks)
**Depends on:** Steps 1–2 verified (agent has a working keychain-free identity)

## What this changes

Deletes the keychain re-open from `~/.config/sandbox-exec/grants.sb`: the
`file-read* file-write*` grant on `~/Library/Keychains`, the
`System.keychain`/`prefs`/`mds` reads, and the `mach-lookup` on
`SecurityServer` / `security.agent` / `trustd`.

Expected: **5 leaks -> ok**

```
keychain-db(read)       LEAK -> ok
keychain-db(write)      LEAK -> ok
security:any gh token   LEAK -> ok
security:personal       LEAK -> ok
security:bot            LEAK -> ok
```

## Why this is now safe

Because `gh` prefers the keychain over `hosts.yml` while it is readable, removing
the keychain is what *forces* the file token. Verified precedence (bogus account
so the keyring misses):

| hosts.yml | keyring | result |
|---|---|---|
| valid | miss | authenticates |
| invalid | miss | `Bad credentials` |

So once the keychain is unreachable, `gh` uses `~/.agent/gh/hosts.yml`. The agent
keeps a working identity; only *your* keychain becomes unreachable.

## The regression check (use this, not a hash comparison)

Hashes are useless here — the file and keychain currently hold the **same** token
value. The meaningful test is: does `gh` still work with **no** keychain access?

After the change, from a **new** terminal inside the sandbox:

```bash
gh api user --jq .login        # must still print sven1103-agent
```

If that fails with `Bad credentials` or an auth prompt, the fallback broke —
restore immediately (see Rollback).

## Do this (unconfined terminal)

```bash
cd ~/.config/sandbox-exec
cp -p grants.sb "grants.sb.bak-$(date +%Y%m%d-%H%M%S)"
```

Then remove the keychain block. It is delimited by the comment
`Integration: Keychain` and looks like this (line numbers from the investigation;
**re-check with `grep -n` before deleting**):

```scheme
(allow file-read* file-write*
    (home-subpath "/Library/Keychains")
    (home-literal "/Library/Preferences/com.apple.security.plist")
)
(allow file-read*
    (literal "/Library/Preferences/com.apple.security.plist")
    (literal "/Library/Keychains/System.keychain")
    (subpath "/private/var/db/mds")
)
(allow file-read-metadata
    (home-literal "/Library")
    (home-literal "/Library/Keychains")
    (literal "/Library")
    (literal "/Library/Keychains")
)
(allow mach-lookup
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.security.agent")
    (global-name "com.apple.security.trustd")
)
```

**Keep `com.apple.trustd.agent`** — it is already allowed at `agent.sb:209` and
is needed for TLS. Removing the `com.apple.trustd` entry above must not break
HTTPS (verify in the checks below).

A helper is provided:

```bash
scripts/apply-step-03.sh --dry-run    # show what would be removed
scripts/apply-step-03.sh              # back up + remove the block
```

## Verification — two things behave differently

**Important:** the launcher compiles the policy into a temp file at startup and
`sandbox-exec` never reloads it. So:

| What | Sees Step 3 immediately? |
|---|---|
| The **harness** (`selftest.sh` -> `build-policy.sh` re-reads the files each run) | ✅ **yes — no restart needed** |
| An **already-running pi session** | ❌ **no — it keeps the policy it launched with** |

So: to verify the *policy*, just run the harness. To confine *pi itself* under the
new policy, start a new session.

### 1. Verify the policy (no restart needed)

```bash
cd ~/git/pi-sandbox-hardening
scripts/selftest.sh --record baseline-step3.tsv
scripts/selftest.sh --diff baseline-step2.tsv
```

Expected: the 5 keychain checks `REACHABLE/LEAK -> DENIED/ok`, leaks **9 → 4**,
everything else unchanged.

If the keychain checks are *still* `LEAK`, a **later policy layer** is re-granting
it. The effective policy is composed in this order, and later layers win:

```
agent.sb -> dynamic workdir grant -> grants.sb -> ~/.safehouse-tmux.sb  (LAST)
```

`~/.safehouse-tmux.sb` is appended **after** `grants.sb`, so a keychain grant
there would silently undo Step 3. Check with:

```bash
scripts/diagnose-keychain.sh      # per-layer keychain reference counts
```

### 2. Verify pi itself (requires a NEW terminal)

```bash
# inside the freshly started sandboxed pi:
/usr/bin/security find-generic-password -s gh:github.com -w >/dev/null 2>&1 \
  && echo "LEAK" || echo "blocked"          # expect blocked
gh api user --jq .login                      # expect sven1103-agent
curl -s -o /dev/null -w '%{http_code}\n' https://api.github.com   # expect 200
```

## Exit criteria

- [ ] 5 keychain checks `ok` (leaks 9 → 4)
- [ ] `gh api user` still returns `sven1103-agent`
- [ ] `gh pr list` works
- [ ] `api.github.com` returns 200 (TLS/trustd intact)
- [ ] `git credential fill` still blocked
- [ ] ALLOW suite still fully green (no BROKEN)
- [ ] `~/.ssh` reads still denied (unchanged)

## Rollback

```bash
cd ~/.config/sandbox-exec
cp -p grants.sb.bak-<timestamp> grants.sb
```

The keychain `security` grant being restored means `gh` goes back to the keychain.
Nothing else is affected.

## Notes and risks

- **Not a "narrower" option.** Once `SecurityServer` mach-lookup is granted, the
  agent can read *every* login-keychain item (securityd runs outside the sandbox
  and a file-level deny does not stop it). It is all-or-nothing; removing it is
  the only safe setting. See `UPSTREAM_STANCE.md` §3.
- **`gh` may print a warning** about keyring access in some flows. If it errors
  instead of falling back, that is the regression — roll back and report.
- **Other tools that want the keychain will break** by design (e.g. any CLI using
  `security` for credentials). That is the point; the agent should use its own
  file-based credentials.
- Do **not** replace this with `file-read-metadata` only: that still permits
  directory enumeration and does not close the `SecurityServer` route, which is
  the actual hole.
