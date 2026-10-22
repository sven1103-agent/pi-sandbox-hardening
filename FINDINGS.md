# Findings — verified current state

Environment: macOS, user `sven1103`, Homebrew `agent-safehouse` 0.10.1,
`~/.config/sandbox-exec/` custom policy, pi launched via a zsh alias.

Severity legend: **C**ritical / **H**igh / **M**edium / **L**ow

---

## F1 — pi was running UNSANDBOXED in the session that produced these findings  [C]

**Class:** methodology / real exposure

Evidence:
- `head -c1 ~/.ssh/id_rsa`, `~/.zshrc`, `~/Library/Keychains/login.keychain-db`
  all succeeded from pi's bash tool.
- `sandbox-exec -p '(version 1)(allow default)' -- /bin/echo hi`
  → `sandbox_apply: Operation not permitted` (3/3 attempts).
- `/bin/ps` → `Operation not permitted`, while file reads succeeded.

Interpretation: the outer process is confined (nested sandbox creation refused),
but pi's bash tool is **reaching host paths** that the policy denies. Therefore
the effective sandbox was **not** the custom policy. Confirms that alias-based
sandboxing does not bind the child.

**Consequence:** all "ALLOWED/denied" results from the first pass that ran under
a `WORK_DIR=$HOME` test policy are unreliable and were re-measured. See F9 for
the corrected method.

---

## F2 — Keychain is explicitly re-opened by the custom policy  [C]

**File:** `~/.config/sandbox-exec/grants.sb` lines 31–58

```scheme
(allow file-read* file-write*
    (home-subpath "/Library/Keychains")
    (home-literal "/Library/Preferences/com.apple.security.plist"))

(allow file-read*
    (literal "/Library/Preferences/com.apple.security.plist")
    (literal "/Library/Keychains/System.keychain")
    (subpath "/private/var/db/mds"))

(allow mach-lookup
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.security.agent")
    (global-name "com.apple.security.trustd"))
```

Notes:
- `file-read*` (not `file-read-metadata`) on the keychain subpath ⇒ the DB is
  readable, so `security find-generic-password -w` gatekeeps only via
  `SecurityServer`.
- **`file-write*` is granted** ⇒ tampering/deletion of keychain items is in
  scope, which is worse than read-only exposure.
- `System.keychain` and `com.apple.security.trustd` are broad: they affect more
  than `gh`.
- The comment claims "not on user files" — correct for files under
  `~/Library/Keychains/` only insomuch as the keychain DBs live there, but the
  DB *is* user data.

**Why it exists:** so the sandboxed `gh` CLI can read its OAuth token.

---

## F3 — Two GitHub identities are readable from the login keychain  [C]

`security dump-keychain` on `login.keychain-db` shows generic-password items
with service `gh:github.com` for **two accounts**:

| account | notes |
|---|---|
| `sven1103-agent` | bot account, active `gh` session |
| `sven1103` | **personal account token** — same store, no separate protection |

Active session (when unconfined):

```
gh auth status
  ✓ Logged in to github.com account sven1103-agent (keyring)
  Token scopes: 'gist', 'read:org', 'repo', 'workflow'
```

Token scopes of the bot token include **`workflow`** ⇒ editing
`.github/workflows/**` ⇒ arbitrary code execution in CI with any repo/org
secrets. Verified: `.github/workflows` listing succeeded for
`example-org/example-app`, and `permissions.push == true` on
`example-org/example-app` and `example-org/example-lecture`.
Org membership of `example-org`: `role=member, state=active`.

The keychain items have **no restrictive ACL** — no prompt on read. Keychain
Access showed no "Confirm before allowing access" enforcement for
`gh:github.com`.

---

## F4 — ssh-agent access is re-opened by `agent.sb`  [H]

**File:** `~/.config/sandbox-exec/agent.sb` lines ~787–809

- `(allow file-read-metadata (home-literal "/.ssh/agent"))`
- `(allow file-read* file-write* file-read-metadata …)` on
  `~/Library/LaunchAgents`-style launchd SSH_AUTH_SOCK regexes
  (`/private/tmp/com.apple.launchd.*/Listeners`, `/private/var/run/...`) and
  `(home-subpath "/.ssh/agent")`
- `(allow network-outbound (remote unix-socket …))` for all of the above.

Note the base policy at `agent.sb:760` has a **deliberate deny**:

```scheme
(deny file-read* file-write* (home-subpath "/.ssh"))   ;; "Block SSH key reads"
```

…immediately followed by re-allows that reinstate ssh-agent *usage*. So private
keys are not read, but **any key currently in `ssh-agent` can be used** to
authenticate/sign. At investigation time `ssh-add -l` listed an unlocked RSA key
(`you@your-mac.local`).

---

## F5 — Additional key path granted  [M]

`agent.sb` grants `(subpath "/Users/sven1103/.agent/ssh")` (line ~851) tied to a
wizard-generated `git upstream SSH key:
/Users/sven1103/.agent/ssh/agent-github-key`. Another credential in scope.

---

## F6 — Unencrypted SSH private keys on disk  [H]

Probed with `ssh-keygen -y -P "" -f <key>` (empty passphrase ⇒ key is usable):

| key | state |
|---|---|
| `~/.ssh/id_ed25519` | **NO PASSPHRASE** |
| `~/.ssh/id_rsa` | **NO PASSPHRASE** |
| `~/.ssh/jenkins` | **NO PASSPHRASE** |
| `~/.ssh/id_human_ed25519` | passphrase-protected |
| `~/.ssh/id_private` | passphrase-protected |
| `~/.ssh/cupserver` | passphrase-protected |
| `~/.ssh/id_borg` | passphrase-protected |
| `~/.ssh/sven_id_rsa` | passphrase-protected |
| `~/.ssh/sven1103-agent-strongbox` | ed25519, bcrypt-KDF **passphrase-protected** (intended agent key — good) |

Note: `ssh -T git@github.com` failed with `Permission denied (publickey)` during
investigation, so GitHub SSH was not usable at that moment even though key files
are readable. This may change as agent state changes.

---

## F7 — Full environment inheritance into the sandbox  [H]

**File:** `~/.config/sandbox-exec/run-sandboxed.sh` lines 86–88

```bash
exec sandbox-exec -f "$tmp_policy" \
  env TMUX="${TMUX:-}" \
  /opt/homebrew/bin/pi ...
```

`env` **inherits the entire calling environment**. `~/.zshrc` exports
`HF_TOKEN_STRICT` in plaintext, so a correctly sandboxed pi still receives that
token. Any future exported secret has the same problem.

**Action required:** `HF_TOKEN_STRICT` was displayed in plaintext during
investigation ⇒ treat as compromised, rotate it. (Value intentionally not
copied here.)

---

## F8 — Unrestricted network egress  [H]

`agent.sb:242` — `(allow network-outbound (remote ip))`.
Any secret that is read can be exfiltrated to any host. Confirmed reachable from
a confined context where the policy applied.

---

## F9 — Corrected measurement method  [info]

Because nested `sandbox-exec` is refused, tests must be run **in the process that
inherits the intended policy**, and `WORK_DIR` must be set to a **realistic
workdir** (not `$HOME`) or the dynamic workdir grant over-grants and invalidates
results.

Repeatable harness (see `EVIDENCE.md` for the full script):

```bash
# Build the effective policy exactly like the wrapper does, but with a real workdir
WD=/Users/sven1103/git/<some-repo>
sed "s|__SAFEHOUSE_REPLACE_ME_WITH_WORK_DIR_DEFINE__|(define WORK_DIR \"$WD\")|g" \
    ~/.config/sandbox-exec/agent.sb > /tmp/real.sb
printf '\n(allow file-read* file-write* (subpath "%s"))\n' "$WD" >> /tmp/real.sb
cat ~/.config/sandbox-exec/grants.sb >> /tmp/real.sb
cat ~/.safehouse-tmux.sb >> /tmp/real.sb
```

Then assert reachability. **Use exit status, never print the secret:**

```bash
sandbox-exec -f /tmp/real.sb -- /usr/bin/security \
  find-generic-password -s "gh:github.com" -w >/dev/null 2>&1 \
  && echo "LEAK" || echo "blocked"
```

Previous (valid) observations with a realistic workdir and this policy:
`keychain`, `gh token`, `~/.config/gh/hosts.yml`, `ssh-add -l`, `~/.zshrc`,
JetBrains `github.xml` → **denied**. Those runs demonstrate the *base* policy is
sound; the keychain/ssh-agent holes in F2/F4 are conditional on `grants.sb` and
the specific re-allow blocks, and F1 shows the whole policy can be bypassed.

---

## F10 — Other credential stores checked (negative results)  [L]

- No plaintext tokens found in `~/.zshrc`, `~/.zshenv`, `~/.zprofile`,
  `~/.bashrc`, `~/.bash_profile`, `~/.profile`, or `~/.config/**`
  (only `HF_TOKEN_STRICT` in `.zshrc`).
- No `~/.git-credentials`, no `~/.netrc`.
- No `op` (1Password), `pass`, `vault`, `bw`, `lpass`, `envchain` CLI installed.
- `~/.pi/agent/auth.json` exists (pi's own model creds, mode `0600`).
- JetBrains stores "GitHub OAuth token" entries in the same login keychain
  (`~/Library/Application Support/JetBrains/*/options/github.xml` present).
- `git config` has **global** `credential.helper=gh`, so any `git` command
  anywhere silently authenticates to GitHub.

---

## Risk summary

| ID | Finding | Sev | Primary fix |
|---|---|---|---|
| F1 | Sandbox bypassable via alias | C | Sandbox the session, not the call (P1) |
| F2 | Keychain re-opened (rw) by grants.sb | C | Delete keychain block (P2) |
| F3 | Personal GitHub token in keychain | C | Remove from keychain; rotate (P5) |
| F4 | ssh-agent usage re-opened | H | Delete ssh-agent allows (P3) |
| F5 | Extra `~/.agent/ssh` key path | M | Remove or relocate (P6) |
| F6 | No-passphrase SSH keys | H | Passphrase or relocate (P7) |
| F7 | Full env inheritance | H | `env -i` allowlist (P4) |
| F8 | Unrestricted egress | H | Optional egress allowlist (P8) |
| F10 | Global git credential helper | M | Per-repo helper (P9) |

## Upstream status of each finding

See `UPSTREAM_STANCE.md` for sources. Summary of who owns the fix:

| Finding | Upstream | Owner |
|---|---|---|
| F1 sandbox bypassable via alias | not a safehouse issue (invocation, not policy) | local (P1) |
| F2 keychain rw | **by design**, opt-in; docs advise read-only | local deviation (P2) |
| F3 two GitHub tokens | `gh`/`glab` token exposure is **default-on** via core `scm-clis.sb`; exfil explicitly not a goal | local + least privilege (P5) |
| F4 ssh-agent usage | reported **#36**, fixed by core default-deny in **v0.4.0** | local deviation — revert to upstream (P3) |
| F5 extra `~/.agent/ssh` key | wizard-generated extra grant | local (P6) |
| F6 no-passphrase keys | out of scope for safehouse | local (P7) |
| F7 env inheritance | `--env` warned against; sanitized mode is the default | local deviation (P4) |
| F8 egress | documented **non-goal** ("preventing exfiltration/C2 is NOT a goal") | your call (P8) |
| F10 global git helper | out of scope | local (P9) |
| — version drift | local v0.10.1 vs upstream **v0.12.0** | consider upgrade (P11) |

