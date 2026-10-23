# Findings — verified current state

Environment: macOS 26.7.1 (Tahoe), user `sven1103`, Homebrew `agent-safehouse` 0.12.0 (upgraded; see P11.1),
`~/.config/sandbox-exec/` custom policy, pi launched via a zsh alias.

Severity legend: **C**ritical / **H**igh / **M**edium / **L**ow

> **Status:** these are findings about the state *before* hardening. All
> credential-exposure findings (F2, F3, F4, F5, F7, F12) have since been
> addressed — see [`README.md`](README.md) for the result and `STEP-*.md` for the
> implementations. F1 is **retracted** (see F1/F11). F8 (unrestricted egress)
> remains open by design.

---

## F1 — RETRACTED: the "unsandboxed" result was a `WORK_DIR=$HOME` artifact  [was C → info]

**Class:** methodology error (retracted finding)

The original F1 concluded pi was running **unconfined**. That was wrong. The
sandbox *was* active; the "ALLOWED" reads were caused by the session running
from the user's home folder, so `WORK_DIR=$HOME` and the wrapper appended
`(allow file-read* file-write* (subpath "$HOME"))` — the *entire* home dir,
including `~/.ssh`, `~/.zshrc` and `~/Library/Keychains`.

The original evidence is fully consistent with a **confined but over-granted**
process, not an unconfined one:

| Observation | Unconfined reading | Correct reading |
|---|---|---|
| nested `sandbox-exec` refused | (ignored) | outer confinement **is** present |
| `/bin/ps` → Operation not permitted | (ignored) | policy **is** applied |
| `~/.ssh`, `~/.zshrc`, keychain readable | "no sandbox" | the HOME-wide workdir grant |

**Re-measured** in a later, self-confined session with workdir = a real repo (no
HOME grant): `read` → `EPERM`; `touch $HOME/.t`, `~/.config/.probe`,
`/Library/.probe` → denied; `~/.ssh/id_rsa`, `~/.zshrc` → denied; nested
sandbox → refused. See **F11** for the full re-verification.

**Residual real issue (keep):** the alias is not a boundary — `pi-native` or a
direct `pi` invocation runs unconfined. That is an *invocation* problem (P1),
not a policy hole. Do not "fix" it by trusting the alias.

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

`agent.sb` grants `(subpath "/Users/sven1103/.agent/ssh")` (line ~851).
**Corrected filename:** the private key there is
`~/.agent/ssh/github_login_ed25519` (mode `0600`), **not** `agent-github-key`
(which does not exist). Re-verified live (F11): the key is readable from a
sandboxed process with a realistic workdir.

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

Repeatable harness (see [`EVIDENCE.md`](EVIDENCE.md) for the full script):

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
the specific re-allow blocks, and the retracted F1 was an artifact of running
from `$HOME` rather than evidence of a bypass.

---

## F12 — Ambient git auth is a blue route to the keychain (global gitconfig)  [H]

**New (found while designing Step 2).** `git` reaches the login keychain through
**your global gitconfig**, independently of `grants.sb`'s `security` grant. This
matters because a file-token workflow can be defeated by ambient git auth.

`~/.gitconfig` contains a **host-scoped** credential helper:

```
credential.helper gh
credential.https://github.com.helper =
credential.https://github.com.helper = !/opt/homebrew/bin/gh auth git-credential
```

The host-scoped `!gh auth git-credential` line is what answers for github.com —
not the bare `credential.helper gh` (note: **`git-credential-gh` does not exist
on PATH**, so that line is inert).

Measured from **inside the sandbox** (2×2, only variable is human-global vs
system config):

| human global gitconfig | system gitconfig | `git credential fill` |
|---|---|---|
| `~/.gitconfig` (as-is) | `/usr/local/etc/gitconfig` | **LEAK** |
| `~/.gitconfig` (as-is) | neutralised | **LEAK** |
| neutralised | `/usr/local/etc/gitconfig` | blocked |
| agent gitconfig | neutralised | blocked |

The row pattern shows the leaker is the **global** gitconfig (F10), and the
system `credential.helper=osxkeychain` is **latent, not active**: there is no
`github.com` internet-password item in the keychain
(`security find-internet-password -s github.com` → not found), and isolating
`-c credential.helper=osxkeychain` alone yields no credential.

> **Correction note.** An earlier draft of this finding blamed
> `/usr/local/etc/gitconfig`'s `osxkeychain` helper. That was wrong — it was
> inferred from a test where `-c credential.helper=…` *appends* to rather than
> replaces the inherited helpers, so the human `gh` helper was still answering.
> The isolated 2×2 above is the valid measurement. The practical conclusion is
> unchanged, but the mechanism is different and matters for the fix: what must be
> neutralised is the **user's global gitconfig** (P9), not the system one.

**Two consequences for the plan:**

1. **P9 is now load-bearing, not cosmetic.** Setting `GIT_CONFIG_GLOBAL` to an
   agent-specific gitconfig (which is Step 2's plan anyway) both removes your
   identity *and* closes this keychain route. `GIT_CONFIG_SYSTEM=/dev/null` is
   **not** required for this leak, but is harmless extra isolation.
2. **A new DENY check was added** to `scripts/selftest.sh`
   (`git credential fill`), because the previous suite tested only the `security`
   CLI and would have missed this route entirely — i.e. the suite would have gone
   green after P2 while a keychain path remained open.

---

## F13 — gh's keyring reads fall through, but its writes do not  [info]

Measured while evaluating whether the agent's own `gh` token could move from a
plaintext file into the agent keychain. Two asymmetries that are easy to get
wrong, and that no `gh` documentation states:

`gh` uses `zalando/go-keyring`, which shells out to `security` with **no
keychain argument** in both directions:

```
read : security find-generic-password -s gh:github.com -a <account> -w
write: security add-generic-password -U -s %s -a %s -w %s
```

- **Read** → searches the user-wide **search list**, so a file-denied
  `login.keychain-db` **falls through** to `~/.agent/agent.keychain-db`. Proven
  by planting a bogus token in the agent keychain and observing `gh` read it:
  `Failed to log in ... (keyring) - The token in keyring is invalid`.
- **Write** → `security` sends an argument-less write to the **default**
  keychain, which is `login` — the one the sandbox denies. So `gh auth login`
  can never persist a token from inside the sandbox, and the agent **cannot
  self-heal an expired token**. Migration must be an unconfined, deliberate step.

Also worth recording:

- The keychain is a **positional** argument to `add-generic-password`; there is no
  `-k` flag. A `-k` invocation prints usage and stores nothing — a silent no-op.
- `gh` distinguishes the paths in `gh auth status`: `(default)` = no keychain item
  found, `(keyring)` = a keychain item was located. That makes verification easy
  without ever printing a token.
- Values are stored as `go-keyring-base64:<base64(token)>`.

**Consequence for the harness:** once the agent's token lives in the agent
keychain, the DENY probes `security:any gh token` and `security:bot` would find
it — correctly. They must be re-scoped (`security:personal` stays DENY;
`security:bot` becomes ALLOW) or the suite will report a `LEAK` for a state we
deliberately created. See [`STEP-01b-gh-token-in-agent-keychain.md`](STEP-01b-gh-token-in-agent-keychain.md).

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

## F11 — Re-verification in a confined session with a real workdir  [info]

A later session ran **inside** the sandbox: pi's own `read` tool returned
`EPERM` for `~/.config/sandbox-exec/agent.sb`; `touch $HOME/.t`,
`~/.config/.probe`, `/Library/.probe`, `head -c1 ~/.ssh/id_rsa`, `~/.zshrc` and
`/bin/ps` were all denied; nested `sandbox-exec` was refused. Workdir was a real
repo, so **no HOME-wide grant** was in play. This is the clean measurement F9
intended, and it removes the `$HOME` artifact from the picture.

| Probe | Result |
|---|---|
| `security find-generic-password -s gh:github.com -w` | **ALLOWED** (both accounts) |
| `head -c1 ~/Library/Keychains/login.keychain-db` | **ALLOWED** |
| keychain dir write (`touch ~/Library/Keychains/.x`) | **ALLOWED** — F2's write grant is real |
| `~/.config/gh/hosts.yml` | **ALLOWED** |
| `ssh-add -l` **and signing** (`ssh-keygen -Y sign`) | **ALLOWED** — valid signature produced |
| socket connect to `$SSH_AUTH_SOCK` | **CONNECT OK** (network-outbound path) |
| `~/.agent/ssh/github_login_ed25519` | **ALLOWED** |
| `HF_TOKEN_STRICT` in sandboxed env | **present** |
| egress `example.com` / `paste.rs` | **200** |
| `~/.ssh/id_rsa`, `~/.ssh/config` | denied — the deny holds |
| `~/.ssh/known_hosts` | ALLOWED (intended, for host verification) |
| `~/.config/sandbox-exec` | denied — refutes F1's "unconfined" |

Corrections and updates this produced:

- **F4 is stronger than stated.** `ssh-add -l` only proves listing; the agent
  also **signed** arbitrary data. Reachability is via `network-outbound (remote
  unix-socket …)`, confirmed by opening the socket directly.
- **F9's "these are denied with a realistic workdir"** describes the *base*
  `agent.sb` only. The **effective** policy the wrapper actually loads
  (base + `grants.sb` + `~/.safehouse-tmux.sb`) re-opens keychain and ssh-agent
  even with a realistic workdir.
- **`gh` uses the login keyring**, so `~/.config/gh/hosts.yml` holds **no
  token** (only `git_protocol` and `users`). This inverts the P2 caveat:
  removing the keychain grant *does* remove the only in-sandbox source of the
  `gh` token. The token is not safe, however — it is exposed via `grants.sb`, and
  upstream core `scm-clis.sb` still grants `~/.config/gh` regardless.
- **safehouse is already v0.12.0**, not v0.10.1 (P11.1 satisfied). The
  hand-edited `agent.sb`/`grants.sb` fork is still what the wrapper loads, so the
  upgrade alone changes nothing.

---

## Risk summary

| ID | Finding | Sev | Primary fix |
|---|---|---|---|
| F1 | ~~Sandbox bypassable via alias~~ **retracted** — `$HOME` workdir over-grant | info | Use a real workdir; scripts now refuse `$PWD=$HOME` (P0.5/P1.0) |
| F2 | Keychain re-opened (rw) by grants.sb | C | Delete keychain block (P2) |
| F3 | Personal GitHub token in keychain | C | Remove from keychain; rotate (P5) |
| F4 | ssh-agent usage re-opened | H | Delete ssh-agent allows (P3) |
| F5 | Extra `~/.agent/ssh` key path | M | Remove or relocate (P6) |
| F6 | No-passphrase SSH keys | H | Passphrase or relocate (P7) |
| F7 | Full env inheritance | H | `env -i` allowlist (P4) |
| F8 | Unrestricted egress | H | Optional egress allowlist (P8) |
| F10 | Global git credential helper | M | Per-repo helper (P9) |
| F12 | **Global gitconfig** = keychain route via host-scoped `!gh` helper | H | `GIT_CONFIG_GLOBAL` = agent gitconfig (P9) |

## Upstream status of each finding

See [`UPSTREAM_STANCE.md`](UPSTREAM_STANCE.md) for sources. Summary of who owns the fix:

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
| — version drift | local fork authored for v0.10.1; **installed is now v0.12.0** | P11.1 done; P11.2 (use generated policy) still open |

