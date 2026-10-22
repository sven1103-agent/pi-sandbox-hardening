# Evidence — raw excerpts and reproduction

Line numbers are from the versions present at investigation time. Re-check with
`grep -n` before editing; the files may have moved.

---

## E1 — Launch path

`~/.zshrc:142-146`
```zsh
# pi with custom safehouse sandbox policy (agent-safehouse.dev)
# Uses pre-built policy at ~/.config/sandbox-exec/agent.sb with dynamic workdir,
# keychain support (for gh CLI GitHub auth), and tmux/nvim integration.
alias pi='~/.config/sandbox-exec/run-sandboxed.sh'
alias pi-native=/opt/homebrew/bin/pi
```

`~/.config/sandbox-exec/run-sandboxed.sh:84-88`  ← **env inheritance (F7)**
```bash
# --- Launch sandboxed Pi ---
exec sandbox-exec -f "$tmp_policy" \
  env TMUX="${TMUX:-}" \
  /opt/homebrew/bin/pi ${passthrough_args[@]+"${passthrough_args[@]}"}
```

Policy composition order in the wrapper: base `agent.sb` (with `WORK_DIR`
placeholder replaced) → dynamic workdir grant → `grants.sb` → `~/.safehouse-tmux.sb`.

---

## E2 — The keychain hole  (F2)

`~/.config/sandbox-exec/grants.sb`, full block, lines 31-58:
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

Also note `(home-subpath "/Library")` appears in `agent.sb:828` but only under
`file-read-metadata`, which is fine.

---

## E3 — The ssh-agent re-open  (F4)

`~/.config/sandbox-exec/agent.sb:757-809` (abridged, order preserved):
```scheme
;; Defense-in-depth: block private key reads/writes by default.
(deny file-read* file-write*
    (home-subpath "/.ssh")
)
…
;; Directory traversal so Tahoe-style ~/.ssh/agent sockets can resolve.
(allow file-read-metadata
    (home-literal "/.ssh/agent")
)

;; SSH agent socket access via launchd-managed SSH_AUTH_SOCK …
(allow file-read* file-write* file-read-metadata
    (regex #"^/private/tmp/com\.apple\.launchd\.[^/]+/Listeners$")
    (regex #"^/tmp/com\.apple\.launchd\.[^/]+/Listeners$")
    (regex #"^/private/var/run/com\.apple\.launchd\.[^/]+/Listeners$")
    (regex #"^/var/run/com\.apple\.launchd\.[^/]+/Listeners$")
    (home-subpath "/.ssh/agent")
)

(allow network-outbound
    (remote unix-socket (path-regex #"^/private/tmp/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex #"^/tmp/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex #"^/private/var/run/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex #"^/var/run/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex (string-append "^" HOME_DIR "/\\.ssh/agent(/.*)?$")))
)
```

Related: `agent.sb:242` — `(allow network-outbound (remote ip))`.
Related: `agent.sb:209` — `com.apple.trustd.agent` already allowed (TLS).
Related: `agent.sb:723` — `(home-prefix "/.gitconfig")` readable.

---

## E4 — Keychain contents  (F3)

Enumeration (metadata only, no secrets):
```bash
security dump-keychain | grep -iE 'gh:|github'
```
Revealed generic-password items, service `gh:github.com`, for accounts
`sven1103-agent` **and** `sven1103`; plus
`IntelliJ Platform GitHub — <uuid>` items with acct `GitHub OAuth token`.

Reachability probe — **use exit status, do not print the secret**:
```bash
/usr/bin/security find-generic-password -s "gh:github.com" -a "sven1103-agent" -w >/dev/null 2>&1 \
  && echo LEAK || echo blocked
```
Observed `LEAK` from the unconfined session. Also observed:
```bash
gh auth status
# ✓ Logged in to github.com account sven1103-agent (keyring)
# Token scopes: 'gist', 'read:org', 'repo', 'workflow'
printf 'protocol=https\nhost=github.com\n\n' | git credential fill   # returned a username+password
```

The keychain ACL did **not** prompt:
```bash
security find-generic-password -s "gh:github.com"   # showed full attributes, no Access Control prompt
```

---

## E5 — Token capability probes  (F3)

```bash
gh api user --jq '{login,type,created_at}'          # sven1103-agent, User, 2026-02-13
gh api user/orgs --jq '.[].login'                   # example-org
gh api user/memberships/orgs/example-org --jq '{state,role}'   # {"role":"member","state":"active"}
gh api repos/example-org/example-app --jq '.permissions'
                                                        # push=true
gh api repos/example-org/example-app/contents/.github/workflows --jq '.[].name'
                                                        # succeeded => workflow scope usable
```

---

## E6 — SSH key state  (F6)

```bash
for k in ~/.ssh/*; do
  case "$k" in *.pub|*/known_hosts*|*/config*|*/allowed_signers) continue;; esac
  if ssh-keygen -y -P "" -f "$k" >/dev/null 2>&1; then
    echo "NO PASSPHRASE: $k"
  fi
done
```
Result: `id_rsa`, `jenkins`, `id_ed25519` usable with an empty passphrase.
`ssh -T git@github.com` → `Permission denied (publickey)` at that time.
`ssh-add -l` → one unlocked RSA key present in the agent.

---

## E7 — Sandbox bypass / nesting behaviour  (F1 retracted, F9)

> **Correction:** the "ALLOWED" results below are *not* evidence that pi was
> unsandboxed. That session ran from `$HOME`, so the wrapper's dynamic workdir
> grant added `(allow file-read* file-write* (subpath "$HOME"))` and exposed
> `~/.ssh`, `~/.zshrc` and the keychain. The process was **confined but
> over-granted**. See FINDINGS F1 (retracted) and F11 (clean re-measurement).
> The nesting refusal and the `/bin/ps` denial below actually *prove* the sandbox
> was applied. Keep these commands as the "am I confined?" check; do not read
> them as a bypass.

```bash
sandbox-exec -p '(version 1)(allow default)' -- /bin/echo hi
# sandbox-exec: sandbox_apply: Operation not permitted   (reproducible, 3/3)
/bin/ps
# /bin/bash: /bin/ps: Operation not permitted
head -c1 ~/.ssh/id_rsa >/dev/null && echo ALLOWED
# ALLOWED   <-- host read succeeded despite the policy denying ~/.ssh
```

---

## E8 — Corrected measurement harness  (F9)

`WORK_DIR` **must** be a realistic workdir. Setting it to `$HOME` adds
`(allow file-read* file-write* (subpath "$HOME"))` and over-grants, producing
false "ALLOWED" results.

```bash
build_policy() {                       # $1 = realistic workdir
  local wd="$1" out="/tmp/real.sb"
  sed "s|__SAFEHOUSE_REPLACE_ME_WITH_WORK_DIR_DEFINE__|(define WORK_DIR \"$wd\")|g" \
      ~/.config/sandbox-exec/agent.sb > "$out"
  printf '\n(allow file-read* file-write* (subpath "%s"))\n' "$wd" >> "$out"
  printf '\n;; --- grants.sb ---\n' >> "$out"
  cat ~/.config/sandbox-exec/grants.sb >> "$out"
  cat ~/.safehouse-tmux.sb >> "$out"
  echo "$out"
}
```

Probe helper (exit-status only):
```bash
probe() { printf '%-46s ' "$1"; shift
  sandbox-exec -f /tmp/real.sb -- /bin/sh -c "$1" >/dev/null 2>&1 && echo ALLOWED || echo denied; }
probe "keychain DB"        'head -c1 "$HOME/Library/Keychains/login.keychain-db"'
probe "gh token"           '/usr/bin/security find-generic-password -s gh:github.com -w'
probe "ssh-add -l"         '/usr/bin/ssh-add -l'
probe "HF_TOKEN in env"    '[ -n "$HF_TOKEN_STRICT" ]'
```

Observed with a realistic workdir (base policy sound): keychain, gh token,
`~/.config/gh/hosts.yml`, `ssh-add -l`, `~/.zshrc`, JetBrains `github.xml`
→ all **denied**. The F2/F4 holes are `grants.sb`-/re-allow-specific. Note this
list describes the *base* `agent.sb` in isolation: the **effective** policy the
wrapper loads also concatenates `grants.sb` (+ `~/.safehouse-tmux.sb`), which
re-opens keychain and ssh-agent even with a realistic workdir. See F11.

---

## E9 — Negative results  (F10)

```bash
grep -rIlE 'ghp_|gho_|github_pat_|GH_TOKEN|GITHUB_TOKEN' ~/.zshrc ~/.zshenv ~/.zprofile \
  ~/.bashrc ~/.bash_profile ~/.profile ~/.config 2>/dev/null
# (only ~/.zshrc, and only for HF_TOKEN_STRICT, not GitHub)

ls ~/.git-credentials ~/.netrc 2>&1        # both absent
for c in op pass vault bw lpass envchain; do command -v "$c"; done   # none installed
git config --global --get credential.helper   # gh   <-- ambient auth (P9)
```

---

## E10 — Helper scripts to add

Suggested layout for this repo:

```
scripts/
  build-policy.sh     # render effective policy for a given workdir (from E8)
  probe.sh            # single-path reachability probe, exit-status only
  selftest.sh         # assert all credentials are unreachable; non-zero on leak
  agent-tmux.sh       # confined tmux launcher (P1.1)
```

`scripts/selftest.sh` contract — **must not print secrets**:
```bash
#!/usr/bin/env bash
# Exits 0 only if every credential probe is blocked.
set -uo pipefail
policy="${1:?usage: selftest.sh <policy-file>}"
fail=0
chk() { # name, command
  printf '%-40s ' "$1"
  if sandbox-exec -f "$policy" -- /bin/sh -c "$2" >/dev/null 2>&1
  then echo "LEAK"; fail=1; else echo "ok"; fi
}
chk "keychain-db"      'head -c1 "$HOME/Library/Keychains/login.keychain-db"'
chk "security gh token" '/usr/bin/security find-generic-password -s gh:github.com -w'
chk "ssh-add"          '/usr/bin/ssh-add -l'
chk "ssh private key"  'head -c1 "$HOME/.ssh/id_rsa"'
chk "env secret"       '[ -n "${HF_TOKEN_STRICT:-}" ]'
chk "git credentials"  'cat "$HOME/.config/gh/hosts.yml"'
exit "$fail"
```

Note: `selftest.sh` itself must be run from an **unconfined** context, or the
probes will all report `ok` for the wrong reason (nested sandbox refused).
