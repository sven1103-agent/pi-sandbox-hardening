# STEP-05 — Environment sanitization (PROPOSAL — not applied)

**Status:** proposal only. Nothing in this document has been applied.
**Risk:** medium (touches the launcher's exec line — the same line involved in the
earlier launcher incident).
**Reversible:** yes, single-file backup + restore.

## Problem

`FINDINGS.md` F5: the launcher inherits the **entire** shell environment.

```bash
exec sandbox-exec -f "$tmp_policy" \
  env \                              # <-- no -i, no allowlist
    TMUX="${TMUX:-}" \
    GH_CONFIG_DIR="$HOME/.agent/gh" \
    GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \
    GIT_CONFIG_SYSTEM=/dev/null \
  /opt/homebrew/bin/pi ...
```

`env` without `-i` **adds** variables to the inherited set; it does not restrict
it. Measured:

```
$ export DEMO_SECRET="leaked-value-123"
$ env TMUX="" OTHER=1 /bin/sh -c 'echo $DEMO_SECRET'
leaked-value-123
```

Consequences:

| Var | Why it matters |
|---|---|
| `SSH_AUTH_SOCK` | Lets the agent (and every subagent) sign as **you** with any key loaded in ssh-agent. This is F4. |
| `HF_TOKEN_STRICT` | Demonstrated live: reached pi, the sandbox, and 10 session transcripts. |
| anything exported in `~/.zshrc` | Reaches pi regardless of the sandbox — env vars are not a filesystem concept, so no SBPL grant or deny affects them. |

### Amplified by subagents

`pi-subagents` spawns each subagent as a **new `pi` process** and builds its env as:

```js
// src/runs/background/async-execution.js:503
const runnerEnv = {
    ...omitGitRoutingEnv(omitExtensionBindingsEnv(process.env)),
    ...childCacheRetentionEnv(),
    ...
};
```

It strips only git-routing and extension-binding variables — **not secrets**.
So every subagent inherits `SSH_AUTH_SOCK` and any exported token.

Sanitizing at the **launcher** fixes this for pi *and* all subagents at once,
because subagents inherit from the parent pi process. This is why Step 5 is
higher value than Step 4 alone.

## Design

Replace the inherited environment with an explicit allowlist, using `env -i`.

### Verification of the allowlist (all measured)

Every variable below was confirmed needed, or confirmed droppable:

| Variable | Needed? | Evidence |
|---|---|---|
| `HOME` | **yes** | pi resolves config/session paths from it (14 references in the bundle) |
| `PATH` | **yes** | `git`, `gh`, `node` resolution inside the sandbox |
| `USER`, `LOGNAME` | **yes** | `security add-generic-password -a "$USER"` and ACL checks |
| `SHELL` | **yes** | pi spawns shells for tool calls (3 references) |
| `TMPDIR` | **yes** | temp files / compile cache (4 references) |
| `TERM`, `COLORTERM` | **yes** | interactive TUI rendering |
| `LANG` | yes | locale / UTF-8 handling |
| `TMUX` | yes | tmux integration profile (already passed) |
| `EDITOR`, `VISUAL` | yes | pi reads both (6 references each) |
| `GH_CONFIG_DIR`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM` | **yes** | Step 2 agent identity |
| `PI_OFFLINE`, `PI_SKIP_VERSION_CHECK`, `PI_TIMING`, `PI_CODING_AGENT_DIR`, `PI_PACKAGE_DIR` | pass through if set | pi + pi-subagents read them (see list below) |
| `TERM_PROGRAM`, `LC_TERMINAL*`, `ITERM_*`, `COLORFGBG` | optional | terminal-detection niceties; harmless, but could be dropped |
| **`SSH_AUTH_SOCK`** | **NO — dropped** | measured: git-over-SSH authenticates as `sven1103-agent` with `env -u SSH_AUTH_SOCK`; the agent config sets `IdentitiesOnly yes` + explicit `IdentityFile` |
| **`HF_TOKEN_STRICT`** | **NO — dropped** | not used by pi |
| `DISPLAY`, `SECURITYSESSIONID`, `LaunchInstanceID`, `XPC_*`, `__CF*` | drop | GUI/keychain-session plumbing not needed by pi |
| `CONDA_*`, `SDKMAN_*`, `_CE_*`, `JAVA_HOME`, `GRADLE_HOME`, `GROOVY_HOME`, `MICRONAUT_HOME`, `HOMEBREW_*` | drop | toolchain junk inherited from the shell |
| `P9K_*`, `_P9K_*`, `PAGER`, `LESS`, `LSCOLORS`, `ZSH`, `FPATH`, `INFOPATH`, `SHLVL`, `PWD`, `OLDPWD`, `_` | drop | shell/session bookkeeping |
| `AI_AGENT`, `PI_MODEL`, `PI_PROVIDER`, `PI_REASONING_LEVEL`, `PI_SESSION_FILE`, `PI_SESSION_ID` | drop | set by pi for its own children; do **not** inherit stale values from a parent session |
| `CI`, `DEBUG`, `NODE_DEBUG`, `HTTP(S)_PROXY` | drop by default | add explicitly if you need a proxy |

### Proposed launcher change

```bash
# --- pi-sandbox-hardening step-05: sanitized environment ---------------------
# Started from an EMPTY environment: 'env' without -i only ADDS variables, so
# secrets exported in ~/.zshrc (SSH_AUTH_SOCK, *_TOKEN) reached pi and every
# subagent. Everything below was measured as needed; everything else is dropped.
#
# NOTE: keep comments ABOVE the exec line. A '#' inside the backslash-continued
# command truncates it and pi never starts (see STEP-02).
env -i \
  PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  HOME="$HOME" \
  USER="${USER:-$(id -un)}" \
  LOGNAME="${LOGNAME:-$(id -un)}" \
  SHELL="${SHELL:-/bin/zsh}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  TERM="${TERM:-xterm-256color}" \
  COLORTERM="${COLORTERM:-}" \
  LANG="${LANG:-en_US.UTF-8}" \
  EDITOR="${EDITOR:-}" \
  VISUAL="${VISUAL:-}" \
  TMUX="${TMUX:-}" \
  GH_CONFIG_DIR="$HOME/.agent/gh" \
  GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \
  GIT_CONFIG_SYSTEM=/dev/null \
  ...
```

`exec sandbox-exec -f "$tmp_policy" <the env -i block> /opt/homebrew/bin/pi ...`

Note the ordering change: currently `sandbox-exec ... env VAR=... pi`; the
proposal keeps that shape but adds `-i` to the `env` invocation.

## Guard: never re-introduce a leak silently

Add a hard failure for known-bad variables, so a future edit cannot
accidentally pass them through:

```bash
for bad in SSH_AUTH_SOCK SSH_AGENT_PID HF_TOKEN_STRICT; do
  if [[ -n "${!bad:-}" ]]; then
    echo "step-05: dropping inherited $bad" >&2
  fi
done
```

(Informational during rollout; can become a hard exit later.)

## Verification plan

1. **Static**: `scripts/verify-launcher.sh` must still pass (pi invoked, the
   three `GIT_CONFIG*`/`GH_CONFIG_DIR` present). Extend it to assert
   `SSH_AUTH_SOCK` is **absent** in the child argv.
2. **Behavioural dummy**: export a sentinel before launching and prove it does
   **not** arrive:
   ```bash
   export PI_SANDBOX_TEST_SENTINEL="must-not-appear"
   # then, inside the sandboxed session:
   printenv PI_SANDBOX_TEST_SENTINEL    # must print nothing
   ```
3. **Capability checks inside a new sandboxed session** (all must PASS):
   - `git ls-remote git@github.com:example-org/example-app HEAD` → works (SSH)
   - `gh api user --jq .login` → `sven1103-agent`
   - providers resolve (`security find-generic-password -ws litellm`)
   - a subagent runs and reaches its model
4. **Leak checks inside the same session** (all must FAIL to read):
   - `printenv SSH_AUTH_SOCK` → empty
   - `ssh-add -l` → cannot connect to agent
   - `head -c1 ~/Library/Keychains/login.keychain-db` → denied
5. **Harness**: `scripts/selftest.sh --record baseline-step5.tsv` then
   `--diff baseline-step3b.tsv`. Exit criteria: **no `LEAK` in DENY, no `BROKEN`
   in ALLOW**.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| pi fails to start (missing var) | `verify-launcher.sh` gate; backup + one-command restore |
| `env -i` breaks TUI / terminal detection | keep `TERM`, `COLORTERM`, `LANG`; test interactively |
| `git`/`gh` stop working | PATH is explicit; SSH verified without the socket |
| Subagent spawn fails | `pi-subagents` reads only `HOME`, `PATH`, `PI_*` — all preserved |
| Cron/non-interactive launches | `env -i` is *safer* there; no TTY-dependent behaviour added |

## What this does NOT fix

- **ssh-agent socket access via the sandbox policy** (F4). This step removes the
  *environment variable*, so nothing can find the socket — but the SBPL grant
  that allows the socket path is still present and is Step 4's job. Step 5 is a
  strong mitigation, not a substitute.
- **Ambient secrets already on disk** in `~/.zsh_history`, `~/.viminfo`, and pi
  session transcripts. Those must be rotated or scrubbed separately.
- **A process that re-derives a secret** (e.g. re-reading `~/.zshrc` itself).
  `~/.zshrc` is not readable inside the sandbox, but this is worth confirming
  rather than assuming.

## Rollback

```bash
cp -p ~/.config/sandbox-exec/run-sandboxed.sh.bak-<stamp> \
      ~/.config/sandbox-exec/run-sandboxed.sh
```

No policy change, no keychain change — this step touches only the launcher.
