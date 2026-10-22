# Regression harness — how to test hardening safely

The harness exists so we can change the sandbox **without guessing**. It encodes
the real invariant:

> **human credentials must be unreachable, while the agent keeps working with its
> own granted rights.**

It is *not* "any readable credential is a leak" — that rule is wrong, because the
agent legitimately owns credentials (`~/.pi/agent/auth.json`, `~/.agent/**`) and
must be able to use them.

## Two suites

| Suite | Question | A failure means |
|---|---|---|
| **DENY** | Can the agent reach a **human** credential? | `LEAK` — hardening is incomplete |
| **ALLOW** | Can the agent still do its job? | `BROKEN` — hardening went too far and killed productivity |

Checks are tagged `required` or `optional`. `optional` is how we stage a
migration: a not-yet-available agent capability reports `NOTYET` (not a failure)
until the step that introduces it lands — then it flips to `ok`.

## The restart rule (important)

The launcher compiles the policy into a temp file at startup and `sandbox-exec`
never reloads it. Therefore:

| Target | Picks up a policy change |
|---|---|
| The **harness** (re-reads the files every run) | immediately — no restart |
| An **already-running pi session** | only on restart |

So a session can still reach something the current policy denies, purely because
it launched earlier. That is expected, not a bug. To confine a change, **start a
new pi**; to check the change itself, the harness is enough.

If the harness still reports a keychain `LEAK` after a step that should have
closed it, a *later* policy layer is re-granting it. The effective policy is
composed in this order, and later layers win:

```
agent.sb -> dynamic workdir grant -> grants.sb -> ~/.safehouse-tmux.sb  (LAST)
```

Check per-layer counts with `scripts/diagnose-keychain.sh`.

## Run it

**Rule 1: run from an UNCONFINED terminal.** Inside a sandbox, nested
`sandbox-exec` is refused and every probe misreports. The script exits `3` with
`FATAL` if it detects this.

**Rule 2: run from a REAL workdir, never `$HOME`.** A workdir of `$HOME`
appends a whole-home read/write grant, exposing `~/.ssh`, `~/.zshrc` and the
keychain and producing false `LEAK`s. This is the artifact behind the retracted
finding F1 (see `FINDINGS.md` F1/F11). The script exits `2` if `$PWD` is `$HOME`.

```bash
cd ~/git/pi-sandbox-hardening
scripts/selftest.sh                 # auto-builds the effective policy for $PWD
scripts/selftest.sh /path/to.sb     # or test a specific policy file
scripts/selftest.sh --json          # machine-readable
```

### Agent session environment

Probes run with the **agent session's** environment
(`GH_CONFIG_DIR`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM=/dev/null`), because
that is what the launcher actually sets. Without this, checks that depend on
those overrides would report a `LEAK` the real agent session does not have —
e.g. the ambient-keychain route via the host global gitconfig (FINDINGS F12).

To inspect the *raw policy* instead (no env overrides), use
`--agent-env=ambient`. Note the baseline must be recorded with the same mode you
compare against.

Exit codes: `0` pass · `1` leak/broken · `2` bad usage · `3` inconclusive
(already sandboxed).

### Check scopes

| Scope | How it runs | Used for |
|---|---|---|
| `sandbox` | under `sandbox-exec` with the agent env | credential reachability + capability |
| `host` | **unconfined**, no `sandbox-exec` | *wiring* facts the policy dir hides (launcher patched? files present?) |

Host-scope checks exist because the policy denies reading
`~/.config/sandbox-exec`, so a wiring assertion cannot be made from inside the
sandbox. They guard against a false pass: agent-env probing assumes the launcher
sets `GH_CONFIG_DIR`/`GIT_CONFIG_GLOBAL`, and if it does not, the harness would
measure a target state that never occurs.

## Baseline and diff (the point of this harness)

Capture the state **before** any config change, so every later step is a diff
against known ground truth:

```bash
scripts/selftest.sh --record baseline-before.tsv   # capture "before"
#   ... apply one mitigation step ...
scripts/selftest.sh --diff baseline-before.tsv     # what actually changed
```

`--diff` prints `CHANGED <check> <old-state>/<old-verdict> -> <new>/<new>` and
`NEW` for checks absent from the baseline. A staged migration therefore reads
cleanly, e.g. the keychain-free GitHub step should show:

```
CHANGED  agent: gh config   DENIED/NOTYET -> REACHABLE/ok
CHANGED  security:bot       REACHABLE/LEAK -> DENIED/ok
```

## Working agreement for this repo

1. **Record a baseline before each step.** No step is "done" without a diff.
2. **A step is correct only when DENY has no `LEAK` and ALLOW has no `BROKEN`.**
   `NOTYET` on an `optional` check is expected mid-migration.
3. **Never print secret values.** Every check reports reachability only.
4. If a step breaks an ALLOW check, that is a regression — revert it and narrow
   the policy rather than accepting lost capability.

## Baseline files and git

Baseline snapshots contain only check names, states and verdicts — no secret
values — so they are safe to commit. If you prefer to keep them local, add
`baseline-*.tsv` to `.gitignore`.
