# Hardening a local coding agent on macOS

**A worked example: giving an AI coding agent its own identity, and taking away
access to yours — without breaking the workflow.**

How I stopped a locally-running coding agent from reading my macOS keychain, my
SSH keys, my GitHub auth and my ambient tokens, while keeping it fully
productive on its own credentials.

Everything here was **measured on a real machine**, not reasoned about. Several
of my initial conclusions turned out to be wrong, and the corrections are kept
in the record — that is arguably the most useful part.

- **Result:** 9 credential-exposure leaks → **0**, with agent capability intact
  (`DENY 19/19 ok`, `ALLOW 13/13 ok`).
- **Scope:** macOS `sandbox-exec` / SBPL, one human user, no second account, no
  account switching.
- **License:** MIT.

---

## Why this matters

Running a coding agent locally is convenient — that is exactly why so many
people do it. But by default such an agent runs **as you**: same UID, same
`~/.ssh`, same login keychain, same environment. Any prompt injection, any
over-eager tool call, any leaked token in a transcript is then effectively your
credential.

A sandbox helps, but a sandbox is not a boundary for credentials unless you
deliberately make it one. The two failure modes I hit:

1. **The sandbox re-opened the doors.** The policy explicitly granted the
   keychain and the ssh-agent socket, so the sandbox was real but the
   credentials were reachable *by design*.
2. **The environment bypassed the sandbox entirely.** `sandbox-exec ... env VAR=x pi`
   does not restrict the environment — it only *adds*. Every secret exported in
   `~/.zshrc` reached the sandboxed process. Environment variables are not a
   filesystem concept, so **no SBPL rule can constrain them.**

## The approach

Two principles did most of the work.

**1. Least-privilege credentials, not hiding.** Rather than trying to conceal
paths (which fails — see the "all-or-nothing" note below), give the agent **its
own** credentials and remove its need for yours:

| Resource | Human | Agent |
|---|---|---|
| GitHub identity | personal key + token | `sven1103-agent` key + token |
| git auth | ssh-agent | explicit `IdentityFile`, `IdentitiesOnly yes` |
| `gh` auth | login keychain | file token, own `GH_CONFIG_DIR` |
| Model API keys | login keychain | **own keychain** |
| Environment | ambient shell | explicit allowlist (`env -i`) |

**2. Verify with a DENY/ALLOW harness and record a baseline before every change.**
A change is done only when the diff is understood: no `LEAK` in the DENY suite,
no `BROKEN` in the ALLOW suite. This caught several mistakes that would otherwise
have shipped silently.

## Results

| | Before | After |
|---|---|---|
| Login keychain (read) | reachable | **denied** |
| System keychain | reachable | **denied** |
| Personal GitHub token | reachable | **denied** |
| SSH private keys | denied | denied |
| ssh-agent (sign as human) | **reachable** | **denied** (env + policy) |
| Ambient env tokens | **reachable** | **denied** (`env -i`) |
| Personal `gh` config | readable + writable | **denied** |
| Agent's own 3 API keys | n/a | **working** |
| Agent `git` over SSH | n/a | **working** |
| Agent `gh` API | n/a | **working** |

Keychain enumeration, measured the same way in both cases:

```
unconfined            : 384 items visible
inside the sandbox    :   3 items visible   (only the agent's own)
```

Progression, recorded by the harness:

```
baseline-before   9 leaks
baseline-step2    9 leaks   (identity wired; nothing removed yet)
baseline-step3b   4 leaks   (agent keychain; login/System keychains closed)
baseline-step5    1 leak    (env sanitized: ssh-agent + token inheritance)
baseline-step6    0 leaks
baseline-step4    0 leaks   (ssh-agent also denied in the policy)
```

## The non-obvious findings

These are the parts I could not find documented elsewhere, and each cost real
debugging time. All are measured; see `FINDINGS.md` and the step documents.

1. **SBPL is last-match-wins.** A `deny` *after* a broad `allow` wins; the
   reverse does not. Getting this backwards makes a policy look correct while
   doing nothing.
2. **`SecurityServer` mach-lookup is required even to read your own keychain.**
   But it does **not** re-expose the login keychain once the keychain *files*
   are denied — the file deny is what holds.
3. **Keychain lookups fall through.** If an earlier keychain in the search list
   is file-denied, `security` falls through to the next entry. That is the whole
   trick behind giving the agent its own keychain: the search list stays
   `[login, agent, System]`, so *your* shell still resolves from `login` while
   the sandboxed agent resolves from `agent`. No per-session state change.
4. **The search list lives in `~/Library/Preferences/com.apple.security.plist`.**
   If that one file is unreadable, `security` silently falls back to the built-in
   `[login, System]` list, never sees the agent keychain, and **every** provider
   fails with no useful error.
5. **`security create-keychain` mutates user-wide state.** It appends the new
   keychain to the global search list — and was observed to **drop the login
   keychain** from it, breaking the *human's* shell. Restore afterwards.
6. **`exec` defeats an `EXIT` trap.** `trap ... EXIT; exec cmd` never fires,
   because `exec` replaces the shell. A per-session search-list restore built
   this way silently never ran.
7. **`create-keychain` applies a 300s auto-lock.** Combined with
   `pi-subagents` spawning a **fresh `pi` process per subagent** (each
   re-resolving `auth.json`), this produced a keychain-prompt storm. Subagents
   also inherit `process.env` — `pi-subagents` strips git/extension routing but
   **not secrets** — so sanitizing at the launcher fixes the agent *and* every
   subagent at once.
8. **The keychain is all-or-nothing via IPC.** Because `SecurityServer`
   mach-lookup is required, you cannot partially hide a keychain: the fix is
   least-privilege credentials, not path hiding.

### Mistakes I made, and kept

Recording these matters more than the successes:

- **A retracted "the sandbox is bypassable" finding.** The evidence was an
  artifact of running the agent from `$HOME`, which appends a whole-home grant.
  With a realistic workdir the sandbox held. `FINDINGS.md` F1 keeps the
  retraction visible.
- **Three separate cases of measuring the wrong thing.** The harness once
  reported leaks the real session could not have (it did not model the sanitized
  environment); a policy renderer once verified the *unpatched* policy; and a
  genericised probe pointed at a file that did not exist, so it silently tested
  nothing. Each is now fixed **and** guarded (including a negative control that
  proves the ssh-agent probe actually detects a re-opened socket).
- **`$(cat <<'X' ...)` is a trap under bash 3.2.** An unbalanced apostrophe in
  the body breaks the parse, and backslash-newline continuations are stripped —
  which reproduced the launcher-truncation bug that made `pi` never start.

## Repository layout

| File | Contents |
|---|---|
| `FINDINGS.md` | Each finding (F1–F12) with evidence, status and severity |
| `STEP-01…06` | What was actually done, per step, with measurements |
| `TESTING.md` | **The harness**: DENY/ALLOW suites, baseline + diff workflow |
| `EVIDENCE.md` | Raw excerpts, line numbers, reproduction commands |
| `MITIGATION_PLAN.md` | The original ordered plan (kept for traceability) |
| `UPSTREAM_STANCE.md` | What the upstream sandbox project does/does not promise |
| `OPEN_QUESTIONS.md` | Unresolved items |

### Steps applied

| Step | What it did |
|---|---|
| [01](STEP-01-agent-github-identity.md) | Agent's own GitHub identity (SSH key + token) |
| [01b](STEP-01b-gh-token-in-agent-keychain.md) | Move that token from plaintext into the agent keychain *(script ready, not applied)* |
| [02](STEP-02-wire-agent-identity.md) | Wire it in: `GH_CONFIG_DIR`, `GIT_CONFIG_*`; close the gitconfig→keychain route |
| [03](STEP-03-remove-keychain-grant.md) | Remove the keychain grant (superseded by 03b) |
| [03b](STEP-03b-agent-keychain.md) | **Dedicated agent keychain**; deny login + System |
| [04](STEP-04-ssh-agent-deny.md) | Deny ssh-agent in the policy |
| [05](STEP-05-env-sanitization.md) | **`env -i` allowlist** — closes env inheritance |
| [06](STEP-06-personal-gh-config.md) | Deny the personal `gh` config |

## Reproducing / adapting

This repo is **genericised** — endpoints, org names and personal details are
placeholders (`example-org`, `llm.internal.example.com`, `you@example.com`).
Override via environment variables rather than editing files:

```bash
MODEL_ENDPOINT="https://your-gateway.example.org" \
LITELLM_MODELS_URL="https://your-gateway.example.org/v1/models" \
  scripts/selftest.sh
```

See the table in [`TESTING.md`](TESTING.md). Git hooks live in `scripts/hooks/`
(versioned) — install with `scripts/install-hooks.sh`.

Each `scripts/apply-step-*.sh` is idempotent, backs up before writing, refuses to
run from inside a sandbox, and **verifies functionally** — restoring the backup
automatically if verification fails.

```bash
scripts/apply-step-05.sh --dry-run   # preview
scripts/apply-step-05.sh             # apply, verify, or roll back
```

## Caveats — read before trusting this

- **This is a hardening layer, not a security boundary.** It is not a VM. A
  determined attacker with code execution can still exfiltrate anything the
  agent can legitimately read.
- **`no-timeout` was a deliberate trade-off.** The agent keychain stays unlocked
  until you lock it or reboot, because a 300s auto-lock caused repeated prompts
  that broke the workflow. Revert with
  `security set-keychain-settings -t 300 -l ~/.agent/agent.keychain-db` if you
  prefer the opposite trade.
- **Subagents inherit confinement; they do not re-apply it.** `pi-subagents`
  contains no `sandbox-exec` wrapper, so a sandboxed parent yields sandboxed
  subagents, but launching via an unconfined path makes **every** subagent a
  bypass. Verify with the procedure in `TESTING.md`.
- **Least privilege beats concealment.** The strongest control here is that the
  agent has its own credentials and no need for yours.
- **macOS-only**, and tied to the policy layout of the sandbox tool used.
  The *techniques* generalise; the exact rules do not.

## License

MIT — see [`LICENSE`](LICENSE).
