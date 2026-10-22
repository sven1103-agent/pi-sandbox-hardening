# Upstream Safehouse stance on these issues

Source: https://agent-safehouse.dev/docs/overview ,
https://agent-safehouse.dev/docs/options ,
https://agent-safehouse.dev/docs/default-assumptions ,
https://github.com/eugene1g/agent-safehouse (Apache-2.0, 2.1k stars, HEAD 2026-10-21)

Local install: **v0.12.0** (upgraded from v0.10.1, which the fork was authored
against — see P11.1). Upstream latest release: **v0.12.0** (2026-09-07).
→ Version drift is now resolved; the remaining gap is that the wrapper still
loads the hand-edited `agent.sb`/`grants.sb` instead of a generated policy,
so the upgrade alone changed no effective grant (P11.2).

**Bottom line:** upstream does *not* treat keychain exposure as a flaw — it is the
documented, opt-in purpose of the `keychain` integration. The **ssh-agent** variant
*was* reported (#36) and fixed by deny-by-default in v0.4.0. The local custom
policy **turns both opt-ins into always-on and removes the ssh-agent
default-deny**, so the local setup is *less* safe than upstream defaults.
Additionally, upstream already accepts `gh`/`glab` credential exposure by design.

---

## 1. Category-level acknowledgment (explicit, in docs)

`docs/overview` → **Important Limitations** — safehouse does not fully protect against:

- Data exfiltration over network from files the sandbox is allowed to read.
- Sandbox escapes (it is not a VM/hypervisor boundary).
- **Abuse through already-allowed IPC/credential channels.**
- **Leakage of data from explicitly allowed paths.**

The third bullet is exactly F2/F3 (keychain via allowed mach/IPC channel) and
F4 (ssh-agent via allowed unix socket). The fourth covers F5/F7.

Also, framing statement (site + README):

> It is a hardening layer, not a perfect security boundary against a determined attacker.

And `profiles/50-integrations-core/scm-clis.sb` carries its own threat-model note:

> Threat-model note: preventing exfiltration/C2 is NOT a goal; this keeps SCM workflows available to agents.

---

## 2. ssh-agent exposure — REPORTED and FIXED upstream (#36)

Issue: `ssh-agent socket reachable via network-outbound` — **closed, resolved in v0.4.0**.
The reporter's diagnosis matches F4 exactly:

> macOS SBPL treats connecting to a Unix domain socket as network-outbound, not
> file-read* … `(allow network*)` in 20-network.sb still allows the sandboxed
> process to connect to the ssh-agent socket and ask the agent to sign on its
> behalf. The process never reads the key file directly.
> … people could easily overlook this and assume their SSH credentials are
> locked down when they're not.

Maintainer's fix: a **core, always-loaded** profile
`profiles/50-integrations-core/ssh-agent-default-deny.sb`, which is present in
the shipped v0.10.1 binary (still present in v0.12.0):

```scheme
;; #safehouse-test-id:ssh-agent-socket-deny# Keep SSH agent credential use opt-in.
(deny network-outbound
    (remote unix-socket (path-regex #"^/private/tmp/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex #"^/tmp/com\.apple\.launchd\.[^/]+/Listeners$"))
    (remote unix-socket (path-regex (string-append "^" HOME_DIR "/\\.ssh/agent(/.*)?$")))
)
```

The agent socket is then re-opened **only** by `--enable=ssh`.

**Local delta:** `~/.config/sandbox-exec/agent.sb` **does not contain
`ssh-agent-default-deny.sb`**, and the ssh-agent allows at `agent.sb:~787-809`
are a verbatim copy of upstream's *optional* `55-integrations-optional/ssh.sb`
(local `agent.sb:752` = `;; Integration: SSH`). So the custom/wizard-generated
policy **dropped the core deny and baked in the `--enable=ssh` allow**.

This is corroborated by `docs/options`:

> Before using `--enable=shell-init`, audit shell startup/config files for
> credentials or tokens exported into the environment.

and `default-assumptions` → *Not Granted (or Explicitly Denied) by Default*:

> SSH agent sockets (`SSH_AUTH_SOCK`, including launchd listeners and
> `~/.ssh/agent/*`) unless `ssh` is enabled.

So **upstream's documented default is deny**; the local policy contradicts it.

Design tension noted in #36 by the maintainer (worth knowing, since it explains
why these options exist):

> It's now a dilemma: should we break `git` for many people who never use `ssh`
> to manage servers, or leave `ssh` exposed by default, where real damage can
> happen … My fear is that with overly strict defaults, people will forgo all
> sandboxing entirely.

---

## 3. Keychain — documented as sensitive opt-in, not a bug

`default-assumptions` → *Opt-In (Disabled by Default)*:

> `keychain`: macOS Keychain and `security`-tool access for credential-backed
> helper or plugin flows that need explicit opt-in.

`docs/options`:

> `keychain` is mainly for plugin or helper flows that need macOS credential
> access but are not auto-detected by a built-in Safehouse profile. For example,
> core `opencode` does not require keychain access, but plugin-based auth flows
> such as `opencode-claude-auth` can opt in with `--enable=keychain`.

`default-assumptions` → *Before You Enable Anything*:

> Is this required for the current task, or just convenient? Can I scope it to a
> narrower path or single feature? **Can I make it read-only instead of
> read/write?** Should this be temporary instead of shell-default?

**Local delta:** the two `grants.sb` blocks (lines 31–58) are a **trimmed copy of
upstream's `55-integrations-optional/keychain.sb`** (identical file rules; a
subset of the mach names: `SecurityServer`, `security.agent`, `trustd`). That
profile is opt-in upstream and auto-injected only for agent profiles that
declare it — **`60-agents/pi.sb` does not** declare the dependency.

Critically, upstream's own guidance is to make it **read-only**, whereas the
local copy grants `file-write*` on `~/Library/Keychains` (see FINDINGS F2). Note
also the open issue **#102** acknowledging the same write-grant/persistence class
for toolchain paths ("Toolchain write-allowances let agent backdoor host-invoked
CLIs").

---

## 4. `gh`/`glab` credentials are exposed BY DEFAULT upstream

Important context that softens the "custom policy introduced this" claim for
tokens specifically:

`profiles/50-integrations-core/scm-clis.sb` is **core (always loaded)** and grants
`file-read* file-write*` on:

```
~/.config/gh   ~/.cache/gh   ~/.local/share/gh   ~/.local/state/gh
~/.config/glab-cli  ~/.cache/glab-cli  ~/.local/share/glab-cli  ~/.local/state/glab-cli
```

Note the comment: `gh auth tokens/config for repo and PR automation.`

So upstream **deliberately exposes SCM CLI tokens** to the agent, and asserts
that preventing exfiltration is not a goal. Consequently:

- Removing the keychain grant alone does **not** hide the `gh` token if it lives
  in `~/.config/gh/hosts.yml` — that path is granted by core `scm-clis.sb` in the
  local `agent.sb` too.
- A keychain-only `gh` install is exposed via the keychain grant; a hosts.yml
  install is exposed via `scm-clis.sb`. **Either way the token is in scope.**

⇒ This is the strongest argument for the dedicated, least-privilege **agent
keychain / bot token** approach in MITIGATION_PLAN P2.3/P5: don't try to hide the
credential, make it *worthless-ish* if stolen.

---

## 5. Environment inheritance — upstream warns, local wrapper opts out

`docs/options`:

> `--env` Pass the full inherited host env to the wrapped command, **including
> secrets** … `--env` disables that boundary and forwards the entire inherited
> host environment, including cloud credentials, API keys, and other secrets.

> Prefer sanitized mode plus `--env-pass` … when only a few host variables are needed.

`default-assumptions` lists "Sanitized runtime environment (not full shell env by
default …)" under *Allowed by Default*.

**Local delta:** `run-sandboxed.sh` uses a bare `env TMUX=…`, which inherits
everything — effectively the documented-dangerous `--env` behaviour, and it
doesn't even use upstream's sanitized mode. See F7.

Also relevant, `default-assumptions` on another "escape hatch":

> Launch Services always starts processes OUTSIDE the sandbox with the current
> user's full permissions.

---

## 6. What this means for the plan

| Finding | Upstream status | Implication |
|---|---|---|
| F2 keychain rw | By design, opt-in; docs say prefer read-only; not a bug | **Local deviation.** Delete the block (P2) or narrow to `file-read-metadata`. |
| F3 two gh tokens | Upstream exposes `~/.config/gh` **by default**; exfil not a goal | Not fixable by policy alone → least-privilege token (P5). |
| F4 ssh-agent | Reported #36, **fixed** by core default-deny in v0.4.0, re-opened only by `--enable=ssh` | **Local deviation.** Restore the deny (P3) = revert to upstream default. |
| F7 env inheritance | Explicitly warned for `--env` / `shell-init` | **Local deviation.** Use sanitized env + `--env-pass` (P4). |
| F8 egress | Documented limitation ("preventing exfiltration/C2 is NOT a goal") | Won't be "fixed" upstream; treat as accepted risk or add your own controls. |
| — | local fork authored for v0.10.1; **installed is now v0.12.0** | Upgrade done. The fork is still loaded, so re-generate before expecting stricter defaults. Re-check issues #102, #118. |

### Recommended direction

1. **Don't fork the policy.** Prefer letting `safehouse` generate it, then add
   only a small `--append-profile` final-deny overlay. Deliberate upstream
   features exist for this:
   `--append-profile=PATH`, `--allow-profile-writes`, and the trusted
   `<workdir>/.safehouse` config (`add-dirs-ro=`, `add-dirs=`, `enable=`,
   `append-profile=`) with `--trust-workdir-config`.
   Upstream states: *"Final-deny overlays should always remain possible
   (`--append-profile`)."*
2. **Drop `--enable=ssh`** unless remote-over-SSH inside the sandbox is genuinely
   required; use HTTPS+token or do SSH work in the unconfined terminal.
3. **Do not keep keychain always-on.** If `gh` must work in-sandbox, use a
   dedicated agent keychain holding only the bot token.
4. Upstream also runs `safehouse --explain` output showing effective grants —
   use it to diff against expectations.

## Open question for the next agent

- [ ] Was the local `agent.sb`/`grants.sb` produced by the safehouse wizard, by
      an LLM, or hand-written? If wizard-generated, check whether a newer
      safehouse would generate a stricter policy (the wizard may have emitted the
      unsafe combination, which would be worth reporting upstream).
- [ ] Consider filing/checking an upstream issue for "wizard output can bake in
      `--enable=ssh` + keychain and omit ssh-agent-default-deny".
      Related existing: #71 (opencode plugin needs keychain), #102, #118.
