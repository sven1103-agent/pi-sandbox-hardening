# Step 6 — Deny the personal gh config (applied)

Closes the last remaining leak: the Safehouse core SCM grant on `~/.config/gh`.
See [`README.md`](README.md) for the project overview and [`TESTING.md`](TESTING.md) for the harness.

`agent.sb` carries the Safehouse core SCM grant:

```
agent.sb:740  (allow file-read* file-write*
agent.sb:741      (home-subpath "/.config/gh")   ;; gh auth tokens/config
```

That is the **personal** gh config. Step 2 gave the agent its own
(`~/.agent/gh` via `GH_CONFIG_DIR`), so the personal path is redundant.

**What was actually at risk** (measured, correcting an earlier overstatement):
`~/.config/gh/hosts.yml` is 96 bytes and holds **no `oauth_token`** — it is
metadata only. The real personal token lives in the **login keychain** as
`gh:github.com` / acct `sven1103`, which Step 3b already denies. Confirmed
inside the sandbox: `gh api` with the personal config returns **HTTP 401**.
So this was a metadata + **write** surface, not a credential leak. The write
grant was the more meaningful part (config tampering).

**Approach:** append a deny to `grants.sb`, which the launcher concatenates
*after* `agent.sb`. SBPL is last-match-wins, so this wins without editing the
upstream-generated base policy (which a Safehouse upgrade may replace).

```scheme
(deny file-read* file-write*
    (home-subpath "/.config/gh")
)
(allow file-read-metadata
    (home-literal "/.config")
)
```

**Verified the agent's own `gh` is unaffected** — this was the explicit concern:

| Check | Result |
|---|---|
| `~/.config/gh/hosts.yml` | blocked ✅ |
| `~/.config/gh/config.yml` | blocked ✅ |
| `~/.config/gh` write | blocked ✅ |
| `~/.config` traversal | allowed ✅ |
| **agent `~/.agent/gh` read** | **allowed ✅** |
| **`gh api user` as agent** | **`sven1103-agent` ✅** |
| **`gh auth status`** | **`Logged in to github.com account sven1103-agent` ✅** |
| `~/.cache/gh`, `~/.local/state/gh` write | still allowed ✅ |

Note `gh` invoked **without** `GH_CONFIG_DIR` now fails closed (no personal
config fallback). That is intended: the launcher always sets `GH_CONFIG_DIR`.

### Result: zero leaks

```
baseline-step5 : human gh hosts.yml
baseline-step6 : (none)
diff           : CHANGED human gh hosts.yml  REACHABLE/LEAK -> DENIED/ok
selftest       : PASS — human creds unreachable, agent capability intact
```

DENY 17/17 ok · ALLOW 13/13 ok.

### Harness bug fixed: verification rendered the wrong policy

`build-policy.sh` hardcoded `POLICY_DIR="$HOME/.config/sandbox-exec"`, so
`apply-step-06.sh`'s replica test rendered the **unpatched** grants and reported
four false failures. `build-policy.sh` now honours `SANDBOX_POLICY_DIR`,
`SANDBOX_GRANTS`, and `SANDBOX_TMUX_PROFILE`, and `apply-step-06.sh` passes its
target grants file through. Same class of bug as the Step 5 harness issue:
verifying against something other than the thing under test.
