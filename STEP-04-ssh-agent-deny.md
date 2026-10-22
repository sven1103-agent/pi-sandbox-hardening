# STEP-04 — Deny ssh-agent access in the policy (applied)

Closes FINDINGS F4: the policy re-opened ssh-agent socket access.
See `README.md` for the project overview and `TESTING.md` for the harness.

`FINDINGS.md` F4. `agent.sb` re-opens ssh-agent access in two places:

```
agent.sb:795  (allow file-read* file-write* file-read-metadata
                 regex #"^/private/tmp/com\.apple\.launchd\.[^/]+/Listeners$" ...)
agent.sb:803  (allow network-outbound
                 (remote unix-socket ... launchd Listeners ...))
agent.sb:855  (allow network-outbound (remote unix-socket ~/.agent/ssh ...))
```

This lets a sandboxed process sign with **any key loaded in your ssh agent** —
i.e. your personal keys — without reading the key files. Measured with
`SSH_AUTH_SOCK` forced into the sandbox:

```
before step-04 : ssh-add -l -> REACHABLE (1 key: sven1103@... RSA)
after  step-04 : ssh-add -l -> blocked
```

Step 5 already strips `SSH_AUTH_SOCK`, so nothing can find the socket in
practice. **Step 4 removes the policy grant as well**, so the exposure is closed
at both layers: if any future code re-derives the socket path, the policy holds.

**The agent needs no ssh-agent.** Its git-over-SSH uses an explicit
`IdentityFile` with `IdentitiesOnly=yes` and a passphrase-less key. Verified
inside the policy with the denies in place:

```
agent ssh key readable : yes
github ssh auth        : Hi sven1103-agent! You've successfully authenticated
gh api user            : sven1103-agent
```

### Probe hygiene: measure the POLICY, not the environment

With Step 5 in place, the original ssh-agent probes passed **for the wrong
reason** — `SSH_AUTH_SOCK` was absent from the environment, so the socket was
unreachable even though the policy still granted it. Two policy-level probes were
added that force the captured ambient socket path back into the sandbox:

```
ssh-agent(policy)        DENIED   ok
ssh: agent socket(policy) DENIED  ok
```

**Negative control** — rendering the pre-step-04 policy and forcing the socket
back in yields `REACHABLE`, confirming the probes actually detect a re-opened
socket rather than always reporting `DENIED`.

### Result

```
DENY  19/19 ok   (was 17, +2 policy-level probes)
ALLOW 13/13 ok
PASS: human creds unreachable, agent capability intact
```

### Step 5 announcement quieted

The launcher printed `step-05: dropping inherited SSH_AUTH_SOCK ...` on every
launch. Now gated behind `PI_SANDBOX_VERBOSE`:

```bash
PI_SANDBOX_VERBOSE=1 pi     # see what is dropped
pi                          # silent (default)
```

Verified: silent by default, loud with the flag, and the sanitization itself is
**unconditional** — `SSH_AUTH_SOCK` is absent from the child env in both modes.
