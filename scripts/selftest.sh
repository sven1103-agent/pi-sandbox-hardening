#!/usr/bin/env bash
# Two-suite policy regression test for the sandboxed pi agent.
#
#   DENY  suite — HUMAN credentials that must be UNREACHABLE from the agent
#                 (keychain, personal tokens, ssh-agent, ~/.ssh keys, ~/.zshrc,
#                  ambient exported secrets). A reachable DENY check = LEAK.
#   ALLOW suite — the AGENT'S OWN capability, which must SURVIVE hardening
#                 (its own model creds + own ssh/gh identity, workdir rw, egress
#                  to the model/MCP endpoints). A blocked ALLOW check = BROKEN.
#
# Rationale: "any readable credential is a leak" is the wrong invariant. The goal
# is human creds unreachable while the agent keeps working with its OWN granted
# rights. Agent-owned secrets (~/.pi/agent/auth.json, ~/.agent/**) are therefore
# ALLOW, not DENY.
#
# Never prints secret values: every check reports reachability only.
#
# Usage:
#   selftest.sh [policy-file]            run all checks, exit non-zero on any failure
#   selftest.sh --record FILE [policy]   write a baseline snapshot of all results
#   selftest.sh --diff FILE   [policy]   compare current results against a baseline
#   selftest.sh --json        [policy]   machine-readable results
#
# MUST be run from an UNCONFINED terminal, in a REAL workdir (not $HOME):
#   - nested sandbox-exec is refused inside a sandbox, so probes would misreport
#   - workdir=$HOME appends a whole-home grant and produces false LEAKs
#     (this is the artifact behind the retracted finding F1; see FINDINGS.md F11)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Endpoint of the model provider you actually use. Override to match your setup;
# the default is a placeholder so the public example stays generic.
MODEL_ENDPOINT="${MODEL_ENDPOINT:-https://llm.internal.example.com}"
# Ambient ssh-agent socket, captured so a probe can force it back INTO the
# sandbox. Step 5 strips SSH_AUTH_SOCK from pi's environment, which means the
# ordinary ssh-agent probes would pass even if the POLICY still granted the
# socket. Injecting it here makes those probes measure the policy itself.
AMBIENT_SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"

MODE=run
SNAPSHOT=""
JSON=0
AGENT_ENV_MODE="agent"   # agent|ambient — see classify()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --record) MODE=record; SNAPSHOT="${2:?--record needs a file}"; shift 2 ;;
    --diff)   MODE=diff;   SNAPSHOT="${2:?--diff needs a file}";   shift 2 ;;
    --json)   JSON=1; shift ;;
    --agent-env=*) AGENT_ENV_MODE="${1#*=}"; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
POLICY="${1:-}"

# --- guards -----------------------------------------------------------------

if [[ "${PWD:-}" == "$HOME" && -z "$POLICY" ]]; then
  cat >&2 <<'EOF'
ERROR: refusing to auto-build a policy with workdir=$HOME.

That appends a whole-home read/write grant, which exposes the paths this repo
protects and makes probes report false LEAKs (the cause of the retracted F1).

cd into a real repository first, or pass an explicit policy file:
  cd ~/git/<some-repo> && scripts/selftest.sh
EOF
  exit 2
fi

if ! sandbox-exec -p '(version 1)(allow default)' -- /usr/bin/true >/dev/null 2>&1; then
  echo "FATAL: nested sandbox-exec is refused — you are already inside a sandbox." >&2
  echo "       Probes would misreport. Run this from an UNCONFINED terminal (P0.3)." >&2
  exit 3
fi

if [[ -z "$POLICY" ]]; then
  POLICY="$("$HERE/build-policy.sh" "$PWD")"
fi
[[ -f "$POLICY" ]] || { echo "policy not found: $POLICY" >&2; exit 2; }

# --- check registry ---------------------------------------------------------

names=(); exps=(); cmds=(); opts=(); scopes=()

# expect: deny|allow ; opt: required|optional ; scope: sandbox|host
add() { # expect name opt cmd
  scopes+=("sandbox"); exps+=("$1"); names+=("$2"); opts+=("$3"); cmds+=("$4")
}
add_host() { # expect name opt cmd  (evaluated unconfined, no sandbox-exec)
  scopes+=("host"); exps+=("$1"); names+=("$2"); opts+=("$3"); cmds+=("$4")
}

# === DENY: human identity / human credentials ==============================

add deny "keychain-db(read)"     required 'head -c1 "$HOME/Library/Keychains/login.keychain-db"'
add deny "keychain-db(write)"    required 'touch "$HOME/Library/Keychains/.pi-selftest-probe"'
add deny "security:any gh token" required '/usr/bin/security find-generic-password -s gh:github.com -w'
add deny "security:personal"     required '/usr/bin/security find-generic-password -s gh:github.com -a sven1103 -w'
add deny "security:bot"          required '/usr/bin/security find-generic-password -s gh:github.com -a sven1103-agent -w'
add deny "ssh-agent(list)"       required '/usr/bin/ssh-add -l'
# Policy-level: force SSH_AUTH_SOCK back in, so this measures the SBPL deny and
# not merely step-05's env stripping. Fails if the policy re-opens the socket.
add deny "ssh-agent(policy)"     required 'SSH_AUTH_SOCK="'"$AMBIENT_SSH_AUTH_SOCK"'" /usr/bin/ssh-add -l'
add deny "ssh: id_rsa"           required 'head -c1 "$HOME/.ssh/id_rsa"'
add deny "ssh: id_ed25519"       required 'head -c1 "$HOME/.ssh/id_ed25519"'
  # Probe ANY remaining private key, so a renamed key is still covered.
  # The repo is genericized: do not hardcode a personal key filename.
  add deny "ssh: any private key"  required 'for f in "$HOME"/.ssh/id_* "$HOME"/.ssh/*_id_*; do case "$f" in *.pub) continue;; esac; [ -f "$f" ] && head -c1 "$f" && exit 0; done; exit 1' 
add deny "ssh: agent socket"     required 'python3 -c "import socket,os;s=socket.socket(socket.AF_UNIX);s.connect(os.environ[\"SSH_AUTH_SOCK\"])"'
add deny "ssh: agent socket(policy)" required 'SSH_AUTH_SOCK="'"$AMBIENT_SSH_AUTH_SOCK"'" python3 -c "import socket,os;s=socket.socket(socket.AF_UNIX);s.connect(os.environ[\"SSH_AUTH_SOCK\"])"'
add deny "human gh hosts.yml"    required 'cat "$HOME/.config/gh/hosts.yml"'
add deny "zshrc"                 required 'cat "$HOME/.zshrc"'
add deny "env: HF_TOKEN_STRICT"  required '[ -n "${HF_TOKEN_STRICT:-}" ]'
add deny "git-credentials"       required 'cat "$HOME/.git-credentials"'
add deny "netrc"                 required 'cat "$HOME/.netrc"'
add deny "git credential fill"    required 'printf "protocol=https\nhost=github.com\n\n" | GIT_TERMINAL_PROMPT=0 git credential fill >/dev/null'
add deny "policy dir"            required 'ls "$HOME/.config/sandbox-exec"'

# === ALLOW: agent's own capability =========================================

add allow "workdir(read)"        required 'head -c1 "./README.md"'
add allow "workdir(write)"       required 'touch "./.pi-selftest-probe"'
add allow "agent: pi auth.json"  required 'head -c1 "$HOME/.pi/agent/auth.json"'
add allow "agent: ssh key"       required 'head -c1 "$HOME/.agent/ssh/github_login_ed25519"'
add allow "agent: gh config"     optional 'head -c1 "$HOME/.agent/gh/hosts.yml"'
add allow "agent: gh api(own)"   optional 'head -c1 "$HOME/.agent/gh/hosts.yml" >/dev/null && GH_CONFIG_DIR="$HOME/.agent/gh" /opt/homebrew/bin/gh api user --jq .login'
add allow "net: model endpoint"  required "curl -s --max-time 10 -o /dev/null $MODEL_ENDPOINT"
add allow "net: openrouter"      required 'curl -s --max-time 10 -o /dev/null https://openrouter.ai'
add allow "net: mcp.vaadin.com"  required 'curl -s --max-time 10 -o /dev/null https://mcp.vaadin.com'
add allow "net: github https"    required 'git ls-remote https://github.com/eugene1g/agent-safehouse HEAD'

# === WIRING (host scope): the launcher must actually set the agent-scoped env we
# probe with. Evaluated WITHOUT sandbox-exec (the policy denies the policy dir).
# Without these, agent-env probing could measure a target state the launcher
# never produces. A3 = host-scope expectation (allow=present, deny=absent).
add_host allow "wiring: launcher env"  required 'grep -q GIT_CONFIG_GLOBAL "$HOME/.config/sandbox-exec/run-sandboxed.sh" && grep -q GH_CONFIG_DIR "$HOME/.config/sandbox-exec/run-sandboxed.sh" || { echo "launcher not patched: missing GH_CONFIG_DIR/GIT_CONFIG_GLOBAL"; exit 1; }'
add_host allow "wiring: agent gitconfig" required 'test -f "$HOME/.agent/gitconfig" || { echo "No such file or directory: $HOME/.agent/gitconfig"; exit 1; }'
add_host allow "wiring: agent gh token"  required 'test -f "$HOME/.agent/gh/hosts.yml"'

# --- classification ---------------------------------------------------------

classify() { # cmd -> REACHABLE|DENIED|MISSING|FAILED|INCONCLUSIVE
  local cmd="$1" scope="${2:-sandbox}" out rc
  if [[ "$scope" == host ]]; then
    # Host-scope wiring check: run directly, no sandbox-exec.
    out="$(/bin/sh -c "$cmd" 2>&1)"; rc=$?
    if [[ $rc -eq 0 ]]; then echo REACHABLE; else
      local lch; lch="$(printf '%s' "$out" | tr '[:upper:]' '[:lower:]')"
      case "$lch" in
        *"no such file or directory"*) echo MISSING ;;
        *)                              echo FAILED ;;
      esac
    fi
    return
  fi
  # Run with the AGENT session environment, not the ambient shell env.
  # Otherwise checks that depend on the launcher's overrides (GIT_CONFIG_GLOBAL,
  # GIT_CONFIG_SYSTEM, GH_CONFIG_DIR) measure the wrong thing: they would report
  # a LEAK that the real agent session does not actually have.
  # --agent-env=ambient disables this to inspect the raw policy.
  if [[ "${AGENT_ENV_MODE:-agent}" == agent ]]; then
    # Mirror the launcher's Step 5 sanitization: env -i with the same allowlist,
    # so ambient secrets (SSH_AUTH_SOCK, *_TOKEN) are NOT visible. Without this
    # the harness would report LEAKs the real session cannot have.
    out="$(sandbox-exec -f "$POLICY" -- /usr/bin/env -i \
            PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
            HOME="$HOME" USER="${USER:-$(id -un)}" LOGNAME="${LOGNAME:-$(id -un)}" \
            SHELL="${SHELL:-/bin/zsh}" TMPDIR="${TMPDIR:-/tmp}" \
            TERM="${TERM:-xterm-256color}" LANG="${LANG:-en_US.UTF-8}" \
            GH_CONFIG_DIR="$HOME/.agent/gh" \
            GIT_CONFIG_GLOBAL="$HOME/.agent/gitconfig" \
            GIT_CONFIG_SYSTEM=/dev/null \
            /bin/sh -c "$cmd" 2>&1)"; rc=$?
  else
    out="$(sandbox-exec -f "$POLICY" -- /bin/sh -c "$cmd" 2>&1)"; rc=$?
  fi
  if [[ $rc -eq 0 ]]; then echo REACHABLE; return; fi
  # match case-insensitively; sandbox and tooling vary in capitalisation
  local lc; lc="$(printf '%s' "$out" | tr '[:upper:]' '[:lower:]')"
  case "$lc" in
    *"sandbox_apply: operation not permitted"*) echo INCONCLUSIVE ;;
    *"permissionerror"*)                        echo DENIED ;;  # python socket/open probe
    *"operation not permitted"*)                echo DENIED ;;
    *"permission denied"*)                      echo DENIED ;;
    *"not permitted"*)                          echo DENIED ;;
    *"could not read username"*)                echo NO_CREDENTIAL ;;  # git found no helper
    *"terminal prompts disabled"*)              echo NO_CREDENTIAL ;;
    *"no such file or directory"*)              echo MISSING ;;
    *"does not exist"*)                         echo MISSING ;;
    *)                                          echo FAILED ;;
  esac
}

verdict() { # expect state -> ok|LEAK|BROKEN|NOTYET|WARN|FATAL
  local expect="$1" state="$2" opt="${3:-required}"
  case "$state" in
    INCONCLUSIVE) echo FATAL; return ;;
  esac
  if [[ "$expect" == deny ]]; then
    case "$state" in
      REACHABLE) echo LEAK ;;
      *)         echo ok ;;
    esac
  else
    case "$state" in
      REACHABLE)   echo ok ;;
      NO_CREDENTIAL) echo BROKEN ;;  # an ALLOW check that needs a credential got none
      MISSING)   [[ "$opt" == optional ]] && echo NOTYET || echo BROKEN ;;
      DENIED)    [[ "$opt" == optional ]] && echo NOTYET || echo BROKEN ;;
      *)         [[ "$opt" == optional ]] && echo WARN   || echo BROKEN ;;
    esac
  fi
}

# --- run --------------------------------------------------------------------

# List failing checks (LEAK/BROKEN). Built with an accumulating variable rather
# than a `case ... | ...` inside $(...) — bash mis-parses a `|` in that context
# (the earlier version produced "syntax error near unexpected token `newline'").
failing_list() {
  local i out=""
  for i in "${!names[@]}"; do
    case "${verdicts[$i]}" in LEAK|BROKEN) out+="${names[$i]}(${verdicts[$i],,}) " ;; esac
  done
  printf '%s' "${out% }"
}

results=(); states=(); verdicts=()
inconclusive=0; failures=0

for i in "${!names[@]}"; do
  st="$(classify "${cmds[$i]}" "${scopes[$i]}")"
  vd="$(verdict "${exps[$i]}" "$st" "${opts[$i]}")"
  states+=("$st"); verdicts+=("$vd")
  [[ "$vd" == FATAL ]] && inconclusive=1
  case "$vd" in LEAK|BROKEN|FATAL) failures=1 ;; esac
done

# --- output -----------------------------------------------------------------

if (( JSON )); then
  printf '{"policy":%s,"results":[' "$(printf '%s' "$POLICY" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')"
  for i in "${!names[@]}"; do
    sep=""; (( i )) && sep=","
    printf '%s{"name":"%s","expect":"%s","opt":"%s","state":"%s","verdict":"%s"}' \
      "$sep" "${names[$i]}" "${exps[$i]}" "${opts[$i]}" "${states[$i]}" "${verdicts[$i]}"
  done
  printf ']}\n'
  exit "$failures"
fi

if (( inconclusive )); then
  echo "INCONCLUSIVE: nested sandbox refused for at least one probe."
  echo "              Re-run from an UNCONFINED terminal (P0.3)."
  exit 3
fi

echo "policy: $POLICY"
echo

# --- snapshot / diff modes --------------------------------------------------

snapshot_lines() {
  for i in "${!names[@]}"; do
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "${exps[$i]}" "${names[$i]}" "${opts[$i]}" "${states[$i]}" "${verdicts[$i]}"
  done
}

if [[ "$MODE" == record ]]; then
  {
    echo "# pi-sandbox selftest baseline"
    echo "# recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# policy:   $POLICY"
    echo "# columns: expect<TAB>name<TAB>opt<TAB>state<TAB>verdict"
    snapshot_lines
  } > "$SNAPSHOT"
  echo "recorded baseline -> $SNAPSHOT ($(snapshot_lines | wc -l | tr -d ' ') checks)"
  exit 0
fi

if [[ "$MODE" == diff ]]; then
  [[ -f "$SNAPSHOT" ]] || { echo "baseline not found: $SNAPSHOT" >&2; exit 2; }
  changed=0
  while IFS=$'\t' read -r exp name opt st vd; do
    [[ "$exp" == \#* || -z "$exp" ]] && continue
    for i in "${!names[@]}"; do
      if [[ "${names[$i]}" == "$name" ]]; then
        if [[ "${states[$i]}" != "$st" || "${verdicts[$i]}" != "$vd" ]]; then
          printf 'CHANGED  %-26s %s/%s -> %s/%s\n' "$name" "$st" "$vd" "${states[$i]}" "${verdicts[$i]}"
          changed=1
        fi
        break
      fi
    done
  done < "$SNAPSHOT"
  # newly added checks not present in the baseline
  while IFS=$'\t' read -r exp name opt st vd; do
    [[ "$exp" == \#* || -z "$exp" ]] && continue
    awk -F'\t' -v n="$name" '$2==n{f=1} END{exit !f}' "$SNAPSHOT" \
      || { printf 'NEW      %-26s %s/%s\n' "$name" "$st" "$vd"; changed=1; }
  done < <(snapshot_lines)
  (( changed )) || echo "no changes vs $SNAPSHOT"
  # still surface hard failures
  (( failures )) && { echo "FAIL: $(failing_list)"; exit 1; }
  exit 0
fi

print_suite() { # expect, heading
  echo "$2"
  for i in "${!names[@]}"; do
    [[ "${exps[$i]}" == "$1" ]] || continue
    printf '  %-26s %-12s %s\n' "${names[$i]}" "${states[$i]}" "${verdicts[$i]}"
  done
  echo
}

print_suite deny  "DENY — human credentials (must be unreachable)"
print_suite allow "ALLOW — agent's own capability (must keep working)"

if (( failures )); then
  echo "FAIL: $(failing_list)"
  exit 1
fi
echo "PASS: human creds unreachable, agent capability intact"
exit 0
