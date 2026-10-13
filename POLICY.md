# agentcheck: safety policies for multi-agent setups

Write what "safe" means in a small policy language, then check it against a
multi-agent configuration: either the agents on this Mac (`--scan`) or a
configuration file (`--config`). Each policy **passes** when the SAT solver
proves that no attack fits its budget, and the proof is written out. A policy
that **fails** comes with the cheapest attacks and a step-by-step path.

```bash
python3 agentcheck.py check policies/mac.policy --scan --proofs ~/.agentwatch/proofs
python3 agentcheck.py check policies/devbox.policy --config examples/devbox.json
python3 agentcheck.py names --scan        # the names a policy can use
python3 agentcheck.py explain policies/mac.policy --scan
```

The exit code is 0 when every policy passes, 1 when any fails, and 2 when the
policy file or the configuration cannot be read, so a check can gate CI or a
setup script.

## The language

```
attacker controls web                 # untrusted inputs the attacker writes (default: all)

secret deploy_key = ~/keys/deploy.pem # name a new secret location
group cloud = aws, docker             # name a set

policy "Cloud keys never leave, even with one approval mistake"
  never cloud -> internet
  tolerate 0 agents, 1 approval

policy "Cursor never sees the SSH key"
  never ssh -> cursor

policy "Web content never steers Claude Code"
  never attacker -> instructions(claude_code)
  never hijack claude_code
  tolerate 0 agents, any approvals
```

| Statement | Violated when |
|---|---|
| `never DATA -> PLACES` | the data reaches a place. When the place is an agent, the violation is that the agent can read it. |
| `never attacker -> PLACES` | attacker-written content reaches a place. When the place is an agent, the violation is that the agent is taken over. |
| `never hijack AGENTS` | an agent ends up working for the attacker |
| `tolerate N agents, M approvals, K injections` | sets the policy's budget. The policy must still hold when the attacker breaks into N agents, you approve M prompts, and the attacker lands K prompt injections. Defaults: agents 0, approvals 0, injections `any` (unbounded, the old behavior). `any` means no limit; `0 injections` means "holds even if no agent can be fooled" (a purely structural guarantee). |

A policy with several `never` lines is violated if any one of them is. Each
policy needs its own title: `diff` and `watch` compare results by title, so two
policies with one title are an error.

**Names** you can use:
- agent names, resource names, and globs over resource names (`net:*`)
- file paths (`~/.ssh`)
- secret labels, plus their short forms (`ssh` for `ssh_key`)
- groups you define
- the built-ins:
  - `secrets`: every secret label
  - `internet`: every outbound sink
  - `agents`: every agent
  - `settings(AGENT)`: that agent's own configuration files, including a settings
    group it shares (a scan gives every Claude Code project the same `ctl:claude_code`)
  - `instructions(AGENT)`: every file that steers that agent, including shared ones such as `CLAUDE.md`

An unknown name is an error that gives the line number and suggests close
matches. So is a right side that names no place or agent in this configuration
(for example `internet` where nothing leaves the machine): such a statement
could never be violated, and the policy would pass without checking anything.

## How it is checked

Each statement compiles to one or more atoms. There are four kinds: a secret
reaches a place, an agent can read a secret, attacker content reaches a place,
and an agent is taken over. A policy's goal is the disjunction of its atoms.
`sat.py` unrolls the spreading rules into CNF, adds cardinality limits for the
two budgets, and calls CaDiCaL:

- **UNSAT:** the policy passes, and CaDiCaL writes a DRAT proof.
- **SAT:** the model is an attack. The simulator replays it to confirm, and
  produces the readable path.

The tests compare the solver against brute force on random configurations:
`tests/test_sat.py` (240 cases) and `tests/test_policy.py` (156 general goals
plus 8 error messages). There were no mismatches.

## Limits

- Rights in scan mode come from documented defaults wherever a setting cannot
  be read. `agentwatch.py scan` lists every assumption.
- Policies are about reachability under the model, not about what an agent
  will actually decide to do.
- The DRAT proofs have not been checked by an independent tool yet.
