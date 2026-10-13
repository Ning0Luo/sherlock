# agentcheck

Checks whether the AI agents on a computer, alone or together, can violate
safety policies you write. Policies compile to SAT and are solved with CaDiCaL.
A passing policy comes with a proof you can check independently. A failing
policy comes with the cheapest attack, step by step.

## Install

```bash
./install.sh            # installs into ~/.local; PREFIX=... to change
```

The installer:
- needs Python 3.9 or newer
- installs the CaDiCaL solver with Homebrew or apt if it is missing
- creates three commands: `agentcheck`, `agentwatch` and `drat-check`
- runs a self-test at the end

Remove everything with `./uninstall.sh`.

## Use

```bash
agentcheck names --scan                              # agents, secrets and names on this Mac
agentcheck check policies/mac.policy --scan          # check policies against this Mac
agentcheck collude policies/mac.policy --scan        # groups of agents that break a policy together
agentcheck check policies/devbox.policy --config examples/devbox.json   # any described setup
agentcheck formula policies/mac.policy out.cnf --scan  # write the SAT formula
drat-check out.cnf out.drat                          # check a solver proof independently
agentcheck ruleoftwo --scan                          # Meta's Agents Rule of Two, per agent and fleet
agentcheck conditions policies/mac.policy --scan     # what the agents it could not read must not do
agentcheck check POLICY --bedrock DIR                 # AWS Bedrock Agents (exported JSON)
agentcheck check POLICY --llamastack run.yaml         # Meta Llama Stack deployment
agentcheck validate SCENARIOS.py                     # do findings reproduce as real behavior?
agentwatch scan                                      # rights of every agent on this Mac
```

See `POLICY.md` for the policy language, and `agentwatch/README.md` for how
agent rights are read. Scanning reads only the structure of agent
configuration files (rules, modes, plugin names), never secret values, and
sends nothing off the machine.

## NVIDIA OpenShell sandboxes

`--openshell FLEET` reads a fleet of [OpenShell](https://github.com/NVIDIA/OpenShell)
sandbox policies, one per agent, and checks them together. OpenShell's own prover
checks each policy against a boundary; Sherlock finds attacks that pass through
several sandboxes. See `examples/openshell/README.md`.

```bash
python3 agentcheck.py check examples/openshell/fleet.policy --openshell examples/openshell/fleet.yaml
```

## Meta's Agents Rule of Two

`agentcheck ruleoftwo` (with `--scan`, `--config` or `--openshell`) checks Meta's
rule that an AI agent should hold at most two of [A] untrusted input,
[B] secrets or sensitive systems, [C] state changes or outside contact.
Each agent gets its letters twice: from its own rights, and inside the fleet
(where attacker text, secrets and writes travel through other agents). The
solver then checks the fleet, with nobody broken into and no approvals, and
flags **composition** failures: every agent follows the rule, the fleet does
not. See `examples/ruleoftwo/README.md`.

## Rights the scan could not confirm

`agentcheck conditions` treats each right the scan could not confirm as an open
question. Those are the rights of an agent whose settings could not be read,
and rights that come only from an assumption, such as an unrecognized MCP
server. Each policy then gets one of three results: FAIL (broken even without
those rights), PASS (holds even with all of them, with a proof), or DEPENDS. A
DEPENDS result lists the exact minimal sets of rights that allow an attack, and
the smallest set to rule out, with a proof that ruling it out is enough. See
`examples/conditions/README.md`.

## Validating findings

A FAIL is a path in the model, not a demonstrated attack. `agentcheck validate`
checks whether a finding reproduces when the agents actually run, on a test
fleet you own: secrets become canary tokens, sinks become local collectors, an
egress guard blocks any real send, and the untrusted input carries a neutral
marker. Each finding comes back REPRODUCED, BLOCKED or ERROR, giving a precision
number over a batch. See `validate/README.md` and `examples/validate/`.

## Prompt injection as a budget

By default any LLM agent that reads attacker-influenced data is assumed fully
steered, which over-reports. You can now reason about it precisely:

- **Count it.** A policy's budget has a third axis: `tolerate 0 agents, 0 approvals, K injections`. `0 injections` asks "does this hold even if no agent can be fooled?" — a purely structural guarantee. `--injections` on `check` lists the cheapest attack as `(agents hacked, approvals, injections)`, so you see how much it leans on injection.
- **Rule it out per input.** Mark an input an agent consumes as data, not instructions (`reads_as_data`), and reading it no longer steers the agent. Sound because you assert it; in LangGraph, `metadata={"sherlock": {"reads_as_data": ["messages"]}}`.

`## Access settings and configuration changes

Some agents can edit access settings: permission rules, MCP configs, approval
lists. `--guard-access` sets aside attacks that need such an edit and marks
those policies GUARDED. `agentcheck diff` (before a change) and
`agentcheck watch` (after one) re-check the new configuration and raise an
ALARM only when the change brings an attack. See `examples/access/README.md`.

## What Sherlock can read

- **This Mac** (`web/agentcheck_scan.py`, which visitors run from sherlocksec.org):
  - It finds about 27 agents and reads the approval settings of 15: Claude Code (per project, with saved approvals), Codex, Copilot (VS Code and CLI), Gemini CLI, Cline, Aider, Continue, OpenCode, Goose, Zed, Kiro, Amazon Q, Devin, and their MCP servers.
  - Anything it cannot read is modeled as unrestricted. Each scan reports its coverage.
- **LangGraph apps** (`integrations/langgraph.py`): see below.
- **NVIDIA OpenShell sandbox fleets** (`openshell.py`).
- **Any setup written as JSON** (`--config`).

## What a result means

- **FAIL** comes with the cheapest attack, as (agents hacked, approvals clicked). For example, (0, 0) means text the agents read is enough. It is a path in the model, not a demonstrated exploit.
- **PASS** comes with evidence you can check without trusting Sherlock: a DRAT proof checked by `drat_check.py` on the command line (the formula it refutes is kept next to it as `<proof>.cnf`), or a certificate checked by `web/verify_cert.py` in the browser. A PASS covers only what the scan or the annotations describe.
- **Rules can name the attacker**: `attacker controls web` or `attacker controls state:messages`.
- **Agents can be marked `trusted`** (never hacked or steered) or given `strips` (their output never carries attacker text or a given secret).

## Tests

| What | Suite | Result |
|---|---|---|
| SAT vs exhaustive search | `test_sat` 240, `test_policy` 60, `test_openshell` 51, `test_langgraph` 54, `test_trust` 240, `test_ruleoftwo` 236, `test_access` 224, `test_synth` 542, `test_bedrock` 85, `test_strands` 120, `test_llamastack` 234, `test_injection` | no mismatches |
| Web engine vs SAT | demo variants and trust cases | agree |
| Certificates | | 647 verified; tampered and forged ones are rejected |
| Settings readers | `test_parsers` | 29 checks |

Benchmarks: `bench/LANGGRAPH_BENCH.md` (patterns and scaling) and `bench/realworld/REPORT.md` (26 official LangChain apps; internal, not yet disclosed).

## Platforms

Every reader builds the same model, so `check`, `ruleoftwo`, `conditions`, `diff`
and `validate` work on all of them:

- **LangGraph** (`integrations/langgraph.py`): a compiled graph, read without running it.
- **AWS Bedrock Agents** (`bedrock.py`, `--bedrock DIR`): exported JSON — agents and
  multi-agent collaboration, action groups (with/without `requireConfirmation`),
  knowledge bases, memory. Needs no AWS credentials. See `examples/bedrock/`.
- **AWS Strands Agents** (`integrations/strands.py`): a constructed Agent / Swarm / Graph,
  used like the LangGraph integration. See `examples/strands/`.
- **Meta Llama Stack** (`llamastack.py`, `--llamastack run.yaml`): agents, tool groups,
  MCP endpoints and shields, plus a **LlamaFirewall what-if** (`shield_whatif.py`) that
  shows how much each input/output shield is worth. See `examples/llamastack/`.
- **NVIDIA OpenShell** (`openshell.py`), the **Mac scan**, and any **JSON config**.

## LangGraph apps

`integrations/langgraph.py` reads a compiled LangGraph graph (nodes, ToolNodes,
shared state, `input_schema`, `interrupt_before`) and checks rules against it.
See `examples/langgraph/README.md`.

## Core model (`collusion.py`)

The original static t-collusion checker, still usable on its own:
`python3 collusion.py examples/devbox.json` compares the traditional and agentic
models and lists every minimal violating coalition with a witness chain.

- `resources`: `labels` (secrets held), `untrusted` (attacker-writable),
  `sink` (leaves the machine), `protected` (integrity-critical), `controls`
  (agents that take instructions from it: CLAUDE.md, settings.json, MCP config,
  memory files).
- `agents`: `read`/`write` fnmatch patterns, `injectable` (LLM = true,
  deterministic tool = false), `flows` (src→dst relays done even when honest),
  `ask` (rights behind named approval gates).
- **Traditional** mode: agents are corrupted only by the coalition and by
  attacker-written control files. **Agentic** mode adds: any injectable agent
  that reads attacker-influenced data.

### Limitations

- Honest agents leak only along declared `flows`; accidental LLM leaks (e.g.
  quoting a secret in a summary) are not modeled unless declared.
- Labels are copied, never declassified; "uses the key without revealing it"
  (a signer) is modeled by leaving the label out of `flows`.
- No threshold gates (k-of-n approval).
- Permissions are static within one check. Edits to access settings are
  handled by checking each change (`--guard-access`, `diff`, `watch`), not
  inside the model; agents spawning sub-agents remain future work.
- Covert, timing and steganographic channels exist only if listed as resources.
- Places in scan mode come from a fixed list (all projects are one `proj:src`),
  which can over- or under-approximate real sharing between folders.
