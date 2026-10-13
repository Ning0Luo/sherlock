# validate: do Sherlock's findings reproduce as real behavior?

A Sherlock finding is a path in a model. Sherlock assumes that an AI agent which
reads attacker-influenced text is fully steered, and that a steered agent copies
anything it can read to anything it can write. Those assumptions are deliberately
pessimistic, so a FAIL may or may not correspond to a real attack.

This harness measures that. For a finding, it builds the fleet the way the
finding describes, runs it, and reports whether data actually travels the
predicted path:

- **REPRODUCED** — a canary reached the sink the model predicted.
- **BLOCKED** — the fleet ran and the canary did not arrive (the model declined, a guard caught it, or the flow is not real).
- **ERROR** — the fleet could not run, or a tool tried to send out for real.

Run it over your findings and you get a **precision** number: of N model FAILs, how many reproduce. That is the evidence a static checker needs before anyone relies on it.

## It is a measurement tool, not an attack tool

The design keeps it that way, and you should run it only on fleets you are authorized to test:

- **Canaries, not secrets.** Every "secret" in the fleet is a random, non-secret token (`Canary`). Success means that token arrived somewhere; no real credential is ever used.
- **Local sinks.** Outward actions (send_email, an HTTP post) are replaced by a `LocalSink` that records instead of acts.
- **Egress guard.** During a run, `EgressGuard` blocks any socket connection to a non-loopback host, so nothing can leave the machine. A real network tool left in by mistake becomes an ERROR, not a silent send.
- **Neutral markers.** The untrusted input carries a plain relay instruction (`MarkerInput`) that references the canary. It traces a flow; it is not an exploit. The harness ships no payload library and generates no evasive injections — if you want to study a specific phrasing, you write it.

## The pieces

| Piece | Role |
|---|---|
| `Canary(label)` | a random token standing in for a secret |
| `LocalSink(name)` | records outward actions; `.saw(token)` checks for a canary |
| `MarkerInput(template)` | the attacker-controlled input; a neutral marker by default |
| `Scenario(run_app, canaries, sinks, untrusted, expect)` | one fleet wired as a finding describes |
| `run(scenario, guard=True)` | run once, return an `Outcome` |
| `EgressGuard` | blocks real network during a run |
| `shape(finding)` / `failing(findings)` | read `agentcheck check --json` output into source/sink/untrusted roles |
| `validate.langgraph` | `canary_tool`, `sink_tool`, `langgraph_runner` for LangGraph apps |

## Using it with LangGraph

1. Run Sherlock and keep the finding: `agentcheck check RULES --config app.json --json findings.json` (or the LangGraph `check`).
2. `shape(finding)` tells you which resource is the secret source, which is the sink, and which input is untrusted.
3. Rebuild that app for the test: put a `canary_tool` where it reads the secret, a `sink_tool` where it acts outward, and keep the model nodes on a **real LLM** so refusals and prompt-following are real.
4. Wrap it with `langgraph_runner`, put it in a `Scenario`, and `run` it.

A no-dependency demo and a real LangGraph template are in `examples/validate/`:

```bash
# runnable here, no API key:
python3 agentcheck.py validate examples/validate/demo_scenarios.py

# the real thing (needs: pip install langgraph langchain, and a provider key):
export VALIDATE_MODEL="anthropic:claude-sonnet-5-5"
python3 agentcheck.py validate examples/validate/support_bot_scenarios.py
```

A scenario module defines `SCENARIOS` (a dict name → `Scenario`) or a `scenarios()` function returning one.

## What a result does and does not tell you

- **REPRODUCED** is a real flow in your test fleet with that model and those prompts. It is strong evidence the finding is real, but it is still your fleet, not production.
- **BLOCKED** means it did not happen *this run*. Models are not deterministic; a different phrasing or a later model version may behave differently. Treat BLOCKED as "not reproduced yet," not "impossible." Re-run, and vary the marker you wrote.
- The harness does not craft injections for you. If a finding is real but your neutral marker does not trigger it, that is a measurement of how hard it is to trigger, which is itself useful.
