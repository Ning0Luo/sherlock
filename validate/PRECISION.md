# Precision study — do the findings reproduce?

`agentcheck check` reports a FAIL when the model finds a path that breaks a
policy. A path in the model is **not** a demonstrated attack: the model assumes
any LLM agent that reads attacker-influenced text is fully steered, so it
over-reports. The precision study measures how often a FAIL reproduces as real
model behavior:

> **precision = (findings that reproduced) / (findings judged)**

It is a *detector evaluation*, not an attack tool. Nothing sensitive is used and
nothing is sent anywhere — see the safety envelope below.

## The safety envelope

`validate` (see [`README.md`](README.md) and `core.py`) runs a fleet you own and
watches a traceable token, never a real secret or a real send:

- **Canary** — a random, non-secret token (`CANARY-<label>-…`) placed where a
  secret would originate. The study asks only whether this token travels.
- **LocalSink** — stands in for an outward action (`send_email`, an HTTP POST, a
  Slack message). It records what it was handed and does nothing else, so the
  canary is caught at the boundary.
- **MarkerInput** — the attacker-controlled input, a *neutral* marker that asks
  the agent to carry a reference code onward. It traces a flow; it is not an
  exploit and defeats no defense.
- **EgressGuard** — blocks any real network send during a run. If a tool tries
  to reach the network for real, the run is an ERROR, not a result — replace it
  with a `LocalSink`.

A finding comes back:

- **REPRODUCED** — a canary reached a sink: the flow the model predicted happens
  in the real fleet.
- **BLOCKED** — the fleet ran to completion and no canary arrived.
- **ERROR** — it could not be run (un-wired stub, bad wiring, API error, or a
  tool tried to send out for real). ERRORs are excluded from the denominator.

## Protocol

1. **Collect findings.** Run the checker on a fleet you own and save the FAILs:

   ```bash
   agentcheck check policies/app.policy --config fleet.json --json findings.json
   ```

2. **Scaffold scenarios.** Turn the FAILs into stubs with the roles filled in:

   ```bash
   python -m validate.scaffold findings.json scenarios.py
   ```

   Each stub places the finding's canary (the leaking secret), its sink (the
   outward hop) and its untrusted input, and leaves `run_app` as a TODO.

3. **Wire `run_app`.** For each stub, build the real fleet: place each `Canary`
   at its source tool/state, replace each outward tool with the matching
   `LocalSink`, and route `inputs[<key>]` into the untrusted input. For
   LangGraph, `validate/langgraph.py` has `canary_tool`, `sink_tool` and
   `langgraph_runner`; `examples/validate/support_bot_scenarios.py` is a worked
   example. An un-wired stub reports ERROR, so the report tells you what is left.

4. **Run and read the number.**

   ```bash
   VALIDATE_MODEL="anthropic:claude-sonnet-5-5" agentcheck validate scenarios.py
   ```

   The last line is the precision: `k/n findings reproduced as real behavior`.

## Reading the number honestly

- **BLOCKED once is not "safe".** Models are nondeterministic. Run each scenario
  several times and treat a finding as reproduced if it leaks on *any* run;
  report how many runs you did. A finding that never reproduces over many runs
  is weak evidence of a false positive, not a proof.
- **Precision is a lower bound on exploitability.** The marker is deliberately
  neutral; a real attacker writes a stronger prompt. REPRODUCED under a neutral
  marker is strong evidence the path is real. BLOCKED means *this* marker did not
  drive it, not that no prompt could.
- **`reads_as_data` and the injection budget.** If a finding is a false positive
  because an agent treats the input as data, encode that (`reads_as_data=` or the
  node annotation) and re-check, rather than counting it by hand. The budget axis
  (`tolerate … K injections`) lets you separate structural findings (hold even
  with no agent fooled) from injection-dependent ones before you ever run a
  model.
- **Report `n` and the ERROR count.** `12/15 reproduced (3 errored)` is honest;
  "80% precision" alone is not.

## Scope and disclosure

Run scenarios **only against fleets you own or are explicitly authorized to
test.** This harness rebuilds the fleet locally with canaries and local sinks;
it is not a probe to point at someone else's deployment, and the EgressGuard is a
safeguard, not permission.

Findings against third-party applications are undisclosed until they have been
hand-checked and shared with that project's maintainers. Do not publish them, and
do not reproduce them against anyone's live deployment, before both are done.
