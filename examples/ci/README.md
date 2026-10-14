# CI example — gate pull requests on collusion

Drop [`agentcheck.yml`](agentcheck.yml) into `.github/workflows/` to run
`agentcheck` on every pull request. It uses the bundled action,
[`../../agentcheck-action`](../../agentcheck-action/README.md), which installs
the tool and CaDiCaL and fails the check when a change introduces an attack
within your budget.

Files here:

- `agentcheck.yml` — a pull-request workflow. You commit `fleet.json` (a
  reviewable snapshot of the graph's rights); CI regenerates it from the live
  graph and runs the action in `diff` mode, so only *new* attacks block the PR.
  Drop `base:` to gate on all attacks instead.
- `export_app.py` — the one helper the workflow calls: `module:attribute` of a
  compiled LangGraph app → a sherlock-scan JSON config. The same JSON pastes
  into <https://sherlocksec.org>.

For AWS Bedrock or Llama Stack, skip the export step and point the action at
`bedrock:` (a directory of exported JSON) or `llamastack:` (a `run.yaml`). See
the [action README](../../agentcheck-action/README.md) for every input.
