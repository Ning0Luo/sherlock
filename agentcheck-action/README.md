# Sherlock agentcheck — GitHub Action

Gate your CI on multi-agent collusion. On every pull request, the action checks
your agent system against a Sherlock policy and **fails only when a change
introduces an attack** your budget does not tolerate.

- Works on a LangGraph graph, an AWS Bedrock export, or a Llama Stack `run.yaml`.
- `diff` mode (set `base`) reports *new* attacks only, so a pre-existing finding
  does not block unrelated PRs.
- Runs on `ubuntu-latest` (it installs CaDiCaL with `apt`).

## Quick start — any JSON config

```yaml
# .github/workflows/agentcheck.yml
name: agentcheck
on: [pull_request]
jobs:
  collusion:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ning0Luo/sherlock/agentcheck-action@main
        with:
          policy: policies/app.policy
          config: build/fleet.json
```

The step fails (red check) if any policy fails within its budget. The report is
written to the PR's **step summary**.

## PR gate — fail only on new attacks

Check the config at the PR base against the working tree and alarm only on
attacks the change *introduces*:

```yaml
jobs:
  collusion:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # the action needs the base ref
      - uses: Ning0Luo/sherlock/agentcheck-action@main
        with:
          policy: policies/app.policy
          config: fleet.json        # committed at the repo root
          base: ${{ github.event.pull_request.base.sha }}
```

`diff` compares the config **as committed at `base`** to the one in the working
tree, so the config file must be committed (`git show base:fleet.json` has to
resolve) and the checkout must include the base ref (`fetch-depth: 0`). If the
file is new at `base`, or you point at a generated path that isn't committed,
the action notes it and runs a full check. For a LangGraph graph, commit a
`fleet.json` snapshot and regenerate it in CI before this step — see
[`../examples/ci`](../examples/ci/README.md).

## LangGraph

The action reads a JSON config, not your Python. Generate it from your compiled
graph in a step before the action, with the bundled exporter:

```yaml
jobs:
  collusion:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.x' }
      - name: Export the graph
        run: |
          pip install -e .                       # your app + langgraph
          pip install "git+https://github.com/Ning0Luo/sherlock.git@main"
          python - <<'PY'
          import json
          from integrations.langgraph import export
          from my_app import app                 # your compiled StateGraph
          json.dump(export(app), open("fleet.json", "w"), indent=2)
          PY
      - uses: Ning0Luo/sherlock/agentcheck-action@main
        with:
          policy: policies/app.policy
          config: fleet.json
```

`export(app)` accepts the same keyword arguments as `integrations.langgraph`
(`secrets=`, `writes=`, `approval_tools=`, `reads_as_data=`, …) — see
[`../examples/langgraph/README.md`](../examples/langgraph/README.md). To rule
out a prompt-injection false positive for an input an agent treats as data, pass
`reads_as_data=` (or annotate the node) and keep an injection budget in the
policy.

## AWS Bedrock / Llama Stack

```yaml
      - uses: Ning0Luo/sherlock/agentcheck-action@main
        with:
          policy: policies/bedrock.policy
          bedrock: exports/bedrock          # a directory of exported JSON
```

```yaml
      - uses: Ning0Luo/sherlock/agentcheck-action@main
        with:
          policy: policies/stack.policy
          llamastack: run.yaml
```

`diff` mode is not available for these (a directory / YAML has no single-file
base); the action runs a full check and notes it.

## Inputs

| input | required | default | what it does |
|---|---|---|---|
| `policy` | yes | | the Sherlock policy file to enforce |
| `config` | one of | | a sherlock-scan JSON config |
| `bedrock` | one of | | a directory of exported Bedrock JSON |
| `llamastack` | one of | | a Llama Stack `run.yaml` |
| `base` | no | | a git ref; enables `diff` mode (new attacks only) |
| `guard-access` | no | | `true` → `--guard-access` (set aside access-edit attacks) |
| `show-injections` | no | | `true` → `--injections` (report the injection axis) |
| `fast` | no | | `true` → `--fast` (skip the attack search on a PASS) |
| `ref` | no | `main` | the `Ning0Luo/sherlock` ref to install |
| `python-version` | no | `3.x` | Python to set up |
| `working-directory` | no | `.` | where to resolve `policy` / source paths |

Output `result` is `pass` or `fail`.

The injection *budget* lives in the policy, not an input:
`tolerate 0 agents, 0 approvals, 1 injection`. Pin `ref` to a tag or SHA for a
reproducible check.
