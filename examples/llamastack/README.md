# Checking a Llama Stack deployment

[Llama Stack](https://github.com/meta-llama/llama-stack) runs agents behind one
API. A deployment registers tool groups (`builtin::websearch`, `builtin::rag`,
`builtin::code_interpreter`, and remote ones served over MCP), shields (Llama
Guard, Prompt Guard), and vector DBs; each agent is an `AgentConfig` with the
tool groups it may call and its `input_shields` / `output_shields`. Llama
Stack's safety check runs **one** shield on **one** turn.

Sherlock checks **the agents together**. Two agents can each stay inside their
own config and still move a secret, or attacker content, through a vector DB or
an MCP endpoint they share.

```bash
python3 agentcheck.py check examples/llamastack/deployment.policy --llamastack examples/llamastack/deployment.yaml
```

## The deployment file

`deployment.yaml` holds two agents:

- **assistant** — an LLM with a RAG tool bound to a curated customer store
  (`pii_store`, holding the label `customer_pii`) and a drafts store
  (`reports`). It can read the PII but has no way to reach the outside.
- **publisher** — a fixed, non-LLM step (`deterministic: true`) that reads the
  drafts and posts them to the CRM over MCP. It is the only agent that can reach
  the outside, and its MCP endpoint carries the workspace's CRM credential.

Fields marked real Llama Stack config vs. Sherlock annotations are documented in
the module docstring (`llamastack.py`). In short: `toolgroups`, `shields`,
`vector_dbs`, `input_shields` / `output_shields`, `mcp_endpoint` and
`enable_session_persistence` are Llama Stack; `label`, `untrusted`,
`requires_auth`, `internal_hosts`, `trusted_users` and `deterministic` are
annotations for what the config alone cannot say.

## How tool groups become rights

| Tool group | Reach |
|---|---|
| `builtin::websearch`, browser, wolfram | reads the web (untrusted); its queries leave the machine (a sink). |
| `builtin::rag` / memory | reads and writes the vector DBs it is bound to; ingested documents are untrusted. |
| `builtin::code_interpreter` | broad: runs code, so reaches the web, the local filesystem and the network. |
| an MCP tool group (`mcp::...`) | reaches its endpoint host, and, since its tools are discovered at run time, is assumed able to do anything locally too. A credentialed endpoint adds `acct:<host>`. |
| anything unrecognized | assumed able to do anything (noted). |

A vector DB is `vdb:<id>`; it is attacker-ingestible unless it is a curated
secret store. The end-user's turn is `user_turn`, attacker-controllable unless
`trusted_users: true`. `enable_session_persistence` gives the agent a
`session:<agent>` resource it obeys across turns.

## Result on the example

| Rule | Result | Cheapest attack |
|---|---|---|
| Customer PII never leaves the deployment | FAIL | 0 hacked, 0 approvals: assistant drafts the PII into `reports`, the publisher posts `reports` to the CRM |
| Web content never acts through the CRM account | FAIL | 0 hacked, 0 approvals |
| The publisher is never steered | PASS, with a proof | needs 1 hacked agent (a fixed step is not steerable by what it reads) |

## What the shield is worth

The base check does **not** trust the publisher's Llama Guard output shield —
that is the sound guarantee. `shield_whatif.whatif` re-runs the analysis under
the explicit, conditional assumption that the shield holds:

```bash
python3 shield_whatif.py examples/llamastack/deployment.yaml
```

```
  Customer PII never leaves the deployment
      WITHOUT: [0 hacked + 0 approvals]   WITH: [1 hacked + 0 approvals]   -> shield worth it
  web content never acts through your crm.example.com account
      WITHOUT: [0 hacked + 0 approvals]   WITH: [1 hacked + 0 approvals]   -> shield worth it
```

WITHOUT is the guarantee (no shield believed); WITH only holds if the shield
does. Here an effective shield on the publisher — the one agent at the boundary
— would raise both attacks from free to one hacked agent. A shield is never
silently trusted: you see both numbers and decide.
