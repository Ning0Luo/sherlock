# Checking a LangGraph app

```python
from integrations.langgraph import check
print(check(app, rules, tools=..., secrets=..., deterministic=[...], writes={...}))
```

Sherlock reads a compiled LangGraph graph without running it or calling any model:

| LangGraph | Sherlock |
|---|---|
| node | agent; an AI model unless listed in `deterministic` |
| subgraph node (e.g. a ReAct agent) | one agent with the tools of its ToolNodes |
| ToolNode reached from a node | that node's rights (tool catalog; unknown tools: anything) |
| `interrupt_before` / `interrupt_after` on a ToolNode | an approval |
| state key | resource `state:KEY` |
| node `input_schema` | the keys the node reads (default: all) |
| `writes={node: [keys]}` | the keys the node writes (default: all) |
| what a node does | even an honest node passes what it reads to what it writes |

## What is automatic, and how you tell Sherlock the rest

Read from the compiled app (`app.builder` and the app itself), with nothing for you to write:

- nodes, edges, branches, subgraphs, ToolNodes and their tools
- `input_schema` (what each node reads) and `interrupt_before` / `interrupt_after` (approvals)
- **the app's input keys** (its input schema, or all state keys): set by whoever calls the app, so they count as attacker-written. Pass `untrusted_inputs=[]` if only trusted people call it.
- **the long-term `Store`**: any node that takes `store` or `runtime`, and any tool with an `InjectedStore` / `ToolRuntime` argument, reads and writes `memory:store`, which persists across runs
- standard tools by name (search, fetch, email, Slack, shell, Python, files, memory)

Three places to declare the rest, so it lives next to the code it describes:

```python
# 1. on the tool
lookup_customer.metadata = {"sherlock": {"read": ["data:crm"]}}
# 2. on the node
g.add_node("router", route, metadata={"sherlock": {"trusted": True, "strips": ["attacker"]}})
# 3. or when you check
check(app, rules, secrets={"data:crm": "customer_pii"}, deterministic=["router"],
      writes={"account": ["account_summary"]}, approval_tools=["send_email"])
```

Rules can say who the attacker is: `attacker controls web` (web pages only) or
`attacker controls state:messages` (the people who message the app).

`export(app, ...)` returns the JSON the web page reads, so you can paste it at
https://sherlocksec.org and get certificates for the rules that pass.

## The example: `support_bot.py`

A support app with a web researcher, an account agent that reads the CRM, a
writer and an email tool.

| Rule | Naive app | Hardened app |
|---|---|---|
| Customer data never leaves the app | FAIL (0 hacked, 0 approvals) | PASS; needs 1 approval |
| …even if I approve one email | FAIL | FAIL (0 hacked, 1 approval) |
| Web content never steers the account agent | FAIL | PASS; needs 1 hacked agent |
| A customer's message never steers the account agent | FAIL | FAIL: the router copies the message into `customer_id` |

This is an example we built, not a real app.

The live demo on https://sherlocksec.org toggles three fixes on this bot and recomputes the results in the browser:
- each node reads only its own keys
- email needs approval
- the customer ID comes from the login session

All three are needed before the last rule passes. The demo's data is `web/demo/support_bot_variants.json`, exported from the LangGraph code with `export(app)`. The browser engine's answers match the SAT checker on all 8 combinations.

The naive app is how most LangGraph apps are written: every node shares
`messages`, so web text the researcher reads reaches the account agent, and the
email tool runs without asking. The hardened app gives each node an
`input_schema` with only the keys it needs and adds `interrupt_before=["email"]`.
Even then, approving an email that contains customer data sends it out. So the
reviewer of that email is the last line of defense, and Sherlock tells you so.

## Trusted nodes and sanitizers

Mark what you have reviewed, either as arguments or on the node itself:

```python
g.add_node("router", route, metadata={"sherlock": {"trusted": True, "strips": ["attacker", "customer_pii"]}})
check(app, rules, trusted=["router"], strips={"router": ["attacker", "customer_pii"]})
```

- `trusted`: the attacker can neither break into the node nor steer it with what it reads. Use it for reviewed code or a human step.
- `strips`: what the node's output never carries. `"attacker"` means no attacker text gets through (for example, a router that returns one of a fixed set of routes). A secret's label means that secret is removed (a redaction step).

A trusted node that strips nothing still passes data along. In the hierarchical-teams benchmark, marking the top router trusted and stripping `attacker` and `customer_pii` turns "PII never leaves" from a 0-cost attack into one that needs your approval.
