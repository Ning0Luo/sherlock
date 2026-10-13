# Meta's Agents Rule of Two

```bash
python3 agentcheck.py ruleoftwo --config examples/ruleoftwo/inbox.json --why
```

Meta's rule: within a session, an AI agent should hold at most two of

| | Meta | Sherlock |
|---|---|---|
| A | processes untrustworthy input | reads an untrusted resource |
| B | reaches sensitive systems or private data | reads a resource holding a secret, or reads/writes a sensitive one (`protected`, or named by an integrity policy) |
| C | changes state or communicates externally | writes a sink or a sensitive resource |

If an agent needs all three, a person should approve its actions.

Changing a sensitive system counts as **both B and C**: it is access to a sensitive system and a state change, as Meta words it. This holds whether the agent writes the system itself or other agents carry its writes there. Without this rule, an agent that reads the web and deploys to production would show only `A . C`, the combination the rule allows.

## Two views per agent

- **own**: the agent's rights alone, the way a per-agent review sees them.
- **fleet**: the same letters with the other agents in the picture, nobody broken into, agentic model. Attacker text counts as A wherever it can reach. A secret another agent copies in counts as B. A write that other agents carry to a sink counts as C, and a write they carry into a sensitive system counts as B and C.

A lowercase letter means the property needs an approved prompt.

## Fleet verdict

The letters are only a summary. The verdict comes from the SAT solver, which gets two goals with 0 agents broken into and 0 approvals:

- **trifecta**: attacker text makes a secret leave
- **sensitive**: attacker text changes a sensitive resource

| Result | Meaning |
|---|---|
| FAIL | it happens with nobody's help; the attack path is printed |
| FAIL, COMPOSITION | no agent on the path holds A, B and C on its own rights. Each agent passes a per-agent Rule-of-Two review, and the fleet still breaks the rule. |
| PASS, only if you approve N prompts | the rule's person-in-the-loop case |
| PASS | cannot happen even with every approval (`--proofs DIR` keeps the DRAT proof) |

The exit code is 1 if any goal fails.

## `inbox.json`

`triage` reads the inbox (A only). `analyst` reads its notes and the CRM export (B only). `sender` sends email and updates billing (B and C). Each one is within the rule. Together, inbox text steers triage, triage's notes steer the analyst, the analyst copies customer data into a draft, and the sender emails it out. Both goals fail as compositions. The non-AI `backup` job is listed but does not count toward the rule.

## Limits

- The output covers the model only: the rights the scan or the configuration describes. Prompts, guard models (PromptGuard, AlignmentCheck) and model behavior are not considered.
- Meta's C also covers local state changes. Here C is limited to sinks and sensitive resources; otherwise any agent that writes a file would have C.
