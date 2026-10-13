# Checking NVIDIA OpenShell sandboxes together

[OpenShell](https://github.com/NVIDIA/OpenShell) gives each agent sandbox a
policy: the paths it can read or write, and the network endpoints each binary
can reach, down to HTTP methods and MCP tools. Its prover checks **one**
policy against a boundary.

Sherlock checks **the sandboxes together**. Two sandboxes can each stay within
their boundaries and still leak through a shared volume, or through a website
one writes and the other reads.

```bash
python3 agentcheck.py check examples/openshell/fleet.policy --openshell examples/openshell/fleet.yaml
```

## The fleet file

The fleet file lists the sandboxes and adds what their policies cannot say.
See `fleet.yaml`:

| Key | Meaning |
|---|---|
| `sandboxes.NAME.policy` | The OpenShell policy file for that sandbox. |
| `sandboxes.NAME.ai` | `false` for a fixed job (not steerable by what it reads). Default `true`. |
| `sandboxes.NAME.relays` | Data a fixed job copies as its normal work, as `[from, to]` pairs (paths or hosts). |
| `sandboxes.NAME.proposals` | Pending policy-advisor proposals. Each is one approval. |
| `sandboxes.NAME.workdir` | Working directory used by `include_workdir` (default `/sandbox`). |
| `shared` | Storage mounted in several sandboxes: `{name, mounts: {sandbox: path}}`. |
| `secrets` | Files holding secrets: `{sandbox, path, label}`. |
| `internal_hosts` | Hosts that the attacker cannot write to and that do not count as leaving. |

## How policies become rights

- **Sandboxes.** Each sandbox is one agent. Its binaries are not told apart: an agent that can run one allowed binary is assumed to run the others.
- **Paths.** A path a sandbox can read or write reaches every path inside it or containing it, in its own filesystem or in shared storage mounted there.
- **External hosts.** An external host is written by the attacker, since anyone can post to a public site. It is also a way out: even a GET can carry data in its URL. Two sandboxes that reach the same host are connected through it.
- **Internal hosts.** A sandbox changes an internal host only through write-capable access: a non-GET method, a GraphQL mutation, an MCP `tools/call`, raw TCP, an uninspected endpoint, or `enforcement: audit`, which logs but does not block.
- **Credentialed endpoints.** An endpoint that carries provider credentials adds `acct:HOST`. Write access there acts as you. The credentials themselves stay in the proxy, so the agent cannot read them.
- **Landlock `best_effort`.** It is reported as a note, not modeled.

## Result on the example

| Rule | Result | Cheapest attack |
|---|---|---|
| The coder's SSH key never leaves the fleet | FAIL | 0 hacked, 0 approvals |
| Web content never ships to production | FAIL | 0 hacked, 0 approvals: researcher → shared workspace → deploy job → internal API |
| Web content never acts through your GitHub account | FAIL | 0 hacked, 0 approvals |
| The researcher never sees the SSH key | FAIL | 0 hacked, 0 approvals |
| The deploy job is never steered | PASS, with a verified proof | needs 1 hacked agent |

The deploy job itself cannot be steered. Web content still reaches production *through* it, because the researcher, whose network access is read-only, writes to the workspace that the deploy job ships.
