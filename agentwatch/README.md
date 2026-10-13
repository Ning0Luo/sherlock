# agentwatch

Monitors the rights of every AI agent on this Mac and reports how many
compromised agents it takes to break each policy. Built on `../collusion.py`.

## Parts

| Part | What it does |
|---|---|
| `agentwatch.py scan` | Discovers agents (Claude Code, Claude desktop, Codex, Cursor, OpenClaw), turns their configs into the collusion model, prints k (compromised agents needed) for each policy, shows a witness chain, and runs a staged hardening plan. |
| `agentwatch.py watch` | Rescans and sends a macOS notification whenever any agent control file changes (settings, MCP configs, instruction files, memory, shell rc), or any other settings file the scan read: each Claude Code project's `.claude/settings.json`, `.claude/settings.local.json` and `.mcp.json`, managed settings, the VS Code settings Copilot uses, and the editors' extension lists. |
| `claude-plugin/` | Claude Code extension: blocks Claude from reading secret stores or writing other agents' control files, flags writes to shared instruction files (CLAUDE.md, AGENTS.md, ...), shows k in the status line, and adds `/agentwatch` (pane, `scan`, `allow <path>`, `allowed`, `forget`). |

```
python3 agentwatch.py scan
python3 agentwatch.py scan --json ~/.agentwatch/report.json
python3 agentwatch.py watch --every 30
claude --plugin-dir ~/Code/agent-collusion/agentwatch/claude-plugin
```

## Analysis: SAT with approval gates

Every right is either **open** (used without asking) or behind a named **gate**
that asks you (Claude Code's `edit`/`shell`/`web`, Codex `escalate` and
`computer_use`, Cursor `terminal`, MCP tool calls). Approving a gate once
grants all of its rights. For each policy, `../sat.py` encodes "an attack with
at most t agents broken and at most h approvals" as CNF and solves it with
CaDiCaL. It reports every Pareto-minimal (agents, approvals) pair with the
attack path, and leaves a DRAT proof in `~/.agentwatch/proofs` for each "no
cheaper attack" claim. `../tests/test_sat.py` checks the solver against brute
force: 240 random cases, 0 mismatches.

## Model

- **Capabilities.** An unsandboxed shell (`*`) reads and writes everything your
  user can, including the network. A sandbox, as shipped, reads the disk,
  writes the project, and reaches an allowlist of hosts (still a sink). Web or
  chat access is untrusted input.
- **Control files.** Each agent's config, instruction and memory files control
  it. Project instruction files control every agent that works in the project.
  Shell rc files control every agent that spawns a shell.
- **Policies.** Each secret store present must not reach the network, and each
  agent's config must not come under attacker influence.

## Privacy

- The scanner checks only whether secret stores *exist*; it never reads them.
- From agent configs it reads only structure: permission rules, sandbox mode,
  and MCP server and plugin names. It never reads env values or tokens.
- OpenClaw keeps credentials next to its config, so it is detected by presence
  only unless you pass `--parse openclaw`.
- Nothing leaves the machine.

## Limits

- Capabilities are inferred from documented defaults; every assumption is
  printed per agent. Check them against your setup. Rights that only an
  assumption grants (Cursor's defaults, unrecognized MCP servers, plugins) are
  used by every check, and `agentcheck conditions` treats them as open questions.
- MCP servers are recognized only by their name, command and package name,
  never by path arguments. Any other server is assumed able to do anything.
- MCP servers, Chrome and plugins run outside an agent's sandbox. The hardening
  plan's sandbox and secret-blocking steps do not limit them.
- An exact `Bash(...)` rule counts as that one command only when its paths are
  literal. With `$VAR`, `~user`, braces, globs or `..`, it counts as a command
  that can read and write anything.
- Editor extensions are found both from their folders and from
  `extensions.json`, which lists only the default profile's extensions. The
  Claude Code extension counts as Claude Code only when `~/.claude` or
  `~/.claude.json` exists. Otherwise (for example with `CLAUDE_CONFIG_DIR` set
  elsewhere) it is modeled as unrestricted.
- The Bash guard matches paths in the command text, which is best effort: a
  variable or a script file can hide a path. The Write/Edit/Read guards resolve
  real paths and are robust.
- The guard only governs Claude Code. The other agents need their own sandbox,
  and the watcher only detects changes to their files.
- The watcher sees *that* a control file changed, not which process changed it.
  Attributing the writer needs `fs_usage`/EndpointSecurity (root).
