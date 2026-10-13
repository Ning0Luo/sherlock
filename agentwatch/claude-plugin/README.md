# agentwatch — a Claude Code plugin

Runtime guard for a machine running several AI coding agents. It:

- **blocks** an agent from reading or writing a **secret store** (`~/.ssh`, cloud
  credentials, …) and from writing **another agent's control files** (settings,
  MCP config, instruction/memory files) — the cross-agent escalation Sherlock
  finds statically;
- **flags** writes to shared instruction files (`CLAUDE.md`, `AGENTS.md`, …);
- shows the machine's **t-collusion resilience** in a pane (`/agentwatch`): the
  cheapest attack per policy, updated live.

It enforces at `PreToolUse` for `Read`, `Write`, `Edit`, `NotebookEdit` and
`Bash`. A denied action tells the user how to permit it (`/agentwatch allow
<path>`), so you stay in control.

## Install

```bash
claude --plugin-dir /path/to/sherlock/agentwatch/claude-plugin
```

## Setup — point it at the scanner

The plugin runs the `agentwatch.py` scanner to learn which paths are secrets and
control files. Tell it where that scanner is, either with an environment
variable:

```bash
export AGENTWATCH_SCANNER=/path/to/sherlock/agentwatch/agentwatch.py
```

or by placing it at the default location:

```bash
mkdir -p ~/.agentwatch && ln -s /path/to/sherlock/agentwatch/agentwatch.py ~/.agentwatch/agentwatch.py
```

`HOME` and `AGENTWATCH_SCANNER` are the only environment values it reads; it
writes none. Its scan report is cached at `~/.agentwatch/report.json`.

## Commands

`/agentwatch` opens the pane. Subcommands:

| | |
|---|---|
| `/agentwatch scan` | re-run the scan now |
| `/agentwatch allow <path>` | permit access to a path (kept across sessions) |
| `/agentwatch allowed` | list what you've allowed |
| `/agentwatch forget` | clear the allow list |

## Notes

- The Bash guard matches paths in the command text (best effort); the
  Read/Write/Edit guards resolve real paths and are robust.
- The guard governs Claude Code only. Other agents need their own sandbox; the
  `agentwatch watch` command (see `../README.md`) detects changes to their files.
- Validate the plugin with `claude plugin validate .` from this directory.
