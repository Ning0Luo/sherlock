# Access settings: set aside, then checked on change

Some agents can edit access settings: their own or another agent's permission rules, MCP configs, approval lists. In the model, such a file is a resource marked `"access": true`. The scan marks every agent's `.json`, `.toml` and `.yaml` control files this way. Instruction, skill and memory files are not marked, so attacks through `CLAUDE.md` or memory still count.

The check is split in two:

1. **Static, with access frozen** (`check --guard-access`, `ruleoftwo --guard-access`, `conditions --guard-access`). Nobody can write an access file. A policy that fails only through such an edit is reported as **GUARDED**, along with the attack that was set aside. Every other claim in that output (cheapest attacks, "cannot be broken at all", proofs) is about the frozen system and says so.
2. **On every change** (`diff` before a change, `watch` after one). The new configuration is checked the same way. An **ALARM** is raised only when a policy that held now has an attack that needs no further access edit. NOTE means new attacks that all need another access edit. FIXED means an attack went away. Removing rights can never add an attack, because the model is monotone. On this Mac (`--scan`), `watch` also raises **REVIEW** when a changed file is one that a GUARDED policy's set-aside attack edits, even if no verdict changes (see Limits).

The guarantee is "no attack in the current configuration, and every change is checked." It is only as strong as the change check:
- `diff` runs *before* a change: in CI, or on a proposed edit.
- `watch` runs *after*: by polling, so a change has a window of `--every` seconds. With `--scan` it watches every file the scan reads (control files, shell startup files, each project's `.claude/settings*.json` and `.mcp.json`, managed and editor settings), including files that do not exist yet. With `--openshell` it watches the fleet file and every sandbox policy and proposal it names, wherever they are. A file that cannot be read mid-edit, or a policy whose names are gone, prints (and on this Mac notifies) `cannot re-check`; the other policies are still checked and `watch` keeps running.

```bash
python3 agentcheck.py check examples/access/access.policy --config examples/access/before.json --guard-access
python3 agentcheck.py diff  examples/access/access.policy --config examples/access/before.json --to examples/access/after_slack.json
python3 agentcheck.py diff  examples/access/access.policy --config examples/access/before.json --to examples/access/after_lockdown.json
python3 agentcheck.py watch policies/mac.policy --scan
```

## The example

- **`before.json`.** The non-AI `sync` job holds the SSH key and uploads to a backup server. Only its config, `cfg/sync`, decides what it uploads, and the AI `assistant`, which reads the web, can edit that config. Both policies are **GUARDED**: the only attack is the assistant rewriting the sync config.
- **`after_slack.json`.** The `reader` gets a Slack tool. **ALARM**: web text steers the assistant, the assistant's notes steer the reader, and the reader posts the SSH key to Slack. No access edit is needed.
- **`after_lockdown.json`.** The assistant can no longer edit `cfg/sync`. Both policies are **FIXED**.

## Limits

- **The model does not grant rights through edits.** Writing an access file corrupts the agents it controls, but does not give them new rights (for example, an `allow` rule that skips an approval). The rescan after the edit reads the new rules, which is why the check on change is needed.
- **An edit that only steers an agent changes no verdict.** In `--config` and `--openshell` mode the configuration file describes rights, not the access files themselves, so a set-aside attack that only steers an agent through its access file (like `before.json`'s: the assistant rewrites `cfg/sync`) cannot be observed by watching the configuration file; only an edit to the configuration is. On this Mac the edited file itself is watched: its change is reported as REVIEW for each GUARDED policy whose set-aside attack edits it.
- **Settings the scanner does not parse are not re-checked.** In `~/.claude/settings.json` the scan reads permissions, sandbox, additional directories and MCP servers. Other entries, such as `hooks`, `env`, `statusLine` and `apiKeyHelper`, can run commands without a prompt but are not modeled, so adding one changes no verdict. The file change itself is still reported (and REVIEW when a set-aside attack edits that file).
- **Polling cannot stop a change.** `watch` alarms after a change has happened. Preventing one needs a hook that checks a proposed edit before it is written (for example, Claude Code's `PreToolUse` running `diff` on the proposed file).
- **Freezing does not shrink unknowns.** On a Mac where some agents' settings cannot be read, those agents are still modeled as unrestricted, and most attacks need no access edit.
