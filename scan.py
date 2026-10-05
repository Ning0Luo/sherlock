#!/usr/bin/env python3
"""Sherlock scanner: finds the AI agents on this Mac and prints their rights
as JSON. It reads only the structure of agent settings files (permission
rules, modes, plugin and MCP server names) and checks whether secret folders
such as ~/.ssh exist. It never opens secrets, never prints file contents or
paths under your home folder, and sends nothing anywhere: output goes to stdout."""
from __future__ import annotations
import fnmatch, json, os, sys, time
try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Agent:
    name: str
    read: list
    write: list
    injectable: bool = True
    flows: list = field(default_factory=list)
    ask: dict = field(default_factory=dict)


@dataclass
class Resource:
    name: str
    labels: set = field(default_factory=set)
    untrusted: bool = False
    sink: bool = False
    protected: bool = False
    controls: list = field(default_factory=list)


@dataclass
class Policy:
    name: str
    kind: str
    label: str | None = None
    to: list | None = None
    resource: str | None = None
    agent: str | None = None


@dataclass
class System:
    agents: dict
    resources: dict
    policies: list

HOME = Path.home()
APP_SUPPORT = HOME / "Library/Application Support"
PROOFS = HOME / ".agentwatch/proofs"
OPT_IN = {"openclaw"}

# Secret stores: (resource, label, paths). Only existence is checked.
SECRETS = [
    ("secret:ssh", "ssh_key", [".ssh"]),
    ("secret:aws", "aws_creds", [".aws"]),
    ("secret:gh", "gh_token", [".config/gh", ".netrc"]),
    ("secret:docker", "docker_creds", [".docker/config.json"]),
    ("secret:kube", "kube_creds", [".kube/config"]),
    ("secret:pkg", "registry_tokens", [".npmrc", ".pypirc"]),
    ("secret:gpg", "gpg_key", [".gnupg"]),
    ("secret:browser", "browser_sessions",
     ["Library/Application Support/Google/Chrome", "Library/Application Support/Arc",
      "Library/Application Support/Firefox", "Library/Safari"]),
]

SHELL_RC = [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"]


@dataclass
class Found:
    """One detected agent: open rights, rights behind approval gates, notes."""
    name: str
    title: str
    read: list[str]                                  # open: no prompt
    write: list[str]
    ask: dict[str, dict[str, list[str]]] = field(default_factory=dict)   # gate -> rights
    injectable: bool = True
    control_paths: list[str] = field(default_factory=list)
    reads_project_instructions: bool = False
    uses_shell: bool = False
    deny_read: list[str] = field(default_factory=list)   # enforced below every tool (sandbox)
    notes: list[str] = field(default_factory=list)


def exists(rel: str) -> bool:
    return (HOME / rel).exists()


def load_json(path: Path) -> dict:
    try:
        with open(path) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def mini_toml(text: str) -> dict:
    """Enough TOML for Codex's config: top-level and [table] key = scalar."""
    import re as _re
    root: dict = {}
    cur = root
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _re.fullmatch(r"\[([^\]]+)\]", line)
        if m:
            cur = root
            for part in _re.findall(r'"[^"]*"|[^.]+', m.group(1)):
                cur = cur.setdefault(part.strip().strip('"'), {})
            continue
        if "=" in line:
            k, v = (x.strip() for x in line.split("=", 1))
            v = {"true": True, "false": False}.get(v, v.strip('"'))
            cur[k.strip('"')] = v
    return root


def secret_for_path(p: str) -> str | None:
    """Map a rule path such as ~/.ssh/** to a secret resource."""
    p = p.replace("~/", "").replace(str(HOME) + "/", "").lstrip("/")
    for r, _, paths in SECRETS:
        if any(p.startswith(x) for x in paths):
            return r
    return None


def rule_arg(rule: str) -> tuple[str, str]:
    """'Bash(git push:*)' -> ('Bash', 'git push:*'); 'Edit' -> ('Edit', '')."""
    if "(" in rule and rule.endswith(")"):
        tool, arg = rule.split("(", 1)
        return tool, arg[:-1]
    return rule, ""


def open_gate(f: Found, gate: str) -> None:
    rights = f.ask.pop(gate, None)
    if rights:
        f.read += rights.get("read", [])
        f.write += rights.get("write", [])


# ---------------------------------------------------------------- collectors
# Vocabulary: "*" = anything your user can touch; "web" = untrusted content;
# "net" / "net:allowlist" = outbound sinks; "proj:*" = project files;
# "proj:instructions" = CLAUDE.md / AGENTS.md / .cursorrules in projects;
# "ctl:<agent>" = that agent's own settings, instructions and memory.

def claude_code(mode_override: str | None) -> Found | None:
    if not (exists(".claude") or exists(".claude.json")):
        return None
    s = load_json(HOME / ".claude/settings.json")
    perms = s.get("permissions") or {}
    allow, deny = perms.get("allow") or [], perms.get("deny") or []
    sandbox = s.get("sandbox") or {}
    mode = mode_override or perms.get("defaultMode", "default")
    f = Found("claude_code", "Claude Code", read=["proj:*", "proj:instructions", "ctl:claude_code"],
              write=[], ask={
                  "edit": {"write": ["proj:*", "proj:instructions"]},
                  "shell": {"read": ["*"], "write": ["*"]},
                  "web": {"read": ["web"], "write": ["net"]},
                  "read_outside": {"read": ["*"]},
              },
              control_paths=["~/.claude/settings.json", "~/.claude/settings.local.json",
                             "~/.claude.json", "~/.claude/CLAUDE.md", "~/.claude/agents",
                             "~/.claude/skills", "~/.claude/plugins", "~/.claude/hooks",
                             "~/.claude/commands", "~/.claude/projects/*/memory"],
              reads_project_instructions=True, uses_shell=True)
    f.notes.append(f"mode: {mode}{' (from --claude-mode)' if mode_override else ''}; "
                   f"{len(allow)} allow / {len(deny)} deny rules")

    if sandbox.get("enabled"):
        fs = sandbox.get("filesystem") or {}
        dr = [secret_for_path(p) for p in fs.get("denyRead", [])]
        f.deny_read += [r for r in dr if r]
        net = ["net:allowlist"] if (sandbox.get("network") or {}).get("allowedDomains") else []
        f.ask["shell"] = {"read": ["*"], "write": ["proj:*", "proj:instructions"] + net}
        f.uses_shell = False
        f.notes.append("sandbox on: shell writes only the project; network only to its allowlist")
        if sandbox.get("autoAllowBashIfSandboxed", True):
            open_gate(f, "shell")
            f.notes.append("sandboxed shell commands run without asking")
    for rule in allow:
        tool, arg = rule_arg(rule)
        if tool == "Bash" and arg in ("", "*", ":*"):
            open_gate(f, "shell")
        elif tool in ("Edit", "Write", "MultiEdit") and arg in ("", "*", "**"):
            open_gate(f, "edit")
        elif tool in ("WebFetch", "WebSearch") and arg == "":
            open_gate(f, "web")
        elif tool == "Read" and arg in ("", "*", "**"):
            open_gate(f, "read_outside")
    for rule in deny:
        tool, arg = rule_arg(rule)
        if tool == "Read" and "read_outside" in f.ask and secret_for_path(arg):
            f.ask["read_outside"]["read"] = f.ask["read_outside"]["read"] + [f"!{secret_for_path(arg)}"]
            f.notes.append(f"deny {rule}: blocks the Read tool only; shell commands can still read it")
        if tool in ("WebFetch", "WebSearch") and arg == "":
            f.ask.pop("web", None)

    if mode == "acceptEdits":
        open_gate(f, "edit")
    elif mode == "bypassPermissions":
        for g in list(f.ask):
            open_gate(f, g)
        f.notes.append("bypass mode: nothing asks")
    elif mode == "plan":
        f.ask.pop("edit", None)
        if "shell" in f.ask:
            f.ask["shell"] = {"read": ["*"]}
        f.notes.append("plan mode: read-only")
    elif mode == "auto":
        f.notes.append("auto mode: a safety classifier answers prompts; counted as approvals")
    if f.ask:
        f.notes.append("asks before: " + ", ".join(sorted(f.ask)))
    if exists("Library/Application Support/Code/User/settings.json"):
        f.notes.append("also runs as the VS Code extension with the same ~/.claude config")
    return f


def claude_desktop() -> Found | None:
    cfg = APP_SUPPORT / "Claude/claude_desktop_config.json"
    if not cfg.exists():
        return None
    mcp = sorted((load_json(cfg).get("mcpServers") or {}).keys())
    f = Found("claude_desktop", "Claude desktop chat", read=["web", "cowork"],
              write=["net", "cowork"], control_paths=[str(cfg).replace(str(HOME), "~")])
    f.notes.append("web search and fetch run without asking; Cowork folder open")
    if mcp:
        f.ask["mcp"] = {"read": ["proj:*", "proj:instructions"]}
        f.notes.append(f"local MCP servers ({', '.join(mcp)}): each tool call asks unless "
                       f"you chose 'always allow'; assumed to reach project files")
    return f


def codex() -> Found | None:
    cfg = HOME / ".codex/config.toml"
    if not cfg.exists():
        return None
    try:
        if tomllib is not None:
            with open(cfg, "rb") as fh:
                c = tomllib.load(fh)
        else:
            c = mini_toml(cfg.read_text())
    except Exception:
        c = {}
    sandbox = c.get("sandbox_mode", "workspace-write")
    policy = c.get("approval_policy", "on-request")
    net = bool((c.get("sandbox_workspace_write") or {}).get("network_access"))
    plugins = sorted(k.split("@")[0] for k, v in (c.get("plugins") or {}).items()
                     if isinstance(v, dict) and v.get("enabled"))
    f = Found("codex", "Codex", read=["*"], write=["proj:*", "proj:instructions"],
              control_paths=["~/.codex/config.toml", "~/.codex/AGENTS.md", "~/.codex/skills"],
              reads_project_instructions=True, uses_shell=True)
    f.notes.append(f"sandbox: {sandbox}; approvals: {policy}"
                   + (" (defaults)" if "sandbox_mode" not in c else ""))
    if net:
        f.write.append("net")
    if sandbox == "danger-full-access":
        f.write = ["*"]
    elif sandbox == "read-only":
        f.write = []
    if policy != "never" and sandbox != "danger-full-access":
        f.ask["escalate"] = {"write": ["*"]}
        f.notes.append("commands outside the sandbox ask first")
    if policy == "untrusted":
        f.ask["commands"] = {"write": f.write}
        f.write = []
    if any(p in plugins for p in ("browser", "chrome")):
        f.read.append("web")
        f.write.append("net")
        f.notes.append("browser/Chrome plugin: reads the web and can send data out "
                       "(assumed to run without asking)")
    if any("computer-use" in p for p in plugins):
        f.ask["computer_use"] = {"read": ["web"], "write": ["*"]}
        f.notes.append("computer use: drives apps you grant, outside the sandbox (asks per app)")
    return f


def cursor() -> Found | None:
    if not (exists(".cursor") or (APP_SUPPORT / "Cursor").exists()):
        return None
    f = Found("cursor", "Cursor", read=["proj:*", "proj:instructions", "web"],
              write=["proj:*", "proj:instructions"],
              ask={"terminal": {"read": ["*"], "write": ["*"]}},
              control_paths=["~/.cursor/mcp.json", "~/.cursor/rules",
                             "~/Library/Application Support/Cursor/User/settings.json"],
              reads_project_instructions=True, uses_shell=True)
    f.notes.append("assumed defaults: edits apply without asking, terminal commands ask, "
                   "web search open (auto-run mode not detected)")
    return f


def openclaw(parse: bool) -> Found | None:
    if not exists(".openclaw"):
        return None
    f = Found("openclaw", "OpenClaw", read=["*", "web", "inbound:chat"], write=["*"],
              control_paths=["~/.openclaw/openclaw.json", "~/.openclaw/exec-approvals.json",
                             "~/.openclaw/agents", "~/.openclaw/cron"], uses_shell=True)
    f.notes.append("config not read (its folder holds credentials): modeled as worst case")
    return f


# ------------------------------------------------------------- model builder

def expand(lst: list[str], res: dict[str, Resource], deny: list[str],
           reading: bool = False) -> list[str]:
    """'*' = every local place. Outgoing sinks are written, never read back:
    reading them would let data return without going through the web."""
    out = set()
    neg = {x[1:] for x in lst if x.startswith("!")}
    for x in lst:
        if x == "*":
            out |= {r for r, v in res.items() if not v.untrusted and not (reading and v.sink)}
        elif not x.startswith("!"):
            out.add(x)
    return sorted(r for r in out
                  if r not in neg and not any(r.startswith(d) for d in deny))


def build_system(found: list[Found], secrets_present) -> System:
    res: dict[str, Resource] = {
        "web": Resource("web", untrusted=True),
        "net": Resource("net", sink=True),
        "net:allowlist": Resource("net:allowlist", sink=True),
        "cowork": Resource("cowork"),
        "proj:src": Resource("proj:src"),
    }
    if any("inbound:chat" in f.read for f in found):
        res["inbound:chat"] = Resource("inbound:chat", untrusted=True)
    for r, label, _ in secrets_present:
        res[r] = Resource(r, labels={label})
    for f in found:
        res[f"ctl:{f.name}"] = Resource(f"ctl:{f.name}", controls=[f.name])
    res["proj:instructions"] = Resource(
        "proj:instructions", controls=[f.name for f in found if f.reads_project_instructions])
    res["shell_rc"] = Resource("shell_rc", controls=[f.name for f in found if f.uses_shell])

    agents = {}
    for f in found:
        rd = expand(f.read, res, f.deny_read, reading=True)
        wr = [w for w in expand(f.write, res, []) if not res.get(w, Resource(w)).untrusted]
        ask = {g: {"read": expand(r.get("read", []), res, f.deny_read, reading=True),
                   "write": [w for w in expand(r.get("write", []), res, [])
                             if not res.get(w, Resource(w)).untrusted]}
               for g, r in f.ask.items()}
        agents[f.name] = Agent(f.name, read=rd, write=wr, injectable=f.injectable, ask=ask)

    policies = [Policy(f"{label} stays on this machine", "no_flow", label=label)
                for _, label, _ in secrets_present]
    for f in found:
        policies.append(Policy(f"{f.title} settings not attacker-controlled", "integrity",
                               resource=f"ctl:{f.name}"))
    return System(agents, res, policies)



def main() -> None:
    found = [x for x in (claude_code(None), claude_desktop(), codex(), cursor(), openclaw(False)) if x]
    ig = HOME / ".agentwatch/ignore"
    skip = {l.strip() for l in ig.read_text().splitlines() if l.strip()} if ig.exists() else set()
    found = [f for f in found if f.name not in skip]
    secrets_present = [(r, l, ps) for r, l, ps in SECRETS if any(exists(p) for p in ps)]
    s = build_system(found, secrets_present)
    titles = {f.name: f.title for f in found}
    notes = {f.name: f.notes for f in found}
    out = {
        "format": "sherlock-scan/1",
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "agents": {a: {"title": titles[a], "read": x.read, "write": x.write,
                       "injectable": x.injectable, "ask": x.ask, "notes": notes[a]}
                   for a, x in s.agents.items()},
        "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                             ("sink", x.sink), ("controls", x.controls)) if v}
                      for r, x in s.resources.items()},
        "policies": [{k: v for k, v in p.__dict__.items() if v is not None} for p in s.policies],
    }
    text = json.dumps(out, indent=1)
    if str(Path.home()) in text:
        sys.exit("refusing to print: output would contain your home path")
    print(text)


if __name__ == "__main__":
    main()
