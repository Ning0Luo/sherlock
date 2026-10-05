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
    places: list[str] = field(default_factory=list)      # extra resources this agent brings (its project)
    obeys: list[str] = field(default_factory=list)       # instruction files it follows (globs); empty = all projects'


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

# --- Claude Code, fine grained ------------------------------------------------
# Claude Code is modeled as one agent per project it has been used in, because
# its permission rules are layered per project: user settings, the project's
# shared .claude/settings.json, its personal .claude/settings.local.json (where
# "Yes, and don't ask again" approvals are saved), the per-project allowedTools
# in ~/.claude.json, and managed (company) settings. Each permission rule is
# mapped to the concrete rights it grants. Each MCP server and the Chrome
# integration is its own approval gate.

CLAUDE_MANAGED = [Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
                  Path("/etc/claude-code/managed-settings.json")]
SHELL_ALL = {"read": ["*"], "write": ["*", "net"]}

# What a pre-approved shell command can reach, by its first word(s).
CMD_NET = {"curl", "wget", "http", "https", "httpie", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
           "ftp", "telnet", "gh", "glab", "aws", "gcloud", "az", "kubectl", "helm", "docker",
           "podman", "vercel", "netlify", "heroku", "fly", "firebase", "wrangler"}
CMD_FULL = {"python", "python3", "node", "ruby", "perl", "php", "bash", "sh", "zsh", "fish",
            "osascript", "eval", "exec", "xargs", "env", "sudo", "npx", "uvx", "uv", "pip",
            "pip3", "npm", "yarn", "pnpm", "bun", "deno", "make", "cmake", "cargo", "go",
            "java", "mvn", "gradle", "open", "lake", "swift", "dotnet", "pytest", "jupyter"}
CMD_READ = {"cat", "head", "tail", "less", "more", "grep", "rg", "ag", "find", "fd", "ls", "wc",
            "diff", "file", "stat", "tree", "jq", "sort", "uniq", "cut", "du", "df", "pwd",
            "which", "echo", "printf", "date", "whoami", "ps", "pbpaste", "strings", "md5",
            "shasum", "sha256sum", "xxd", "hexdump", "base64", "awk"}
CMD_WRITE = {"cp", "mv", "rm", "mkdir", "rmdir", "touch", "tee", "sed", "chmod", "chown", "ln",
             "unzip", "tar", "zip", "gzip", "gunzip", "patch", "truncate", "dd"}
CMD_PROJ = {"pdflatex", "latexmk", "xelatex", "lualatex", "bibtex", "biber", "tsc", "eslint",
            "prettier", "black", "ruff", "mypy", "rustc", "gcc", "clang", "g++", "javac"}
GIT_NET = {"push", "fetch", "pull", "clone", "remote", "ls-remote", "submodule"}


def shell_rights(cmd: str, proj: str = "proj:*") -> tuple[dict, str]:
    """Rights granted by a pre-approved Bash(...) rule, and a plain description."""
    words = cmd.replace(":*", " ").replace("*", " ").split()
    if not words:
        return SHELL_ALL, "any shell command"
    w0 = words[0].rsplit("/", 1)[-1]
    if w0 == "git":
        sub = words[1] if len(words) > 1 else ""
        if sub in GIT_NET or not sub:
            return {"read": ["web", proj], "write": [proj, "net"]}, "git with network access"
        return {"read": [proj], "write": [proj]}, f"local git {sub}"
    if w0 in CMD_NET:
        return {"read": ["*", "web"], "write": ["net"]}, f"{w0}: sends data over the network"
    if w0 in CMD_FULL:
        return SHELL_ALL, f"{w0}: runs arbitrary code"
    if w0 in CMD_READ:
        return {"read": ["*"], "write": []}, f"{w0}: reads any file"
    if w0 in CMD_WRITE:
        return {"read": ["*"], "write": ["*"]}, f"{w0}: changes any file"
    if w0 in CMD_PROJ:
        return {"read": [proj], "write": [proj]}, f"{w0}: builds project files"
    return SHELL_ALL, f"{w0}: unrecognized command, treated as a full shell"


def path_places(path: str, proj: str) -> list[str]:
    """Resources a Read/Edit path rule reaches."""
    p = path.strip()
    if p in ("", "*", "**", "/**", "//**", "~/**", "~"):
        return ["*"]
    sec = secret_for_path(p.replace("//", "/"))
    if sec:
        return [sec]
    name = p.rstrip("*/").rsplit("/", 1)[-1]
    if name in ("CLAUDE.md", "AGENTS.md", ".cursorrules"):
        return [f"{proj}:instructions"]
    if ".claude" in p or ".codex" in p or ".cursor" in p:
        return ["ctl:*"]
    if any(rc in p for rc in SHELL_RC):
        return ["shell_rc"]
    if p.startswith(("./", "src", "*")) or not p.startswith(("/", "~")):
        return [proj, f"{proj}:instructions"] if "**" in p or p in (".", "./") else [proj]
    return ["*"]


MCP_CATALOG = [   # (substring of name or command, reach, plain description)
    (("playwright", "puppeteer", "browser", "chrome", "selenium", "browserbase"),
     {"read": ["web"], "write": ["net"]}, "drives a web browser"),
    (("fetch", "search", "brave", "tavily", "exa", "firecrawl", "perplexity", "web"),
     {"read": ["web"], "write": ["net"]}, "fetches web content"),
    (("github", "gitlab", "linear", "jira", "atlassian", "slack", "notion", "gmail", "google",
      "drive", "sentry", "discord", "telegram", "email", "calendar"),
     {"read": ["web"], "write": ["net"]}, "reads and writes a hosted service"),
    (("filesystem", "file-system", "files", "desktop-commander", "shell", "terminal", "exec"),
     {"read": ["*"], "write": ["*"]}, "reads and writes local files"),
]


def mcp_reach(name: str, spec: dict) -> tuple[dict, str]:
    key = (name + " " + str(spec.get("command", "")) + " " + " ".join(map(str, spec.get("args", []) or []))).lower()
    for subs, reach, desc in MCP_CATALOG:
        if any(x in key for x in subs):
            return reach, desc
    if spec.get("url") or spec.get("type") in ("http", "sse"):
        return {"read": ["web"], "write": ["net"]}, "remote server: assumed to read and send over the network"
    return {"read": ["proj:*"], "write": []}, "local server, unknown tools: assumed to read project files"


def proj_slug(path: str) -> str:
    base = path.rstrip("/").rsplit("/", 1)[-1] or "root"
    return "proj:" + "".join(c if c.isalnum() or c in "-_." else "-" for c in base)[:40]


def claude_scopes() -> list[tuple[str | None, list[tuple[str, dict]], dict]]:
    """(project path or None, [(scope label, settings dict)], ~/.claude.json project entry)."""
    user = [("user settings", load_json(HOME / ".claude/settings.json")),
            ("user local settings", load_json(HOME / ".claude/settings.local.json"))]
    managed = [("managed settings", load_json(p)) for p in CLAUDE_MANAGED if p.exists()]
    projects = (load_json(HOME / ".claude.json").get("projects") or {})
    out: list = [(None, managed + user, {})]
    for path, entry in sorted(projects.items()):
        if not isinstance(entry, dict) or not Path(path).is_dir() or Path(path) == HOME:
            continue
        pj = [("project settings", load_json(Path(path) / ".claude/settings.json")),
              ("project local settings (your saved approvals)", load_json(Path(path) / ".claude/settings.local.json"))]
        has_own = any(d for _, d in pj) or entry.get("allowedTools") or entry.get("mcpServers") \
            or (Path(path) / ".mcp.json").exists()
        if has_own:
            out.append((path, managed + user + pj, entry))
    return out


def claude_code_agent(path: str | None, layers, entry: dict, mode_override: str | None,
                      chrome: bool, user_mcp: dict) -> Found:
    proj = proj_slug(path) if path else "proj:*"
    instr = f"{proj}:instructions" if path else "proj:*"
    where = path_title(path)
    name = f"claude_code@{proj[5:]}" if path else "claude_code"
    title = f"Claude Code in {where}" if path else "Claude Code (other folders)"
    rd = [proj, instr, "ctl:claude_code"] if path else ["proj:*", "ctl:claude_code"]
    edit_w = [proj, instr] if path else ["proj:*"]
    f = Found(name, title, read=list(rd), write=[], ask={
                  "edit": {"write": list(edit_w)},
                  "shell": dict(SHELL_ALL),
                  "web": {"read": ["web"], "write": ["net"]},
                  "read_outside": {"read": ["*"]},
              },
              control_paths=["~/.claude/settings.json", "~/.claude/settings.local.json",
                             "~/.claude.json", "~/.claude/CLAUDE.md", "~/.claude/agents",
                             "~/.claude/skills", "~/.claude/plugins", "~/.claude/hooks",
                             "~/.claude/commands", "~/.claude/projects/*/memory"],
              reads_project_instructions=True, uses_shell=True,
              places=[proj, instr] if path else [], obeys=[instr, "proj:instructions"] if path else [])
    if chrome:
        f.ask["chrome"] = {"read": ["web", "secret:browser"], "write": ["net"]}
    allow, ask, deny, mode, sandbox = [], [], [], "default", {}
    for label, d in layers:
        perms = d.get("permissions") or {}
        allow += [(r, label) for r in perms.get("allow") or []]
        ask += perms.get("ask") or []
        deny += perms.get("deny") or []
        mode = perms.get("defaultMode", mode)
        sandbox = d.get("sandbox") or sandbox
        for extra in perms.get("additionalDirectories") or []:
            f.ask["edit"]["write"] = f.ask["edit"]["write"] + path_places(extra + "/**", proj)
            f.read += path_places(extra + "/**", proj)
    allow += [(r, "approvals saved in ~/.claude.json") for r in entry.get("allowedTools") or []]
    mode = mode_override or mode
    mcp = dict(user_mcp)
    mcp.update(entry.get("mcpServers") or {})
    if path:
        mcp.update(load_json(Path(path) / ".mcp.json").get("mcpServers") or {})
    for srv, spec in sorted(mcp.items()):
        reach, desc = mcp_reach(srv, spec if isinstance(spec, dict) else {})
        f.ask[f"mcp:{srv}"] = {"read": list(reach["read"]), "write": list(reach["write"])}
        f.notes.append(f"MCP server {srv}: {desc}")

    if sandbox.get("enabled"):
        fs = sandbox.get("filesystem") or {}
        f.deny_read += [r for r in (secret_for_path(p) for p in fs.get("denyRead", [])) if r]
        net = ["net:allowlist"] if (sandbox.get("network") or {}).get("allowedDomains") else []
        f.ask["shell"] = {"read": ["*"], "write": list(edit_w) + net}
        f.uses_shell = False
        f.notes.append("sandbox on: shell writes only the project; network only to its allowlist")
        if sandbox.get("autoAllowBashIfSandboxed", True):
            open_gate(f, "shell")
            f.notes.append("sandboxed shell commands run without asking")

    granted: list[str] = []
    for rule, label in allow:
        tool, arg = rule_arg(rule)
        if tool == "Bash":
            if arg in ("", "*", ":*"):
                open_gate(f, "shell")
                granted.append(f"{rule} ({label}): any shell command without asking")
            else:
                rights, desc = shell_rights(arg, proj if path else "proj:*")
                if "shell" in f.ask or not sandbox.get("enabled"):
                    f.read += rights["read"]
                    f.write += rights["write"]
                granted.append(f"{rule} ({label}): {desc}")
        elif tool in ("Read", "Glob", "Grep", "LS"):
            places = path_places(arg, proj) if arg else ["*"]
            f.read += places
            granted.append(f"{rule} ({label}): reads {', '.join(places)}")
        elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
            places = path_places(arg, proj) if arg else list(edit_w)
            f.write += places
            if not arg or arg in ("*", "**"):
                f.ask.pop("edit", None)
            granted.append(f"{rule} ({label}): edits {', '.join(places)}")
        elif tool in ("WebFetch", "WebSearch"):
            f.read.append("web")
            f.write.append("net")
            if not arg:
                f.ask.pop("web", None)
            granted.append(f"{rule} ({label}): reads web pages and sends requests out")
        elif tool.startswith("mcp__"):
            srv = tool[5:].split("__", 1)[0]
            g = f"mcp:{srv}"
            if g in f.ask:
                open_gate(f, g)
            granted.append(f"{rule} ({label}): uses MCP server {srv} without asking")
        elif tool.startswith("mcp__claude-in-chrome") or tool == "Chrome":
            open_gate(f, "chrome")
            granted.append(f"{rule} ({label}): drives your Chrome without asking")
    for rule in deny:
        tool, arg = rule_arg(rule)
        if tool == "Read" and secret_for_path(arg):
            f.notes.append(f"deny {rule}: blocks the Read tool only; approved shell commands can still read it")
        elif tool in ("WebFetch", "WebSearch") and not arg:
            f.ask.pop("web", None)
        elif tool.startswith("mcp__"):
            f.ask.pop(f"mcp:{tool[5:].split('__', 1)[0]}", None)
        elif tool == "Bash" and arg in ("", "*"):
            f.ask.pop("shell", None)
    for rule in ask:
        tool, _ = rule_arg(rule)
        if tool == "Bash":
            f.notes.append(f"ask {rule}: still asks before this command")

    if mode == "acceptEdits":
        open_gate(f, "edit")
    elif mode == "bypassPermissions":
        for g in list(f.ask):
            open_gate(f, g)
        f.notes.append("bypass mode: nothing asks")
    elif mode == "dontAsk":
        f.ask.clear()
        f.notes.append("dontAsk mode: anything not pre-approved is refused")
    elif mode == "plan":
        f.ask.pop("edit", None)
        if "shell" in f.ask:
            f.ask["shell"] = {"read": ["*"]}
        f.notes.append("plan mode: read-only")
    elif mode == "auto":
        f.notes.append("auto mode: a safety classifier answers prompts; counted as approvals")
    f.read = sorted(set(f.read))
    f.write = sorted(set(f.write))
    f.notes.insert(0, f"mode: {mode}; {len(granted)} pre-approved rule(s)")
    f.notes += granted
    if f.ask:
        f.notes.append("asks before: " + ", ".join(sorted(f.ask)))
    return f


def path_title(path: str | None) -> str:
    if not path:
        return "other folders"
    p = Path(path)
    try:
        return "~/" + str(p.relative_to(HOME))
    except ValueError:
        return p.name


def claude_code(mode_override: str | None) -> list[Found]:
    if not (exists(".claude") or exists(".claude.json")):
        return []
    cj = load_json(HOME / ".claude.json")
    chrome = exists(".claude/chrome") or bool(cj.get("cachedChromeExtensionInstalled"))
    user_mcp = cj.get("mcpServers") or {}
    out = []
    for path, layers, entry in claude_scopes():
        out.append(claude_code_agent(path, layers, entry, mode_override, chrome, user_mcp))
    if len(out) > 1:
        out[0].notes.append(f"{len(out) - 1} project(s) have their own rules and are listed separately")
    if exists("Library/Application Support/Code/User/settings.json"):
        out[0].notes.append("also runs as the VS Code extension with the same ~/.claude config")
    return out


def claude_desktop() -> Found | None:
    cfg = APP_SUPPORT / "Claude/claude_desktop_config.json"
    if not cfg.exists():
        return None
    mcp = sorted((load_json(cfg).get("mcpServers") or {}).keys())
    f = Found("claude_desktop", "Claude desktop chat", read=["web", "cowork"],
              write=["net", "cowork"], control_paths=[str(cfg).replace(str(HOME), "~")])
    f.notes.append("web search and fetch run without asking; Cowork folder open")
    servers = load_json(cfg).get("mcpServers") or {}
    for srv in mcp:
        reach, desc = mcp_reach(srv, servers[srv] if isinstance(servers[srv], dict) else {})
        f.ask[f"mcp:{srv}"] = {"read": list(reach["read"]), "write": list(reach["write"])}
        f.notes.append(f"MCP server {srv}: {desc}; asks unless you chose 'always allow'")
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


def ctl_key(agent: str) -> str:
    """Settings resource of an agent: every Claude Code project shares ~/.claude."""
    return "claude_code" if agent.startswith("claude_code") else agent


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
        for pl in f.places:
            res.setdefault(pl, Resource(pl))
    ctl_of = {}
    for f in found:
        ctl_of.setdefault(ctl_key(f.name), []).append(f.name)
    for key, members in ctl_of.items():
        res[f"ctl:{key}"] = Resource(f"ctl:{key}", controls=members)
    res["proj:instructions"] = Resource("proj:instructions")
    for r in [x for x in res if x == "proj:instructions" or x.endswith(":instructions")]:
        res[r].controls = [f.name for f in found if f.reads_project_instructions and
                           (any(fnmatch.fnmatchcase(r, p) for p in f.obeys) if f.obeys else True)]
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
    seen = set()
    for f in found:
        key = ctl_key(f.name)
        if key in seen:
            continue
        seen.add(key)
        title = "Claude Code" if key == "claude_code" else f.title
        policies.append(Policy(f"{title} settings not attacker-controlled", "integrity",
                               resource=f"ctl:{key}"))
    return System(agents, res, policies)



def main() -> None:
    found = claude_code(None) + [x for x in (claude_desktop(), codex(), cursor(), openclaw(False)) if x]
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
