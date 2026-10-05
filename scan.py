#!/usr/bin/env python3
"""Sherlock scanner: finds the AI agents on this Mac and prints their rights
as JSON. It reads only the structure of agent settings files (permission
rules, modes, plugin and MCP server names) and checks whether secret folders
such as ~/.ssh exist. It never opens secrets, never prints file contents or
paths under your home folder, and sends nothing anywhere: output goes to stdout."""
from __future__ import annotations
import fnmatch, json, os, shutil, sys, time
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

import re

class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    out, q = [], None
    for i, c in enumerate(line):
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(c)
    return "".join(out).rstrip()


def _scalar(tok: str):
    t = tok.strip()
    if not t:
        return None
    if t[0] in "'\"" and t[-1] == t[0] and len(t) >= 2:
        return t[1:-1].replace("''", "'") if t[0] == "'" else json.loads(t)
    low = t.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d*", t):
        return float(t)
    return t


def _flow(s: str, i: int = 0):
    """Parse a flow value starting at s[i]; return (value, next index)."""
    while i < len(s) and s[i] == " ":
        i += 1
    if i < len(s) and s[i] in "[{":
        close = "]" if s[i] == "[" else "}"
        is_map = s[i] == "{"
        out = {} if is_map else []
        i += 1
        while True:
            while i < len(s) and s[i] in " ,":
                i += 1
            if i >= len(s):
                raise YamlError("unclosed flow collection")
            if s[i] == close:
                return out, i + 1
            if is_map:
                k, i = _flow_token(s, i, ":")
                i += 1
                v, i = _flow(s, i)
                out[_scalar(k)] = v
            else:
                v, i = _flow(s, i)
                out.append(v)
    tok, i = _flow_token(s, i, ",]}")
    return _scalar(tok), i


def _flow_token(s: str, i: int, stops: str):
    j, q = i, None
    while j < len(s):
        c = s[j]
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c in stops:
            break
        j += 1
    return s[i:j], j


class MiniYaml:
    def __init__(self, text: str):
        self.lines = []
        for raw in text.splitlines():
            if raw.strip().startswith("---") and not self.lines:
                continue
            line = _strip_comment(raw)
            if line.strip():
                if "\t" in line[: len(line) - len(line.lstrip())]:
                    raise YamlError("tabs are not allowed for indentation")
                self.lines.append((len(line) - len(line.lstrip()), line.strip()))
        self.i = 0

    def parse(self):
        if not self.lines:
            return None
        return self.block(self.lines[0][0])

    def block(self, ind: int):
        if self.lines[self.i][1].startswith("- ") or self.lines[self.i][1] == "-":
            return self.seq(ind)
        return self.map(ind)

    def value_after(self, rest: str, ind: int):
        rest = rest.strip()
        if rest in ("|", ">", "|-", ">-"):
            raise YamlError("block scalars are not supported; install PyYAML")
        if rest:
            return _flow(rest)[0] if rest[0] in "[{" else _scalar(rest)
        if self.i < len(self.lines) and self.lines[self.i][0] > ind:
            return self.block(self.lines[self.i][0])
        if self.i < len(self.lines) and self.lines[self.i][0] == ind and self.lines[self.i][1].startswith("-"):
            return self.seq(ind)
        return None

    @staticmethod
    def split_key(text: str):
        """'key: rest' -> (key, rest); None when the line is not a mapping entry."""
        key, j = _flow_token(text, 0, ":")
        if j >= len(text) or (j + 1 < len(text) and text[j + 1] != " "):
            return None
        return key.strip(), text[j + 1:]

    def map(self, ind: int):
        out = {}
        while self.i < len(self.lines) and self.lines[self.i][0] == ind:
            text = self.lines[self.i][1]
            if text.startswith("- ") or text == "-":
                break
            kv = self.split_key(text)
            if kv is None:
                raise YamlError(f"expected 'key: value', got {text!r}")
            self.i += 1
            out[_scalar(kv[0])] = self.value_after(kv[1], ind)
        return out

    def seq(self, ind: int):
        out = []
        while self.i < len(self.lines) and self.lines[self.i][0] == ind:
            text = self.lines[self.i][1]
            if not (text.startswith("- ") or text == "-"):
                break
            item = text[1:].strip()
            if not item:
                self.i += 1
                nested = self.i < len(self.lines) and self.lines[self.i][0] > ind
                out.append(self.block(self.lines[self.i][0]) if nested else None)
            elif item[0] in "[{" or self.split_key(item) is None:
                self.i += 1
                out.append(_flow(item)[0] if item[0] in "[{" else _scalar(item))
            else:
                # "- key: value": a map whose further keys line up with "key"
                sub = ind + len(text) - len(item)
                self.lines[self.i] = (sub, item)
                out.append(self.map(sub))
        return out



def load_jsonc(text: str):
    """Parse JSON that may contain comments and trailing commas."""
    out, i, n, q = [], 0, len(text), False
    while i < n:
        c = text[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                q = False
        elif c == '"':
            q = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned) if cleaned.strip() else {}


def load_config(path: Path):
    """Read a JSON, JSONC or YAML config; {} when missing or unreadable."""
    try:
        text = Path(path).read_text()
    except OSError:
        return {}
    try:
        if Path(path).suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                return yaml.safe_load(text) or {}
            except ImportError:
                return MiniYaml(text).parse() or {}
        return load_jsonc(text)
    except Exception:
        return {}


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
    coverage: str = "read"   # "read": settings parsed; "assumed": defaults assumed; "worst": modeled as unrestricted


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

# What a pre-approved shell command can reach, by its first word(s). Shell
# redirection (`echo x >> ~/.zshrc`) lets any command write any file, so every
# approved command at least reads and writes everywhere. Only commands with no
# known way to run other programs stay off the network.
CMD_NET = {"curl", "wget", "http", "https", "httpie", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
           "ftp", "telnet", "gh", "glab", "aws", "gcloud", "az", "kubectl", "helm", "docker",
           "podman", "vercel", "netlify", "heroku", "fly", "firebase", "wrangler", "rsync"}
CMD_NO_EXEC = {"cat", "head", "tail", "grep", "ls", "wc", "diff", "file", "stat", "tree", "jq",
               "cut", "du", "df", "pwd", "which", "echo", "printf", "date", "whoami", "ps",
               "strings", "md5", "shasum", "sha256sum", "xxd", "hexdump", "base64", "uniq", "cp",
               "mv", "rm", "mkdir", "rmdir", "touch", "tee", "chmod", "ln", "unzip", "gzip",
               "gunzip", "truncate", "dd", "pbpaste", "basename", "dirname", "realpath", "nl"}
SHELL_RW = {"read": ["*"], "write": ["*"]}


def shell_rights(cmd: str, proj: str = "proj:*") -> tuple[dict, str]:
    """Rights granted by a pre-approved Bash(...) rule, and a plain description."""
    words = cmd.replace(":*", " ").replace("*", " ").split()
    if not words:
        return SHELL_ALL, "any shell command"
    w0 = words[0].rsplit("/", 1)[-1]
    if w0 in CMD_NET:
        return {"read": ["*", "web"], "write": ["*", "net"]}, f"{w0}: sends data over the network"
    if w0 in CMD_NO_EXEC:
        return dict(SHELL_RW), f"{w0}: reads any file, and writes any file through redirection"
    return SHELL_ALL, f"{w0}: can run other programs (directly, through hooks, plugins or options), treated as a full shell"


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
     {"read": ["web", "*"], "write": ["net", "*"]}, "drives a web browser, which can also open and save local files"),
    (("fetch", "search", "brave", "tavily", "exa", "firecrawl", "perplexity"),
     {"read": ["web"], "write": ["net"]}, "fetches web content"),
    (("github", "gitlab", "linear", "jira", "atlassian", "slack", "notion", "gmail",
      "drive", "sentry", "discord", "telegram", "email", "calendar"),
     {"read": ["web"], "write": ["net"]}, "reads and writes a hosted service"),
]


def mcp_reach(name: str, spec: dict) -> tuple[dict, str]:
    key = (name + " " + str(spec.get("command", "")) + " " + " ".join(map(str, spec.get("args", []) or []))).lower()
    for subs, reach, desc in MCP_CATALOG:
        if any(x in key for x in subs):
            return reach, desc
    return dict(SHELL_ALL, read=["*", "web"]), "unrecognized server: assumed able to do anything"


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
                granted.append(f"{safe_rule(rule)} ({label}): any shell command without asking")
            else:
                rights, desc = shell_rights(arg, proj if path else "proj:*")
                if "shell" in f.ask or not sandbox.get("enabled"):
                    f.read += rights["read"]
                    f.write += rights["write"]
                granted.append(f"{safe_rule(rule)} ({label}): {desc}")
        elif tool in ("Read", "Glob", "Grep", "LS"):
            places = path_places(arg, proj) if arg else ["*"]
            f.read += places
            granted.append(f"{safe_rule(rule)} ({label}): reads {', '.join(places)}")
        elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
            places = path_places(arg, proj) if arg else list(edit_w)
            f.write += places
            if not arg or arg in ("*", "**"):
                f.ask.pop("edit", None)
            granted.append(f"{safe_rule(rule)} ({label}): edits {', '.join(places)}")
        elif tool in ("WebFetch", "WebSearch"):
            f.read.append("web")
            f.write.append("net")
            if not arg:
                f.ask.pop("web", None)
            granted.append(f"{safe_rule(rule)} ({label}): reads web pages and sends requests out")
        elif tool.startswith("mcp__"):
            srv = tool[5:].split("__", 1)[0]
            g = f"mcp:{srv}"
            if g in f.ask:
                open_gate(f, g)
            granted.append(f"{safe_rule(rule)} ({label}): uses MCP server {srv} without asking")
        elif tool.startswith("mcp__claude-in-chrome") or tool == "Chrome":
            open_gate(f, "chrome")
            granted.append(f"{safe_rule(rule)} ({label}): drives your Chrome without asking")
    for rule in deny:
        tool, arg = rule_arg(rule)
        if tool == "Read" and secret_for_path(arg):
            f.notes.append(f"deny {safe_rule(rule)}: blocks the Read tool only; approved shell commands can still read it")
        elif tool in ("WebFetch", "WebSearch") and not arg:
            f.ask.pop("web", None)
        elif tool.startswith("mcp__"):
            f.ask.pop(f"mcp:{tool[5:].split('__', 1)[0]}", None)
        elif tool == "Bash" and arg in ("", "*"):
            f.ask.pop("shell", None)
    for rule in ask:
        tool, _ = rule_arg(rule)
        if tool == "Bash":
            f.notes.append(f"ask {safe_rule(rule)}: still asks before this command")

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


def safe_rule(rule: str) -> str:
    """A permission rule as shown in notes: home folder as ~, token-like strings hidden, short."""
    import re as _re
    r = rule.replace("/" + str(HOME), "~").replace(str(HOME), "~").replace("//Users/", "/Users/")
    r = _re.sub(r"[A-Za-z0-9_\-+/=]{24,}", "<hidden>", r)
    return r if len(r) <= 90 else r[:87] + "..."


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
    f.coverage = "assumed"
    f.notes.append("desktop extensions and connectors are not read")
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
    f.coverage = "assumed"
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
    f.coverage = "worst"
    return f


# --- every other agent: detected, then modeled as unrestricted ---------------
# Each entry: (key, title, config paths under ~, apps, command names, editor
# extension ids). Any one signal is enough. These agents' settings are not read
# yet, so each is modeled as able to read and write everything and use the
# network without asking. A PASS therefore never depends on an unread agent.

OTHER_AGENTS = [
    ("copilot", "GitHub Copilot (VS Code agent mode)", [".config/github-copilot"], [], [],
     ["github.copilot-chat", "github.copilot"]),
    ("copilot_cli", "GitHub Copilot CLI", [".copilot"], [], ["copilot"], []),
    ("windsurf", "Windsurf Cascade (legacy agent)", [".codeium/windsurf"], ["Windsurf.app"], ["windsurf"], ["codeium.windsurf"]),
    ("gemini_cli", "Gemini CLI", [".gemini"], [], ["gemini"], []),
    ("gemini_code_assist", "Gemini Code Assist (IDE)", [], [], [], ["google.geminicodeassist"]),
    ("aider", "Aider", [".aider.conf.yml"], [], ["aider"], []),
    ("continue", "Continue", [".continue"], [], ["cn"], ["continue.continue"]),
    ("cline", "Cline", [".cline"], [], ["cline"], ["saoudrizwan.claude-dev"]),
    ("roo", "Roo Code", [], [], [], ["rooveterinaryinc.roo-cline"]),
    ("kilo", "Kilo Code", [".kilocode"], [], ["kilocode"], ["kilocode.kilo-code"]),
    ("augment", "Augment", [".augment"], [], ["auggie"], ["augment.vscode-augment"]),
    ("amazon_q", "Amazon Q Developer CLI", [".aws/amazonq"], [], ["q"], ["amazonwebservices.amazon-q-vscode"]),
    ("kiro", "Kiro", [".kiro"], ["Kiro.app"], ["kiro", "kiro-cli"], []),
    ("devin", "Devin Local / Devin CLI", [".config/devin"], ["Devin.app", "Devin Desktop.app"], ["devin"], []),
    ("zed", "Zed agent", [".config/zed"], ["Zed.app"], ["zed"], []),
    ("cursor_cli", "Cursor CLI", [], [], ["cursor-agent"], []),
    ("opencode", "OpenCode", [".config/opencode"], [], ["opencode"], []),
    ("goose", "Goose", [".config/goose"], [], ["goose"], []),
    ("amp", "Amp", [".config/amp"], [], ["amp"], ["sourcegraph.amp"]),
    ("crush", "Crush", [".config/crush"], [], ["crush"], []),
    ("qwen_code", "Qwen Code", [".qwen"], [], ["qwen"], []),
    ("factory", "Factory Droid", [".factory"], [], ["droid"], []),
    ("junie", "JetBrains Junie / AI Assistant", [], [], [], []),
    ("trae", "Trae", [".trae"], ["Trae.app"], [], []),
    ("antigravity", "Google Antigravity", [".antigravity"], ["Antigravity.app"], [], []),
    ("chatgpt", "ChatGPT desktop", [], ["ChatGPT.app"], [], ["openai.chatgpt"]),
    ("warp", "Warp agent", [".warp"], ["Warp.app"], [], []),
    ("comet", "Perplexity Comet (AI browser)", [], ["Comet.app"], [], []),
    ("atlas", "ChatGPT Atlas (AI browser)", [], ["ChatGPT Atlas.app"], [], []),
    ("dia", "Dia (AI browser)", [], ["Dia.app"], [], []),
]
EXT_DIRS = [".vscode/extensions", ".vscode-insiders/extensions", ".cursor/extensions",
            ".windsurf/extensions", ".vscode-oss/extensions", ".kiro/extensions", ".trae/extensions"]
AI_WORDS = ("copilot", "gpt", "claude", "gemini", "llm", "agent", "assistant", "codeium",
            "cody", "codex", "openai", "anthropic", "ollama", "chatbot", "aicoder", "ai-")
KNOWN_EXT = {"anthropic.claude-code"}   # modeled by its own collector
NOT_CHECKED = [
    "agents running inside containers, VMs or remote dev boxes (scan those machines too)",
    "browser extensions that act as agents",
    "cloud agents that act on your accounts from outside this Mac (e.g. hosted coding agents with repo access)",
    "agents installed under another macOS user",
]


def _which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _extensions() -> dict[str, str]:
    """Installed editor extension ids -> the editor folder they were found in."""
    out = {}
    for d in EXT_DIRS:
        base = HOME / d
        if not base.is_dir():
            continue
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for n in names:
            ext_id = n.lower().rsplit("-", 1)[0] if n[-1:].isdigit() else n.lower()
            out.setdefault(ext_id, d.split("/")[0].lstrip("."))
    return out


def worst_case(name: str, title: str, how: list[str], ctl: list[str]) -> Found:
    f = Found(name, title, read=["*", "web"], write=["*", "net"], control_paths=ctl,
              reads_project_instructions=True, uses_shell=True, coverage="worst")
    f.notes.append("found: " + "; ".join(how))
    f.notes.append("settings not read yet: modeled as able to do anything without asking")
    return f


# --- settings readers for other agents ------------------------------------------
# Each reader returns the agent's rights from its own settings and documented
# defaults, or None to fall back to "unrestricted". A reader may only narrow an
# agent below "unrestricted" for reasons it can read; anything it cannot read
# (launch flags, per-project files it cannot find, UI-only toggles) is noted.

PROJ = ["proj:*", "proj:instructions"]
WEB = {"read": ["web"], "write": ["net"]}


def parsed(name: str, title: str, how: list[str], ctl: list[str], read=(), write=(), ask=None,
           notes=(), coverage: str = "read") -> Found:
    f = Found(name, title, read=list(read), write=list(write), ask=dict(ask or {}),
              control_paths=ctl, reads_project_instructions=True, uses_shell=True, coverage=coverage)
    f.notes = ["found: " + "; ".join(how)] + list(notes)
    return f


def _open(f: Found, gate: str) -> None:
    open_gate(f, gate)


def mcp_gates(servers: dict) -> tuple[dict, list[str]]:
    gates, notes = {}, []
    for srv, spec in sorted((servers or {}).items()):
        reach, desc = mcp_reach(srv, spec if isinstance(spec, dict) else {})
        gates[f"mcp:{srv}"] = {"read": list(reach["read"]), "write": list(reach["write"])}
        notes.append(f"MCP server {srv}: {desc}")
    return gates, notes


def parse_aider(how, ctl):
    conf = {}
    for p in [HOME / ".aider.conf.yml"]:
        conf.update(load_config(p) or {})
    env = lambda k: os.environ.get("AIDER_" + k.upper().replace("-", "_"))
    val = lambda k, d: (env(k).lower() in ("1", "true", "yes")) if env(k) is not None else bool(conf.get(k, d))
    f = parsed("aider", "Aider", how, ctl, read=PROJ, write=PROJ,
               ask={"shell": dict(SHELL_ALL), "new_files": {"write": ["proj:*"]}, "web": dict(WEB)},
               notes=["edits files in the chat without asking and commits them",
                      "shell commands it suggests always ask, even with yes-always",
                      "only ~/.aider.conf.yml is read; a .aider.conf.yml in a repo can change this"])
    if val("yes-always", False):
        _open(f, "new_files")
        _open(f, "web")
        f.notes.append("yes-always: new files and adding web pages run without asking")
    if (val("auto-lint", True) and conf.get("lint-cmd")) or (val("auto-test", False) and conf.get("test-cmd")):
        _open(f, "shell")
        f.notes.append("runs your lint or test command after every edit, which runs code the agent just wrote")
    return f


def parse_continue(how, ctl, exts):
    if "continue.continue" in exts:
        return None   # the IDE's tool toggles live in webview storage this scan cannot read
    perms = load_config(HOME / ".continue/permissions.yaml") or {}
    cfg = load_config(HOME / ".continue/config.yaml") or {}
    servers = {s.get("name", f"server{i}"): s for i, s in enumerate(cfg.get("mcpServers") or []) if isinstance(s, dict)}
    mg, mn = mcp_gates(servers)
    f = parsed("continue", "Continue CLI (cn)", how, ctl, read=["*", "web"], write=["net"],
               ask={"edit": {"write": ["proj:*", "proj:instructions"]}, "shell": dict(SHELL_ALL), **mg},
               notes=["reads files, searches and fetches the web without asking",
                      "launch flags are not visible: --auto allows everything, and --readonly still allows shell and MCP"] + mn)
    for pat in perms.get("allow") or []:
        tool = str(pat).split("(", 1)[0].strip()
        if tool in ("*",):
            for g in list(f.ask):
                _open(f, g)
        elif tool in ("Bash", "Shell"):
            _open(f, "shell")
        elif tool in ("Edit", "MultiEdit", "Write"):
            _open(f, "edit")
        f.notes.append(f"allowed without asking: {pat}")
    for pat in perms.get("exclude") or []:
        tool = str(pat).split("(", 1)[0].strip()
        if tool in ("Bash", "Shell") and "(" not in str(pat):
            f.ask.pop("shell", None)
        if tool in ("Edit", "MultiEdit", "Write") and "(" not in str(pat):
            f.ask.pop("edit", None)
    return f


def _last_match(rules: dict, cmd: str):
    """OpenCode pattern maps: the last matching pattern wins."""
    out = None
    for pat, act in rules.items():
        if fnmatch.fnmatchcase(cmd, pat):
            out = act
    return out


def parse_opencode(how, ctl):
    cfg = {}
    for p in (HOME / ".config/opencode/opencode.json", HOME / ".config/opencode/opencode.jsonc"):
        if p.exists():
            cfg = load_config(p) or {}
    perm = dict(cfg.get("permission") or {})
    try:
        perm.update(json.loads(os.environ.get("OPENCODE_PERMISSION", "") or "{}"))
    except ValueError:
        pass
    default = perm.get("*", "allow") if isinstance(perm.get("*", "allow"), str) else "allow"
    get = lambda k: perm.get(k, default)
    mg, mn = mcp_gates(cfg.get("mcp") or {})
    f = parsed("opencode", "OpenCode", how, ctl, read=PROJ, write=[],
               ask={"edit": {"write": list(PROJ)}, "shell": dict(SHELL_ALL), "web": dict(WEB),
                    "outside": {"read": ["*"], "write": ["*"]}, **mg},
               notes=["by default every tool runs without asking, except reaching outside the project",
                      "a project opencode.json, managed config or a per-agent permission can change this; only the global file and OPENCODE_PERMISSION are read"] + mn)
    plain = lambda v: v if isinstance(v, str) else None
    for key, gate in (("edit", "edit"), ("webfetch", "web"), ("websearch", "web")):
        if plain(get(key)) == "allow":
            _open(f, gate)
    bash = get("bash")
    if plain(bash) == "allow" or (isinstance(bash, dict) and _last_match(bash, "anything") == "allow"):
        _open(f, "shell")
    elif isinstance(bash, dict):
        for pat, act in bash.items():
            if act == "allow" and pat.strip() not in ("*",):
                rights, desc = shell_rights(pat)
                f.read += rights["read"]
                f.write += rights["write"]
                f.notes.append(f"bash {pat!r} runs without asking: {desc}")
    if plain(get("external_directory")) == "allow":
        _open(f, "outside")
    if default == "allow":
        for g in [g for g in f.ask if g.startswith("mcp:")]:
            _open(f, g)
    f.notes.append("permission: " + ", ".join(f"{k}={v if isinstance(v, str) else 'patterns'}" for k, v in sorted(perm.items())) if perm else "permission: defaults (everything allowed)")
    return f


GOOSE_BUILTIN = {"developer": (SHELL_ALL, "shell and file editing"),
                 "computercontroller": ({"read": ["web", "*"], "write": ["net", "*"]}, "web scraping and app automation"),
                 "memory": ({"read": [], "write": []}, "notes it keeps for itself")}


def parse_goose(how, ctl):
    root = Path(os.environ.get("GOOSE_PATH_ROOT", str(HOME / ".config/goose")))
    cfg = load_config(root / "config.yaml") or {}
    mode = os.environ.get("GOOSE_MODE") or cfg.get("GOOSE_MODE") or "auto"
    perms = ((load_config(root / "permission.yaml") or {}).get("user") or {})
    gates, notes = {}, []
    for ext, spec in sorted((cfg.get("extensions") or {}).items()):
        spec = spec if isinstance(spec, dict) else {}
        if spec.get("enabled") is False:
            continue
        if spec.get("type") == "builtin" or ext in GOOSE_BUILTIN:
            reach, desc = GOOSE_BUILTIN.get(ext, (SHELL_ALL, "built-in extension"))
        else:
            reach, desc = mcp_reach(ext, {"command": spec.get("cmd", ""), "args": spec.get("args", []),
                                          "url": spec.get("uri") or spec.get("url")})
        gates[f"ext:{ext}"] = {"read": list(reach["read"]), "write": list(reach["write"])}
        notes.append(f"extension {ext}: {desc}")
    if not cfg.get("extensions"):
        gates["ext:developer"] = dict(SHELL_ALL)
        notes.append("extension developer (default): shell and file editing")
    f = parsed("goose", "Goose", how, ctl, read=PROJ, write=[], ask=gates,
               notes=[f"mode: {mode}"] + notes + ["the mode can also be changed mid-session with /mode"])
    if mode == "chat":
        f.ask.clear()
        f.notes.append("chat mode: no tools")
    elif mode in ("auto", "smart_approve"):
        for g in list(f.ask):
            _open(f, g)
        f.notes.append("auto mode runs every tool without asking and ignores permission.yaml" if mode == "auto"
                       else "smart_approve lets a model decide which calls need you; treated as no approval")
    else:
        for tool in perms.get("always_allow") or []:
            g = "ext:" + str(tool).split("__", 1)[0]
            if g in f.ask:
                _open(f, g)
                f.notes.append(f"always allowed: {tool}")
    return f


def _regex_prefix(rx: str) -> str | None:
    """A Zed always_allow regex reduced to the command prefix it allows, if it has one."""
    if not rx.startswith("^"):
        return None
    lit = re.match(r"[A-Za-z0-9_./ \-]+", rx[1:])
    return lit.group(0).strip() if lit and lit.group(0).strip() else None


def parse_zed(how, ctl):
    import re as _re  # noqa: F401
    s = load_config(HOME / ".config/zed/settings.json") or {}
    agent = s.get("agent") or {}
    mg, mn = mcp_gates(s.get("context_servers") or {})
    f = parsed("zed", "Zed agent", how, ctl, read=["*"], write=[],
               ask={"terminal": dict(SHELL_ALL), "edit": {"write": list(PROJ)}, "fetch": dict(WEB), **mg},
               notes=["reads files without asking (assumed: any file it can open)",
                      "terminal, edits, fetch and MCP tools ask by default",
                      "only ~/.config/zed/settings.json is read; project .zed/settings.json is not"] + mn)
    profile = agent.get("default_profile", "write")
    if profile == "minimal":
        f.ask.clear()
        f.read = []
    elif profile == "ask":
        for g in [g for g in f.ask if g not in ("fetch",)]:
            f.ask.pop(g)
    tp = agent.get("tool_permissions") or {}
    if agent.get("always_allow_tool_actions") or tp.get("default") == "allow":
        for g in list(f.ask):
            _open(f, g)
        f.notes.append("tool actions run without asking")
    tools = tp.get("tools") or {}
    for tool, gate in (("terminal", "terminal"), ("edit_file", "edit"), ("write_file", "edit"), ("fetch", "fetch"),
                       ("search_web", "fetch")):
        t = tools.get(tool) or {}
        if t.get("default") == "allow" and gate in f.ask:
            _open(f, gate)
        elif tool == "terminal" and gate in f.ask:
            for rule in t.get("always_allow") or []:
                rx = rule.get("pattern", "") if isinstance(rule, dict) else str(rule)
                pre = _regex_prefix(rx)
                rights, desc = shell_rights(pre) if pre else (SHELL_ALL, "pattern without a fixed start: any command")
                f.read += rights["read"]
                f.write += rights["write"]
                f.notes.append(f"terminal {rx!r} runs without asking: {desc}")
    f.notes.append(f"profile: {profile}")
    return f


def parse_devin(how, ctl):
    """Devin Local / Devin CLI (Devin Desktop's default agent, formerly Windsurf)."""
    layers = [load_config(HOME / ".config/devin/config.json") or {}]
    allow, ask_r, deny = [], [], []
    for d in layers:
        p = d.get("permissions") or {}
        allow += p.get("allow") or []
        ask_r += p.get("ask") or []
        deny += p.get("deny") or []
    mcp = {}
    for p in (HOME / ".config/devin/mcp_config.json", HOME / ".codeium/windsurf/mcp_config.json"):
        mcp.update((load_config(p) or {}).get("mcpServers") or {})
    mg, mn = mcp_gates(mcp)
    mode = os.environ.get("DEVIN_PERMISSION_MODE", "normal").lower()
    f = parsed("devin", "Devin Local / Devin CLI (Devin Desktop, formerly Windsurf)", how, ctl,
               read=["*"], write=[],
               ask={"exec": dict(SHELL_ALL), "edit": {"write": list(PROJ)}, "fetch": dict(WEB), **mg},
               notes=["reads, grep and glob run without asking (assumed: any file)",
                      "commands, web fetches and edits ask in normal mode",
                      "project .devin/config.json and launch flags (--permission-mode) are not read"] + mn)
    for rule in allow:
        tool, arg = rule_arg(str(rule))
        t = tool.lower()
        if t == "exec":
            if arg:
                rights, desc = shell_rights(arg)
                f.read += rights["read"]
                f.write += rights["write"]
                f.notes.append(f"{rule}: {desc}")
            else:
                _open(f, "exec")
        elif t in ("write", "edit"):
            f.write += path_places(arg, "proj:*") if arg else list(PROJ)
        elif t == "fetch":
            f.read.append("web")
            f.write.append("net")
        elif t.startswith("mcp__"):
            srv = t[5:].split("__", 1)[0]
            for g in [g for g in f.ask if g.startswith("mcp:") and (srv == "*" or g == f"mcp:{srv}")]:
                _open(f, g)
        f.notes.append(f"allowed without asking: {rule}")
    if mode in ("bypass", "autonomous"):
        for g in list(f.ask):
            _open(f, g)
        f.notes.append(f"{mode} mode: everything runs without asking")
    elif mode in ("accept_edits", "acceptedits", "accept-edits"):
        _open(f, "edit")
    return f


def parse_cline(how, ctl):
    base = Path(os.environ.get("CLINE_DATA_DIR") or os.environ.get("CLINE_DIR", str(HOME / ".cline")) + "/data")
    st = (load_config(base / "globalState.json") or {}).get("autoApprovalSettings") or {}
    acts = {"readFiles": True, "editFiles": True, "executeSafeCommands": False, "useBrowser": True, "useMcp": True}
    acts.update(st.get("actions") or {})
    enabled = st.get("enabled", True)
    mcp_path = Path(os.environ.get("CLINE_MCP_SETTINGS_PATH", str(base / "settings/cline_mcp_settings.json")))
    servers = {k: v for k, v in ((load_config(mcp_path) or {}).get("mcpServers") or {}).items()
               if not (isinstance(v, dict) and v.get("disabled"))}
    mg, mn = mcp_gates(servers)
    f = parsed("cline", "Cline", how, ctl, read=list(PROJ), write=[],
               ask={"read": {"read": ["*"]}, "edit": {"write": ["*"]}, "shell": dict(SHELL_ALL),
                    "browser": dict(WEB), **mg},
               notes=["settings: " + ("~/.cline/data/globalState.json" if st else "Cline's defaults (no saved settings found)")] + mn)
    if enabled:
        for key, gates in (("readFiles", ["read"]), ("editFiles", ["edit"]), ("executeSafeCommands", ["shell"]),
                           ("useBrowser", ["browser"]), ("useMcp", [g for g in f.ask if g.startswith("mcp:")])):
            if acts.get(key):
                for g in gates:
                    _open(f, g)
                f.notes.append(f"{key}: without asking")
    if _which("cline"):
        for g in list(f.ask):
            _open(f, g)
        f.notes.append("the cline command auto-approves everything unless run with --auto-approve false")
    if os.environ.get("CLINE_COMMAND_PERMISSIONS"):
        f.notes.append("CLINE_COMMAND_PERMISSIONS is set in this shell; it can only restrict commands")
    return f


def parse_kiro(how, ctl):
    home = Path(os.environ.get("KIRO_HOME", str(HOME / ".kiro")))
    ide = load_config(APP_SUPPORT / "Kiro/User/settings.json") or {}
    autonomy = ide.get("kiroAgent.agentAutonomy", "Autopilot")
    servers = {k: v for k, v in ((load_config(home / "settings/mcp.json") or {}).get("mcpServers") or {}).items()
               if not (isinstance(v, dict) and v.get("disabled"))}
    mg, mn = mcp_gates(servers)
    f = parsed("kiro", "Kiro", how, ctl, read=list(PROJ), write=[],
               ask={"fs_read": {"read": ["*"]}, "fs_write": {"write": ["*"]}, "shell": dict(SHELL_ALL),
                    "web": dict(WEB), **mg},
               notes=[f"IDE autonomy: {autonomy}"] + mn +
                     ["workspace permission files and --trust-all-tools / --trust-tools flags are not read"])
    for srv, spec in servers.items():
        if isinstance(spec, dict) and spec.get("autoApprove"):
            _open(f, f"mcp:{srv}")
            f.notes.append(f"MCP server {srv}: auto-approved tools {spec['autoApprove']}")
    cap_gate = {"fs_read": ["fs_read"], "fs_write": ["fs_write"], "shell": ["shell"], "web_fetch": ["web"],
                "web_search": ["web"], "mcp": [g for g in f.ask if g.startswith("mcp:")], "all": list(f.ask)}
    for rule in (load_config(home / "settings/permissions.yaml") or {}).get("rules") or []:
        if not isinstance(rule, dict) or rule.get("effect") != "allow":
            continue
        cap = rule.get("capability")
        if cap == "shell" and rule.get("match"):
            for m in rule["match"]:
                rights, desc = shell_rights(str(m))
                f.read += rights["read"]
                f.write += rights["write"]
                f.notes.append(f"shell {m!r} allowed: {desc}")
        else:
            for g in cap_gate.get(cap, []):
                if g in f.ask:
                    _open(f, g)
            f.notes.append(f"allowed: {cap} {rule.get('match') or ''}".strip())
    if (APP_SUPPORT / "Kiro").exists() or (Path("/Applications/Kiro.app")).exists():
        if str(autonomy).lower() != "supervised":
            for g in ("fs_write", "shell"):
                if g in f.ask:
                    _open(f, g)
            f.notes.append("Autopilot (the default) edits files and runs commands without asking")
    return f


def parse_amazon_q(how, ctl):
    agents_dir = HOME / ".aws/amazonq/cli-agents"
    agent = load_config(agents_dir / "default.json") or {}
    allowed = agent.get("allowedTools", ["fs_read"]) if agent else ["fs_read"]
    servers = (load_config(HOME / ".aws/amazonq/mcp.json") or {}).get("mcpServers") or {}
    mg, mn = mcp_gates(servers)
    f = parsed("amazon_q", "Amazon Q Developer CLI", how, ctl, read=[], write=[],
               ask={"fs_read": {"read": ["*"]}, "fs_write": {"write": ["*"]}, "execute_bash": dict(SHELL_ALL),
                    "use_aws": {"read": ["web"], "write": ["net"]}, **mg},
               notes=["custom agents in ~/.aws/amazonq/cli-agents other than default.json, and /tools trust-all, are not read"] + mn)
    for t in allowed:
        t = str(t)
        if t in ("*", "@builtin"):
            for g in [g for g in f.ask if not g.startswith("mcp:")] if t == "@builtin" else list(f.ask):
                _open(f, g)
        elif t in f.ask:
            _open(f, t)
        elif t.startswith("@"):
            srv = t[1:].split("/", 1)[0]
            if f"mcp:{srv}" in f.ask:
                _open(f, f"mcp:{srv}")
        f.notes.append(f"trusted without asking: {t}")
    bash = ((agent.get("toolsSettings") or {}).get("execute_bash") or {})
    for rx in bash.get("allowedCommands") or []:
        pre = _regex_prefix("^" + str(rx).replace("\\A", "").lstrip("^"))
        rights, desc = shell_rights(pre) if pre else (SHELL_ALL, "pattern: any command")
        f.read += rights["read"]
        f.write += rights["write"]
        f.notes.append(f"command {rx!r} trusted: {desc}")
    return f


VSCODE_USER = APP_SUPPORT / "Code/User"


def _key_prefix(k: str) -> str | None:
    """A VS Code terminal auto-approve key reduced to the command prefix it allows."""
    if k.startswith("/"):
        body = k[1:k.rfind("/")] if k.rfind("/") > 0 else k[1:]
        return _regex_prefix(body if body.startswith("^") else "x" + body)  # unanchored regex: no prefix
    return k.strip() or None


def parse_copilot(how, ctl):
    """GitHub Copilot agent mode in VS Code."""
    s = load_config(VSCODE_USER / "settings.json") or {}
    g = lambda k, d=None: s.get(k, d)
    servers = (load_config(VSCODE_USER / "mcp.json") or {}).get("servers") or {}
    mg, mn = mcp_gates(servers)
    f = parsed("copilot", "GitHub Copilot (VS Code agent mode)", how, ctl,
               read=list(PROJ), write=["proj:*", "proj:instructions"],
               ask={"terminal": dict(SHELL_ALL), "fetch": dict(WEB), "read_outside": {"read": ["*"]},
                    "sensitive_edits": {"write": ["ctl:*"]}, **mg},
               notes=["edits workspace files without asking, except sensitive ones (.vscode, .mcp.json, agent settings)",
                      "a repo's .vscode/settings.json can add terminal auto-approve rules; those are not read here",
                      "'allow in this session/workspace' approvals live in VS Code storage and are not read"] + mn)
    if g("chat.tools.terminal.enableAutoApprove", True):
        if not g("chat.tools.terminal.ignoreDefaultAutoApproveRules", False):
            f.read.append("*")                          # cat, head, grep, find, rg ... run without asking
            f.notes.append("built-in rules run cat, grep, find, sed, git log and similar without asking: reads any file")
        if g("chat.tools.terminal.autoApproveWorkspaceNpmScripts", True):
            _open(f, "terminal")
            f.notes.append("npm/yarn/pnpm run <script> runs without asking (default), and the agent can edit the files "
                           "those scripts run: any code")
        for k, v in (g("chat.tools.terminal.autoApprove") or {}).items():
            ok = v is True or (isinstance(v, dict) and v.get("approve") is True)
            if not ok or "terminal" not in f.ask:
                continue
            pre = _key_prefix(str(k))
            rights, desc = shell_rights(pre) if pre else (SHELL_ALL, "pattern without a fixed start: any command")
            f.read += rights["read"]
            f.write += rights["write"]
            f.notes.append(f"terminal {k!r} runs without asking: {desc}")
    if any(v is True or (isinstance(v, dict) and v.get("approveRequest")) for v in (g("chat.tools.urls.autoApprove") or {}).values()):
        f.read.append("web")
        f.write.append("net")
        f.notes.append("some URLs are fetched without asking")
    glob_ = g("chat.tools.global.autoApprove")
    if glob_ is True or g("chat.permissions.default") in ("autoApprove", "autopilot") or \
            (g("chat.defaultConfiguration") or {}).get("approvals") == "allowAll":
        for x in list(f.ask):
            _open(f, x)
        f.notes.append("approvals are bypassed: every tool runs without asking")
    if str(g("chat.agent.sandbox.enabled", "off")).lower() in ("on", "true") and g("chat.agent.sandbox.mcpServers", True):
        for x in [x for x in f.ask if x.startswith("mcp:")]:
            _open(f, x)
        f.notes.append("sandboxed MCP servers' tools run without asking")
    return f


def parse_copilot_cli(how, ctl):
    home = Path(os.environ.get("COPILOT_HOME", str(HOME / ".copilot")))
    s = load_config(home / "settings.json") or {}
    servers = (load_config(home / "mcp-config.json") or {}).get("mcpServers") or {}
    mg, mn = mcp_gates(servers)
    f = parsed("copilot_cli", "GitHub Copilot CLI", how, ctl, read=list(PROJ), write=[],
               ask={"write": {"write": list(PROJ)}, "shell": dict(SHELL_ALL), "url": dict(WEB),
                    "outside": {"read": ["*"], "write": ["*"]}, **mg},
               notes=["reads, search and read-only shell commands in the working folder run without asking",
                      "launch flags (--allow-tool, --allow-all, --yolo) and saved approvals in permissions-config.json are not read"] + mn)
    if s.get("allowedUrls"):
        f.read.append("web")
        f.write.append("net")
        f.notes.append(f"URLs fetched without asking: {', '.join(map(str, s['allowedUrls']))[:120]}")
    if s.get("defaultPermissionMode") == "allow-all" or os.environ.get("COPILOT_ALLOW_ALL"):
        for x in list(f.ask):
            _open(f, x)
        f.notes.append("allow-all: every tool runs without asking")
    return f


def parse_gemini(how, ctl):
    home = Path(os.environ.get("GEMINI_CLI_HOME", str(HOME / ".gemini")))
    s = {}
    for p in (Path("/Library/Application Support/GeminiCli/system-defaults.json"), home / "settings.json",
              Path("/Library/Application Support/GeminiCli/settings.json")):
        for k, v in (load_config(p) or {}).items():
            s[k] = {**s[k], **v} if isinstance(v, dict) and isinstance(s.get(k), dict) else v
    tools, mcp = s.get("tools") or {}, s.get("mcp") or {}
    servers = s.get("mcpServers") or {}
    mg, mn = mcp_gates(servers)
    f = parsed("gemini_cli", "Gemini CLI", how, ctl, read=list(PROJ) + ["web"], write=["net"],
               ask={"shell": dict(SHELL_ALL), "edit": {"write": list(PROJ)}, "web_fetch": dict(WEB), **mg},
               notes=["reads workspace files and runs Google web searches without asking: it reads the web, and its queries leave the machine",
                      "project .gemini/settings.json (trusted folders) and launch flags such as --yolo are not read"] + mn)
    allow = list(tools.get("allowed") or []) + list(tools.get("core") or [])
    for t in allow:
        tool, arg = rule_arg(str(t))
        if tool == "run_shell_command":
            if arg:
                rights, desc = shell_rights(arg)
                f.read += rights["read"]
                f.write += rights["write"]
                f.notes.append(f"{t}: {desc}")
            else:
                _open(f, "shell")
        elif tool in ("write_file", "replace", "edit"):
            _open(f, "edit")
        elif tool == "web_fetch":
            _open(f, "web_fetch")
        f.notes.append(f"allowed without asking: {t}")
    if tools.get("core"):
        named = {rule_arg(str(t))[0] for t in tools["core"]}
        for x, tool in (("shell", "run_shell_command"), ("web_fetch", "web_fetch")):
            if tool not in named:
                f.ask.pop(x, None)
        if "google_web_search" not in named:
            f.read.remove("web")
            f.write.remove("net")
        f.notes.append("tools.core: only the listed tools exist")
    allowed_srv = mcp.get("allowed") or []
    for srv, spec in servers.items():
        if "*" in allowed_srv or srv in allowed_srv or (isinstance(spec, dict) and spec.get("trust")):
            _open(f, f"mcp:{srv}")
            f.notes.append(f"MCP server {srv}: trusted, its tools run without asking")
    if (s.get("general") or {}).get("defaultApprovalMode") == "auto_edit":
        _open(f, "edit")
        _open(f, "web_fetch")
        f.notes.append("auto_edit: edits and web fetches run without asking")
    pol_dir = home / "policies"
    pols = sorted(pol_dir.glob("*.toml")) if pol_dir.is_dir() else []
    if pols:
        if tomllib is None:
            raise RuntimeError("policy files need Python 3.11+ to read")
        for p in pols:
            with open(p, "rb") as fh:
                for rule in tomllib.load(fh).get("rule") or []:
                    if rule.get("decision") != "allow":
                        continue
                    name = rule.get("toolName") or ""
                    if rule.get("mcpName"):
                        g = f"mcp:{rule['mcpName']}"
                        if g in f.ask:
                            _open(f, g)
                    elif name == "run_shell_command":
                        pre = rule.get("commandPrefix")
                        pres = pre if isinstance(pre, list) else [pre] if pre else []
                        if not pres:
                            _open(f, "shell")
                        for x in pres:
                            rights, desc = shell_rights(str(x))
                            f.read += rights["read"]
                            f.write += rights["write"]
                    elif name in ("write_file", "replace"):
                        _open(f, "edit")
                    elif name == "web_fetch":
                        _open(f, "web_fetch")
                    elif name == "*" or not name:
                        for x in list(f.ask):
                            _open(f, x)
                    f.notes.append(f"policy {p.name}: allows {name or rule.get('mcpName')}")
    return f


PARSERS = {"aider": parse_aider, "continue": parse_continue, "opencode": parse_opencode, "goose": parse_goose,
           "zed": parse_zed, "devin": parse_devin, "cline": parse_cline, "kiro": parse_kiro,
           "amazon_q": parse_amazon_q, "copilot": parse_copilot, "copilot_cli": parse_copilot_cli,
           "gemini_cli": parse_gemini}


def other_agents() -> list[Found]:
    exts = _extensions()
    apps = lambda a: (Path("/Applications") / a).exists() or (HOME / "Applications" / a).exists()
    found, claimed = [], set(KNOWN_EXT)
    for key, title, paths, app_names, cmds, ext_ids in OTHER_AGENTS:
        how = [f"~/{p}" for p in paths if exists(p)]
        how += [f"/Applications/{a}" for a in app_names if apps(a)]
        how += [f"`{c}` command" for c in cmds if _which(c)]
        for e in ext_ids:
            if e in exts:
                how.append(f"{e} extension in {exts[e]}")
                claimed.add(e)
        if key == "junie":
            jb = APP_SUPPORT / "JetBrains"
            if jb.is_dir() and any((x / "plugins").is_dir() and any(n.lower().startswith(("junie", "ml-llm", "fullline"))
                                   for n in os.listdir(x / "plugins")) for x in jb.iterdir() if x.is_dir()):
                how.append("JetBrains AI plugin")
        if how:
            ctl = [f"~/{p}" for p in paths]
            f = None
            if key in PARSERS:
                try:
                    fn = PARSERS[key]
                    f = fn(how, ctl, exts) if fn is parse_continue else fn(how, ctl)
                except Exception as e:   # a reader that fails never narrows the agent
                    f = None
                    how = how + [f"settings reader failed ({type(e).__name__})"]
            found.append(f or worst_case(key, title, how, ctl))
    for e, editor in sorted(exts.items()):
        if e in claimed or not any(w in e for w in AI_WORDS):
            continue
        name = "ext_" + "".join(c if c.isalnum() else "_" for c in e)[:40]
        found.append(worst_case(name, f"Unrecognized AI extension {e}", [f"extension in {editor}"], []))
    return found


def coverage_report(found: list[Found]) -> dict:
    return {"read": [f.title for f in found if f.coverage == "read"],
            "assumed": [f.title for f in found if f.coverage == "assumed"],
            "worst": [f.title for f in found if f.coverage == "worst"],
            "not_checked": NOT_CHECKED}


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
    found = claude_code(None) + [x for x in (claude_desktop(), codex(), cursor(), openclaw(False)) if x] + other_agents()
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
        "coverage": coverage_report(found),
    }
    text = json.dumps(out, indent=1).replace(str(Path.home()), "~")
    if "--print" in sys.argv[1:]:
        print(text)
        return
    import subprocess
    try:
        subprocess.run(["pbcopy"], input=text.encode(), check=True)
    except Exception:
        print(text)          # no clipboard (e.g. Linux): print it; save with > scan.json
        return
    n, w = len(out["agents"]), len(out["coverage"]["worst"])
    print(f"Copied: {n} agent{'s' if n != 1 else ''} found" + (f", {w} modeled as unrestricted because their settings are not read yet" if w else "")
          + ". Paste it into the page at https://sherlocksec.org")


if __name__ == "__main__":
    main()
