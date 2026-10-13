"""Settings readers for other agents: run the single-file scanner on fake home
folders and check what each agent is allowed to do without asking."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

SCANNER = Path("web/agentcheck_scan.py").resolve()
AGENTWATCH = Path("agentwatch").resolve()
fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


def fake_home(files: dict, cmds=(), env=None) -> tuple[Path, dict]:
    """A temporary home folder with these files (None = a folder; @HOME@ in content
    = the folder's path) and fake commands; returns it and the environment to use."""
    home = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            p.mkdir(exist_ok=True)
        else:
            text = content if isinstance(content, str) else json.dumps(content)
            p.write_text(text.replace("@HOME@", str(home)))
    bin_ = home / "bin"
    bin_.mkdir()
    for c in cmds:
        (bin_ / c).write_text("#!/bin/sh\n")
        (bin_ / c).chmod(0o755)
    e = {"HOME": str(home), "PATH": f"{bin_}:/usr/bin:/bin"}
    e.update(env or {})
    return home, e


def run_json(argv, env) -> dict:
    out = subprocess.run(argv, env=env, capture_output=True, text=True)
    if out.returncode != 0:
        print("  (crashed:", out.stderr.strip().splitlines()[-1:] or out.returncode, ")")
        return {"agents": {}, "resources": {}, "coverage": {"worst": []}, "crashed": True}
    return json.loads(out.stdout)


def scan(files: dict, cmds=(), env=None) -> dict:
    home, e = fake_home(files, cmds, env)
    return run_json([sys.executable, str(SCANNER), "--print"], e)


def aw_run(files: dict, code: str, cmds=()) -> dict:
    """Run code with agentwatch imported as aw, on a fake home; code prints JSON.
    For the parts the web scanner does not carry (watch, hardening plan)."""
    home, e = fake_home(files, cmds, {"CADICAL": os.environ.get("CADICAL") or shutil.which("cadical") or "cadical"})
    prog = f"import json, sys\nsys.path.insert(0, {str(AGENTWATCH)!r})\nimport agentwatch as aw\nH = {str(home)!r}\n" + code
    return run_json([sys.executable, "-c", prog], e)


def agent(d, name):
    return d["agents"].get(name)


def free(a):            # can it use a shell / run anything without asking?
    return "net" in a["write"] and any(w.startswith(("secret", "shell_rc", "ctl:")) for w in a["write"]) or \
        ("net" in a["write"] and "proj:src" in a["write"])


# --- Goose: auto by default runs everything; approve mode asks ----------------------
a = agent(scan({}, cmds=["goose"]), "goose")
expect(a and "net" in a["write"] and not a["ask"], "goose default (auto) runs every tool without asking")
a = agent(scan({".config/goose/config.yaml": "GOOSE_MODE: approve\n"}, cmds=["goose"]), "goose")
expect(a and "ext:developer" in a["ask"] and "net" not in a["write"], "goose approve mode asks")
a = agent(scan({".config/goose/config.yaml": "GOOSE_MODE: approve\n",
                ".config/goose/permission.yaml": "user:\n  always_allow: [developer__shell]\n"}, cmds=["goose"]), "goose")
expect(a and "ext:developer" not in a["ask"] and "net" in a["write"], "goose always_allow opens the extension")
a = agent(scan({".config/goose/config.yaml": "GOOSE_MODE: approve\n"}, cmds=["goose"], env={"GOOSE_MODE": "auto"}), "goose")
expect(a and not a["ask"], "GOOSE_MODE env wins over the config file")

# --- OpenCode: everything allowed by default -----------------------------------------
a = agent(scan({}, cmds=["opencode"]), "opencode")
expect(a and "shell" not in a["ask"] and "net" in a["write"], "opencode default allows bash")
a = agent(scan({".config/opencode/opencode.json": {"permission": {"*": "ask", "bash": {"*": "ask", "git status*": "allow"}}}},
               cmds=["opencode"]), "opencode")
expect(a and "shell" in a["ask"] and "edit" in a["ask"], "opencode ask rules keep approvals")
expect(a and "proj:src" in a["write"], "an allowed git pattern still counts as a full shell (git can run hooks)")

# --- Zed: asks by default; always_allow_tool_actions opens everything ---------------------
a = agent(scan({".config/zed/settings.json": "{ // comment\n \"agent\": {}, }"}), "zed")
expect(a and "terminal" in a["ask"] and "net" not in a["write"], "zed asks before the terminal by default")
a = agent(scan({".config/zed/settings.json": {"agent": {"always_allow_tool_actions": True}}}), "zed")
expect(a and not a["ask"], "zed always_allow_tool_actions")
a = agent(scan({".config/zed/settings.json": {"agent": {"tool_permissions": {"tools": {"terminal": {
    "always_allow": [{"pattern": "status"}]}}}}}}), "zed")
expect(a and "net" in a["write"], "an unanchored regex allows any command")

# --- Aider ------------------------------------------------------------------------
a = agent(scan({}, cmds=["aider"]), "aider")
expect(a and "shell" in a["ask"] and "web" in a["ask"], "aider asks before shell and web by default")
a = agent(scan({".aider.conf.yml": "yes-always: true\nauto-test: true\ntest-cmd: pytest\n"}, cmds=["aider"]), "aider")
expect(a and "shell" not in a["ask"] and "web" not in a["ask"], "auto-test runs agent-written code; yes-always opens web")

# --- Cline: defaults approve everything but commands ------------------------------------
a = agent(scan({".cline": None}), "cline")
expect(a and "shell" in a["ask"] and "read" not in a["ask"] and "browser" not in a["ask"], "cline defaults")
a = agent(scan({".cline/data/globalState.json": {"autoApprovalSettings": {"enabled": False}}}), "cline")
expect(a and {"shell", "read", "edit", "browser"} <= set(a["ask"]), "cline master switch off")
a = agent(scan({".cline": None}, cmds=["cline"]), "cline")
expect(a and not a["ask"], "the cline CLI auto-approves by default")

# --- Kiro, Amazon Q, Devin ------------------------------------------------------------------
a = agent(scan({".kiro/settings/permissions.yaml": "rules:\n  - capability: web_fetch\n    effect: allow\n"}, cmds=["kiro-cli"]), "kiro")
expect(a and "web" not in a["ask"] and "shell" in a["ask"], "kiro CLI permission rules")
a = agent(scan({".aws/amazonq": None}, cmds=["q"]), "amazon_q")
expect(a and "fs_read" not in a["ask"] and "execute_bash" in a["ask"], "amazon q trusts reads only")
a = agent(scan({".config/devin": None}, env={"DEVIN_PERMISSION_MODE": "bypass"}), "devin")
expect(a and not a["ask"], "devin bypass mode")
a = agent(scan({".config/devin/config.json": {"permissions": {"allow": ["Fetch(domain:docs.python.org)"]}}}), "devin")
expect(a and "web" in a["read"] and "exec" in a["ask"], "devin allow rules")

# --- Continue: IDE extension unreadable -> unrestricted; CLI parsed ----------------------------
d = scan({".continue": None, ".vscode/extensions/continue.continue-1.2.0": None})
expect(d["agents"]["continue"]["notes"][-1].startswith("settings not read"), "Continue IDE stays unrestricted")
a = agent(scan({".continue/permissions.yaml": "allow:\n  - Bash\n"}, cmds=["cn"]), "continue")
expect(a and "shell" not in a["ask"] and "web" in a["read"], "cn permissions.yaml")

# --- GitHub Copilot in VS Code -------------------------------------------------------
VS = "Library/Application Support/Code/User/settings.json"
d = scan({".vscode/extensions/github.copilot-chat-0.40.0": None})
a = agent(d, "copilot")
expect(a and "terminal" not in a["ask"] and "shell_rc" in a["read"], "copilot default: npm scripts run code; cat reads anything")
a = agent(scan({".vscode/extensions/github.copilot-chat-0.40.0": None,
                VS: '{"chat.tools.terminal.autoApproveWorkspaceNpmScripts": false, "chat.tools.terminal.ignoreDefaultAutoApproveRules": true,}'}), "copilot")
expect(a and "terminal" in a["ask"] and "shell_rc" not in a["read"] and "fetch" in a["ask"], "copilot locked down")
a = agent(scan({".vscode/extensions/github.copilot-chat-0.40.0": None,
                VS: {"chat.tools.terminal.autoApproveWorkspaceNpmScripts": False, "chat.tools.global.autoApprove": True}}), "copilot")
expect(a and not a["ask"], "copilot YOLO")

# --- Copilot CLI, Gemini CLI -----------------------------------------------------------
a = agent(scan({".copilot/settings.json": {"defaultPermissionMode": "allow-all"}}, cmds=["copilot"]), "copilot_cli")
expect(a and not a["ask"], "copilot cli allow-all")
a = agent(scan({".copilot": None}, cmds=["copilot"]), "copilot_cli")
expect(a and "shell" in a["ask"] and "web" not in a["read"], "copilot cli defaults")
a = agent(scan({".gemini": None}, cmds=["gemini"]), "gemini_cli")
expect(a and "web" in a["read"] and "net" in a["write"] and "shell" in a["ask"], "gemini searches the web without asking")
a = agent(scan({".gemini/settings.json": {"tools": {"allowed": ["run_shell_command(git status)"]},
                                          "mcpServers": {"x": {"command": "node", "trust": True}}}}, cmds=["gemini"]), "gemini_cli")
expect(a and "mcp:x" not in a["ask"] and "shell" in a["ask"], "gemini trusted MCP server")
a = agent(scan({".gemini/policies/mine.toml": '[[rule]]\ntoolName = "run_shell_command"\ndecision = "allow"\n'}, cmds=["gemini"]), "gemini_cli")
expect(a and "shell" not in a["ask"], "gemini policy file allowing every shell command")

# --- Claude Code: exact Bash rules allow only that command -----------------------------
def claude(allow, extra=None, deny=(), settings=None):
    files = {".claude/settings.json": {"permissions": {"allow": allow, "deny": list(deny)}, **(settings or {})}}
    files.update(extra or {})
    return agent(scan(files), "claude_code")


a = claude(['Bash(echo "YES")', 'Bash([ -f "$CFG" ])', "Bash(pwd)"])
expect(a and "secret:ssh" not in a["read"] and "shell_rc" not in a["write"] and "net" not in a["write"],
       f"exact print/test rules grant nothing: {a and (a['read'], a['write'])}")
a = claude(["Bash(cat ~/.ssh/id_rsa)"])
expect(a and "secret:ssh" in a["read"] and "net" not in a["write"], "exact cat reads only the named file")
a = claude(["Bash(cat src/main.py)"], {".ssh/id_rsa": "x"})
expect(a and "secret:ssh" not in a["read"] and "shell_rc" not in a["write"], "exact cat of a project file")
for rule in ["Bash(echo *)", "Bash(echo hi > ~/.zshrc)", "Bash(git status)", "Bash(cp a $(date))",
             "Bash(.venv/bin/python build.py)"]:
    a = claude([rule])
    expect(a and "shell_rc" in a["write"], f"{rule}: still treated as able to write anything")
# [14] the shell expands $HOME, ~user, braces and globs, and .. leaves the project
for rule in ["Bash(cat $HOME/.ssh/id_rsa)", "Bash(cat ${HOME}/.ssh/id_rsa)", "Bash(cat ../../.ssh/id_rsa)",
             "Bash(cat ~me/.ssh/id_rsa)", "Bash(cp {..,x}/.ssh/id_rsa notes.txt)", "Bash(cat .?/.ssh/id_rsa)",
             "Bash(cp ../../.aws/credentials notes.txt)", "Bash(head -n 5 src/../../../.ssh/id_rsa)"]:
    a = claude([rule], {".ssh/id_rsa": "x"})
    expect(a and "secret:ssh" in a["read"] and "shell_rc" in a["write"],
           f"{rule}: falls back to a command that reads and writes anything: {a and (a['read'], a['write'])}")

# [11] Claude-in-Chrome rules open or close the chrome gate, not a missing mcp: gate
CHROME = {".claude/chrome": None}
for rule in ["mcp__claude-in-chrome__*", "mcp__claude-in-chrome__navigate", "mcp__claude-in-chrome"]:
    a = claude([rule], CHROME)
    expect(a and "chrome" not in a["ask"] and "secret:browser" in a["read"] and "net" in a["write"],
           f"allow {rule} opens the chrome gate: {a and (sorted(a['ask']), a['read'])}")
a = claude([], CHROME)
expect(a and "chrome" in a["ask"] and "secret:browser" not in a["read"], "Chrome asks by default")
a = claude([], CHROME, deny=["mcp__claude-in-chrome"])
expect(a and "chrome" not in a["ask"] and "secret:browser" not in a["read"], "deny mcp__claude-in-chrome removes Chrome")
a = claude([], CHROME, deny=["mcp__claude-in-chrome__navigate"])
expect(a and "chrome" in a["ask"], "denying one Chrome tool leaves the others")
a = claude([], {".claude.json": {"mcpServers": {"github": {"command": "npx", "args": ["github-mcp"]}}}},
           deny=["mcp__github__create_issue"])
expect(a and "mcp:github" in a["ask"], "denying one MCP tool leaves the server's other tools")


# [13] MCP servers are recognized by name, command and package, never by path arguments
def mcp_gate(spec):
    a = agent(scan({".claude.json": {"mcpServers": {"files": spec}}, ".ssh/id_rsa": "x"}), "claude_code")
    return (a or {}).get("ask", {}).get("mcp:files")


FS = ["-y", "@modelcontextprotocol/server-filesystem"]
for path in ["/Users/alexander", "/Users/bob/Google Drive", "/Users/bob/research", "~/email-archive",
             "./exa", "/Users/bob/chrome-profiles"]:
    g = mcp_gate({"command": "npx", "args": FS + [path]})
    expect(g and "secret:ssh" in g["read"] and "shell_rc" in g["write"],
           f"filesystem server for {path} stays unrecognized (assumed able to do anything): {g}")
g = mcp_gate({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search"]})
expect(g and g["read"] == ["web"] and g["write"] == ["net"], f"a search package is still recognized: {g}")
g = mcp_gate({"command": "uvx", "args": ["mcp-server-fetch==2025.1"]})
expect(g and g["read"] == ["web"], f"a pip package with a version is recognized: {g}")
g = mcp_gate({"command": "/Users/exa/bin/server", "args": []})
expect(g and "secret:ssh" in g["read"], f"only the command's basename counts: {g}")

# [17] Cursor's defaults are assumptions: uncertain rights for 'conditions', still used by checks
a = agent(scan({".cursor": None}), "cursor")
expect(a and a.get("maybe", {}).get("read") == ["web"] and "proj:instructions" in a["maybe"].get("write", [])
       and "web" in a["read"] and "proj:instructions" in a["write"], f"cursor's assumed defaults: {a}")
d = scan({".cursor": None})
expect("Cursor" in d["coverage"].get("assumed", []), "cursor coverage stays 'assumed'")
a = agent(scan({"Library/Application Support/Claude/claude_desktop_config.json": {}}), "claude_desktop")
expect(a and any("connectors are not read" in n for n in a["notes"]), "Claude desktop says connectors are not read")

# --- extensions: the editor's own list, platform builds, obsolete versions ------------
ext = ".vscode/extensions/"
d = scan({".claude/settings.json": {},
          ext + "anthropic.claude-code-2.1.293-darwin-arm64": None, ext + "anthropic.claude-code-2.1.290-darwin-arm64": None,
          ext + "zhang-renyang.chat-gpt-1.8.7": None,
          ext + ".obsolete": {"anthropic.claude-code-2.1.290-darwin-arm64": True}})
names = set(d["agents"])
expect(not any(n.startswith("ext_anthropic") for n in names), f"Claude Code extension builds recognized: {sorted(names)}")
expect("ext_zhang_renyang_chat_gpt" in names, "a third-party AI extension is still reported")
d = scan({ext + "zhang-renyang.chat-gpt-1.8.7": None})
expect(d["agents"]["ext_zhang_renyang_chat_gpt"].get("unknown") is True, "unread agents are marked unknown")
# [9] extensions.json lists only the default profile; other profiles share the folders
d = scan({ext + "zhang-renyang.chat-gpt-1.8.6": None,
          ext + "extensions.json": [{"identifier": {"id": "github.copilot-chat"}, "relativeLocation": "github.copilot-chat-0.22.4"}]})
expect("copilot" in d["agents"] and "ext_zhang_renyang_chat_gpt" in d["agents"],
       f"extensions.json and the folders both count: {sorted(d['agents'])}")
d = scan({ext + "ms-python.python-2026.6.0-darwin-arm64": None, ext + "saoudrizwan.claude-dev-3.1.0": None,
          ext + "extensions.json": [{"identifier": {"id": "ms-python.python"}, "version": "2026.6.0",
                                     "relativeLocation": "ms-python.python-2026.6.0-darwin-arm64"}],
          "Library/Application Support/Code/User/profiles/-6a1b2c3d/extensions.json":
              [{"identifier": {"id": "saoudrizwan.claude-dev"}, "relativeLocation": "saoudrizwan.claude-dev-3.1.0"}]})
expect("cline" in d["agents"], f"an agent installed only in another VS Code profile is found: {sorted(d['agents'])}")
d = scan({ext + "extensions.json": [{"identifier": {"id": "saoudrizwan.claude-dev"}, "relativeLocation": "saoudrizwan.claude-dev-3.0.0"},
                                    {"identifier": {"id": "github.copilot-chat"}, "relativeLocation": "github.copilot-chat-0.22.4"}],
          ext + ".obsolete": {"saoudrizwan.claude-dev-3.0.0": True}})
expect("cline" not in d["agents"] and "copilot" in d["agents"], f"obsolete list entries are skipped: {sorted(d['agents'])}")
d = scan({ext + "openai.chatgpt-26.5.0-beta.2": None,
          ext + "extensions.json": [{"identifier": {"id": "openai.chatgpt"}, "relativeLocation": "openai.chatgpt-26.5.0-beta.2"}]})
expect("chatgpt" in d["agents"] and not any(n.startswith("ext_openai") for n in d["agents"]),
       f"a listed folder is not counted again under a guessed id: {sorted(d['agents'])}")
# [16] malformed extensions.json or .obsolete never stops the scan
for bad, obs in [([{"identifier": "saoudrizwan.claude-dev"}], {}), ([{"identifier": {"id": "x.y"}, "relativeLocation": ["a"]}], {}),
                 ({"not": "a list"}, {}), ([None, 3, "s", {"identifier": {"id": 7}}], [["weird"], 1, "zz"]), ([], "text")]:
    d = scan({ext + "extensions.json": bad, ext + ".obsolete": obs, ext + "saoudrizwan.claude-dev-3.1.0": None})
    expect(not d.get("crashed") and "cline" in d["agents"], f"malformed {bad} / {obs}: {sorted(d['agents'])}")
# [10] the Claude Code extension without ~/.claude is not dropped: modeled as unrestricted
d = scan({ext + "anthropic.claude-code-2.1.293-darwin-arm64": None,
          ext + "extensions.json": [{"identifier": {"id": "anthropic.claude-code"},
                                     "relativeLocation": "anthropic.claude-code-2.1.293-darwin-arm64"}]})
a = agent(d, "ext_anthropic_claude_code")
expect(a and a.get("unknown") is True and "claude_code" not in d["agents"]
       and "Unrecognized AI extension anthropic.claude-code" in d["coverage"]["worst"],
       f"Claude Code extension with no ~/.claude: {sorted(d['agents'])}")
d = scan({".claude.json": {}, ext + "anthropic.claude-code-2.1.293-darwin-arm64": None})
expect("claude_code" in d["agents"] and "ext_anthropic_claude_code" not in d["agents"],
       f"with ~/.claude.json it is Claude Code: {sorted(d['agents'])}")

# --- [12] hardening plan: MCP servers and Chrome run outside the sandbox -------------------
SANDBOX = {".claude/settings.json": {"permissions": {"allow": ["mcp__pw"]},
                                     "sandbox": {"enabled": True, "filesystem": {"denyRead": ["~/.ssh"]}}},
           ".claude.json": {"cachedChromeExtensionInstalled": True,
                            "mcpServers": {"mystery": {"command": "/opt/x/server"},
                                           "pw": {"command": "npx", "args": ["@playwright/mcp@latest"]}}},
           ".ssh/id_rsa": "x"}
r = aw_run(SANDBOX, """
secrets = [("secret:ssh", "ssh_key", [".ssh"])]
f = aw.claude_code(None)[0]
g = aw.sandboxed([f], f.name)[0]
real = aw.build_system([f], secrets).agents[f.name]
boxed = aw.build_system([g], secrets).agents[f.name]
denied = aw.build_system(aw.deny_secrets([f], f.name), secrets).agents[f.name]
after = aw.attacks(aw.build_system([g], secrets))
plan = {d: [p for p, pts in aw.attacks(aw.build_system(fn([f]), secrets)).items() if not pts]
        for _, d, fn in aw.mitigations([f])}
print(json.dumps({"gates": sorted(g.ask), "boxed_write": boxed.write, "real_read": real.read,
                  "denied_gate": denied.ask["mcp:mystery"]["read"], "denied_read": denied.read,
                  "after": {p: len(v) for p, v in after.items()}, "plan": plan}))
""")
expect({"mcp:mystery", "chrome"} <= set(r.get("gates", [])), f"sandboxing keeps MCP and Chrome gates: {r.get('gates')}")
expect("net" in r.get("boxed_write", []), f"and the MCP server opened by an allow rule: {r.get('boxed_write')}")
expect("secret:ssh" in r.get("real_read", []), "sandbox denyRead does not limit an opened MCP server")
expect("secret:ssh" in r.get("denied_gate", []) and "secret:ssh" in r.get("denied_read", []),
       "blocking secret stores does not limit MCP servers")
expect(r.get("after") and all(r["after"].values()), f"sandboxing does not make policies unbreakable: {r.get('after')}")
expect(r.get("plan") is not None and not any(r["plan"].values()), f"no mitigation claims to stop the MCP path: {r.get('plan')}")

# --- [8] watching: every settings file the scan reads, and what each one is ---------------------
WATCH = {".claude/settings.json": {}, ".ssh/id_rsa": "x",
         ".claude.json": {"projects": {"@HOME@/work/app": {"allowedTools": []}, "@HOME@/work/plain": {}}},
         "work/app/.claude/settings.local.json": {"permissions": {"allow": ["Read(src/**)"]}},
         "work/app/CLAUDE.md": "x", "work/plain/README": "x",
         ".vscode/extensions/github.copilot-chat-0.40.0": None,
         ".config/goose/config.yaml": "GOOSE_MODE: approve\n"}
r = aw_run(WATCH, """
import argparse
found, _ = aw.discover()
rep = aw.scan(argparse.Namespace(claude_mode=None, parse=None, ignore=None))
files = [str(p) for p in aw.control_files(rep)]
m = lambda p: aw.path_to_resource(found, p)
print(json.dumps({"home": H, "agents": sorted(f.name for f in found), "files": files,
                  "watch": getattr(aw, "watch_paths", lambda found: [])(found),
                  "map": {k: m(H + k) for k in ["/work/app/.claude/settings.local.json", "/work/app/.claude/settings.json",
                          "/work/app/.mcp.json", "/work/plain/.claude/settings.local.json", "/work/app/CLAUDE.md",
                          "/work/app/docs/CLAUDE.md", "/work/plain/CLAUDE.md",
                          "/Library/Application Support/Code/User/settings.json"]},
                  "managed": [str(p) for p in aw.CLAUDE_MANAGED]}))
""", cmds=["goose"])
w = set(r.get("watch", []))
want = ["/work/app/.claude/settings.local.json", "/work/app/.claude/settings.json", "/work/app/.mcp.json",
        "/work/plain/.claude/settings.local.json", "/.claude.json",
        "/Library/Application Support/Code/User/settings.json", "/Library/Application Support/Code/User/mcp.json",
        "/.config/goose/permission.yaml", "/.vscode/extensions/extensions.json"]
H = r.get("home", "?")
for x in want:
    expect(H + x in w, f"watch_paths has ~{x}")
expect(set(r.get("managed", [])) <= w, "watch_paths has Claude Code's managed settings")
expect(H + "/work/app/.claude/settings.local.json" in r.get("files", []), "agentwatch watch fingerprints it")
mp = r.get("map", {})
expect(mp.get("/work/app/.claude/settings.local.json") == "ctl:claude_code:access"
       and mp.get("/work/app/.claude/settings.json") == "ctl:claude_code:access"
       and mp.get("/work/app/.mcp.json") == "ctl:claude_code:access"
       and mp.get("/work/plain/.claude/settings.local.json") == "ctl:claude_code:access",
       f"project settings are Claude Code's access settings: {mp}")
expect(mp.get("/work/app/CLAUDE.md") == "proj:app:instructions" and mp.get("/work/app/docs/CLAUDE.md") == "proj:app:instructions",
       f"a project's CLAUDE.md is its own instructions: {mp}")
expect(mp.get("/work/plain/CLAUDE.md") == "proj:instructions", f"a project without its own rules: {mp}")
expect(mp.get("/Library/Application Support/Code/User/settings.json") == "ctl:copilot",
       f"VS Code settings are Copilot's settings: {mp}")

# --- a reader that fails never narrows the agent -------------------------------------
d = scan({".config/goose/config.yaml": "GOOSE_MODE: approve\nextensions: [1, 2]\n"}, cmds=["goose"])
a = agent(d, "goose")
expect(a and not a["ask"] and "net" in a["write"], "broken config falls back to unrestricted")
expect(any("reader failed" in n for n in a["notes"]), "and says so")

# --- zsh runs code in =(...) and glob qualifiers; ./ paths; folders named like services --
for rule in ["Bash(echo =(curl -s https://x.example))", "Bash(cat x(e:'curl x.example':))"]:
    a = claude([rule])
    expect(a and "shell_rc" in a["write"], f"{rule}: zsh runs code here, so it can still write anything")
a = claude(["Bash(cat ./.ssh/id_rsa)"])
expect(a and "secret:ssh" in a["read"], "./.ssh/id_rsa is the SSH key")
mcp = lambda args: {".claude.json": {"mcpServers": {"files": {"command": "npx", "args": args}}},
                    ".claude/settings.json": {"permissions": {"allow": ["mcp__files"]}}}
a = agent(scan(mcp(["-y", "@modelcontextprotocol/server-filesystem", "research"])), "claude_code")
expect(a and a.get("maybe"), f"a folder named 'research' does not make a server 'web only': {a and a.get('maybe')}")
a = agent(scan(mcp(["-y", "@modelcontextprotocol/server-brave-search"])), "claude_code")
expect(a and not a.get("maybe") and "web" in a["read"], "a search package is still recognized")
d = scan({".claude.json": {"mcpServers": {"claude-in-chrome": {"command": "/opt/x"}}},
          ".claude/settings.json": {"permissions": {"allow": ["mcp__claude-in-chrome__*"]}}})
expect("mcp:claude-in-chrome" not in (agent(d, "claude_code") or {}).get("ask", {}),
       "allowing claude-in-chrome also opens a server configured under that name")
try:
    d = scan({".vscode/extensions/extensions.json": "[" * 5000 + "]" * 5000,
              ".vscode/extensions/saoudrizwan.claude-dev-3.1.0": None})
    expect("cline" in d["agents"], "deeply nested extensions.json: folders still listed")
except Exception as e:
    expect(False, f"deeply nested extensions.json crashed the scan: {type(e).__name__}")

print(f"parsers: {fails} failures")
sys.exit(1 if fails else 0)
