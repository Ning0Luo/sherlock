"""Tests for frozen access settings: freeze() itself, SAT vs brute force on frozen
random systems, monotonicity (freezing only removes attacks), the change report,
the scan's split of access files, the examples/access walk-through, and the
commands around them: export, check/ruleoftwo/conditions --guard-access, diff,
watch (in-process, a few rounds, on temporary files and a fake home folder)."""
import argparse, contextlib, fnmatch, io, itertools, json, os, pathlib, random, shutil, subprocess, sys
import tempfile, time
from pathlib import Path
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
sys.path.insert(0, "agentwatch")
from collusion import Agent, Policy, Resource, System, analyze, freeze, literal, load, violated
from policy import parse
from sat import frontier, solve
from test_sat import brute, rand_system
import agentcheck
import agentwatch as aw
from agentwatch import is_access_path

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


# --- freeze() -------------------------------------------------------------------
s = System({"a": Agent("a", read=["*"], write=["*"], ask={"sh": {"read": [], "write": ["cfg", "x"]}},
                       flows=[("x", "cfg")])},
           {"x": Resource("x"), "cfg": Resource("cfg", controls=["a"], access=True)}, [])
f = freeze(s)
expect(f.matches(f.agents["a"].write) == {"x"}, "open writes lose the access file, globs included")
expect(f.matches(f.agents["a"].ask["sh"]["write"]) == {"x"}, "gated writes lose the access file")
expect(f.agents["a"].read == ["*"], "reads unchanged")
expect(f.resources is s.resources, "resources shared, so policy labels carry over")
expect(freeze(System({}, {"x": Resource("x")}, [])).resources is not None, "no access files: same system")

# --- random systems: SAT == brute force when frozen; freezing never adds attacks ---
rng = random.Random(5)
cases = guarded = 0
for trial in range(40):
    s = rand_system(rng, rng.choice([3, 4]))
    if len(agentcheck.gates(s)) > 6:
        continue
    for r in s.resources.values():
        if r.controls and rng.random() < 0.7:
            r.access = True
            for a in r.controls:           # a tool steered only by its config file
                if rng.random() < 0.6:
                    s.agents[a].injectable = False
            if rng.random() < 0.5:
                s.policies.append(Policy(f"{r.name} untouched", "integrity", resource=r.name))
    for x in s.agents.values():          # let some agents write the access files
        if rng.random() < 0.4:
            x.write.append(rng.choice([r for r in s.resources if s.resources[r].controls]))
    f = freeze(s)
    for p in s.policies:
        for inj in (False, True):
            got = [(t, h) for t, h, _ in frontier(f, p, inj)]
            want = brute(f, p, inj)
            expect(got == want, f"trial {trial} {p.name} inj={inj}: SAT {got} vs brute {want}")
            open_ = {(t, h) for t, h, _ in frontier(s, p, inj)}
            for t, h in got:   # every frozen attack is also an attack without freezing
                expect(any(t2 <= t and h2 <= h for t2, h2 in open_), f"trial {trial}: monotone")
            if set(got) != open_:          # freezing made some attack cost more, or impossible
                guarded += 1
            cases += 1
expect(guarded > 0, "random systems include attacks that need an access edit")

# --- the change report ---------------------------------------------------------
ch = {c["policy"]: c["kind"] for c in agentcheck.compare(
    {"p1": ("PASS", None), "p2": ("GUARDED", None), "p3": ("FAIL", None), "p4": ("PASS", None)},
    {"p1": ("FAIL", None), "p2": ("PASS", None), "p3": ("GUARDED", None), "p4": ("GUARDED", None)})}
expect(ch == {"p1": "alarm", "p2": "resolved", "p3": "resolved", "p4": "guarded"}, f"change kinds {ch}")
expect(agentcheck.compare({"p": ("FAIL", None)}, {"p": ("FAIL", None)}) == [], "no change, no report")

# --- the scan's access split -----------------------------------------------------
for p, want in [("~/.claude/settings.json", True), ("~/.codex/config.toml", True), ("~/.cursor/mcp.json", True),
                ("~/.codex/AGENTS.md", False), ("~/.cursor/rules", False), ("~/.codex/skills", False)]:
    expect(is_access_path(p) == want, f"is_access_path({p})")

# --- examples/access -------------------------------------------------------------
text = open("examples/access/access.policy").read()
v = {k: agentcheck.verdicts(load(f"examples/access/{k}.json"), parse(text), None)
     for k in ("before", "after_slack", "after_lockdown")}
expect({t: st for t, (st, _) in v["before"].items()} ==
       {"The SSH key never leaves": "GUARDED", "Web content never reconfigures the sync job": "GUARDED"},
       "before: both guarded")
kinds = {c["policy"]: c["kind"] for c in agentcheck.compare(v["before"], v["after_slack"])}
expect(kinds == {"The SSH key never leaves": "alarm"}, f"slack tool: {kinds}")
kinds = {c["policy"]: c["kind"] for c in agentcheck.compare(v["before"], v["after_lockdown"])}
expect(set(kinds.values()) == {"resolved"} and len(kinds) == 2, f"lockdown: {kinds}")

# --- helpers for the command tests ---------------------------------------------
TMP = Path(tempfile.mkdtemp())
stamp = [time.time() - 1000]


def put(path, data) -> Path:
    """Write a file (JSON unless a string) with a fresh modification time."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    stamp[0] += 1
    os.utime(path, (stamp[0], stamp[0]))
    return path


def cli(*argv):
    r = subprocess.run([sys.executable, "agentcheck.py", *argv], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def watch(edits, **kw):
    """agentcheck watch in-process, one round per edit; edits[i] runs while round i sleeps."""
    a = argparse.Namespace(**{"config": None, "openshell": None, "scan": False, "ignore": None,
                              "claude_mode": None, "every": 0, "rounds": len(edits), **kw})
    todo, sleep, out = list(edits), time.sleep, io.StringIO()
    time.sleep = lambda n: todo.pop(0)() if todo else None
    try:
        with contextlib.redirect_stdout(out):
            code = agentcheck.cmd_watch(a)
    except SystemExit as e:          # what a config error did before
        code = f"exit {e.code}"
    except Exception as e:
        code = f"crash {type(e).__name__}: {e}"
    finally:
        time.sleep = sleep
    return code, out.getvalue()


ACCESS = Path("examples/access/access.policy").read_text()
BEFORE = json.loads(Path("examples/access/before.json").read_text())

# --- literal() and freeze() with names that hold fnmatch characters ---------------
names = ["".join(x) for k in range(1, 4) for x in itertools.product("a*?[]", repeat=k)]
expect(all(fnmatch.fnmatchcase(m, literal(n)) == (m == n) for n in names for m in names),
       "literal(name) matches that name and nothing else")
s = System({"x": Agent("x", read=["web", "key"], write=["*"])},
           {"web": Resource("web", untrusted=True), "key": Resource("key", labels={"k"}),
            "net[eu]": Resource("net[eu]", sink=True),
            "ctl:x:access": Resource("ctl:x:access", controls=["x"], access=True)}, [])
f = freeze(s)
expect(f.matches(f.agents["x"].write) == {"web", "key", "net[eu]"}, "frozen writes keep net[eu]")
expect(solve(f, Policy("leak", "no_flow", label="k"), True, 0, 0).sat,
       "a leak to net[eu] needs no access edit, so freezing keeps it")
g = System({"a": Agent("a", read=["web"], write=["cfg", "notes*"]),
            "b": Agent("b", read=["notes*", "key"], write=["net"]),
            "x": Agent("x", read=[], write=[], injectable=False)},
           {"web": Resource("web", untrusted=True), "notes[1]": Resource("notes[1]"),
            "key": Resource("key", labels={"k_key"}), "net": Resource("net", sink=True),
            "cfg": Resource("cfg", controls=["x"], access=True)}, [])
v = agentcheck.verdicts(g, parse('policy "k stays"\n  never k -> internet\n'), None)
expect(v["k stays"][0] == "FAIL", f"an attack through notes[1] is a FAIL, not GUARDED: {v['k stays'][0]}")

# --- export writes everything load reads -------------------------------------------
full = {"agents": {
    "x": {"read": ["web", "key"], "write": ["out"], "injectable": True, "unknown": True,
          "ask": {"sh": {"read": ["key"], "write": ["net"]}}, "flows": [["out", "net"]]},
    "y": {"read": ["out"], "write": ["net", "cfg"], "injectable": True, "maybe": {"write": ["net"]}},
    "z": {"read": ["cfg", "key"], "write": ["net"], "injectable": False, "trusted": True,
          "strips": ["attacker"], "flows": [["key", "net"]]}},
    "resources": {"web": {"untrusted": True}, "key": {"labels": ["k"]}, "out": {}, "net": {"sink": True},
                  "cfg": {"controls": ["z"], "access": True}, "prod": {"protected": True}},
    "policies": [{"name": "k leaks", "kind": "no_flow", "label": "k"}]}
for src in [put(TMP / "full.json", full), Path("examples/access/before.json"),
            Path("examples/conditions/home.json")]:
    out = TMP / f"export-{src.stem}.json"
    with contextlib.redirect_stdout(io.StringIO()):
        agentcheck.cmd_export(argparse.Namespace(config=str(src), openshell=None, scan=False, out=str(out),
                                                 ignore=None, claude_mode=None))
    a, b = load(str(src)), load(str(out))
    expect((a.agents, a.resources, a.policies) == (b.agents, b.resources, b.policies),
           f"export of {src} loads back as the same system")
    pol = Path("examples/conditions/home.policy").read_text() if "home" in src.stem else \
        ACCESS if "before" in src.stem else 'policy "k"\n  never k -> internet\n'
    va, vb = (agentcheck.verdicts(load(str(x)), parse(pol), None) for x in (src, out))
    expect({k: st for k, (st, _) in va.items()} == {k: st for k, (st, _) in vb.items()},
           f"export of {src}: the same verdicts")
    import synth
    from policy import compile_file
    ca, cb = (synth.check(load(str(x)), compile_file(load(str(x)), parse(pol)), agentcheck.budget)
              for x in (src, out))
    expect([(r.title, r.status) for r in ca["results"]] == [(r.title, r.status) for r in cb["results"]]
           and ca["unknown_agents"] == cb["unknown_agents"], f"export of {src}: the same conditions")

# --- --guard-access says what holds only with access settings frozen ----------------
code, out = cli("check", "examples/access/access.policy", "--config", "examples/access/before.json",
                "--guard-access")
lines = [l.strip() for l in out.splitlines()]
expect(code == 0 and "GUARDED  Web content never reconfigures the sync job" in out, "check: GUARDED rows")
expect(not any(l.startswith(("cannot be broken", "cheapest attacks")) for l in lines),
       "check --guard-access: every frontier sentence says access settings are frozen")
code, out = cli("ruleoftwo", "--config", "examples/access/before.json", "--guard-access",
                "--json", str(TMP / "r2.json"))
expect("cannot happen, even with every approval" not in out.replace("with access settings frozen, cannot", "")
       and "GUARDED  attacker text makes a secret leave" in out, f"ruleoftwo --guard-access: {out}")
expect(json.loads((TMP / "r2.json").read_text())["fleet"][0].get("guarded", {}).get("status") == "FAIL",
       "ruleoftwo JSON marks the guarded goal")
code, out = cli("conditions", "examples/access/access.policy", "--config", "examples/access/before.json",
                "--guard-access")
expect(out.count("GUARDED  ") == 2 and "\nPASS " not in out, f"conditions --guard-access: {out}")
for argv in (["ruleoftwo", "--config", "examples/devbox.json", "--guard-access"],
             ["conditions", "examples/conditions/home.policy", "--config", "examples/conditions/home.json",
              "--guard-access"]):
    code, out = cli(*argv)
    expect("access settings frozen" not in out, f"{argv[0]}: no banner when nothing is frozen")

# --- configuration errors: ValueError from load, exit code 2, never 1 ---------------
bad = {"controls": dict(BEFORE, resources={**BEFORE["resources"],
                                           "cfg/sync": {"controls": ["sync", "ghost"], "access": True}}),
       "list": {"agents": [], "resources": {}},
       "gate": {"agents": {"a": {"read": [], "write": [], "ask": {"g": ["x"]}}}, "resources": {}},
       "read": {"agents": {"a": {"read": "web", "write": []}}, "resources": {}}}
for k, raw in bad.items():
    p = put(TMP / f"bad-{k}.json", raw)
    try:
        load(str(p))
        expect(False, f"load {k}: no error")
    except ValueError as e:
        expect(str(p) in str(e), f"load {k}: the message names the file: {e}")
    except BaseException as e:
        expect(False, f"load {k}: {type(e).__name__} instead of ValueError")
    for argv in (["check", "examples/access/access.policy", "--config", str(p)],
                 ["diff", "examples/access/access.policy", "--config", "examples/access/before.json",
                  "--to", str(p)]):
        code, out = cli(*argv)
        expect(code == 2 and "Traceback" not in out, f"{argv[0]} on bad {k}: exit {code} {out}")
fleet_bad = put(TMP / "fleet-bad.json", {"sandboxes": ["coder"]})
code, out = cli("check", "examples/openshell/fleet.policy", "--openshell", str(fleet_bad))
expect(code == 2 and "Traceback" not in out, f"a malformed fleet: exit {code} {out}")

# --- watch keeps watching through broken edits; one bad policy does not stop the others
cfg = put(TMP / "watched.json", BEFORE)
nosync = json.loads(json.dumps(BEFORE))
del nosync["agents"]["sync"], nosync["resources"]["cfg/sync"]
slack = json.loads(json.dumps(nosync))
slack["agents"]["reader"]["write"].append("net:slack")
slack["resources"]["net:slack"] = {"sink": True}
code, out = watch([lambda: put(cfg, bad["controls"]), lambda: put(cfg, bad["list"]),
                   lambda: put(cfg, nosync), lambda: put(cfg, slack)],
                  config=str(cfg), policy="examples/access/access.policy")
expect(code == 0 and out.count("cannot re-check: ") == 2, f"watch survives broken edits: {code} {out}")
expect("cannot re-check Web content never reconfigures the sync job: line" in out,
       "a policy whose names are gone is reported")
expect("ALARM  The SSH key never leaves: PASS -> FAIL" in out, f"the other policy is still checked: {out}")

# a file deleted between listing and stat() does not end the watch
cfg = put(TMP / "watched2.json", BEFORE)
exists = pathlib.Path.exists
pathlib.Path.exists = lambda self, *a, **k: True        # as if it vanished right after exists()
try:
    code, out = watch([lambda: cfg.unlink(), lambda: put(cfg, BEFORE)], config=str(cfg),
                      policy="examples/access/access.policy")
finally:
    pathlib.Path.exists = exists
expect(code == 0 and "cannot re-check" in out, f"watch survives a vanished file: {code} {out}")

# --- watch --openshell watches every policy file the fleet names --------------------
os_dir = TMP / "os"
hard = {"version": 1, "landlock": {"compatibility": "hard_requirement"}}
put(os_dir / "pols/coder.json", {**hard, "filesystem_policy": {"read_write": ["/home/sandbox"]}})
put(os_dir / "pols/coder-p.json", hard)
put(os_dir / "pols/browser.json", {**hard, "network_policies": {"web": {"endpoints": [
    {"host": "example.org", "port": 443, "protocol": "rest", "access": "read-only", "enforcement": "enforce"}]}}})
fleet = put(os_dir / "fleet/fleet.json", {
    "sandboxes": {"coder": {"policy": "../pols/coder.json", "proposals": ["../pols/coder-p.json"]},
                  "browser": {"policy": str(os_dir / "pols/browser.json")}},
    "secrets": [{"sandbox": "coder", "path": "/home/sandbox/.ssh", "label": "ssh_key"}]})
pol = put(os_dir / "p.policy", 'policy "SSH key stays"\n  never ssh_key -> internet\n')
rel = os.path.relpath(fleet)
s, _ = agentcheck.load_system(argparse.Namespace(openshell=rel, config=None), parse(""))
ws = [p.resolve() for p in agentcheck.watched_files(argparse.Namespace(openshell=rel, config=None), s)]
want = {fleet.resolve()} | {(os_dir / "pols" / n).resolve() for n in ("coder.json", "coder-p.json", "browser.json")}
expect(set(ws) == want and len(ws) == len(want), f"openshell: watched files {ws}")
code, out = watch([lambda: put(os_dir / "pols/coder.json", {
    **hard, "filesystem_policy": {"read_write": ["/home/sandbox"]},
    "network_policies": {"w": {"endpoints": [{"host": "example.com", "port": 443}]}}})],
    openshell=str(fleet), policy=str(pol))
expect("ALARM  SSH key stays: PASS -> FAIL" in out, f"watch --openshell sees the policy edit: {out}")

# --- watch on this Mac (a fake home folder; the scan is replaced by a fixed one) ------
saved = {k: getattr(aw, k) for k in ("HOME", "discover", "notify", "watch_paths") if hasattr(aw, k)}
home = TMP / "home"
put(home / ".claude/settings.json", {})
put(home / ".codex/config.toml", "")
put(home / ".codex/rules/default.rules", "")
put(home / ".zshrc", "")
found = [aw.Found("claude_code", "Claude Code", read=["proj:*"], write=["proj:*"],
                  control_paths=["~/.claude/settings.json"]),
         aw.Found("codex", "Codex", read=["proj:*"], write=["proj:*"], control_paths=["~/.codex/config.toml"]),
         aw.Found("helper", "Helper", read=["web"], write=["ctl:claude_code:access"]),
         aw.Found("helper2", "Helper 2", read=["web"], write=["ctl:codex:access"])]
said = []
aw.HOME, aw.discover = home, lambda *a, **k: (found, [])
aw.notify = lambda msg: (said.append(msg), print(msg))
try:
    # every file the scan reads is watched, once
    proj = home / "work/app/.claude/settings.local.json"
    aw.watch_paths = lambda f: [str(proj), "~/.claude/settings.json", "~/.codex"]
    sargs = argparse.Namespace(config=None, openshell=None, scan=True, claude_mode=None, ignore=None)
    s, _ = agentcheck.load_system(sargs, parse(""))
    ws = agentcheck.watched_files(sargs, s)
    expect(proj in ws, "a project's settings file is watched, before it exists")
    expect(len({p.resolve() for p in ws}) == len(ws), f"each file once: {ws}")
    expect(home / ".codex/rules/default.rules" in ws, "a folder from the scan stands for its files")

    # an edit to a file that a set-aside attack writes is reported, though no verdict changes
    aw.watch_paths = lambda f: []
    pol = put(TMP / "mac.policy", 'policy "Claude Code access settings stay"\n'
                                  '  never attacker -> ctl:claude_code:access\n'
                                  'policy "Codex access settings stay"\n  never attacker -> ctl:codex:access\n'
                                  'policy "Both stay"\n  never attacker -> ctl:claude_code:access, ctl:codex:access\n')
    code, out = watch([lambda: put(home / ".claude/settings.json", {"hooks": {"PreToolUse": []}}),
                       lambda: put(home / ".zshrc", "export X=1\n"),
                       lambda: put(home / ".codex/config.toml", "approval_policy = 'never'\n")],
                      scan=True, policy=str(pol))
    review = [m.split(" has a")[0] for m in said if m.startswith("REVIEW")]
    expect(code == 0 and out.count("GUARDED  ") == 3 and out.count("no change in any policy") == 3,
           f"scan watch: {out}")
    # "Both stay" shows one attack, through one of the two files; the other is found by the solver
    expect(review == ["REVIEW ~/.claude/settings.json changed: Claude Code access settings stay",
                      "REVIEW ~/.claude/settings.json changed: Both stay",
                      "REVIEW ~/.codex/config.toml changed: Codex access settings stay",
                      "REVIEW ~/.codex/config.toml changed: Both stay"], f"REVIEW notices: {said}")
finally:
    for k, x in saved.items():
        setattr(aw, k, x)
    if "watch_paths" not in saved and hasattr(aw, "watch_paths"):
        del aw.watch_paths

# --- a statement naming nothing here holds trivially (with a note); empty settings() is refused
cfg = put(TMP / "nosink.json", {"agents": {"a": {"read": ["key", "web"], "write": ["notes"]}},
                                "resources": {"key": {"labels": ["ssh_key"]}, "web": {"untrusted": True}, "notes": {}}})
r = subprocess.run([sys.executable, "agentcheck.py", "check", str(put(TMP / "n.policy", 'policy "k"\n  never ssh -> internet\n')),
                    "--config", str(cfg)], capture_output=True, text=True)
expect(r.returncode == 0 and "holds trivially" in r.stdout, f"no sink: trivial PASS with a note: {r.stdout}{r.stderr}")
r = subprocess.run([sys.executable, "agentcheck.py", "check", str(put(TMP / "e.policy", 'policy "s"\n  never attacker -> settings(a)\n')),
                    "--config", str(cfg)], capture_output=True, text=True)
expect(r.returncode == 2 and "settings(a) names no file" in r.stderr, f"empty settings() is refused: {r.stderr}")

# --- conditions --guard-access marks a DEPENDS whose 'holds if' an access edit gets past
cfg = put(TMP / "dep.json", {
    "agents": {"assistant": {"read": ["web"], "write": ["notes", "cfg"]},
               "sync": {"read": ["key"], "write": ["net"], "injectable": False, "flows": [["photos", "net"]]},
               "x": {"read": ["key", "web"], "write": ["net"], "unknown": True}},
    "resources": {"web": {"untrusted": True}, "notes": {}, "photos": {}, "key": {"labels": ["k_key"]},
                  "net": {"sink": True}, "cfg": {"controls": ["sync"], "access": True}}})
js = TMP / "dep_out.json"
r = subprocess.run([sys.executable, "agentcheck.py", "conditions", str(put(TMP / "k.policy", 'policy "k stays"\n  never k -> internet\n')),
                    "--config", str(cfg), "--guard-access", "--json", str(js)], capture_output=True, text=True)
expect("DEPENDS  k stays" in r.stdout and "gets past 'holds if'" in r.stdout and "with access settings frozen" in r.stdout,
       f"guarded DEPENDS is marked: {r.stdout}{r.stderr}")
expect(js.exists() and "guarded" in json.loads(js.read_text())["results"][0], "and in the JSON")

# --- scanner pieces of watch: literal paths, extension folders, ~/.claude.json, notify --
saved = {k: getattr(aw, k) for k in ("HOME", "discover", "watch_paths")}
home = TMP / "home2"
put(home / ".claude/settings.json", {})
try:
    aw.HOME = home
    wp = [Path(p) for p in aw.watch_paths([])]
    expect(home / ".vscode/extensions" in wp and home / ".agentwatch/ignore" in wp,
           "a new extension folder and the ignore file are watched")
    found = [aw.Found("claude_code", "Claude Code", read=["proj:*"], write=["proj:*"],
                      control_paths=["~/.claude/settings.json"])]
    aw.discover = lambda *a, **k: (found, [])
    odd = home / "work/app[1]/.claude/settings.local.json"
    aw.watch_paths = lambda f: [str(odd), str(home / ".vscode/extensions")]
    put(home / ".vscode/extensions/pub.ext-1.0.0/package.json", "{}")
    sargs = argparse.Namespace(config=None, openshell=None, scan=True, claude_mode=None, ignore=None)
    s, _ = agentcheck.load_system(sargs, parse(""))
    ws = agentcheck.watched_files(sargs, s)
    expect(odd in ws, "a project folder named 'app[1]' is watched (a literal path, not a glob)")
    expect(home / ".vscode/extensions" in ws and home / ".vscode/extensions/pub.ext-1.0.0/package.json" not in ws,
           "the extension folder is watched as a whole, not file by file")
    cj = home / ".claude.json"
    put(cj, {"numStartups": 1, "projects": {"/a": {"allowedTools": [], "lastCost": 1}}})
    k1 = agentcheck.snapshot([cj])
    put(cj, {"numStartups": 9, "projects": {"/a": {"allowedTools": [], "lastCost": 7}}})
    k2 = agentcheck.snapshot([cj])
    put(cj, {"numStartups": 9, "projects": {"/a": {"allowedTools": ["Bash(curl:*)"], "lastCost": 7}}})
    expect(k1 == k2 != agentcheck.snapshot([cj]), "~/.claude.json counts only by what the scan reads")
finally:
    for k, x in saved.items():
        setattr(aw, k, x)
expect(not aw.outside_sandbox("ext:developer") and aw.outside_sandbox("ext:fetcher") and aw.outside_sandbox("mcp:x"),
       "Goose's built-in shell is the agent itself; other extensions and MCP servers run outside")
calls = []
real_run, aw.subprocess.run = aw.subprocess.run, lambda cmd, **k: calls.append(cmd)
real_platform, aw.sys.platform = aw.sys.platform, "darwin"
try:
    aw.notify('REVIEW ~/work/app$(touch PWNED)/"x" changed')
finally:
    aw.subprocess.run, aw.sys.platform = real_run, real_platform
expect(calls and calls[0][0] == "osascript" and isinstance(calls[0], list) and '\\"x\\"' in calls[0][2],
       f"notify runs osascript without a shell, quoting the message: {calls}")

# --- install.sh installs only the tests that run in the install -----------------------
if Path("install.sh").exists() and shutil.which("cadical"):
    prefix = TMP / "prefix"
    env = dict(os.environ, PREFIX=str(prefix), NO_SOLVER_INSTALL="1")
    r = subprocess.run(["bash", "install.sh"], capture_output=True, text=True, env=env)
    dest = prefix / "share/agentcheck"
    tests = {p.name for p in (dest / "tests").glob("*.py")}
    expect(r.returncode == 0, f"install.sh: {r.stdout}{r.stderr}")
    expect(tests and not tests & {"test_parsers.py", "test_trust.py", "test_langgraph.py"},
           f"installed tests: {sorted(tests)}")
    expect(all((dest / f).exists() for f in ("synth.py", "openshell.py", "miniyaml.py", "integrations/langgraph.py",
                                              "examples/conditions/home.json", "examples/langgraph/README.md")),
           "install.sh copies every module and the examples the docs use")
    subprocess.run(["bash", "uninstall.sh"], capture_output=True, env=env)
    expect(not dest.exists(), "uninstall.sh removes it")
shutil.rmtree(TMP, ignore_errors=True)

print(f"access: {cases} random cases ({guarded} need an access edit), SAT vs brute and monotonicity checked")
print("ok" if not fails else f"{fails} failures")
sys.exit(1 if fails else 0)
