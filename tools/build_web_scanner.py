#!/usr/bin/env python3
"""Build web/agentcheck_scan.py: one stdlib-only file that a visitor pastes into
a terminal. It reuses agentwatch's collectors verbatim and prints the scanned
setup as JSON for the Sherlock web page. Re-run after editing agentwatch.py."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
src = (ROOT / "agentwatch/agentwatch.py").read_text()
start = src.index("HOME = Path.home()")
end = src.index("# ------------------------------------------------------------------ analysis")
body = src[start:end]

HEADER = '''#!/usr/bin/env python3
"""Sherlock scanner: finds the AI agents on this Mac and prints their rights
as JSON. It reads only the structure of agent settings files (permission
rules, modes, plugin and MCP server names) and checks whether secret folders
such as ~/.ssh exist. It never opens secrets, never prints file contents or
paths under your home folder, and sends nothing anywhere: output goes to stdout."""
from __future__ import annotations
import fnmatch, json, os, shlex, shutil, sys, time
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
    unknown: bool = False                       # settings not read: every right is a guess
    maybe: dict = field(default_factory=dict)   # rights granted only by an assumption


@dataclass
class Resource:
    name: str
    labels: set = field(default_factory=set)
    untrusted: bool = False
    sink: bool = False
    protected: bool = False
    controls: list = field(default_factory=list)
    access: bool = False                        # editing it changes what agents may do


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

'''

FOOTER = '''
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
                       "injectable": x.injectable, "ask": x.ask, "notes": notes[a],
                       **({"unknown": True} if x.unknown else {}), **({"maybe": x.maybe} if x.maybe else {})}
                   for a, x in s.agents.items()},
        "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                             ("sink", x.sink), ("controls", x.controls),
                                             ("access", x.access)) if v}
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
'''

mini = (ROOT / "miniyaml.py").read_text()
mini = mini[mini.index("class YamlError"):]          # drop its docstring and imports
mini = mini.replace("def load_yaml(path: Path):", "def _unused_load_yaml(path: Path):")
body = "import re\n\n" + mini + "\n\n" + body
out = ROOT / "web/agentcheck_scan.py"
out.parent.mkdir(exist_ok=True)
out.write_text(HEADER + body + FOOTER)
print(f"wrote {out} ({len((HEADER + body + FOOTER).splitlines())} lines)")
