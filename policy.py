"""A small language for multi-agent safety policies, compiled to SAT goals.

    # who the attacker is (default: every untrusted input)
    attacker controls web

    # names for things
    secret deploy_key = ~/keys/deploy.pem
    group cloud = aws, docker

    policy "Cloud keys never leave the machine"
      never cloud -> internet
      tolerate 1 agent, 0 approvals

    policy "Cursor never sees the SSH key"
      never ssh -> cursor

    policy "Web content never steers Claude Code"
      never attacker -> settings(claude_code)
      never hijack claude_code

Statements inside a policy (a policy is violated if ANY statement is):
  never DATA -> PLACES     DATA (secrets, files) reaches a place; if a place is
                           an agent, the agent becomes able to read it
  never attacker -> PLACES attacker-written content reaches a place; an agent
                           as a place means the agent is taken over
  never hijack AGENTS      the agent ends up working for the attacker
  tolerate N agents, M approvals, K injections
                           the policy must hold even if the attacker breaks
                           into N agents and you approve M prompts
                           (default 0 and 0; "any" = no limit)
  attacker controls INPUTS overrides the global attacker line for this policy

Names: agent names, resource names, globs over resource names (net:*), paths
(~/.ssh), secret labels and their short forms (ssh for ssh_key), and the
built-ins: secrets, internet, agents, settings(AGENT) (the agent's own
configuration files, and the settings group ctl:* it shares, e.g. every Claude
Code project's) and instructions(AGENT) (every file that steers it, shared
project files such as CLAUDE.md included).

A statement whose places resolve to nothing is an error (it could never be
violated, so its policy would pass vacuously), and so are two policies with one
title (diff and watch compare results by title).
"""

from __future__ import annotations

import difflib
import fnmatch
import re
import shlex
from dataclasses import dataclass, field
from typing import Callable

from collusion import Policy, System, literal
from sat import Goal

ANY = None


class PolicyError(Exception):
    def __init__(self, line: int, msg: str):
        super().__init__(f"line {line}: {msg}")
        self.line = line


@dataclass
class Stmt:
    line: int
    kind: str                # flow | attack | hijack
    src: list[str]
    dst: list[str]


@dataclass
class PolicyBlock:
    title: str
    line: int
    stmts: list[Stmt] = field(default_factory=list)
    agents: int | None = 0          # tolerated broken agents (None = any)
    approvals: int | None = 0       # tolerated approvals (None = any)
    injections: int | None = None   # tolerated prompt injections (None = any; the default
                                    # keeps the old behavior: the attacker injects freely)
    sources: list[str] | None = None


@dataclass
class PolicyFile:
    secrets: dict[str, tuple[int, str]] = field(default_factory=dict)   # name -> (line, target)
    groups: dict[str, tuple[int, list[str]]] = field(default_factory=dict)
    sources: list[str] | None = None
    policies: list[PolicyBlock] = field(default_factory=list)


def split_list(text: str) -> list[str]:
    return [x.strip() for x in text.split(",") if x.strip()]


def parse_count(tok: str, line: int) -> int | None:
    if tok in ("any", "unlimited"):
        return ANY
    if tok.isdigit():
        return int(tok)
    raise PolicyError(line, f"expected a number or 'any', got '{tok}'")


def parse(text: str) -> PolicyFile:
    pf = PolicyFile()
    cur: PolicyBlock | None = None
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("policy"):
            rest = line[len("policy"):].strip().rstrip(":").strip()
            try:
                title = " ".join(shlex.split(rest)) if rest else ""
            except ValueError:
                raise PolicyError(no, "unbalanced quotes in the policy title")
            if not title:
                raise PolicyError(no, 'a policy needs a title: policy "No key leaks"')
            same = [p for p in pf.policies if p.title == title]
            if same:   # results are reported (and compared by diff/watch) by title
                raise PolicyError(no, f'two policies are titled "{title}" (the other is on line '
                                      f'{same[0].line}); give each a different title')
            cur = PolicyBlock(title, no)
            pf.policies.append(cur)
        elif low.startswith("attacker controls"):
            srcs = split_list(line[len("attacker controls"):])
            if cur is None:
                pf.sources = srcs
            else:
                cur.sources = srcs
        elif low.startswith(("secret ", "group ")) and cur is None:
            kw, _, rest = line.partition(" ")
            name, eq, value = rest.partition("=")
            name = name.strip()
            if not eq or not re.fullmatch(r"[A-Za-z_][\w-]*", name):
                raise PolicyError(no, f"expected: {kw} NAME = ...")
            if kw == "secret":
                pf.secrets[name] = (no, value.strip())
            else:
                pf.groups[name] = (no, split_list(value))
        elif low.startswith("never"):
            if cur is None:
                raise PolicyError(no, "'never' must be inside a policy block")
            body = line[len("never"):].strip()
            if body.lower().startswith("hijack "):
                cur.stmts.append(Stmt(no, "hijack", [], split_list(body[len("hijack "):])))
                continue
            if "->" not in body:
                raise PolicyError(no, "expected: never DATA -> PLACES, never attacker -> PLACES, "
                                      "or never hijack AGENTS")
            left, right = (x.strip() for x in body.split("->", 1))
            src, dst = split_list(left), split_list(right)
            if not src or not dst:
                raise PolicyError(no, "both sides of -> need at least one name")
            kind = "attack" if [x.lower() for x in src] == ["attacker"] else "flow"
            if kind == "flow" and "attacker" in (x.lower() for x in src):
                raise PolicyError(no, "write 'never attacker -> ...' on its own line")
            cur.stmts.append(Stmt(no, kind, src, dst))
        elif low.startswith("tolerate"):
            if cur is None:
                raise PolicyError(no, "'tolerate' must be inside a policy block")
            for part in split_list(line[len("tolerate"):]):
                toks = part.split()
                if len(toks) != 2:
                    raise PolicyError(no, f"expected e.g. '1 agent' or '0 approvals', got '{part}'")
                n = parse_count(toks[0].lower(), no)
                unit = toks[1].lower().rstrip("s")
                if unit == "agent":
                    cur.agents = n
                elif unit == "approval":
                    cur.approvals = n
                elif unit == "injection":
                    cur.injections = n
                else:
                    raise PolicyError(no, f"unknown budget '{toks[1]}' (use agents, approvals or injections)")
        else:
            hint = " (secret/group lines go before the first policy)" \
                if low.startswith(("secret ", "group ")) else ""
            raise PolicyError(no, f"cannot read: '{line}'{hint}")
    for p in pf.policies:
        if not p.stmts:
            raise PolicyError(p.line, f'policy "{p.title}" has no never-statements')
    return pf


# ---------------------------------------------------------------- resolution

@dataclass
class Items:
    labels: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    agents: set[str] = field(default_factory=set)

    def __or__(self, o: "Items") -> "Items":
        return Items(self.labels | o.labels, self.resources | o.resources, self.agents | o.agents)


def short(label: str) -> str:
    return re.sub(r"_(key|keys|creds|token|tokens|sessions)$", "", label)


class Resolver:
    """Turns names in a policy into labels, resources and agents of a System."""

    def __init__(self, s: System, pf: PolicyFile,
                 path_map: Callable[[str], str | None] | None = None):
        self.s, self.pf = s, pf
        self.path_map = path_map or (lambda p: None)
        self.labels = {l for r in s.resources.values() for l in r.labels}
        self.alias: dict[str, str] = {}
        for l in sorted(self.labels):
            self.alias.setdefault(short(l), l)
        for name, (no, target) in pf.secrets.items():
            self.define_secret(name, target, no)

    def define_secret(self, name: str, target: str, no: int) -> None:
        rs = self.resource_names(target, no)
        if not rs:
            raise PolicyError(no, f"secret {name}: '{target}' is not a known file or resource")
        for r in rs:
            self.s.resources[r].labels.add(name)
        self.labels.add(name)

    def resource_names(self, tok: str, no: int) -> set[str]:
        if tok in self.s.resources:
            return {tok}
        if tok.startswith(("~", "/")):
            r = self.path_map(tok)
            return {r} if r else set()
        if any(c in tok for c in "*?["):
            return {r for r in self.s.resources if fnmatch.fnmatchcase(r, tok)}
        return set()

    def known(self) -> list[str]:
        return (sorted(self.s.agents) + sorted(self.s.resources) + sorted(self.labels) +
                sorted(self.alias) + sorted(self.pf.groups) +
                ["secrets", "internet", "agents"] +
                [f"{fn}({a})" for fn in ("settings", "instructions") for a in sorted(self.s.agents)])

    def item(self, tok: str, no: int, seen: frozenset[str] = frozenset()) -> Items:
        low = tok.lower()
        if tok in self.pf.groups:
            if tok in seen:
                raise PolicyError(no, f"group {tok} refers to itself")
            out = Items()
            for x in self.pf.groups[tok][1]:
                out = out | self.item(x, no, seen | {tok})
            return out
        if low == "secrets":
            return Items(labels=set(self.labels))
        if low == "internet":
            return Items(resources={r for r, x in self.s.resources.items() if x.sink})
        if low == "agents":
            return Items(agents=set(self.s.agents))
        m = re.fullmatch(r"(settings|instructions)\((.+)\)", tok)
        if m:
            fn, a = m.group(1), m.group(2).strip()
            if a not in self.s.agents:
                raise PolicyError(no, f"{fn}({a}): no agent named {a}; agents: "
                                      + ", ".join(sorted(self.s.agents)))
            if fn == "settings":   # files that configure only this agent, or its settings
                # group (ctl:*), which a scan shares between e.g. all Claude Code projects
                return Items(resources={r for r, x in self.s.resources.items() if x.controls == [a]
                                        or (r.startswith("ctl:") and a in x.controls)})
            # every file this agent takes instructions from, shared ones included
            return Items(resources={r for r, x in self.s.resources.items() if a in x.controls})
        if tok in self.s.agents:
            return Items(agents={tok})
        if tok in self.labels:
            return Items(labels={tok})
        if tok in self.alias:
            return Items(labels={self.alias[tok]})
        rs = self.resource_names(tok, no)
        if rs:
            return Items(resources=rs)
        close = difflib.get_close_matches(tok, self.known(), n=3, cutoff=0.6)
        hint = f"; did you mean {', '.join(close)}?" if close else \
            "; run 'agentcheck.py names' to list the names you can use"
        raise PolicyError(no, f"unknown name '{tok}'{hint}")

    def items(self, toks: list[str], no: int) -> Items:
        out = Items()
        for t in toks:
            out = out | self.item(t, no)
        return out

    def data_labels(self, it: Items, no: int) -> set[str]:
        if it.agents:
            raise PolicyError(no, "the left side of -> must be data (secrets or files), "
                                  f"not agents ({', '.join(sorted(it.agents))})")
        labels = set(it.labels)
        for r in it.resources:
            res = self.s.resources[r]
            if not res.labels:
                res.labels.add(f"data:{r}")
                self.labels.add(f"data:{r}")
            labels |= res.labels
        if not labels:
            raise PolicyError(no, "the left side of -> names no data")
        return labels

    def sources(self, toks: list[str] | None, no: int) -> frozenset[str] | None:
        if toks is None:
            return None
        out = set()
        for t in toks:
            rs = self.resource_names(t, no)
            bad = [r for r in rs if not self.s.resources[r].untrusted]
            if not rs or bad:
                untrusted = sorted(r for r, x in self.s.resources.items() if x.untrusted)
                raise PolicyError(no, f"attacker controls '{t}': must be an untrusted input; "
                                      f"inputs here: {', '.join(untrusted) or 'none'}")
            out |= rs
        return frozenset(out)


@dataclass
class Compiled:
    title: str
    goal: Goal
    agents: int | None
    approvals: int | None
    stmts: list[str]
    notes: list[str] = field(default_factory=list)   # statements that hold trivially here
    injections: int | None = None                    # tolerated prompt injections (None = any)


def compile_file(s: System, pf: PolicyFile,
                 path_map: Callable[[str], str | None] | None = None) -> list[Compiled]:
    rv = Resolver(s, pf, path_map)
    global_sources = rv.sources(pf.sources, 0) if pf.sources else None
    out = []
    for p in pf.policies:
        atoms: list[Policy] = []
        readable: list[str] = []
        notes: list[str] = []
        for st in p.stmts:
            if st.kind == "hijack":
                it = rv.items(st.dst, st.line)
                if not it.agents or it.labels or it.resources:
                    raise PolicyError(st.line, "never hijack takes agent names")
                for a in sorted(it.agents):
                    atoms.append(Policy(f"{a} taken over", "hijack", agent=a))
                readable.append(f"no agent among {sorted(it.agents)} works for the attacker")
                continue
            dst = rv.items(st.dst, st.line)
            if dst.labels:
                raise PolicyError(st.line, "the right side of -> must be places or agents, "
                                           f"not data ({', '.join(sorted(dst.labels))})")
            # settings(A) / instructions(A) of an agent that exists but resolve to nothing:
            # the configuration does not say which files steer it, so refuse rather than pass
            for tok in st.dst:
                if re.fullmatch(r"(settings|instructions)\(.+\)", tok.strip()) and \
                        not rv.item(tok, st.line).resources:
                    raise PolicyError(st.line, f"{tok} names no file in this configuration, so the "
                                               "statement could never be violated")
            if not dst.resources and not dst.agents:
                # e.g. 'internet' where nothing leaves: true, but say so instead of a silent PASS
                notes.append(f"line {st.line}: {', '.join(st.dst)} names nothing in this configuration, "
                             "so this statement holds trivially")
                continue
            if st.kind == "attack":
                for r in sorted(dst.resources):
                    atoms.append(Policy(f"attacker content reaches {r}", "integrity", resource=r))
                for a in sorted(dst.agents):
                    atoms.append(Policy(f"{a} taken over", "hijack", agent=a))
                readable.append(f"attacker content never reaches {sorted(dst.resources)}"
                                + (f"; agents {sorted(dst.agents)} never taken over" if dst.agents else ""))
                continue
            labels = rv.data_labels(rv.items(st.src, st.line), st.line)
            for l in sorted(labels):
                if dst.resources:
                    atoms.append(Policy(f"{l} reaches {', '.join(sorted(dst.resources))}",
                                        "no_flow", label=l, to=[literal(r) for r in sorted(dst.resources)]))
                for a in sorted(dst.agents):
                    atoms.append(Policy(f"{a} can read {l}", "learn", label=l, agent=a))
            readable.append(f"{sorted(labels)} never reach {sorted(dst.resources)}"
                            + (f" or become readable by {sorted(dst.agents)}" if dst.agents else ""))
        sources = rv.sources(p.sources, p.line) if p.sources else global_sources
        out.append(Compiled(p.title, Goal(p.title, atoms, sources), p.agents, p.approvals, readable, notes,
                            p.injections))
    return out
