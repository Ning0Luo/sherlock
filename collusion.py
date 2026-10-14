#!/usr/bin/env python3
"""Static t-collusion analysis for a set of agents sharing one machine.

Model
-----
Resources are named nodes. Each resource may carry:
  labels     confidentiality labels it holds initially (e.g. "ssh_key")
  untrusted  attacker can write it (web pages, inbound email, issues)
  sink       data written here leaves the machine (network, PR comments)
  protected  integrity-critical; attacker influence here is a violation
  controls   agents that take instructions/config from it (CLAUDE.md,
             settings.json, MCP config, memory files)
  access     editing it changes what agents may do (permission rules, MCP
             configs, approval lists); see freeze()

Agents have read/write patterns (fnmatch over resource names), an
`injectable` flag (true for LLM agents, false for deterministic tools),
and `flows`: [src, dst] pattern pairs the agent relays as part of its
honest job (a deploy step, a summarizer, a CI pipeline).

Semantics (least fixpoint, monotone):
  * Attacker-influenced resources T start as the untrusted ones, and
    grow by everything a corrupted agent can write.
  * An agent becomes corrupted if
      - it is in the initial coalition C, or
      - a resource that controls it is in T                (both modes), or
      - it is injectable and reads anything in T            (agentic mode).
  * A corrupted agent moves every label it can read to everything it
    can write. An honest agent moves labels and attacker influence only
    along its declared flows.

A policy is violated if a label reaches a forbidden sink, or T reaches a
protected resource. We enumerate coalitions by size and report every
minimal coalition that violates each policy, with a witness.
"""

from __future__ import annotations

import argparse
import fnmatch
import itertools
import json
import sys
from dataclasses import dataclass, field


@dataclass
class Agent:
    name: str
    read: list[str]
    write: list[str]
    injectable: bool = True
    flows: list[tuple[str, str]] = field(default_factory=list)
    # Gates that ask the user: gate name -> {"read": [...], "write": [...]}.
    # Approving a gate once grants all of its rights (one approved shell
    # command can read and send in one go, so a gate is the unit of approval).
    ask: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # trusted: the attacker can neither break into this agent nor steer it.
    trusted: bool = False
    # strips: what its honest flows do not pass on: secret labels, and
    # "attacker" for attacker-written content (a sanitizer, a fixed-choice router).
    strips: list[str] = field(default_factory=list)
    # unknown: its open rights are an upper bound nobody could confirm (a scanned
    # agent whose settings could not be read). Checks use them as they are;
    # synth.py treats each one as an open question.
    unknown: bool = False
    # maybe: open rights ({"read": [...], "write": [...]}, patterns) that are only
    # assumed; checks use them, synth.py treats each as an open question.
    maybe: dict[str, list[str]] = field(default_factory=dict)
    # reads_as_data: untrusted resources this agent consumes as data, not as
    # instructions (structured extraction, a validator, a fixed-choice router), so
    # reading them does NOT steer it. A targeted way to drop a prompt-injection
    # false positive -- sound because you assert it. It still relays via `flows`.
    reads_as_data: list[str] = field(default_factory=list)


def gate_id(agent: str, gate: str) -> str:
    return f"{agent}:{gate}"


def injected(res: "Result") -> list[str]:
    """Agents the attack prompt-injected (each one is an injection the attacker must land)."""
    return sorted(a for a, why in res.corrupted.items() if why.startswith("prompt-injected"))


@dataclass
class Resource:
    name: str
    labels: set[str] = field(default_factory=set)
    untrusted: bool = False
    sink: bool = False
    protected: bool = False
    controls: list[str] = field(default_factory=list)
    access: bool = False


@dataclass
class Policy:
    name: str
    kind: str                  # "no_flow" | "integrity" | "hijack" | "learn"
    label: str | None = None   # no_flow, learn
    to: list[str] | None = None  # no_flow targets (default: every sink)
    resource: str | None = None  # integrity
    agent: str | None = None     # hijack, learn


@dataclass
class System:
    agents: dict[str, Agent]
    resources: dict[str, Resource]
    policies: list[Policy]

    def matches(self, patterns: list[str]) -> set[str]:
        return {r for r in self.resources
                if any(fnmatch.fnmatchcase(r, p) for p in patterns)}


def literal(name: str) -> str:
    """An fnmatch pattern that matches exactly the resource name `name`, for code
    that stores concrete names where patterns are expected."""
    return "".join(f"[{c}]" if c in "*?[" else c for c in name)


def _check_shape(raw, path: str) -> None:
    """Raise ValueError, naming the entry, when a configuration has the wrong shape."""
    def need(ok, what: str) -> None:
        if not ok:
            raise ValueError(f"{path}: {what}")
    names = lambda x: isinstance(x, list) and all(isinstance(y, str) for y in x)
    rights = lambda x: isinstance(x, dict) and all(names(v) for v in x.values())
    need(isinstance(raw, dict) and isinstance(raw.get("agents"), dict)
         and isinstance(raw.get("resources"), dict),
         'expected {"agents": {NAME: {...}}, "resources": {NAME: {...}}}')
    for name, spec in raw["resources"].items():
        need(isinstance(spec, dict), f"resource {name} must be an object")
        need(names(spec.get("labels", [])) and names(spec.get("controls", [])),
             f"resource {name}: labels and controls must be lists of names")
    for name, spec in raw["agents"].items():
        need(isinstance(spec, dict), f"agent {name} must be an object")
        for k in ("read", "write", "strips"):
            need(names(spec.get(k, [])), f"agent {name}: {k} must be a list of names")
        need(rights(spec.get("maybe", {})), f"agent {name}: maybe must map read/write to lists")
        ask = spec.get("ask", {})
        need(isinstance(ask, dict) and all(rights(g) for g in ask.values()),
             f"agent {name}: ask must map each gate to its read/write lists")
        need(isinstance(spec.get("flows", []), list)
             and all(names(f) and len(f) == 2 for f in spec.get("flows", [])),
             f"agent {name}: flows must be [source, destination] pairs")
    need(isinstance(raw.get("policies", []), list)
         and all(isinstance(p, dict) for p in raw.get("policies", [])),
         "policies must be a list of objects")


def load(path: str) -> System:
    """Read a configuration file; a malformed one raises ValueError naming the file."""
    with open(path) as f:
        try:
            raw = json.load(f)
        except ValueError as e:      # not JSON, or not text
            raise ValueError(f"{path}: not a JSON file ({e})")
    _check_shape(raw, path)
    resources = {}
    for name, spec in raw["resources"].items():
        resources[name] = Resource(
            name=name,
            labels=set(spec.get("labels", [])),
            untrusted=spec.get("untrusted", False),
            sink=spec.get("sink", False),
            protected=spec.get("protected", False),
            controls=spec.get("controls", []),
            access=spec.get("access", False),
        )
    agents = {name: Agent(name=name, read=spec.get("read", []),
                          write=spec.get("write", []),
                          injectable=spec.get("injectable", True),
                          flows=[tuple(f) for f in spec.get("flows", [])],
                          ask=spec.get("ask", {}),
                          trusted=bool(spec.get("trusted", False)),
                          strips=list(spec.get("strips", [])),
                          unknown=bool(spec.get("unknown", False)),
                          maybe=dict(spec.get("maybe", {})),
                          reads_as_data=list(spec.get("reads_as_data", [])))
              for name, spec in raw["agents"].items()}
    try:
        policies = [Policy(**p) for p in raw.get("policies", [])]
    except TypeError as e:
        raise ValueError(f"{path}: a policy has an unknown field ({e})")
    sys_ = System(agents, resources, policies)
    for r in resources.values():
        for a in r.controls:
            if a not in agents:
                raise ValueError(f"{path}: resource {r.name} controls unknown agent {a}")
    return sys_


@dataclass
class Result:
    corrupted: dict[str, str]                  # agent -> reason
    tainted: dict[str, str]                    # resource -> reason
    labels: dict[str, dict[str, str]]          # resource -> label -> reason
    reads: dict[str, set[str]] = field(default_factory=dict)  # effective read sets


def freeze(s: System, thaw: set[str] | frozenset[str] = frozenset()) -> System:
    """The same system with access settings frozen: no agent can write a resource
    marked `access` (except those in `thaw`), so only attacks that need no permission
    edit remain. Sound only together with a check of every access edit when it happens
    (agentcheck watch/diff). Resources are shared with s, so labels added while
    compiling policies carry over."""
    frozen = {r for r, x in s.resources.items() if x.access and r not in thaw}
    if not frozen:
        return s

    def keep(patterns: list[str]) -> list[str]:   # names become patterns again: escape them
        return [literal(r) for r in sorted(s.matches(patterns) - frozen)]

    agents = {a: Agent(a, read=ag.read, write=keep(ag.write), injectable=ag.injectable,
                       flows=ag.flows,       # relays need a write right, which keep() removed
                       ask={g: {**r, "write": keep(r.get("write", []))} for g, r in ag.ask.items()},
                       trusted=ag.trusted, strips=ag.strips, unknown=ag.unknown, maybe=ag.maybe,
                       reads_as_data=ag.reads_as_data)
              for a, ag in s.agents.items()}
    out = System(agents, s.resources, s.policies)
    out.notes = getattr(s, "notes", [])  # type: ignore[attr-defined]
    return out


def gates(s: System) -> list[str]:
    return [gate_id(a, g) for a, ag in s.agents.items() for g in ag.ask]


def effective(s: System, approved: frozenset[str] | set[str] = frozenset()):
    """Read/write sets per agent: open rights plus the rights of approved gates."""
    reads = {a: s.matches(ag.read) for a, ag in s.agents.items()}
    writes = {a: s.matches(ag.write) for a, ag in s.agents.items()}
    for a, ag in s.agents.items():
        for g, rights in ag.ask.items():
            if gate_id(a, g) in approved:
                reads[a] |= s.matches(rights.get("read", []))
                writes[a] |= s.matches(rights.get("write", []))
    return reads, writes


def analyze(s: System, coalition: frozenset[str], injection: bool,
            approved: frozenset[str] = frozenset(),
            sources: frozenset[str] | None = None, recruit: bool = True,
            inject_set: frozenset[str] | None = None,
            seed_tainted: frozenset[str] = frozenset(),
            seed_labels: dict[str, set[str]] | None = None,
            seed_corrupt: frozenset[str] = frozenset()) -> Result:
    """sources: the untrusted resources the attacker writes (None = all).
    recruit=False: only the coalition acts; no agent is taken over through
    files that steer it (pure collusion among deliberately malicious agents).
    inject_set: if given, only these agents may be prompt-injected (each is one
    injection the attacker must land); None means any injectable agent can be.
    seed_*: observed runtime state (for the live monitor) -- resources already
    holding attacker content, label positions already reached, agents already
    corrupted. They start the fixpoint, so reachability is asked from where we are now."""
    reads, writes = effective(s, approved)
    data_only = {a: s.matches(ag.reads_as_data) for a, ag in s.agents.items()}

    corrupted = {a: "initial coalition" for a in coalition if not s.agents[a].trusted}
    for a in seed_corrupt:
        if not s.agents[a].trusted:
            corrupted.setdefault(a, "already working for the attacker (observed)")
    tainted = {r: "untrusted source" for r, res in s.resources.items()
               if res.untrusted and (sources is None or r in sources)}
    for r in seed_tainted:
        if r in s.resources:
            tainted.setdefault(r, "attacker content observed here")
    labels = {r: {l: "origin" for l in res.labels}
              for r, res in s.resources.items()}
    for l, rs in (seed_labels or {}).items():
        for r in rs:
            if r in labels:
                labels[r].setdefault(l, "observed here (runtime)")

    changed = True
    while changed:
        changed = False
        for a, ag in s.agents.items():
            if a in corrupted or ag.trusted:
                continue
            for r in s.resources.values() if recruit else ():
                if a in r.controls and r.name in tainted:
                    corrupted[a] = f"its control file {r.name} is attacker-influenced"
                    break
            else:
                if injection and ag.injectable and (inject_set is None or a in inject_set):
                    hit = sorted((reads[a] & tainted.keys()) - data_only[a])
                    if hit:
                        corrupted[a] = f"prompt-injected by reading {hit[0]}"
            if a in corrupted:
                changed = True
        for a, ag in s.agents.items():
            if a in corrupted:
                continue
            for sp, dp in ag.flows:
                for r in s.matches([sp]) & reads[a]:
                    for w in s.matches([dp]) & writes[a]:
                        if r in tainted and w not in tainted and "attacker" not in ag.strips:
                            tainted[w] = f"relayed by honest {a} from {r}"
                            changed = True
                        for l in list(labels[r]):
                            if l not in labels[w] and l not in ag.strips:
                                labels[w][l] = f"{a} relays {r} -> {w}"
                                changed = True
        for a in corrupted:
            for w in writes[a]:
                if w not in tainted:
                    tainted[w] = f"written by corrupted {a}"
                    changed = True
            for r in reads[a]:
                for l in list(labels[r]):
                    for w in writes[a]:
                        if l not in labels[w]:
                            labels[w][l] = f"{a} copied {r} -> {w}"
                            changed = True
    return Result(corrupted, tainted, labels, reads)


def violated(s: System, p: Policy, res: Result) -> str | None:
    if p.kind == "no_flow":
        targets = s.matches(p.to) if p.to else {r for r, x in s.resources.items() if x.sink}
        for t in sorted(targets):
            if p.label in res.labels[t]:
                return t
    elif p.kind == "integrity":
        if p.resource in res.tainted:
            return p.resource
    elif p.kind == "hijack":
        if p.agent in res.corrupted:
            return p.agent
    elif p.kind == "learn":
        for r in sorted(res.reads.get(p.agent, ())):
            if p.label in res.labels[r]:
                return r
    else:
        sys.exit(f"unknown policy kind {p.kind}")
    return None


def witness(s: System, p: Policy, res: Result, target: str) -> list[str]:
    """Walk reasons backwards to a readable chain."""
    lines: list[str] = []
    seen_agents: set[str] = set()

    def explain_agent(a: str) -> None:
        if a in seen_agents:
            return
        seen_agents.add(a)
        why = res.corrupted[a]
        if why.startswith("prompt-injected by reading "):
            explain_taint(why.rsplit(" ", 1)[1])
        elif why.startswith("its control file "):
            explain_taint(why.split()[3])
        lines.append(f"  agent {a}: {why}")

    def explain_taint(r: str) -> None:
        why = res.tainted[r]
        if why.startswith("written by corrupted "):
            explain_agent(why.rsplit(" ", 1)[1])
        elif why.startswith("relayed by honest "):
            explain_taint(why.rsplit(" ", 1)[1])
        lines.append(f"  resource {r}: {why}")

    if p.kind == "integrity":
        explain_taint(target)
        return lines
    if p.kind == "hijack":
        explain_agent(target)
        return lines

    # label flow: follow copy steps back to origin
    hops = []
    cur = target
    while True:
        why = res.labels[cur][p.label]
        if why == "origin" or why.startswith("observed"):   # origin, or seeded runtime state
            break
        agent = why.split()[0]
        src = why.split()[2]
        hops.append((agent, src, cur))
        cur = src
    where = "observed at" if res.labels[cur][p.label].startswith("observed") else "originates in"
    lines.append(f"  label {p.label} {where} {cur}")
    for agent, src, dst in reversed(hops):
        if agent in res.corrupted:
            explain_agent(agent)
            lines.append(f"  {agent} copies {p.label}: {src} -> {dst}")
        else:
            lines.append(f"  honest {agent} relays {p.label}: {src} -> {dst}")
    if p.kind == "learn":
        lines.append(f"  {p.agent} can read {target}, which now holds {p.label}")
    return lines


def minimal_coalitions(s: System, injection: bool, max_t: int | None):
    names = sorted(s.agents)
    n = len(names)
    found: dict[str, list[tuple[frozenset[str], Result, str]]] = {p.name: [] for p in s.policies}
    for k in range(0, (n if max_t is None else min(n, max_t)) + 1):
        for combo in itertools.combinations(names, k):
            c = frozenset(combo)
            pending = [p for p in s.policies
                       if not any(prev <= c for prev, _, _ in found[p.name])]
            if not pending:
                continue
            res = analyze(s, c, injection)
            for p in pending:
                t = violated(s, p, res)
                if t is not None:
                    found[p.name].append((c, res, t))
    return found


def report(s: System, injection: bool, max_t: int | None, show: int) -> None:
    mode = "agentic (reads of attacker data corrupt LLM agents)" if injection \
        else "traditional (only control files and coalition corrupt)"
    print(f"== mode: {mode}")
    print(f"   {len(s.agents)} agents, {len(s.resources)} resources\n")
    found = minimal_coalitions(s, injection, max_t)
    baseline = set(analyze(s, frozenset(), injection).corrupted)
    if baseline:
        print(f"   corrupted with no insider at all: {', '.join(sorted(baseline))}\n")
    for p in s.policies:
        hits = found[p.name]
        if not hits:
            bound = "any coalition" if max_t is None else f"coalitions up to {max_t}"
            print(f"[SAFE]  {p.name}: no violation for {bound}")
            continue
        k = min(len(c) for c, _, _ in hits)
        if k == 0:
            print(f"[BROKEN] {p.name}: needs no compromised agent (external attacker suffices)")
        else:
            print(f"[BROKEN] {p.name}: broken by {k} colluding agent(s); "
                  f"resilient to t={k - 1}")
        for c, res, target in sorted(hits, key=lambda h: (len(h[0]), sorted(h[0])))[:show]:
            who = "{" + ", ".join(sorted(c)) + "}" if c else "{} (external attacker only)"
            drafted = sorted(set(res.corrupted) - c - (baseline if c else set()))
            extra = f"  (also conscripts: {', '.join(drafted)})" if drafted else ""
            print(f"   minimal coalition {who} -> {target}{extra}")
            for line in witness(s, p, res, target):
                print("   " + line)
        if len(hits) > show:
            print(f"   ... {len(hits) - show} more minimal coalitions")
        print()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("config")
    ap.add_argument("--mode", choices=["agentic", "traditional", "both"], default="both")
    ap.add_argument("--max-t", type=int, default=None)
    ap.add_argument("--show", type=int, default=3, help="witnesses per policy")
    args = ap.parse_args()
    try:
        s = load(args.config)
    except ValueError as e:
        sys.exit(f"error: {e}")
    modes = {"agentic": [True], "traditional": [False], "both": [False, True]}[args.mode]
    for inj in modes:
        report(s, inj, args.max_t, args.show)


if __name__ == "__main__":
    main()
