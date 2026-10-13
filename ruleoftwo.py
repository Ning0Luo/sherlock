"""Meta's Agents Rule of Two, checked for one agent and for a whole fleet.

The rule: within a session an AI agent should have at most two of
  [A] it processes untrustworthy input
  [B] it can reach sensitive systems or private data
  [C] it can change state or communicate externally
and needs a person in the loop if it has all three.

In Sherlock's model:
  A  reads an untrusted resource (or, in the fleet, anything attacker text reaches)
  B  reads a resource holding a secret label, or reads/writes a sensitive one
  C  writes a sink (leaves the machine) or a sensitive resource
Changing a sensitive resource counts as both B (access to a sensitive system) and
C (a state change), as in Meta's wording; otherwise an agent that reads the web
and deploys to production would look like the A+C case the rule allows.
Sensitive = protected, or named by one of the configuration's integrity policies.

Per agent, two views:
  own    the agent's rights alone, as a per-agent review would see them
  fleet  the same letters once the other agents are taken into account: with
         nobody broken into, attacker text spreads (agentic model), secrets get
         copied, and writes travel on through other agents to sinks
A lowercase letter means the property needs an approved prompt.

The fleet verdict does not rest on the letters. Two goals are given to the SAT
solver with no agent broken into and no approval:
  trifecta   attacker text makes a secret leave (A+B+C, possibly across agents)
  sensitive  attacker text changes a sensitive resource
A failure whose path has no agent holding A, B and C on its own rights is a
composition violation: every agent follows the rule, the fleet does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from collusion import Policy, System, analyze, effective, gates
from sat import Goal, solve

LETTERS = "ABC"


@dataclass
class Props:
    """letter -> 'yes' | 'ask' (only behind an approval), plus a reason each."""
    have: dict[str, str] = field(default_factory=dict)
    why: dict[str, str] = field(default_factory=dict)

    def code(self) -> str:
        return " ".join(L if self.have.get(L) == "yes" else L.lower() if self.have.get(L) == "ask"
                        else "." for L in LETTERS)

    def all_open(self) -> bool:
        return all(self.have.get(L) == "yes" for L in LETTERS)

    def all_any(self) -> bool:
        return all(self.have.get(L) for L in LETTERS)


def sensitive(s: System) -> set[str]:
    """Protected resources, plus any the configuration's own integrity policies name
    (OpenShell's internal services, for instance)."""
    return {r for r, x in s.resources.items() if x.protected} | \
        {p.resource for p in s.policies if p.kind == "integrity" and p.resource in s.resources}


def _first(xs) -> str | None:
    xs = sorted(xs)
    return xs[0] if xs else None


def _letters(s: System, reads: set[str], writes: set[str], untrusted: set[str],
             secret: dict[str, set[str]], reach_out: set[str], reach_sens: set[str]) -> dict[str, str]:
    """Reasons for A, B, C given read/write sets. `reach_out`: written resources from
    which data ends up at a sink or sensitive resource; `reach_sens`: the same, sensitive
    resources only. Changing a sensitive system is access to it (B) and a state change
    (C), whether the agent writes it itself or other agents carry its writes there."""
    R, sens = s.resources, sensitive(s)
    out = {}
    if (r := _first(reads & untrusted)):
        out["A"] = f"reads {r}" + ("" if R[r].untrusted else " (attacker text reaches it)")
    if (r := _first(x for x in reads if secret.get(x))):
        out["B"] = f"reads {r} ({', '.join(sorted(secret[r]))})"
    elif (r := _first(writes & sens)):
        out["B"] = f"can change sensitive {r} (counts as B and C)"
    elif (r := _first(reads & sens)):
        out["B"] = f"reads sensitive {r}"
    elif (r := _first(writes & reach_sens)):
        out["B"] = f"writes {r}, which other agents carry into a sensitive system"
    if (r := _first(x for x in writes if R[x].sink)):
        out["C"] = f"writes {r}"
    elif (r := _first(writes & sens)):
        out["C"] = f"can change sensitive {r} (counts as B and C)"
    elif (r := _first(writes & reach_out)):
        out["C"] = f"writes {r}, which other agents carry out"
    return out


def _onward(s: System, writes_of: dict[str, set[str]], reads_of: dict[str, set[str]],
            corrupted: set[str], targets: set[str]) -> set[str]:
    """Resources from which data reaches `targets`, moved by
    corrupted agents (anything they read to anything they write) or along honest flows."""
    edges: dict[str, set[str]] = {}
    for a, ag in s.agents.items():
        if a in corrupted:
            for r in reads_of[a]:
                edges.setdefault(r, set()).update(writes_of[a])
        else:
            for sp, dp in ag.flows:
                for r in s.matches([sp]) & reads_of[a]:
                    edges.setdefault(r, set()).update(s.matches([dp]) & writes_of[a])
    out = set(targets)
    changed = True
    while changed:
        changed = False
        for r, ws in edges.items():
            if r not in out and ws & out:
                out.add(r)
                changed = True
    return out


def agent_props(s: System) -> dict[str, tuple[Props, Props]]:
    """agent -> (own rights, in the fleet)."""
    all_gates = frozenset(gates(s))
    untrusted0 = {r for r, x in s.resources.items() if x.untrusted}
    secret0 = {r: set(x.labels) for r, x in s.resources.items() if x.labels}
    views = {}
    for tag, approved in (("yes", frozenset()), ("ask", all_gates)):
        reads, writes = effective(s, approved)
        res = analyze(s, frozenset(), True, approved)
        sens = sensitive(s)
        out_t = {r for r, x in s.resources.items() if x.sink} | sens
        fleet_out = _onward(s, writes, reads, set(res.corrupted), out_t)
        fleet_sens = _onward(s, writes, reads, set(res.corrupted), sens)
        own_out = _onward(s, writes, reads, set(), out_t)     # honest flows only
        own_sens = _onward(s, writes, reads, set(), sens)
        secret = {r: set(ls) for r, ls in res.labels.items() if ls}
        for a in s.agents:
            own = _letters(s, reads[a], writes[a], untrusted0, secret0, own_out, own_sens)
            fleet = _letters(s, reads[a], writes[a], set(res.tainted), secret, fleet_out, fleet_sens)
            if a in res.corrupted and "A" not in fleet:
                fleet["A"] = res.corrupted[a]
            views.setdefault(a, ({}, {}))
            for i, d in enumerate((own, fleet)):
                for L, why in d.items():
                    views[a][i].setdefault(L, (tag, why))
    return {a: tuple(Props({L: t for L, (t, _) in d.items()}, {L: w for L, (_, w) in d.items()})
                     for d in v) for a, v in views.items()}


def goals(s: System) -> list[tuple[str, str, Goal | None]]:
    labels = sorted({l for x in s.resources.values() for l in x.labels})
    protected = sorted(sensitive(s))
    out = []
    t1 = "attacker text makes a secret leave (A+B+C)"
    out.append(("trifecta", t1, Goal(t1, [Policy(f"{l} leaves", "no_flow", label=l) for l in labels])
                if labels else None))
    t2 = "attacker text changes a sensitive system (A+C on B)"
    out.append(("sensitive", t2, Goal(t2, [Policy(f"attacker content reaches {r}", "integrity", resource=r)
                                           for r in protected]) if protected else None))
    return out


def path_agents(s: System, witness: list[str]) -> list[str]:
    seen: list[str] = []
    for line in witness:
        for tok in re.findall(r"[^\s,:()]+(?::[^\s,()]+)*", line):
            if tok in s.agents and tok not in seen:
                seen.append(tok)
    return seen


def check(s: System, proof_dir: Path | None = None) -> dict:
    props = agent_props(s)
    n_gates = len(gates(s))
    agents = []
    for a in sorted(s.agents):
        ag = s.agents[a]
        own, fleet = props[a]
        exempt = "not an AI model" if not ag.injectable else "trusted" if ag.trusted else None
        agents.append({"agent": a, "own": own.code(), "fleet": fleet.code(), "exempt": exempt,
                       "own_why": own.why, "fleet_why": fleet.why,
                       "breaks_alone": not exempt and own.all_open(),
                       "breaks_alone_with_approval": not exempt and not own.all_open() and own.all_any(),
                       "breaks_in_fleet": not exempt and fleet.all_open() and not own.all_open()})
    by_name = {r["agent"]: r for r in agents}
    fleet = []
    for key, title, goal in goals(s):
        if goal is None:
            fleet.append({"goal": key, "title": title, "status": "n/a",
                          "note": "no secrets declared" if key == "trifecta" else "no sensitive resources"})
            continue
        ans = solve(s, goal, True, 0, 0, proof_dir)
        row = {"goal": key, "title": title}
        if ans.sat:
            on_path = path_agents(s, ans.witness or [])
            solo = [a for a in on_path if by_name[a]["breaks_alone"]]
            row.update(status="FAIL", violates=ans.violated, path=ans.witness, agents=on_path,
                       composition=not solo, solo=solo)
        else:
            h = next((h for h in range(1, n_gates + 1) if solve(s, goal, True, 0, h).sat), None)
            row.update(status="PASS" if h is None else "HUMAN", proof=ans.proof, approvals_needed=h)
        fleet.append(row)
    return {"agents": agents, "fleet": fleet}


def render(r: dict) -> str:
    L = ["Meta's Agents Rule of Two: an AI agent should hold at most two of",
         "  [A] untrusted input   [B] secrets or sensitive systems   [C] state changes or outside contact",
         "  (lowercase: only after you approve a prompt)", ""]
    w = max([len(a["agent"]) for a in r["agents"]] + [5])
    L.append(f"  {'agent'.ljust(w)}  own    fleet")
    for a in r["agents"]:
        flag = (f"  n/a: {a['exempt']}" if a["exempt"] else
                "  BREAKS THE RULE ALONE" if a["breaks_alone"] else
                "  breaks it only through other agents" if a["breaks_in_fleet"] else
                "  all three only with approval" if a["breaks_alone_with_approval"] else "")
        L.append(f"  {a['agent'].ljust(w)}  {a['own']}  {a['fleet']}{flag}")
    L.append("")
    L.append("Fleet (no agent broken into, no approvals):")
    for f in r["fleet"]:
        st = f["status"]
        if st == "n/a":
            L.append(f"  n/a   {f['title']}: {f['note']}")
            continue
        if st == "PASS":
            L.append(f"  PASS  {f['title']}: cannot happen, even with every approval")
        elif st == "HUMAN":
            n = f["approvals_needed"]
            L.append(f"  PASS  {f['title']}: only if you approve {n} prompt{'s' if n != 1 else ''}"
                     " (the rule allows a person in the loop)")
        else:
            L.append(f"  FAIL  {f['title']}")
            if f["composition"]:
                L.append(f"        COMPOSITION: no agent on the path holds A, B and C on its own; "
                         f"together {' -> '.join(f['agents'])} do")
            else:
                L.append(f"        {', '.join(f['solo'])} already breaks the rule alone")
            L.extend("        " + x.strip() for x in f["path"] or [])
        if f.get("proof"):
            L.append(f"        proof: {f['proof']}")
    return "\n".join(L)


def explain(r: dict) -> str:
    L = []
    for a in r["agents"]:
        for view in ("own", "fleet"):
            for k, why in sorted(a[f"{view}_why"].items()):
                L.append(f"  {a['agent']} [{view}] {k}: {why}")
    return "\n".join(L)
