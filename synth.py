"""Conditions on unknown rights: when does an attack exist, and what rules it out?

An agent marked `unknown` (a scanned agent whose settings could not be read)
gets every right as an upper bound, which makes most policies fail. Here each of
its rights becomes an open question instead: a one-right gate that is not an
approval (sat.encode's `free` gates). The model is monotone (more rights never
remove an attack), so the set of attacks is described exactly by its minimal
sets of unknown rights. For each policy:

  FAIL     an attack exists even if the unknown agents can do nothing
  PASS     no attack even if they can do everything            (DRAT proof)
  DEPENDS  an attack exists exactly when one of the minimal sets holds:
             - sets are listed smallest first; each is minimal (any smaller
               working set would have been found and blocked first)
             - a final UNSAT call with every set blocked proves the list
               complete (DRAT proof), unless --max-size/--max-sets cut it off
           and the smallest set of rights to rule out (a minimum hitting set)
           comes with a DRAT proof that ruling them out leaves no attack.
           When the list was cut off, attacks that slip past a candidate
           rule-out set add more minimal sets (extra_sets: beyond the limits,
           not smallest first), and completeness is checked again with them.

A joint condition covers every DEPENDS policy at once: the smallest set of
rights whose absence makes all of them pass, each re-proved.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from collusion import Agent, System, analyze, gate_id, gates, violated, witness
from sat import CADICAL, CNF, Answer, Goal, solve

Right = tuple[str, str, str]     # (agent, "read" | "write", resource)


def _literal(r: str) -> str:
    """An fnmatch pattern that matches exactly the resource name r."""
    return "".join(f"[{c}]" if c in "*?[" else c for c in r)


def uncertain(s: System, ag: Agent) -> dict[str, set[str]]:
    """The open rights of an agent that are open questions: all of them for an
    unknown agent, else those its `maybe` patterns name."""
    out = {}
    for op, pats in (("read", ag.read), ("write", ag.write)):
        have = s.matches(pats)
        out[op] = have if ag.unknown else have & s.matches(ag.maybe.get(op, []))
    return out


def parametrize(s: System) -> tuple[System, dict[str, Right]]:
    """The same system with every uncertain right turned into its own gate.
    Returns the system and gate id -> right."""
    rights: dict[str, Right] = {}
    agents = {}
    for a, ag in s.agents.items():
        unc = uncertain(s, ag)
        if not any(unc.values()):
            agents[a] = ag
            continue
        ask = dict(ag.ask)
        keep = {}
        for op, pats in (("read", ag.read), ("write", ag.write)):
            keep[op] = [_literal(r) for r in sorted(s.matches(pats) - unc[op])]
            for r in sorted(unc[op]):
                g = f"?{op} {r}"
                ask[g] = {op: [_literal(r)]}
                rights[gate_id(a, g)] = (a, op, r)
        agents[a] = Agent(a, read=keep["read"], write=keep["write"], injectable=ag.injectable,
                          flows=ag.flows, ask=ask, trusted=ag.trusted, strips=ag.strips,
                          unknown=ag.unknown, maybe=ag.maybe, reads_as_data=ag.reads_as_data)
    out = System(agents, s.resources, s.policies)
    out.notes = getattr(s, "notes", [])  # type: ignore[attr-defined]
    return out, rights


def _sat(cnf: CNF) -> set[int] | None:
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "h.cnf"
        f.write_text(cnf.dimacs())
        out = subprocess.run([CADICAL, "-q", str(f)], capture_output=True, text=True)
    if out.returncode == 20:
        return None
    if out.returncode != 10:
        raise RuntimeError(f"cadical exit {out.returncode}: {out.stderr[-300:]}")
    return {int(x) for line in out.stdout.splitlines() if line.startswith("v")
            for x in line[1:].split() if int(x) > 0}


def min_hitting_set(sets: list[frozenset[str]]) -> frozenset[str]:
    """A smallest set that meets every set in `sets` (exact, by SAT)."""
    if not sets:
        return frozenset()
    elems = sorted(set().union(*sets))
    for k in range(1, len(elems) + 1):
        cnf = CNF()
        v = {e: cnf.var(e) for e in elems}
        for st in sets:
            cnf.add(*[v[e] for e in sorted(st)])
        cnf.at_most(list(v.values()), k)
        true = _sat(cnf)
        if true is not None:
            return frozenset(e for e in elems if v[e] in true)
    raise AssertionError("every set is non-empty, so all elements together hit them")


@dataclass
class Result:
    title: str
    status: str                                   # FAIL | PASS | DEPENDS
    attack: Answer | None = None                  # FAIL: an attack using no unknown right
    proof: str | None = None                      # PASS: no attack even with every unknown right
    sets: list[tuple[frozenset[str], Answer]] = field(default_factory=list)        # smallest first
    extra_sets: list[tuple[frozenset[str], Answer]] = field(default_factory=list)  # found for rule_out
    stopped: str | None = None                    # max_size | max_sets: why `sets` stopped short
    complete: bool = True                         # every minimal set is in sets + extra_sets
    complete_proof: str | None = None
    rule_out: frozenset[str] = frozenset()        # smallest set of rights whose absence is safe
    rule_out_proof: str | None = None
    # set by agentcheck --guard-access: an attack through an access-settings edit that this
    # (frozen) result sets aside; for DEPENDS, one that gets past rule_out
    guarded: Answer | None = None


class Synth:
    def __init__(self, s: System, injection: bool = True, proof_dir: Path | None = None,
                 max_size: int = 4, max_sets: int = 50):
        self.s = s
        self.ps, self.rights = parametrize(s)
        self.U = frozenset(self.rights)
        self.inj, self.proof_dir = injection, proof_dir
        self.max_size, self.max_sets = max_size, max_sets
        self._n = 0

    def _solve(self, goal: Goal, t: int, h: int, proof: bool = False, **kw) -> Answer:
        name = None
        if proof and self.proof_dir is not None:
            self._n += 1
            slug = "".join(ch if ch.isalnum() else "_" for ch in goal.name)[:40]
            name = f"{slug}_cond{self._n}.drat"
        return solve(self.ps, goal, self.inj, t, h, self.proof_dir if proof else None,
                     proof_name=name, free=self.U, **kw)

    def unknown_of(self, ans: Answer) -> frozenset[str]:
        return frozenset(g for g in ans.approvals if g in self.U)

    def minimize(self, goal: Goal, t: int, h: int, a: Answer) -> tuple[frozenset[str], Answer]:
        """Drop rights from an attack's set while an attack remains. Returns the
        minimal set and an attack that uses exactly it (the last one found: its
        rights are a subset of the set, and no smaller subset works)."""
        S = self.unknown_of(a)
        for g in sorted(S):
            rest = S - {g}
            b = self._solve(goal, t, h, deny=self.U - rest)
            if b.sat:
                S, a = rest, b
        return S, a

    def trim(self, goal: Goal, a: Answer) -> Answer:
        """The same attack without the broken agents and approvals it does not need
        (checked by the simulator), so 'break into X; you approve Y' lists only what
        it uses. Its uncertain rights stay as they are."""
        free = self.unknown_of(a)
        agents, real = list(a.agents), [g for g in a.approvals if g not in self.U]

        def hit(ag, ap):
            res = analyze(self.ps, frozenset(ag), self.inj, frozenset(ap) | free, goal.sources)
            for atom in goal.atoms:
                target = violated(self.ps, atom, res)
                if target is not None:
                    return atom, res, target
            return None
        for x in list(agents):
            if hit([y for y in agents if y != x], real):
                agents.remove(x)
        for g in list(real):
            if hit(agents, [y for y in real if y != g]):
                real.remove(g)
        atom, res, target = hit(agents, real)
        return Answer(True, agents, sorted(set(real) | free), witness=witness(self.ps, atom, res, target),
                      violated=atom.name, clauses=a.clauses)

    def holds_without(self, goal: Goal, t: int, h: int, deny: frozenset[str]) -> Answer:
        return self._solve(goal, t, h, proof=True, deny=deny)

    def run(self, title: str, goal: Goal, t: int, h: int) -> Result:
        base = self._solve(goal, t, h, k=0)
        if base.sat:
            return Result(title, "FAIL", attack=self.trim(goal, base))
        top = self._solve(goal, t, h, proof=True)
        if not top.sat:
            return Result(title, "PASS", proof=top.proof)
        r = Result(title, "DEPENDS")
        blocked: list[frozenset[str]] = []
        full = self.max_sets <= 0
        for k in range(1, min(self.max_size, len(self.U)) + 1):
            while not full:
                a = self._solve(goal, t, h, k=k, block_free=blocked)
                if not a.sat:
                    break
                S = self.unknown_of(a)
                r.sets.append((S, self.trim(goal, a)))
                blocked.append(S)
                full = len(r.sets) >= self.max_sets
            if full:
                break
        last = self._solve(goal, t, h, proof=True, block_free=blocked)
        r.complete, r.complete_proof = not last.sat, last.proof
        if last.sat:
            r.stopped = "max_sets" if full else "max_size"
        # Smallest set of rights to rule out; when the list was cut off, add each
        # attack that slips through (minimized) and try again.
        while True:
            D = min_hitting_set(blocked)
            chk = self.holds_without(goal, t, h, D)
            if not chk.sat:
                r.rule_out, r.rule_out_proof = D, chk.proof
                break
            S, a = self.minimize(goal, t, h, chk)
            blocked.append(S)
            r.extra_sets.append((S, self.trim(goal, a)))
        if r.extra_sets:     # the extra sets may have completed the list
            last = self._solve(goal, t, h, proof=True, block_free=blocked)
            r.complete, r.complete_proof = not last.sat, last.proof
        return r

    def joint(self, items: list[tuple[str, Goal, int, int]], results: list[Result]) -> dict:
        """One set of rights to rule out that makes every DEPENDS policy pass."""
        dep = [(it, r) for it, r in zip(items, results) if r.status == "DEPENDS"]
        sets = [S for _, r in dep for S, _ in r.sets + r.extra_sets]
        while True:
            D = min_hitting_set(sets)
            bad = None
            proofs = {}
            for (title, goal, t, h), _ in dep:
                chk = self.holds_without(goal, t, h, D)
                if chk.sat:
                    bad = (goal, t, h, chk)
                    break
                proofs[title] = chk.proof
            if bad is None:
                return {"rule_out": sorted(D), "proofs": proofs}
            goal, t, h, chk = bad
            sets.append(self.minimize(goal, t, h, chk)[0])


def say(rights: dict[str, Right], g: str, can: bool = True) -> str:
    a, op, r = rights[g]
    return f"{a} {'can' if can else 'cannot'} {op} {r}"


def say_group(rights: dict[str, Right], gids) -> list[str]:
    """'a cannot write x, y, z' lines: rights grouped by agent and operation."""
    by: dict[tuple[str, str], list[str]] = {}
    for g in gids:
        a, op, r = rights[g]
        by.setdefault((a, op), []).append(r)
    return [f"{a} cannot {op} {', '.join(sorted(rs))}" for (a, op), rs in sorted(by.items())]


def cite(proof: str) -> str:
    """A proof and the formula it refutes (sat.solve keeps it at proof + '.cnf')."""
    return f"{proof} (formula: {proof}.cnf)"


def real_approvals(rights: dict[str, Right], a: Answer) -> list[str]:
    """The approvals an attack needs from the user (its gates that are not uncertain rights)."""
    return [g for g in a.approvals if g not in rights]


def needs(rights: dict[str, Right], a: Answer) -> str:
    """'break into X; you approve Y', leaving out the empty parts."""
    real = real_approvals(rights, a)
    return "; ".join(([f"break into {', '.join(a.agents)}"] if a.agents else [])
                     + ([f"you approve {', '.join(real)}"] if real else []))


def list_sets(rights: dict[str, Right], sets, start: int, show: int) -> list[str]:
    """Numbered lines, one per set of rights, each with what else its attack uses."""
    L = []
    for i, (S, a) in enumerate(sets[:show], start):
        how = needs(rights, a)
        L.append(f"           {i}. " + "  AND  ".join(say(rights, g) for g in sorted(S))
                 + (f"   (e.g. {how})" if how else ""))
    if len(sets) > show:
        L.append(f"           ... {len(sets) - show} more (--json lists all)")
    return L


def attack_set(rights: dict[str, Right], S: frozenset[str], a: Answer) -> dict:
    """JSON for one set: its rights, a path, and the agents that attack breaks into
    and the approvals it uses (left out when empty)."""
    out = {"rights": [list(rights[g]) for g in sorted(S)], "path": a.witness}
    if a.agents:
        out["broken"] = a.agents
    if real := real_approvals(rights, a):
        out["approved"] = real
    return out


CUT = {"max_sets": "stopped at --max-sets; other sets, possibly of the same size, may exist",
       "max_size": "sets larger than --max-size were not searched"}


def check(s: System, compiled, budget, injection: bool = True, proof_dir: Path | None = None,
          max_size: int = 4, max_sets: int = 50) -> dict:
    """compiled: policy.Compiled list; budget(n, cap) as in agentcheck."""
    sy = Synth(s, injection, proof_dir, max_size, max_sets)
    n_agents, n_gates = len(s.agents), len(gates(s))
    items = [(c.title, c.goal, budget(c.agents, n_agents), budget(c.approvals, n_gates)) for c in compiled]
    results = [sy.run(*it) for it in items]
    joint = sy.joint(items, results) if any(r.status == "DEPENDS" for r in results) else None
    return {"unknown_agents": sorted({a for a, _, _ in sy.rights.values()}),
            "unknown_rights": len(sy.U), "rights": sy.rights, "results": results, "joint": joint}


def render(out: dict, show: int = 8) -> str:
    rights = out["rights"]
    L = []
    if not out["unknown_agents"]:
        L.append("No agent has uncertain rights: every result below is the same as 'check'.\n")
    else:
        L.append(f"Agents with rights the scan could not confirm: {', '.join(out['unknown_agents'])} "
                 f"({out['unknown_rights']} uncertain rights, each treated as an open question)\n")
    for r in out["results"]:
        if r.status == "FAIL":
            a = r.attack
            L.append(f"FAIL     {r.title}\n         broken whatever the uncertain rights turn out to be")
            L.append(f"         e.g. break into {', '.join(a.agents) or 'no agent'}; "
                     f"you approve {', '.join(real_approvals(rights, a)) or 'nothing'}:")
            L.extend("            " + x.strip() for x in a.witness or [])
        elif r.status == "PASS":
            if r.guarded:
                L.append(f"GUARDED  {r.title}  (only with access settings frozen)\n"
                         "         holds whatever the uncertain rights turn out to be, while access settings stay as they are")
            else:
                L.append(f"PASS     {r.title}\n         holds whatever the uncertain rights turn out to be")
            if r.proof:
                L.append(f"         proof: {cite(r.proof)}")
        else:
            L.append(f"DEPENDS  {r.title}")
            cut = "" if r.complete else f" ({CUT[r.stopped]})"
            how = "exactly" if r.complete else "at least"
            if r.sets:
                L.append(f"         an attack exists {how} when one of these holds{cut}:")
                L.extend(list_sets(rights, r.sets, 1, show))
                if r.extra_sets:
                    L.append(f"         also found while working out 'holds if' "
                             f"(beyond --{r.stopped.replace('_', '-')}, not necessarily smallest):")
            else:
                L.append(f"         an attack exists {how} when one of these holds{cut}; none is within "
                         f"--{(r.stopped or 'max_size').replace('_', '-')}, so these were found while "
                         "working out 'holds if' (not necessarily smallest):")
            room = max(show - len(r.sets[:show]), 0)        # --show caps both lists together
            if r.extra_sets:
                L.extend(list_sets(rights, r.extra_sets, len(r.sets) + 1, room) if room else
                         [f"           ... {len(r.extra_sets)} more (--json lists all)"])
            if r.complete and r.complete_proof:
                L.append(f"         complete: {cite(r.complete_proof)}")
            L.append("         holds if: " + ";  ".join(say_group(rights, r.rule_out)))
            if r.rule_out_proof:
                L.append(f"           proof: {cite(r.rule_out_proof)}")
        if r.guarded and r.status != "FAIL":
            g = r.guarded
            L.append("         set aside (--guard-access): an attack through an access-settings edit"
                     + (" gets past 'holds if'" if r.status == "DEPENDS" else "")
                     + f"; e.g. {needs(rights, g) or 'with no agent broken and no approval'}:")
            L.extend("            " + x.strip() for x in g.witness or [])
        L.append("")
    j = out["joint"]
    if j:
        frozen = any(r.guarded for r in out["results"] if r.status == "DEPENDS")
        L.append("Every DEPENDS policy holds if all of these are true (check them; each policy re-proved"
                 + (", with access settings frozen" if frozen else "") + "):")
        L.extend(f"  [ ] {line}" for line in say_group(rights, j["rule_out"]))
        L.extend(f"  proof for {title}: {cite(p)}" for title, p in j["proofs"].items() if p)
    return "\n".join(L)


def to_json(out: dict) -> dict:
    rights = out["rights"]
    conv = lambda S: [list(rights[g]) for g in sorted(S)]
    res = []
    for r in out["results"]:
        row = {"policy": r.title, "status": r.status}
        if r.status == "FAIL":
            row["attack"] = {"broken": r.attack.agents, "approved": r.attack.approvals, "path": r.attack.witness}
        elif r.status == "PASS":
            row["proof"] = r.proof
        else:
            # attack_sets: smallest first, up to --max-size/--max-sets; extra_sets: minimal
            # sets beyond those limits, found while working out rule_out (not smallest first).
            # stopped: why attack_sets stopped short (max_size | max_sets), else null.
            row.update(attack_sets=[attack_set(rights, S, a) for S, a in r.sets],
                       extra_sets=[attack_set(rights, S, a) for S, a in r.extra_sets], stopped=r.stopped,
                       complete=r.complete, complete_proof=r.complete_proof,
                       rule_out=conv(r.rule_out), rule_out_proof=r.rule_out_proof)
        if r.guarded:
            row["guarded"] = {"status_without_freezing": "FAIL" if r.status == "PASS" else "rule_out not enough",
                              **attack_set(rights, frozenset(g for g in r.guarded.approvals if g in rights),
                                           r.guarded)}
        res.append(row)
    j = out["joint"]
    return {"unknown_agents": out["unknown_agents"], "results": res,
            "joint": {"rule_out": conv(j["rule_out"]), "proofs": j["proofs"]} if j else None}
