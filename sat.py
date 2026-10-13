#!/usr/bin/env python3
"""SAT encoding of t-collusion with approval gates, solved with CaDiCaL.

Question for one policy and budgets (t, h):
    Is there a set of at most t broken-into agents and at most h approved
    gates such that the attack spreads to a violation?

Variables (all Boolean):
    B[a]        agent a is broken into at the start
    G[g]        the user approves gate g (one approval opens all its rights)
    H[a,i]      agent a works for the attacker by round i
    T[r,i]      resource r holds attacker content by round i
    S[r,i]      the policy's secret label has reached resource r by round i
                (no_flow policies only)
    CR/CW[a,r]  agent a may read / write r (true outright for open rights,
                otherwise only if one of a's gates covering r is approved)

Every fact may be true only for a reason (justification clauses), so a
satisfying assignment is a real attack. Rounds are unrolled to
N = |A| + 2|R| + 1, enough for the monotone closure to reach its fixpoint:
H/T depend only on H/T and settle within |A|+|R| rounds; S, for one label,
settles at most |R| rounds later.

SAT   -> the attack (agents, approvals), re-checked by the simulator.
UNSAT -> CaDiCaL writes a DRAT proof that no such attack exists, kept with
         the formula it refutes (<proof>.cnf) for drat_check.py.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from collusion import Policy, System, analyze, gate_id, gates, injected, violated, witness

CADICAL = os.environ.get("CADICAL", "cadical")


class CNF:
    def __init__(self) -> None:
        self.n = 0
        self.clauses: list[list[int]] = []
        self.names: dict[int, str] = {}

    def var(self, name: str) -> int:
        self.n += 1
        self.names[self.n] = name
        return self.n

    def add(self, *lits: int) -> None:
        self.clauses.append(list(lits))

    def justify(self, v: int, reasons: list[list[int]]) -> None:
        """v -> OR_k AND(reasons[k]); an empty conjunction is 'true'."""
        if any(len(r) == 0 for r in reasons):
            return
        heads = []
        for conj in reasons:
            if len(conj) == 1:
                heads.append(conj[0])
                continue
            z = self.var("aux")
            for lit in conj:
                self.add(-z, lit)
            heads.append(z)
        self.add(-v, *heads)

    def at_most(self, xs: list[int], k: int) -> None:
        """Sinz sequential counter: sum(xs) <= k."""
        n = len(xs)
        if k >= n:
            return
        if k == 0:
            for x in xs:
                self.add(-x)
            return
        s = [[self.var("cnt") for _ in range(k)] for _ in range(n)]
        self.add(-xs[0], s[0][0])
        for j in range(1, k):
            self.add(-s[0][j])
        for i in range(1, n):
            self.add(-xs[i], s[i][0])
            self.add(-s[i - 1][0], s[i][0])
            for j in range(1, k):
                self.add(-xs[i], -s[i - 1][j - 1], s[i][j])
                self.add(-s[i - 1][j], s[i][j])
            self.add(-xs[i], -s[i - 1][k - 1])

    def dimacs(self) -> str:
        out = [f"p cnf {self.n} {len(self.clauses)}"]
        out += [" ".join(map(str, c)) + " 0" for c in self.clauses]
        return "\n".join(out) + "\n"


@dataclass
class Goal:
    """What counts as a violation: any one of the atoms (Policy objects of kind
    no_flow / integrity / hijack / learn). sources: the untrusted inputs the
    attacker writes (None = all of them)."""
    name: str
    atoms: list[Policy]
    sources: frozenset[str] | None = None


def as_goal(p: Policy | Goal) -> Goal:
    return p if isinstance(p, Goal) else Goal(p.name, [p])


@dataclass
class Encoding:
    cnf: CNF
    B: dict[str, int]
    G: dict[str, int]
    I: dict[str, int] = field(default_factory=dict)


def encode(s: System, goal: Policy | Goal, injection: bool, t: int, h: int,
           recruit: bool = True, block: list[frozenset[str]] = (),
           free: frozenset[str] = frozenset(), k: int | None = None,
           block_free: list[frozenset[str]] = (), deny: frozenset[str] = frozenset(),
           max_inj: int | None = None) -> Encoding:
    """free: gate ids that are not approvals but unknown rights (see synth.py); they
    do not count toward h. k bounds how many of them are on (None: no bound).
    block_free: sets of free gates; no answer may switch on all of one set.
    deny: gates forced off.
    max_inj: the attacker may prompt-inject at most this many agents (None: no bound).
    Each injected agent is one uncertain event; I[a] selects it, like B[a] selects a hack."""
    goal = as_goal(goal)
    cnf = CNF()
    A, R = sorted(s.agents), sorted(s.resources)
    N = len(A) + 2 * len(R) + 1
    B = {a: cnf.var(f"B[{a}]") for a in A}
    G = {g: cnf.var(f"G[{g}]") for g in gates(s)}
    # I[a]: the attacker lands a prompt injection on agent a (only injectable, untrusted agents)
    I = {a: cnf.var(f"I[{a}]") for a in A if injection and s.agents[a].injectable and not s.agents[a].trusted}

    # Static access: CR/CW[a,r] -> open, or OR of covering gates.
    CR: dict[tuple[str, str], int] = {}
    CW: dict[tuple[str, str], int] = {}
    for a in A:
        ag = s.agents[a]
        for op, table, open_ in (("read", CR, s.matches(ag.read)),
                                 ("write", CW, s.matches(ag.write))):
            cover: dict[str, list[int]] = {}
            for g, rights in ag.ask.items():
                for r in s.matches(rights.get(op, [])):
                    cover.setdefault(r, []).append(G[gate_id(a, g)])
            for r in sorted(open_ | cover.keys()):
                v = cnf.var(f"C{op[0].upper()}[{a},{r}]")
                table[(a, r)] = v
                if r not in open_:
                    cnf.add(-v, *cover[r])
    can_read = {a: [r for r in R if (a, r) in CR] for a in A}
    controls = {a: [r for r in R if a in s.resources[r].controls] for a in A}
    labels = sorted({x.label for x in goal.atoms if x.kind in ("no_flow", "learn")})
    src = goal.sources

    H = {(a, 0): cnf.var(f"H[{a},0]") for a in A}
    T = {(r, 0): cnf.var(f"T[{r},0]") for r in R}
    S = {(l, r, 0): cnf.var(f"S[{l},{r},0]") for l in labels for r in R}
    for a in A:
        if s.agents[a].trusted:
            cnf.add(-B[a])                 # the attacker cannot break into a trusted agent
        cnf.justify(H[a, 0], [[B[a]]])
    for r in R:
        if not (s.resources[r].untrusted and (src is None or r in src)):
            cnf.add(-T[r, 0])
        for l in labels:
            if l not in s.resources[r].labels:
                cnf.add(-S[l, r, 0])

    for i in range(N):
        j = i + 1
        for a in A:
            H[a, j] = cnf.var(f"H[{a},{j}]")
        for r in R:
            T[r, j] = cnf.var(f"T[{r},{j}]")
            for l in labels:
                S[l, r, j] = cnf.var(f"S[{l},{r},{j}]")

        for a in A:
            reasons = [[H[a, i]]]
            if s.agents[a].trusted:        # nor steer it
                cnf.justify(H[a, j], reasons)
                continue
            if recruit:
                reasons += [[T[r, i]] for r in controls[a]]
            if a in I:
                data_only = s.matches(s.agents[a].reads_as_data)
                reasons += [[T[r, i], CR[a, r], I[a]] for r in can_read[a] if r not in data_only]
            cnf.justify(H[a, j], reasons)

        relays = []   # (a, r, w) honest flows usable this round
        for a in A:
            for sp, dp in s.agents[a].flows:
                for w in s.matches([dp]):
                    for r in s.matches([sp]):
                        if (a, w) in CW and (a, r) in CR:
                            relays.append((a, r, w))
        for w in R:
            t_reasons = [[T[w, i]]]
            s_reasons = {l: [[S[l, w, i]]] for l in labels}
            for a in A:
                if (a, w) not in CW:
                    continue
                t_reasons.append([H[a, i], CW[a, w]])
                for l in labels:
                    s_reasons[l] += [[H[a, i], S[l, r, i], CR[a, r], CW[a, w]]
                                     for r in can_read[a]]
            for a, r, ww in relays:
                if ww != w:
                    continue
                strips = s.agents[a].strips
                if "attacker" not in strips:
                    t_reasons.append([T[r, i], CR[a, r], CW[a, w]])
                for l in labels:
                    if l not in strips:
                        s_reasons[l].append([S[l, r, i], CR[a, r], CW[a, w]])
            cnf.justify(T[w, j], t_reasons)
            for l in labels:
                cnf.justify(S[l, w, j], s_reasons[l])

    # Goal: some atom is violated at round N.
    final: list[int] = []
    for x in goal.atoms:
        if x.kind == "no_flow":
            targets = s.matches(x.to) if x.to else {r for r in R if s.resources[r].sink}
            final += [S[x.label, r, N] for r in sorted(targets)]
        elif x.kind == "integrity":
            final.append(T[x.resource, N])
        elif x.kind == "hijack":
            final.append(H[x.agent, N])
        elif x.kind == "learn":
            for r in can_read[x.agent]:
                z = cnf.var("aux")
                cnf.add(-z, S[x.label, r, N])
                cnf.add(-z, CR[x.agent, r])
                final.append(z)
        else:
            raise ValueError(f"unknown atom kind {x.kind}")
    cnf.add(*final)   # an empty clause here means: this goal cannot be violated
    cnf.at_most(list(B.values()), t)
    cnf.at_most([v for g, v in G.items() if g not in free], h)
    if k is not None:
        cnf.at_most([v for g, v in G.items() if g in free], k)
    if max_inj is not None:
        cnf.at_most(list(I.values()), max_inj)
    for c in block:                      # exclude this coalition and its supersets
        cnf.add(*[-B[a] for a in sorted(c)])
    for c in block_free:                 # exclude this set of unknown rights and its supersets
        cnf.add(*[-G[g] for g in sorted(c)])
    for g in sorted(deny):
        cnf.add(-G[g])
    return Encoding(cnf, B, G, I)


@dataclass
class Answer:
    sat: bool
    agents: list[str]
    approvals: list[str]
    proof: str | None = None
    witness: list[str] | None = None
    violated: str | None = None
    clauses: int = 0
    injections: list[str] = field(default_factory=list)   # agents the attack prompt-injected
    formula: str | None = None          # the DIMACS formula the proof refutes: proof + ".cnf"


def solve(s: System, goal: Policy | Goal, injection: bool, t: int, h: int,
          proof_dir: Path | None = None, recruit: bool = True,
          block: list[frozenset[str]] = (), proof_name: str | None = None, **unknown) -> Answer:
    """unknown: free, k, block_free, deny, passed to encode().
    With proof_dir, an UNSAT answer leaves its DRAT proof there and, next to it as
    <proof>.cnf, the exact formula it refutes, so drat_check.py can check the pair."""
    goal = as_goal(goal)
    enc = encode(s, goal, injection, t, h, recruit, block, **unknown)
    if any(len(c) == 0 for c in enc.cnf.clauses):
        return Answer(False, [], [], clauses=len(enc.cnf.clauses))
    with tempfile.TemporaryDirectory() as tmp:
        cnf_path = Path(tmp) / "q.cnf"
        proof = None
        if proof_dir is not None:
            proof_dir.mkdir(parents=True, exist_ok=True)
            slug = "".join(ch if ch.isalnum() else "_" for ch in goal.name)[:40]
            proof = str(proof_dir / (proof_name or f"{slug}_t{t}_h{h}.drat"))
            cnf_path = Path(proof + ".cnf")
        cnf_path.write_text(enc.cnf.dimacs())
        cmd = [CADICAL, "-q", str(cnf_path)]
        if proof:
            cmd += ["--binary=false", proof]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True)
        except BaseException:            # no solver, Ctrl-C: leave no half-written pair behind
            if proof:
                Path(proof).unlink(missing_ok=True)
                cnf_path.unlink(missing_ok=True)
            raise
    if out.returncode == 20:
        return Answer(False, [], [], proof=proof, clauses=len(enc.cnf.clauses),
                      formula=str(cnf_path) if proof else None)
    if proof:                            # no proof, so no formula to keep
        Path(proof).unlink(missing_ok=True)
        cnf_path.unlink(missing_ok=True)
    if out.returncode != 10:
        raise RuntimeError(f"cadical exit {out.returncode}: {out.stderr[-300:]}")
    true = {int(x) for line in out.stdout.splitlines() if line.startswith("v")
            for x in line[1:].split() if int(x) > 0}
    agents = sorted(a for a, v in enc.B.items() if v in true)
    approvals = sorted(g for g, v in enc.G.items() if v in true)
    sel = frozenset(a for a, v in enc.I.items() if v in true)   # agents the solver injects
    # Re-check with the simulator, limited to that injection selection, for a faithful path.
    res = analyze(s, frozenset(agents), injection, frozenset(approvals), goal.sources, recruit,
                  inject_set=sel)
    for atom in goal.atoms:
        target = violated(s, atom, res)
        if target is not None:
            return Answer(True, agents, approvals, witness=witness(s, atom, res, target),
                          violated=atom.name, clauses=len(enc.cnf.clauses), injections=injected(res))
    raise AssertionError(f"SAT model is not an attack: {agents} {approvals}")


def n_injectable(s: System) -> int:
    return sum(1 for a in s.agents.values() if a.injectable and not a.trusted)


def frontier3(s: System, goal: Policy | Goal, injection: bool = True,
              proof_dir: Path | None = None) -> list[tuple[int, int, int, Answer]]:
    """Pareto-minimal (agents hacked, approvals, injections) triples that break the goal.
    Shows how much each cheapest attack relies on prompt injection."""
    goal = as_goal(goal)
    nA, nG = len(s.agents), len(gates(s))
    nI = n_injectable(s) if injection else 0
    pts: list[tuple[int, int, int, Answer]] = []
    dominated = lambda t, h, m: any(a <= t and b <= h and c <= m for a, b, c, _ in pts)
    for t in range(nA + 1):
        for h in range(nG + 1):
            for m in range(nI + 1):
                if dominated(t, h, m):
                    continue
                ans = solve(s, goal, injection, t, h, proof_dir, max_inj=m)
                if ans.sat:
                    pts.append((t, h, m, ans))
                    break                      # min injections at this (t, h); larger m dominated
    return pts


def frontier(s: System, goal: Policy | Goal, injection: bool = True,
             proof_dir: Path | None = None) -> list[tuple[int, int, Answer]]:
    """All Pareto-minimal (agents broken, approvals) pairs that break the goal.

    Each pair (t, h) comes with an attack; the UNSAT calls made on the way
    (t, h-1), and every (t', h) with t' < t, leave DRAT proofs in proof_dir.
    """
    n_agents, n_gates = len(s.agents), len(gates(s))
    points: list[tuple[int, int, Answer]] = []
    best_h = n_gates + 1
    for t in range(n_agents + 1):
        found = None
        for h in range(best_h):
            ans = solve(s, goal, injection, t, h, proof_dir)
            if ans.sat:
                found = (t, h, ans)
                break
        if found:
            points.append(found)
            best_h = found[1]
            if best_h == 0:
                break
    return points


def coalitions(s: System, goal: Policy | Goal, h: int = 0, max_size: int | None = None,
               injection: bool = False, recruit: bool = False,
               proof_dir: Path | None = None) -> tuple[list[Answer], Answer | None]:
    """Every minimal set of malicious agents that can break the goal together,
    smallest first, using at most h approvals.

    Size by size, ask the solver for an attack that avoids every coalition
    found so far and its supersets; any answer is then minimal (a smaller
    working subset would have been found and blocked earlier). The final
    UNSAT call, with its DRAT proof, shows the list is complete.
    """
    goal = as_goal(goal)
    found: list[Answer] = []
    top = len(s.agents) if max_size is None else min(max_size, len(s.agents))
    last = None
    for t in range(0, top + 1):
        while True:
            ans = solve(s, goal, injection, t, h, proof_dir, recruit,
                        [frozenset(a.agents) for a in found])
            if not ans.sat:
                last = ans
                break
            found.append(ans)
    return found, last
