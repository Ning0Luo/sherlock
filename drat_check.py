#!/usr/bin/env python3
"""A small, independent DRAT proof checker (forward checking).

    python3 drat_check.py formula.cnf proof.drat

A DRAT proof is a list of steps. "l1 l2 ... 0" adds a clause, which must be:
  RUP  (reverse unit propagation): assuming every literal of the clause is
       false and unit-propagating over the current clauses gives a conflict; or
  RAT  (resolution asymmetric tautology) on its first literal p: for every
       current clause D containing -p, the clause C + (D - {-p}) is RUP.
"d l1 l2 ... 0" deletes a clause. The proof is valid if it adds the empty
clause and every addition passes. Shares no code with the solver or with the
encoder, so it checks their result independently. Unit propagation uses two
watched literals; deletions are honored, so RAT checks are exact.
"""

from __future__ import annotations

import sys
from collections import defaultdict


def read_clauses(path: str, proof: bool = False):
    toks: list[str] = []
    with open(path) as f:
        for line in f:
            s = line.strip()
            if not s or s[0] in "cp":
                continue
            toks.extend(s.split())
    out, cur, deleting = [], [], False
    for t in toks:
        if proof and t == "d":
            deleting = True
            continue
        x = int(t)
        if x == 0:
            out.append((deleting, cur))
            cur, deleting = [], False
        else:
            cur.append(x)
    return out


class Checker:
    def __init__(self) -> None:
        self.clauses: list[list[int] | None] = []
        self.watch: dict[int, list[int]] = defaultdict(list)
        self.occ: dict[int, set[int]] = defaultdict(set)
        self.units: set[int] = set()
        self.index: dict[tuple[int, ...], list[int]] = defaultdict(list)
        self.empty = False

    def add(self, lits: list[int]) -> None:
        lits = list(dict.fromkeys(lits))
        if any(-x in lits for x in lits):
            return                                  # tautology: never needed
        cid = len(self.clauses)
        self.clauses.append(lits)
        self.index[tuple(sorted(lits))].append(cid)
        for x in lits:
            self.occ[x].add(cid)
        if not lits:
            self.empty = True
        elif len(lits) == 1:
            self.units.add(cid)
        else:
            self.watch[lits[0]].append(cid)
            self.watch[lits[1]].append(cid)

    def delete(self, lits: list[int]) -> None:
        key = tuple(sorted(dict.fromkeys(lits)))
        ids = self.index.get(key)
        if not ids:
            return
        cid = ids.pop()
        for x in self.clauses[cid]:
            self.occ[x].discard(cid)
        self.units.discard(cid)
        self.clauses[cid] = None                    # watches skip it lazily

    def propagate_conflict(self, assume: list[int]) -> bool:
        """True if assigning all of `assume` true and propagating conflicts."""
        val: dict[int, bool] = {}
        trail: list[int] = []

        def assign(x: int) -> bool:
            v = val.get(abs(x))
            if v is not None:
                return v == (x > 0)
            val[abs(x)] = x > 0
            trail.append(x)
            return True

        for x in assume:
            if not assign(x):
                return True
        for cid in self.units:
            if not assign(self.clauses[cid][0]):
                return True
        i = 0
        while i < len(trail):
            false_lit = -trail[i]
            i += 1
            ws = self.watch[false_lit]
            j = 0
            while j < len(ws):
                cid = ws[j]
                c = self.clauses[cid]
                if c is None or false_lit not in (c[0], c[1]):
                    ws[j] = ws[-1]
                    ws.pop()
                    continue
                if c[0] == false_lit:
                    c[0], c[1] = c[1], c[0]
                other = c[0]
                if val.get(abs(other)) == (other > 0):
                    j += 1
                    continue
                moved = False
                for k in range(2, len(c)):
                    y = c[k]
                    vy = val.get(abs(y))
                    if vy is None or vy == (y > 0):
                        c[1], c[k] = c[k], c[1]
                        self.watch[y].append(cid)
                        ws[j] = ws[-1]
                        ws.pop()
                        moved = True
                        break
                if moved:
                    continue
                if not assign(other):
                    return True
                j += 1
        return False

    def rup(self, lits: list[int]) -> bool:
        return self.propagate_conflict([-x for x in lits])

    def rat(self, lits: list[int]) -> bool:
        if not lits:
            return False
        p = lits[0]
        for cid in list(self.occ[-p]):
            d = self.clauses[cid]
            if d is None:
                continue
            res = lits + [x for x in d if x != -p]
            if any(-x in res for x in res):
                continue
            if not self.rup(res):
                return False
        return True


def check(cnf_path: str, proof_path: str) -> tuple[bool, str]:
    ch = Checker()
    for _, c in read_clauses(cnf_path):
        ch.add(c)
    steps = read_clauses(proof_path, proof=True)
    added = rat_steps = 0
    for n, (is_del, c) in enumerate(steps, 1):
        if is_del:
            ch.delete(c)
            continue
        if ch.rup(c):
            pass
        elif ch.rat(c):
            rat_steps += 1
        else:
            return False, f"step {n}: clause {c} is neither RUP nor RAT"
        ch.add(c)
        added += 1
        if not c:
            return True, (f"VERIFIED: {added} added clauses checked "
                          f"({added - rat_steps} RUP, {rat_steps} RAT); empty clause derived")
    return False, "proof ends without deriving the empty clause"


if __name__ == "__main__":
    ok, msg = check(sys.argv[1], sys.argv[2])
    print(msg)
    sys.exit(0 if ok else 1)
