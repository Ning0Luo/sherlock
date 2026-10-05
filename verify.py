#!/usr/bin/env python3
"""Sherlock certificate checker.

A Sherlock certificate claims that one rule holds on one scanned setup for
every way an attacker can hack up to T agents and get you to approve up to H
prompts. This file checks that claim without trusting Sherlock: it does not
search for attacks, it only checks the evidence in the certificate.

  python3 verify.py certificate.json
  pbpaste | python3 verify.py

Why the evidence is enough
--------------------------
Attacker influence spreads by fixed rules (below). For one choice of hacked
agents C and approved prompts G, the reachable state is the least set of facts
that contains the starting facts and is closed under the rules. So any set
that (1) contains the starting facts, (2) is closed under the rules and
(3) contains no violation, proves that no attack works for that (C, G): the
reachable state sits inside it. The certificate supplies such a set, an
inductive invariant, for each worst case.

The rules are monotone: hacking more agents or approving more prompts only
adds facts. So the worst cases are the choices of exactly min(T, #agents)
agents and min(H, #prompts) prompts. This checker enumerates those itself and
requires an invariant for every one.

Rules (agent A, resource R):
  - A is taken over if a resource that steers A (its "controls") is tainted,
    or if A is an AI model and reads a tainted resource.
  - A taken-over A taints everything it writes and copies every secret it can
    read into everything it can write.
  - An honest A moves taint and secrets only along its declared flows.
Untrusted resources (web pages) start tainted. Approving one of A's prompts
adds that prompt's read and write rights to A.
"""
from __future__ import annotations

import fnmatch
import itertools
import json
import sys


def fail(msg: str) -> None:
    print(f"INVALID: {msg}")
    sys.exit(1)


def main() -> None:
    text = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    try:
        cert = json.loads(text)
    except ValueError:
        fail("not JSON. Copy the whole certificate and try again.")
    if cert.get("format") != "sherlock-cert/1":
        fail("not a Sherlock certificate (format must be sherlock-cert/1)")
    setup, rule, budget = cert["setup"], cert["rule"], cert["budget"]
    res = setup["resources"]
    names = sorted(res)
    agents = setup["agents"]
    ids = sorted(agents)

    def match(pats):
        return {r for r in names if any(fnmatch.fnmatchcase(r, p) for p in pats or [])}

    base_r = {a: match(agents[a].get("read")) for a in ids}
    base_w = {a: match(agents[a].get("write")) for a in ids}
    gates = [(a, g, match(x.get("read")), match(x.get("write")))
             for a in ids for g, x in sorted((agents[a].get("ask") or {}).items())]
    ai = {a: agents[a].get("injectable", True) is not False for a in ids}
    flows = {a: [(match([s]), match([d])) for s, d in agents[a].get("flows") or []] for a in ids}
    controls = {r: set(res[r].get("controls") or []) for r in names}
    untrusted = {r for r in names if res[r].get("untrusted")}
    origin = {r: set(res[r].get("labels") or []) for r in names}
    sinks = {r for r in names if res[r].get("sink")}

    kind = rule["kind"]
    if kind not in ("no_flow", "integrity", "hijack", "learn"):
        fail(f"unknown rule kind {kind}")
    targets = (match(rule["to"]) if rule.get("to") else sinks) if kind == "no_flow" else set()

    t = min(int(budget["agents"]), len(ids))
    h = min(int(budget["approvals"]), len(gates))
    given = {}
    for inv in cert["invariants"]:
        key = (frozenset(inv["hacked"]), frozenset(tuple(x) for x in inv["approved"]))
        given[key] = inv

    cases = 0
    for C in itertools.combinations(ids, t):
        for G in itertools.combinations(range(len(gates)), h):
            cases += 1
            appr = frozenset((gates[j][0], gates[j][1]) for j in G)
            inv = given.get((frozenset(C), appr))
            who = f"hacked={list(C)} approved={sorted(appr)}"
            if inv is None:
                fail(f"no invariant for the worst case {who}")
            R = {a: set(base_r[a]) for a in ids}
            W = {a: set(base_w[a]) for a in ids}
            for j in G:
                a, _, gr, gw = gates[j]
                R[a] |= gr
                W[a] |= gw
            cor = set(inv["corrupted"])
            taint = set(inv["tainted"])
            lab = {r: set(inv["labels"].get(r, [])) for r in names}
            # (1) contains the starting facts
            if not set(C) <= cor:
                fail(f"{who}: a hacked agent is missing from the invariant")
            if not untrusted <= taint:
                fail(f"{who}: an attacker-written resource is missing")
            for r in names:
                if not origin[r] <= lab[r]:
                    fail(f"{who}: secret missing at its origin {r}")
            # (2) closed under the rules
            for a in ids:
                steered = any(a in controls[r] for r in taint)
                injected = ai[a] and bool(R[a] & taint)
                if (steered or injected) and a not in cor:
                    fail(f"{who}: {a} would be taken over but is not in the invariant")
                if a in cor:
                    if not W[a] <= taint:
                        fail(f"{who}: taken-over {a} writes an untainted resource")
                    for r in R[a]:
                        for w in W[a]:
                            if not lab[r] <= lab[w]:
                                fail(f"{who}: {a} could copy a secret from {r} to {w}")
                else:
                    for sp, dp in flows[a]:
                        for s in sp & R[a]:
                            for d in dp & W[a]:
                                if s in taint and d not in taint:
                                    fail(f"{who}: honest {a} relays taint {s} -> {d}")
                                if not lab[s] <= lab[d]:
                                    fail(f"{who}: honest {a} relays a secret {s} -> {d}")
            # (3) no violation
            if kind == "no_flow" and any(rule["label"] in lab[x] for x in targets):
                fail(f"{who}: the secret reaches a forbidden place")
            if kind == "integrity" and rule["resource"] in taint:
                fail(f"{who}: the protected resource is tainted")
            if kind == "hijack" and rule["agent"] in cor:
                fail(f"{who}: the agent is taken over")
            if kind == "learn" and any(rule["label"] in lab[x] for x in R.get(rule["agent"], ())):
                fail(f"{who}: the agent can read the secret")

    print(f"VALID: \"{rule.get('name', kind)}\" holds for every way to hack "
          f"{budget['agents']} agent(s) and approve {budget['approvals']} prompt(s).")
    print(f"Checked {cases} worst case(s) on {len(ids)} agents and {len(names)} resources.")


if __name__ == "__main__":
    main()
