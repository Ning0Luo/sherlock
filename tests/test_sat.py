"""Randomized cross-check: SAT frontier == brute force over (agents, approvals)."""
import itertools, random, sys
sys.path.insert(0, ".")
from collusion import Agent, Policy, Resource, System, analyze, gates, violated
from sat import frontier

def rand_system(rng, n):
    m = 2 * n
    res = {f"r{i}": Resource(f"r{i}") for i in range(m)}
    res["web"] = Resource("web", untrusted=True)
    res["key"] = Resource("key", labels={"k"})
    res["net"] = Resource("net", sink=True)
    res["prod"] = Resource("prod", protected=True)
    shared = [f"r{i}" for i in range(m)]
    agents = {}
    for j in range(n):
        rd, wr = rng.sample(shared, 2), rng.sample(shared, 1)
        ask = {}
        extra = rng.sample(["key", "net", "prod", "web"] + shared, 2)
        if rng.random() < 0.6:
            ask["shell"] = {"read": [x for x in extra if x != "net" and x != "prod"],
                            "write": [x for x in extra if x in ("net", "prod")] + rng.sample(shared, 1)}
        if rng.random() < 0.4:
            ask["web"] = {"read": ["web"], "write": ["net"]}
        if rng.random() < 0.2: rd.append("key")
        if rng.random() < 0.15: wr.append("net")
        agents[f"a{j}"] = Agent(f"a{j}", rd, wr, injectable=rng.random() < 0.7, ask=ask)
    for r in rng.sample(shared, 2):
        res[r].controls = rng.sample(list(agents), 1)
    return System(agents, res, [Policy("conf", "no_flow", label="k"),
                                Policy("integ", "integrity", resource="prod")])

def brute(s, p, inj):
    G, A = gates(s), sorted(s.agents)
    best = {}
    for t in range(len(A) + 1):
        for c in itertools.combinations(A, t):
            for h in range(len(G) + 1):
                if t in best and best[t] <= h:
                    break
                if any(analyze(s, frozenset(c), inj, frozenset(g)) and
                       violated(s, p, analyze(s, frozenset(c), inj, frozenset(g)))
                       for g in itertools.combinations(G, h)):
                    best[t] = min(best.get(t, 99), h)
                    break
    pts, bh = [], 99
    for t in sorted(best):
        if best[t] < bh:
            pts.append((t, best[t])); bh = best[t]
    return pts

if __name__ == "__main__":
    rng = random.Random(7)
    n_cases = mism = 0
    for trial in range(60):
        s = rand_system(rng, rng.choice([3, 4]))
        if len(gates(s)) > 6:
            continue
        for p in s.policies:
            for inj in (False, True):
                want = brute(s, p, inj)
                got = [(t, h) for t, h, _ in frontier(s, p, inj)]
                n_cases += 1
                if want != got:
                    mism += 1
                    print("MISMATCH", trial, p.name, inj, want, got)
    print(f"{n_cases} cases, {mism} mismatches")
