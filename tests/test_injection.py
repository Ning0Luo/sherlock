"""The prompt-injection budget axis (A) and reads_as_data (B), checked against
brute force. A is a third attack cost: how many agents the attacker must
prompt-inject. B marks an untrusted input an agent consumes as data, not
instructions, so reading it does not steer the agent."""
import itertools
import random
import sys
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
from collusion import Agent, Policy, Resource, System, analyze, gates, injected, violated
from sat import as_goal, frontier, frontier3, n_injectable, solve
from test_sat import rand_system

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


def subsets(xs, k):
    for r in range(k + 1):
        yield from itertools.combinations(xs, r)


def brute_feasible(s, goal, inj, t, h, m):
    """Is there an attack with <= t hacks, <= h approvals, <= m prompt injections?"""
    goal = as_goal(goal)
    A, G = sorted(s.agents), gates(s)
    INJ = [a for a in A if s.agents[a].injectable and not s.agents[a].trusted] if inj else []
    for c in subsets(A, t):
        for g in subsets(G, h):
            for iset in subsets(INJ, min(m, len(INJ))):
                res = analyze(s, frozenset(c), inj, frozenset(g), goal.sources,
                              inject_set=frozenset(iset))
                if any(violated(s, a, res) for a in goal.atoms):
                    return True
    return False


def covered(pts, t, h, m):
    return any(a <= t and b <= h and c <= m for a, b, c, _ in pts)


# --- frontier3 vs brute force, over the whole (t, h, m) grid -------------------
def rand_inj_system(rng, n):
    s = rand_system(rng, n)
    for x in s.agents.values():
        if rng.random() < 0.4:
            x.read.append("web")            # more injectable surface
        if rng.random() < 0.25 and x.read:
            x.reads_as_data = [rng.choice(x.read)]   # some inputs are data, not instructions
    return s


rng = random.Random(5)
cases = seen_m = 0
for trial in range(60):
    s = rand_inj_system(rng, rng.choice([2, 3]))
    if len(gates(s)) > 4 or n_injectable(s) > 3:
        continue
    nA, nG, nI = len(s.agents), len(gates(s)), n_injectable(s)
    for p in s.policies:
        for inj in (True, False):
            pts = frontier3(s, p, inj)
            # Pareto-minimal: no listed point dominates another
            for i, (t1, h1, m1, _) in enumerate(pts):
                for j, (t2, h2, m2, _) in enumerate(pts):
                    if i != j:
                        expect(not (t2 <= t1 and h2 <= h1 and m2 <= m1),
                               f"trial {trial}: {pts} not Pareto-minimal")
            # every listed attack really uses exactly its injection count, within budget
            for t, h, m, ans in pts:
                expect(len(ans.agents) <= t and len(ans.approvals) <= h and len(ans.injections) <= m,
                       f"trial {trial}: attack exceeds its budget {(t,h,m)} -> {ans.agents},{ans.approvals},{ans.injections}")
            # grid equivalence: frontier3 covers (t,h,m) iff brute says an attack exists
            for t in range(nA + 1):
                for h in range(nG + 1):
                    for m in range((nI if inj else 0) + 1):
                        expect(covered(pts, t, h, m) == brute_feasible(s, p, inj, t, h, m),
                               f"trial {trial} {p.name} inj={inj}: ({t},{h},{m}) "
                               f"frontier3={covered(pts,t,h,m)} brute={brute_feasible(s,p,inj,t,h,m)}")
                        cases += 1
            if any(m > 0 for _, _, m, _ in pts):
                seen_m += 1

expect(seen_m > 0, "some random attacks genuinely need prompt injection")


# --- deterministic: a 2-injection leak chain ----------------------------------
res = {"web": Resource("web", untrusted=True), "r1": Resource("r1"),
       "key": Resource("key", labels={"k"}), "net": Resource("net", sink=True)}
s = System({"a": Agent("a", read=["web", "key"], write=["r1"]),
            "b": Agent("b", read=["r1"], write=["net"])}, res, [])
g = Policy("leak", "no_flow", label="k")
pts = {(t, h, m) for t, h, m, _ in frontier3(s, g, True)}
expect((0, 0, 2) in pts, f"the leak costs 2 injections with nobody hacked: {pts}")
expect(not solve(s, g, True, 0, 0, max_inj=1).sat, "one injection is not enough")
expect(solve(s, g, True, 0, 0, max_inj=2).sat, "two injections suffice")
expect(solve(s, g, True, 0, 0).injections == ["a", "b"], "the cheapest attack names the injected agents")

# --- B: reads_as_data drops the false positive, soundly -----------------------
s.agents["a"].reads_as_data = ["web"]          # a treats web as data, not instructions
expect(not solve(s, g, True, 0, 0).sat, "with web read as data, a is not steered, so no leak")
expect(not injected(analyze(s, frozenset(), True, inject_set=None)) == ["a"],
       "a is no longer prompt-injectable via web")
# b can still be injected if it reads tainted directly
s.agents["b"].read = ["r1", "web"]
expect(solve(s, g, True, 0, 0, max_inj=1).sat or not solve(s, g, True, 0, 0).sat,
       "the model stays consistent when another agent reads untrusted input")

# --- backward compat: the 2D frontier is unchanged by the new axis ------------
rng = random.Random(7)
mism = 0
for _ in range(40):
    s = rand_system(rng, rng.choice([3, 4]))
    if len(gates(s)) > 6:
        continue
    for p in s.policies:
        for inj in (True, False):
            two = [(t, h) for t, h, _ in frontier(s, p, inj)]
            # the 2D frontier = the (t,h) with unlimited injections (m = n_injectable)
            three_proj = sorted({(t, h) for t, h, m, _ in frontier3(s, p, inj)
                                 if m <= n_injectable(s)})
            # project the 3D frontier to its (t,h) Pareto shadow
            shadow = []
            for t, h in sorted(three_proj):
                if not any(a <= t and b <= h for a, b in shadow):
                    shadow.append((t, h))
            if two != shadow:
                mism += 1

expect(mism == 0, f"2D frontier matches the 3D projection ({mism} mismatches)")

print(f"injection: {cases} grid points vs brute, {seen_m} attacks needing injection; 0 mismatches"
      if not fails else f"{fails} failures")
sys.exit(1 if fails else 0)
