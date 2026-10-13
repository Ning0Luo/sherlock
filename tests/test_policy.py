"""Randomized check of general goals (learn, hijack, multi-atom, attacker
sources) against brute force, parser/resolver error messages, and regressions:
duplicate titles, statements that name nothing, settings() of a shared settings
group, and resource names with fnmatch characters."""
import itertools, random, sys
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
from collusion import Agent, Policy, Resource, System, analyze, gates, violated
from policy import PolicyError, compile_file, parse
from sat import Goal, frontier, solve
from test_sat import rand_system

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


def brute(s, goal, inj):
    G, A = gates(s), sorted(s.agents)
    best = {}
    for t in range(len(A) + 1):
        for c in itertools.combinations(A, t):
            for h in range(len(G) + 1):
                if t in best and best[t] <= h:
                    break
                hit = False
                for g in itertools.combinations(G, h):
                    res = analyze(s, frozenset(c), inj, frozenset(g), goal.sources)
                    if any(violated(s, a, res) for a in goal.atoms):
                        hit = True
                        break
                if hit:
                    best[t] = min(best.get(t, 99), h)
                    break
    pts, bh = [], 99
    for t in sorted(best):
        if best[t] < bh:
            pts.append((t, best[t]))
            bh = best[t]
    return pts


def rand_goal(rng, s):
    A = sorted(s.agents)
    shared = [r for r in s.resources if r.startswith("r")]
    atoms = []
    for _ in range(rng.choice([1, 2, 3])):
        k = rng.choice(["no_flow", "integrity", "hijack", "learn"])
        if k == "no_flow":
            atoms.append(Policy("f", k, label="k", to=rng.choice([None, ["net"], shared[:2]])))
        elif k == "integrity":
            atoms.append(Policy("i", k, resource=rng.choice(["prod"] + shared)))
        elif k == "hijack":
            atoms.append(Policy("h", k, agent=rng.choice(A)))
        else:
            atoms.append(Policy("l", k, label="k", agent=rng.choice(A)))
    src = rng.choice([None, frozenset({"web"}), frozenset()])
    return Goal("g", atoms, src)


rng = random.Random(11)
cases = mism = 0
for trial in range(80):
    s = rand_system(rng, rng.choice([3, 4]))
    if len(gates(s)) > 6:
        continue
    goal = rand_goal(rng, s)
    for inj in (False, True):
        want = brute(s, goal, inj)
        got = [(t, h) for t, h, _ in frontier(s, goal, inj)]
        cases += 1
        if want != got:
            mism += 1
            print("MISMATCH", trial, [a.kind for a in goal.atoms], goal.sources, inj, want, got)
print(f"goals: {cases} cases, {mism} mismatches")
fails += mism

# Parser and resolver errors must name the line and suggest fixes.
s = rand_system(random.Random(1), 3)
bad = {
    'policy "x"\n  never kye -> net\n': "did you mean key",
    'policy "x"\n  never key -> a9\n': "unknown name 'a9'",
    'policy "x"\n  never a0 -> net\n': "must be data",
    'policy "x"\n  never key\n': "expected: never",
    'never key -> net\n': "must be inside a policy",
    'policy "x"\n  never key -> net\n  tolerate 2 bananas\n': "unknown budget",
    'policy "x"\n': "has no never-statements",
    'attacker controls net\npolicy "x"\n  never key -> net\n': "must be an untrusted input",
}
ok = 0
for text, want in bad.items():
    try:
        compile_file(s, parse(text))
        print("NO ERROR for", repr(text))
    except PolicyError as e:
        if want in str(e):
            ok += 1
        else:
            print("WRONG MESSAGE", repr(text), "->", e)
print(f"errors: {ok}/{len(bad)} as expected")
fails += len(bad) - ok

# Minimal malicious coalitions (no injection, no recruitment) vs brute force.
from sat import coalitions
rng = random.Random(23)
cases = mism = 0
for trial in range(60):
    s = rand_system(rng, rng.choice([3, 4, 5]))
    goal = rand_goal(rng, s)
    h = rng.choice([0, 1])
    G, A = gates(s), sorted(s.agents)
    want = []
    for t in range(0, len(A) + 1):
        for c in itertools.combinations(A, t):
            if any(set(w) <= set(c) for w in want):
                continue
            if any(any(violated(s, a, analyze(s, frozenset(c), False, frozenset(g),
                                                goal.sources, recruit=False))
                       for a in goal.atoms)
                   for k in range(h + 1) for g in itertools.combinations(G, k)):
                want.append(c)
    got, _ = coalitions(s, goal, h=h)
    cases += 1
    if sorted(map(tuple, want)) != sorted(tuple(a.agents) for a in got):
        mism += 1
        print("COALITION MISMATCH", trial, want, [a.agents for a in got])
print(f"coalitions: {cases} cases, {mism} mismatches")
fails += mism


def error_of(s, text):
    try:
        compile_file(s, parse(text))
    except PolicyError as e:
        return str(e)
    return None


# Two policies with one title: diff and watch report by title, so one would hide the other.
e = error_of(s, 'policy "x"\n  never key -> net\n\npolicy "x"\n  never attacker -> prod\n')
expect(e and "line 4" in e and "titled" in e, f"duplicate titles rejected: {e}")
expect(error_of(s, 'policy "x"\n  never key -> net\npolicy "y"\n  never key -> net\n') is None,
       "different titles are fine")

# settings()/instructions() that resolve to nothing are refused (the configuration does not
# say what steers the agent); other names that match nothing here (internet where nothing
# leaves) hold trivially, with a note, so diff/watch still work on such configurations.
nosink = System({"a": Agent("a", read=["key"], write=["out"])},
                {"key": Resource("key", labels={"k"}), "out": Resource("out"),
                 "cfg": Resource("cfg", controls=["a", "b"]), "web": Resource("web", untrusted=True)},
                [])
nosink.agents["b"] = Agent("b", read=["web"], write=["cfg"])
e = error_of(nosink, 'policy "x"\n  never attacker -> settings(a)\n')
expect(e and "settings(a) names no file" in e and "line" in e, f"empty settings(a) is refused: {e}")
for text in ('policy "x"\n  never k -> internet\n', 'group g = internet\npolicy "x"\n  never attacker -> g\n'):
    expect(error_of(nosink, text) is None, f"{text!r}: names nothing here, holds trivially")
    c = compile_file(nosink, parse(text))[0]
    expect(c.notes and "holds trivially" in c.notes[0] and not c.goal.atoms, f"{text!r}: with a note: {c.notes}")
expect(error_of(nosink, 'policy "x"\n  never k -> internet, out\n') is None, "a non-empty part is enough")

# settings(AGENT) covers a settings group (ctl:*) the agent shares, e.g. every Claude
# Code project with its own rules; before, it resolved to nothing and passed vacuously.
cc = System({"claude_code": Agent("claude_code", read=["web"], write=["proj"]),
             "claude_code@app": Agent("claude_code@app", read=["web"], write=["proj"]),
             "helper": Agent("helper", read=["web"], write=["ctl:claude_code"])},
            {"web": Resource("web", untrusted=True), "proj": Resource("proj"),
             "ctl:claude_code": Resource("ctl:claude_code", controls=["claude_code", "claude_code@app"]),
             "ctl:helper": Resource("ctl:helper", controls=["helper"])}, [])
for a in ("claude_code", "claude_code@app"):
    c = compile_file(cc, parse(f'policy "x"\n  never attacker -> settings({a})\n'))[0]
    expect([x.resource for x in c.goal.atoms] == ["ctl:claude_code"], f"settings({a}): {c.goal.atoms}")
    expect(solve(cc, c.goal, True, 0, 0).sat, f"settings({a}) is attacker-written: FAIL, not PASS")
c = compile_file(cc, parse('policy "x"\n  never attacker -> settings(helper)\n'))[0]
expect([x.resource for x in c.goal.atoms] == ["ctl:helper"], "an agent's own settings")

# A resource name with fnmatch characters stays one name when stored as a pattern.
br = System({"x": Agent("x", read=["web", "key"], write=["net?eu?"])},   # matches net[eu] only
            {"web": Resource("web", untrusted=True), "key": Resource("key", labels={"k"}),
             "net[eu]": Resource("net[eu]", sink=True), "nete": Resource("nete", sink=True)}, [])
c = compile_file(br, parse('policy "x"\n  never k -> net[eu]\n'))[0]
expect(solve(br, c.goal, True, 0, 0).sat, "the key reaches net[eu] (the place named), not nete")
br.agents["x"].write = ["nete"]
expect(not solve(br, c.goal, True, 0, 0).sat, "writing nete does not reach net[eu]")

print("ok" if not fails else f"{fails} failures")
sys.exit(1 if fails else 0)
