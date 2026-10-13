"""Brute-force check of synth.py: on small random systems with unknown agents and
`maybe` rights, enumerate every subset of the uncertain rights and compare the
status, the minimal attack sets, the size of the rule-out set, the joint
condition, and parametrize() itself against the simulator. Each case is run
again with --max-size/--max-sets cut-offs, checking the listed and extra sets,
the stop reason and the wording. Then: the attack paired with each set, the
approvals a FAIL needs, and the DRAT proofs against the formulas kept next to them."""
import itertools, json, random, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
from collusion import Agent, Policy, Resource, System, analyze, gates, violated
from sat import Goal, solve
import synth

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


def rand_sys(rng):
    shared = [f"r{i}" for i in range(4)]
    res = {r: Resource(r) for r in shared}
    res["web"] = Resource("web", untrusted=True)
    res["key"] = Resource("key", labels={"k"})
    res["net"] = Resource("net", sink=True)
    res["prod"] = Resource("prod", protected=True)
    res[rng.choice(shared)].controls = ["a0"]
    places = shared + ["key", "web"]
    agents = {}
    for j in range(rng.choice([2, 3])):
        rd = rng.sample(places, rng.choice([1, 2, 3]))
        wr = rng.sample(shared + ["net", "prod"], rng.choice([1, 2]))
        ask = {"g": {"read": rng.sample(places, 1), "write": rng.sample(shared + ["net"], 1)}} \
            if rng.random() < 0.4 else {}
        flows = [(rng.choice(rd), rng.choice(wr))] if rng.random() < 0.3 else []
        kind = rng.random()
        a = Agent(f"a{j}", rd, wr, injectable=rng.random() < 0.8, ask=ask, flows=flows,
                  unknown=kind < 0.3,
                  maybe={"read": rng.sample(rd, 1), "write": rng.sample(wr, 1)} if 0.3 <= kind < 0.7 else {})
        agents[a.name] = a
    return System(agents, res, [])


def goals_of(rng):
    pool = [Policy("leak", "no_flow", label="k"), Policy("prod", "integrity", resource="prod"),
            Policy("a0 hijacked", "hijack", agent="a0"), Policy("a1 learns", "learn", label="k", agent="a1")]
    return [Goal(p.name, [p]) for p in rng.sample(pool, 2)]


def attack(ps, goal, gids, t, h, inj):
    """Is there an attack with these uncertain rights (gate ids) granted?"""
    real = [g for g in gates(ps) if g not in synth_ids]
    for k in range(t + 1):
        for c in itertools.combinations(sorted(ps.agents), k):
            for m in range(h + 1):
                for app in itertools.combinations(real, m):
                    res = analyze(ps, frozenset(c), inj, frozenset(app) | gids, goal.sources)
                    if any(violated(ps, a, res) for a in goal.atoms):
                        return True
    return False


def one(sy, r):
    return {"unknown_agents": sorted({a for a, _, _ in sy.rights.values()}), "unknown_rights": len(sy.U),
            "rights": sy.rights, "results": [r], "joint": None}


def works(sy, goal, agents, approvals):
    res = analyze(sy.ps, frozenset(agents), sy.inj, frozenset(approvals), goal.sources)
    return any(violated(sy.ps, a, res) for a in goal.atoms)


def check_attacks(sy, goal, t, h, r, minimal, where):
    """Each set is minimal, and its attack is real, uses exactly that set of uncertain
    rights, and breaks into and approves nothing it does not need."""
    for S, a in r.sets + r.extra_sets:
        expect(S in minimal, f"{where}: {sorted(S)} is not a minimal set")
        expect(sy.unknown_of(a) == S, f"{where}: attack for {sorted(S)} uses {sorted(sy.unknown_of(a))}")
        real = [g for g in a.approvals if g not in sy.U]
        expect(works(sy, goal, a.agents, a.approvals) and len(a.agents) <= t and len(real) <= h,
               f"{where}: attack for {sorted(S)} is not an attack within budget")
        expect(not any(works(sy, goal, [y for y in a.agents if y != x], a.approvals) for x in a.agents)
               and not any(works(sy, goal, a.agents, [y for y in a.approvals if y != g]) for g in real),
               f"{where}: attack for {sorted(S)} breaks into or approves more than it needs")


def check_cut(sy, r, minimal, where):
    """The smallest-first list respects the limits, the extra sets are new, and the
    stop reason, completeness flag, wording and JSON agree with brute force."""
    ms, mx = sy.max_size, sy.max_sets
    listed, extra = [S for S, _ in r.sets], [S for S, _ in r.extra_sets]
    sizes = [len(S) for S in listed]
    expect(sizes == sorted(sizes) and all(n <= ms for n in sizes) and len(listed) <= max(mx, 0),
           f"{where}: listed sizes {sizes} break smallest-first or the limits")
    if len(listed) < mx:
        expect(set(listed) == {S for S in minimal if len(S) <= ms}, f"{where}: a set within --max-size is missing")
    elif listed:
        expect(all(S in listed for S in minimal if len(S) < max(sizes)), f"{where}: not smallest first")
    expect(not set(listed) & set(extra) and len(set(extra)) == len(extra), f"{where}: a set is listed twice")
    expect(r.complete == (set(listed) | set(extra) == minimal), f"{where}: complete={r.complete}")
    if set(listed) == minimal:
        expect(r.stopped is None and not extra, f"{where}: nothing was cut off, yet stopped={r.stopped}")
    else:
        expect(r.stopped == ("max_sets" if len(listed) >= mx else "max_size"), f"{where}: stopped={r.stopped}")
        if r.stopped == "max_size":
            expect(all(len(S) > ms for S in minimal - set(listed)), f"{where}: a small set was skipped")
    txt = synth.render(one(sy, r))
    expect(("exactly when" in txt) == r.complete and ("at least when" in txt) == (not r.complete),
           f"{where}: exactly/at least wording")
    expect(("stopped at --max-sets; other sets, possibly of the same size, may exist" in txt)
           == (not r.complete and r.stopped == "max_sets"), f"{where}: --max-sets wording")
    expect(("sets larger than --max-size were not searched" in txt)
           == (not r.complete and r.stopped == "max_size"), f"{where}: --max-size wording")
    expect(("found while working out 'holds if'" in txt) == bool(extra), f"{where}: extra-sets heading")
    expect(("also found while working out" in txt) == bool(extra and r.sets), f"{where}: 'also' only after listed sets")
    expect("more need larger sets" not in txt, f"{where}: old cut-off wording")
    js = synth.to_json(one(sy, r))["results"][0]
    expect(js["complete"] == r.complete and js["stopped"] == r.stopped and len(js["attack_sets"]) == len(listed)
           and len(js["extra_sets"]) == len(extra), f"{where}: JSON disagrees with the result")


rng = random.Random(3)
cut_rng = random.Random(7)          # cut-off settings; keeps rng's sequence of systems as it was
cases = seen = cut_seen = 0
kinds = set()
for trial in range(300):
    s = rand_sys(rng)
    sy = synth.Synth(s, injection=rng.random() < 0.8)
    synth_ids = sy.U
    if not sy.U or len(sy.U) > 9:
        continue
    U = sorted(sy.U)
    t, h = rng.choice([(0, 0), (0, 1), (1, 0)])
    cut = synth.Synth(s, injection=sy.inj, max_size=cut_rng.choice([0, 1, 2, 4]),
                      max_sets=cut_rng.choice([0, 1, 2, 50]))
    items, results, cut_results = [], [], []
    for goal in goals_of(rng):
        r = sy.run(goal.name, goal, t, h)
        rc = cut.run(goal.name, goal, t, h)
        items.append((goal.name, goal, t, h))
        results.append(r)
        cut_results.append(rc)
        kinds.add(r.status)
        att = {S: attack(sy.ps, goal, frozenset(S), t, h, sy.inj)
               for n in range(len(U) + 1) for S in itertools.combinations(U, n)}
        # parametrize keeps the meaning: all uncertain rights granted == the original system
        orig = any(violated(s, a, analyze(s, frozenset(c), sy.inj, frozenset(app), goal.sources))
                   for k in range(t + 1) for c in itertools.combinations(sorted(s.agents), k)
                   for m in range(h + 1) for app in itertools.combinations(gates(s), m)
                   for a in goal.atoms)
        expect(orig == att[tuple(U)], f"trial {trial} {goal.name}: parametrize changed the result")
        minimal = {frozenset(S) for S, v in att.items()
                   if v and not any(att[tuple(x for x in S if x != y)] for y in S)}
        want = "FAIL" if att[()] else "PASS" if not att[tuple(U)] else "DEPENDS"
        expect(r.status == want, f"trial {trial} {goal.name}: {r.status} vs brute {want}")
        expect(rc.status == want, f"trial {trial} {goal.name}: cut-off run {rc.status} vs brute {want}")
        best = min(len(D) for n in range(len(U) + 1) for D in itertools.combinations(U, n)
                   if all(set(D) & S for S in minimal)) if want == "DEPENDS" else 0
        for run, sx, x in (("default", sy, r), (f"max_size={cut.max_size} max_sets={cut.max_sets}", cut, rc)):
            where = f"trial {trial} {goal.name} {run}"
            if x.status == "FAIL" and want == "FAIL":
                a = x.attack
                expect(not sx.unknown_of(a) and works(sx, goal, a.agents, a.approvals),
                       f"{where}: FAIL attack uses an uncertain right or is not an attack")
            if x.status != "DEPENDS" or want != "DEPENDS":
                continue
            check_attacks(sx, goal, t, h, x, minimal, where)
            check_cut(sx, x, minimal, where)
            expect(len(x.rule_out) == best, f"{where}: rule-out size {len(x.rule_out)} vs {best}")
            rest = tuple(y for y in U if y not in x.rule_out)
            expect(not att[rest], f"{where}: ruling out {sorted(x.rule_out)} leaves an attack")
        if r.status == "DEPENDS":
            got = {S for S, _ in r.sets + r.extra_sets}
            expect(r.complete, f"trial {trial}: small case should be complete")
            expect(got == minimal, f"trial {trial} {goal.name}: sets {sorted(map(sorted, got))} "
                                   f"vs brute {sorted(map(sorted, minimal))}")
            seen += 1
        cut_seen += rc.status == "DEPENDS"
        cases += 1
    for sy2, res2 in ((sy, results), (cut, cut_results)):
        if any(r.status == "DEPENDS" for r in res2):
            j = sy2.joint(items, res2)
            rest = frozenset(U) - set(j["rule_out"])
            for (name, goal, t2, h2), r in zip(items, res2):
                if r.status == "DEPENDS":
                    expect(not attack(sy2.ps, goal, rest, t2, h2, sy2.inj), f"trial {trial}: joint misses {name}")

LEAK = Goal("leak", [Policy("leak", "no_flow", label="k")])

# max-size cut-off: the rule-out set must still be right (found by adding attacks that slip through);
# the one minimal set has 3 rights, so it is an extra set, and with it the list is complete
s = System({"x": Agent("x", read=["web", "key"], write=["r0", "net"], unknown=True)},
           {"web": Resource("web", untrusted=True), "key": Resource("key", labels={"k"}),
            "r0": Resource("r0"), "net": Resource("net", sink=True)}, [])
sy = synth.Synth(s, max_size=1)
r = sy.run("leak", LEAK, 0, 0)
expect(r.status == "DEPENDS" and not r.sets and len(r.extra_sets) == 1 and r.stopped == "max_size"
       and r.complete, f"cut-off: one extra set completes the list ({r.stopped}, {r.complete})")
expect(len(r.rule_out) == 1 and not sy._solve(LEAK, 0, 0, deny=r.rule_out).sat,
       "cut-off: rule-out still blocks the leak")

# A set found while working out 'holds if' is paired with an attack that uses exactly that set
# (it used to keep the un-minimized attack, whose path needed 'x write net', outside the set).
res = {"key": Resource("key", labels={"k"}), "r0": Resource("r0"), "net": Resource("net", sink=True)}
two = System({"x": Agent("x", read=["key"], write=["net", "r0"], unknown=True),
              "y": Agent("y", read=["r0"], write=["net"], unknown=True)}, res, [])
sy = synth.Synth(two, max_size=1)
r = sy.run("leak", LEAK, 2, 0)
expect(r.extra_sets and all(sy.unknown_of(a) == S for S, a in r.sets + r.extra_sets),
       f"extra sets: attack uses exactly its set: {[(sorted(S), a.approvals) for S, a in r.sets + r.extra_sets]}")
js = synth.to_json(one(sy, r))["results"][0]
for row in js["attack_sets"] + js["extra_sets"]:
    granted = {f"{a} {op} {x}" for a, op, x in row["rights"]}
    expect(not any("copies k: key -> net" in line for line in row["path"]) or "x write net" in granted,
           f"extra sets: JSON path uses a right outside the set: {row}")
# max-size cut-off: the 4-right set is not passed off as a smallest one
txt = synth.render(one(sy, r))
expect(not r.sets and not r.complete and r.stopped == "max_size"
       and "sets larger than --max-size were not searched" in txt
       and "none is within --max-size, so these were found while working out 'holds if'" in txt,
       f"max-size cut-off wording:\n{txt}")

# --max-sets cut-off where the extra sets complete the list: 'exactly', and no claim of larger sets
s = System({"x": Agent("x", read=["key"], write=["net1", "net2", "net3"], maybe={"write": ["net*"]})},
           {"key": Resource("key", labels={"k"}), **{f"net{i}": Resource(f"net{i}", sink=True) for i in (1, 2, 3)}},
           [])
sy = synth.Synth(s, max_sets=1)
r = sy.run("leak", LEAK, 1, 0)
txt = synth.render(one(sy, r))
expect(len(r.sets) == 1 and len(r.extra_sets) == 2 and r.complete and r.stopped == "max_sets"
       and "exactly when one of these holds" in txt and "more need larger sets" not in txt
       and "(beyond --max-sets, not necessarily smallest)" in txt, f"max-sets cut-off, completed:\n{txt}")
expect(not sy._solve(LEAK, 1, 0, block_free=[S for S, _ in r.sets + r.extra_sets]).sat,
       "max-sets cut-off: complete means no attack avoids every set")
# --max-sets cut-off that stays incomplete: 9 minimal sets of size 2, 3 listed
res = {f"key{i}": Resource(f"key{i}", labels={"k"}) for i in range(3)}
res.update({f"net{i}": Resource(f"net{i}", sink=True) for i in range(3)})
s = System({"x": Agent("x", read=[f"key{i}" for i in range(3)], write=[f"net{i}" for i in range(3)],
                       unknown=True)}, res, [])
sy = synth.Synth(s, max_sets=3)
r = sy.run("leak", LEAK, 1, 0)
txt = synth.render(one(sy, r))
js = synth.to_json(one(sy, r))["results"][0]
expect(len(r.sets) == 3 and all(len(S) == 2 for S, _ in r.sets + r.extra_sets) and not r.complete
       and "at least when one of these holds (stopped at --max-sets; other sets, possibly of the same size, "
           "may exist):" in txt and js["stopped"] == "max_sets" and js["complete"] is False
       and len(js["attack_sets"]) == 3, f"max-sets cut-off, incomplete:\n{txt}")

# FAIL says whom the attack breaks into and which prompts you approve; so does each DEPENDS set
res = {"key": Resource("key", labels={"k"}), "web": Resource("web", untrusted=True), "r0": Resource("r0"),
       "net": Resource("net", sink=True), "prod": Resource("prod", protected=True)}
s = System({"bot": Agent("bot", read=["web", "key"], write=[], ask={"shell": {"write": ["net", "r0"]}}),
            "z": Agent("z", read=["r0"], write=["prod"], unknown=True)}, res, [])
C = lambda title, goal, n, m: type("C", (), {"title": title, "goal": goal, "agents": n, "approvals": m})()
PROD = Goal("prod", [Policy("prod", "integrity", resource="prod")])
out = synth.check(s, [C("leak", LEAK, 0, 1), C("prod", PROD, 0, 1), C("prod by z", PROD, 1, 0)],
                  lambda n, cap: cap if n is None else min(n, cap))
txt, js = synth.render(out), synth.to_json(out)
expect([r.status for r in out["results"]] == ["FAIL", "DEPENDS", "DEPENDS"], f"approvals case: {txt}")
expect("e.g. break into no agent; you approve bot:shell:" in txt, f"FAIL names its approvals:\n{txt}")
expect("1. z can read r0  AND  z can write prod   (e.g. you approve bot:shell)" in txt
       and "1. z can write prod   (e.g. break into z)" in txt, f"DEPENDS sets name their approvals:\n{txt}")
rows = js["results"]
expect(rows[0]["attack"]["approved"] == ["bot:shell"] and rows[1]["attack_sets"][0].get("approved") == ["bot:shell"]
       and "broken" not in rows[1]["attack_sets"][0] and rows[2]["attack_sets"][0].get("broken") == ["z"]
       and "approved" not in rows[2]["attack_sets"][0], f"JSON attack sets: {json.dumps(rows)}")

# Every proof 'conditions' prints comes with the formula it refutes, and drat_check.py accepts the pair
# (PASS, complete, holds-if after a cut-off, and the joint re-proofs); a SAT answer leaves no files.
drat = Path(__file__).resolve().parent.parent / "drat_check.py"


def drat_ok(proof):
    cnf = proof + ".cnf"
    out = subprocess.run([sys.executable, str(drat), cnf, proof], capture_output=True, text=True)
    return Path(cnf).exists() and out.returncode == 0 and "VERIFIED" in out.stdout


with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    a = solve(s, LEAK, True, 0, 0, d / "plain")
    expect(not a.sat and a.formula == a.proof + ".cnf" and drat_ok(a.proof), f"sat.solve keeps its formula: {a}")
    a = solve(s, LEAK, True, 0, 1, d / "sat")
    expect(a.sat and a.formula is None and not list((d / "sat").iterdir()), "a SAT answer leaves no files")
    NEVER = Goal("never", [Policy("never", "integrity", resource="key")])
    out = synth.check(two, [C("never", NEVER, 2, 0), C("leak", LEAK, 2, 0)],
                      lambda n, cap: cap if n is None else min(n, cap), True, d / "cond", max_size=1)
    txt = synth.render(out)
    p_pass, dep = out["results"][0].proof, out["results"][1]
    proofs = {"PASS": p_pass, "holds if": dep.rule_out_proof,
              **{f"joint {k}": v for k, v in out["joint"]["proofs"].items()}}
    out = synth.check(two, [C("leak", LEAK, 2, 0)], lambda n, cap: cap if n is None else min(n, cap), True,
                      d / "full")
    proofs["complete"] = out["results"][0].complete_proof
    txt += synth.render(out)
    expect(out["results"][0].complete and dep.extra_sets and not dep.complete, "proof cases: shapes")
    for what, p in proofs.items():
        expect(p is not None and drat_ok(p), f"{what} proof {p} does not check against its formula")
        expect(p is None or f"{p} (formula: {p}.cnf)" in txt, f"{what} proof is printed without its formula")

# --- the scanner's side: extension ids and which rights are only assumed -------
sys.path.insert(0, "agentwatch")
import agentwatch as aw
for folder, want in [("anthropic.claude-code-2.1.293-darwin-arm64", "anthropic.claude-code"),
                     ("zhang-renyang.chat-gpt-1.8.7", "zhang-renyang.chat-gpt"),
                     ("ms-python.python-2026.6.0-darwin-arm64", "ms-python.python"),
                     ("publisher.name", "publisher.name")]:
    expect(aw.ext_id(folder) == want, f"ext_id({folder}) = {aw.ext_id(folder)}")
res = {r: Resource(r) for r in ("proj:a", "secret:ssh", "ctl:x")}
res["web"] = Resource("web", untrusted=True)
res["net"] = Resource("net", sink=True)
f = aw.Found("x", "X", read=["*"], write=["proj:a"],
             ask={"mcp:odd": {"read": ["*", "web"], "write": ["*", "net"], "assumed": True}})
aw.open_gate(f, "mcp:odd")
f.read = sorted(set(f.read))            # collectors de-duplicate; must not mix the two
expect(f.read == ["*"] and f.maybe == {"read": ["*", "web"], "write": ["*", "net"]}, f"open_gate: {f.read} {f.maybe}")
rd = aw.expand(f.read + f.maybe["read"], res, [], reading=True)
wr = aw.expand(f.write + f.maybe["write"], res, [])
m = aw.assumed_rights(f, res, rd, wr)
expect(m == {"read": ["web"], "write": ["ctl:x", "net", "secret:ssh"]},
       f"only the assumed part is uncertain: {m}")

# --- render: no set inside the limits; --show caps both lists together; crash leaves no files
import sat, tempfile
from pathlib import Path
s = System({"x": Agent("x", read=["key"], write=["net", "r0"], unknown=True),
            "y": Agent("y", read=["r0"], write=["net"], unknown=True)},
           {"key": Resource("key", labels={"k"}), "r0": Resource("r0"), "net": Resource("net", sink=True)}, [])
class C:                                       # the parts of policy.Compiled synth.check uses
    def __init__(self, title, goal, agents=0, approvals=0):
        self.title, self.goal, self.agents, self.approvals = title, goal, agents, approvals
leak = Goal("leak", [Policy("leak", "no_flow", label="k")])
out = synth.check(s, [C("leak", leak, agents=2)], lambda n, cap: cap if n is None else min(n, cap), max_size=1)
txt = synth.render(out)
expect("none is within --max-size" in txt and "holds:\n" not in txt, f"no dangling header: {txt}")
# three relays that each leak on their own: one set listed (--max-sets 1), two found for 'holds if'
s = System({a: Agent(a, read=["key"], write=[f"n{i}"], injectable=False, unknown=True, flows=[("key", f"n{i}")])
            for i, a in enumerate(("x", "y", "z"), 1)},
           {"key": Resource("key", labels={"k"}), **{f"n{i}": Resource(f"n{i}", sink=True) for i in range(1, 4)}}, [])
out = synth.check(s, [C("leak", leak)], lambda n, cap: cap if n is None else min(n, cap), max_sets=1)
r = out["results"][0]
txt = synth.render(out, show=2)
numbered = [l for l in txt.splitlines() if l.strip()[:2] in ("1.", "2.", "3.")]
expect(len(r.sets) == 1 and len(r.extra_sets) == 2 and len(numbered) == 2 and "1 more (--json lists all)" in txt,
       f"--show 2 prints 2 sets across both lists: {txt}")
d = Path(tempfile.mkdtemp())
old, sat.CADICAL = sat.CADICAL, "/nonexistent/cadical"
try:
    sat.solve(s, leak, True, 0, 0, d)
    expect(False, "a missing solver should raise")
except OSError:
    expect(list(d.iterdir()) == [], f"a solver crash leaves no files: {list(d.iterdir())}")
finally:
    sat.CADICAL = old

expect({"FAIL", "PASS", "DEPENDS"} <= kinds, f"random cases cover every status: {kinds}")
print(f"synth: {cases} random goals ({seen} DEPENDS; {cut_seen} DEPENDS with --max-size/--max-sets cut-offs), "
      "checked against all subsets of uncertain rights")
print("ok" if not fails else f"{fails} failures")
sys.exit(1 if fails else 0)
