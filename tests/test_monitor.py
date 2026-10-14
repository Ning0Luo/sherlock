"""The event-level runtime Monitor: its live reachability query (SAT from an
observed seed state) is cross-checked against brute force, plus deterministic
scenarios and a monotonicity check."""
import itertools
import random
import sys
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
from collusion import Agent, Policy, Resource, System, analyze, gates, violated
from sat import as_goal, n_injectable
from monitor import Monitor
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


def brute_reachable(s, policy, injection, t, h, m, seed_t, seed_l, seed_c):
    goal = as_goal(policy)
    A, G = sorted(s.agents), gates(s)
    INJ = [a for a in A if s.agents[a].injectable and not s.agents[a].trusted] if injection else []
    for c in subsets(A, t):
        for g in subsets(G, h):
            for iset in subsets(INJ, min(m, len(INJ))):
                res = analyze(s, frozenset(c), injection, frozenset(g), goal.sources,
                              inject_set=frozenset(iset), seed_tainted=frozenset(seed_t),
                              seed_labels=seed_l, seed_corrupt=frozenset(seed_c))
                if any(violated(s, a, res) for a in goal.atoms):
                    return True
    return False


# --- SAT reachability-from-seed vs brute force ---------------------------------
rng = random.Random(4)
cases = seeded = 0
for trial in range(60):
    s = rand_system(rng, rng.choice([2, 3]))
    if len(gates(s)) > 4 or n_injectable(s) > 3:
        continue
    resources = sorted(s.resources)
    labels = sorted({l for x in s.resources.values() for l in x.labels})
    agents = sorted(s.agents)
    for _ in range(3):
        seed_t = set(rng.sample(resources, rng.randint(0, min(2, len(resources)))))
        seed_c = set(rng.sample(agents, rng.randint(0, min(1, len(agents)))))
        seed_l = {}
        for l in labels:
            rs = set(rng.sample(resources, rng.randint(0, min(2, len(resources)))))
            if rs:
                seed_l[l] = rs
        if seed_t or seed_c or seed_l:
            seeded += 1
        t, h, m = rng.choice([(0, 0, 0), (0, 0, 1), (1, 0, 0), (0, 1, 1)])
        mon = Monitor(s, budget=(t, h, m))
        mon.tainted, mon.labels, mon.corrupt = set(seed_t), {k: set(v) for k, v in seed_l.items()}, set(seed_c)
        got = {name for name, _ in mon._reachable()}
        for p in s.policies:
            want = brute_reachable(s, p, True, t, h, m, seed_t, seed_l, seed_c)
            expect((p.name in got) == want,
                   f"trial {trial} {p.name} seed(t={sorted(seed_t)},c={sorted(seed_c)},l={seed_l}) "
                   f"budget=({t},{h},{m}): reachable {p.name in got} vs brute {want}")
            cases += 1

expect(seeded > 0, "some trials have a non-empty observed seed state")


# --- scenario: the leak chain, gated step by step ------------------------------
res = {"web": Resource("web", untrusted=True), "r1": Resource("r1"),
       "key": Resource("key", labels={"k"}), "net": Resource("net", sink=True)}
s = System({"a": Agent("a", read=["web", "key"], write=["r1"]),
            "b": Agent("b", read=["r1"], write=["net"])}, res,
           [Policy("k stays", "no_flow", label="k")])
m = Monitor(s, budget=(0, 0, 0))
expect(not m.status(), "nothing reachable at budget 0 from a clean start")
expect(not m.probe("b", reads=["r1"], writes=["net"]), "b emailing an empty r1 is allowed")
m.apply("a", reads=["web", "key"], writes=["r1"], injected=True)
expect("r1" in m.tainted and m.labels.get("k") == {"r1"} and "a" in m.corrupt, "a's step is recorded")
expect(m.probe("b", reads=["r1"], writes=["net"]), "b emailing r1 (now holding the key) is BLOCKED")
expect(not m.allow("b", reads=["r1"], writes=["net"]), "allow() refuses it")
# an action that reads nothing tainted is still allowed (the monitor is not a blanket block)
expect(not m.probe("b", reads=[], writes=["r1"]), "b writing r1 without reading attacker content is allowed")
# but reading the tainted r1 WOULD steer b, which can then email the key out -> blocked
expect(m.probe("b", reads=["r1"], writes=[]), "b even reading r1 is blocked (it would be steered and can reach net)")


# --- scenario: the inbox composition, one injection at a time ------------------
ir = {"inbox": Resource("inbox", untrusted=True), "notes": Resource("notes"),
      "crm": Resource("crm", labels={"pii"}), "draft": Resource("draft"),
      "mail": Resource("mail", sink=True)}
inbox = System({"triage": Agent("triage", read=["inbox"], write=["notes"]),
                "analyst": Agent("analyst", read=["notes", "crm"], write=["draft"]),
                "sender": Agent("sender", read=["draft"], write=["mail"])}, ir,
               [Policy("pii stays", "no_flow", label="pii")])
mon = Monitor(inbox, budget=(0, 0, 0))
expect(not mon.status(), "inbox: safe before any injection at budget 0")
mon.apply("triage", reads=["inbox"], writes=["notes"])              # triage reads attacker email
expect("triage" in mon.corrupt and "notes" in mon.tainted, "triage is steered, notes tainted")
mon.apply("analyst", reads=["notes", "crm"], writes=["draft"])      # analyst pulls PII into the draft
expect(mon.labels.get("pii") == {"draft"} and "analyst" in mon.corrupt, "pii reaches the draft")
expect(mon.probe("sender", reads=["draft"], writes=["mail"]), "sending the draft out is BLOCKED (pii would leave)")


# --- monotonicity: observing more can only make more reachable -----------------
rng = random.Random(9)
for _ in range(20):
    s = rand_system(rng, 3)
    if len(gates(s)) > 4:
        continue
    before = {n for n, _ in Monitor(s, budget=(0, 0, 1)).status().hits}
    mon = Monitor(s, budget=(0, 0, 1))
    r = rng.choice(sorted(s.resources))
    mon.tainted.add(r)                                   # observe one more tainted resource
    after = {n for n, _ in mon.status().hits}
    expect(before <= after, f"observing taint on {r} removed a reachable policy: {before} -> {after}")

print(f"monitor: {cases} reachability points vs brute ({seeded} seeded); scenarios checked"
      if not fails else f"{fails} failures")
sys.exit(1 if fails else 0)
