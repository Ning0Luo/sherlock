"""Tests for the Rule of Two report: the example fleets, approvals as lowercase
letters, and the fleet verdicts against brute force on random systems."""
import itertools, random, sys
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
from collusion import Agent, Resource, System, analyze, gates, load, violated
from ruleoftwo import check, goals
from test_sat import rand_system

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


def by(r):
    return {a["agent"]: a for a in r["agents"]}, {f["goal"]: f for f in r["fleet"]}


# --- each agent within the rule, the fleet not ---------------------------------
ag, fl = by(check(load("examples/ruleoftwo/inbox.json")))
expect(ag["triage"]["own"] == "A . ." and ag["triage"]["fleet"] == "A B C", "triage letters")
expect(ag["analyst"]["own"] == ". B ." and ag["analyst"]["fleet"] == "A B C", "analyst letters")
expect(not any(a["breaks_alone"] for a in ag.values()), "nobody breaks the rule alone")
expect(ag["analyst"]["breaks_in_fleet"] and ag["sender"]["breaks_in_fleet"], "fleet breakers")
expect(ag["backup"]["exempt"] == "not an AI model", "deterministic agent exempt")
for k in ("trifecta", "sensitive"):
    expect(fl[k]["status"] == "FAIL" and fl[k]["composition"], f"inbox {k}: composition failure")
    expect(fl[k]["agents"] == ["triage", "analyst", "sender"], f"inbox {k}: path agents {fl[k]['agents']}")

ag, fl = by(check(load("examples/devbox.json")))
expect(fl["trifecta"]["composition"] and fl["sensitive"]["composition"], "devbox composition")

# --- approvals: lowercase letters, and a person in the loop -------------------
s = System({"bot": Agent("bot", read=["web"], write=["notes"],
                         ask={"shell": {"read": ["key"], "write": ["net"]}})},
           {"web": Resource("web", untrusted=True), "notes": Resource("notes"),
            "key": Resource("key", labels={"k"}), "net": Resource("net", sink=True)}, [])
ag, fl = by(check(s))
expect(ag["bot"]["own"] == "A b c", f"gated letters: {ag['bot']['own']}")
expect(ag["bot"]["breaks_alone_with_approval"] and not ag["bot"]["breaks_alone"], "gated agent")
expect(fl["trifecta"]["status"] == "HUMAN" and fl["trifecta"]["approvals_needed"] == 1, "needs one approval")
expect(fl["sensitive"]["status"] == "n/a", "no sensitive resources")


# --- changing a sensitive system is B and C: reading the web and deploying breaks the rule
s = System({"ops": Agent("ops", read=["web"], write=["prod"])},
           {"web": Resource("web", untrusted=True), "prod": Resource("prod", protected=True)}, [])
ag, fl = by(check(s))
expect(ag["ops"]["own"] == "A B C" and ag["ops"]["breaks_alone"], f"web->prod agent: {ag['ops']['own']}")
expect(fl["sensitive"]["status"] == "FAIL" and not fl["sensitive"]["composition"], "web->prod: solo failure")
# ...and so does reaching it through an honest relay; only the relay's input is written
s.agents["ops"].write = ["repo"]
s.agents["ci"] = Agent("ci", read=["repo"], write=["prod"], injectable=False, flows=[("repo", "prod")])
s.resources["repo"] = Resource("repo")
ag, fl = by(check(s))
expect(ag["ops"]["own"] == "A B C", f"web->repo->prod agent: {ag['ops']['own']}")
expect(ag["ops"]["own_why"]["B"].startswith("writes repo"), "indirect B reason")


# --- fleet verdicts vs brute force -------------------------------------------
def brute_h(s, goal):
    G = gates(s)
    for h in range(len(G) + 1):
        for g in itertools.combinations(G, h):
            res = analyze(s, frozenset(), True, frozenset(g))
            if any(violated(s, a, res) for a in goal.atoms):
                return h
    return None


def rand_fleet(rng, n):
    """rand_system, with some open web reads and open sink/prod writes so that
    free attacks (and compositions) occur too."""
    s = rand_system(rng, n)
    for x in s.agents.values():
        if rng.random() < 0.4:
            x.read.append("web")
        if rng.random() < 0.2:
            x.write.append(rng.choice(["net", "prod"]))
    return s


rng = random.Random(11)
cases = 0
seen = set()
for trial in range(120):
    s = rand_fleet(rng, rng.choice([3, 4]))
    if len(gates(s)) > 6:
        continue
    r = check(s)
    ag, fl = by(r)
    for key, _, goal in goals(s):
        h = brute_h(s, goal)
        f = fl[key]
        want = "FAIL" if h == 0 else "PASS" if h is None else "HUMAN"
        expect(f["status"] == want, f"trial {trial} {key}: {f['status']} vs brute {want}")
        if want == "HUMAN":
            expect(f["approvals_needed"] == h, f"trial {trial} {key}: approvals {f['approvals_needed']} vs {h}")
        if f["status"] == "FAIL" and f["composition"]:
            expect(not any(ag[a]["breaks_alone"] for a in f["agents"]), f"trial {trial}: composition claim")
        seen.add((f["status"], f.get("composition")))
        cases += 1
    # an AI agent that reads attacker text and a secret, and writes a sink, leaks for free
    for a, x in s.agents.items():
        reads = s.matches(x.read)
        if x.injectable and reads & {"web"} and "key" in reads and "net" in s.matches(x.write):
            expect(fl["trifecta"]["status"] == "FAIL", f"trial {trial}: {a} holds A B C but no leak")

expect({("PASS", None), ("HUMAN", None), ("FAIL", True), ("FAIL", False)} <= seen, f"verdict mix {seen}")
print(f"{cases} random fleet verdicts checked: {sorted(map(str, seen))}")
print("ok" if not fails else f"{fails} failures")
sys.exit(1 if fails else 0)
