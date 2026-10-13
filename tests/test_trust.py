"""trusted agents and strips: SAT == brute force == web engine, and certificates verify."""
import json, random, shutil, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
from collusion import Agent, Policy, Resource, System  # noqa: E402
from sat import frontier  # noqa: E402
from test_sat import brute  # noqa: E402

rng = random.Random(21)
names = ["web", "net", "a", "b", "c", "ctl", "sec"]


def rand_system():
    res = {"web": Resource("web", untrusted=True), "net": Resource("net", sink=True), "a": Resource("a"),
           "b": Resource("b"), "c": Resource("c"), "ctl": Resource("ctl"), "sec": Resource("sec", labels={"k"})}
    agents = {}
    for x in "pqrs":
        rd, wr = rng.sample(names, rng.randint(1, 3)), rng.sample(names[1:], rng.randint(1, 2))
        flows = [(r, w) for r in rd for w in wr if rng.random() < .5]
        ask = {"g": {"read": rng.sample(names, 1), "write": rng.sample(names[1:], 1)}} if rng.random() < .4 else {}
        agents[x] = Agent(x, rd, wr, injectable=rng.random() < .7, flows=flows, ask=ask,
                          trusted=rng.random() < .3, strips=rng.sample(["attacker", "k"], rng.randint(0, 2)))
    res["ctl"].controls = rng.sample("pqrs", 2)
    pols = [Policy("k out", "no_flow", label="k"), Policy("a clean", "integrity", resource="a"),
            Policy("q safe", "hijack", agent="q"), Policy("s learns", "learn", agent="s", label="k")]
    return System(agents, res, pols)


def export(s):
    return {"agents": {a: {"read": x.read, "write": x.write, "injectable": x.injectable, "ask": x.ask,
                           "flows": [list(f) for f in x.flows], "trusted": x.trusted, "strips": x.strips}
                       for a, x in s.agents.items()},
            "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                                ("sink", x.sink), ("controls", x.controls)) if v} for r, x in s.resources.items()},
            "policies": [{k: v for k, v in p.__dict__.items() if v is not None} for p in s.policies]}


engine = Path("web/engine.js").resolve()
verify = Path("web/verify_cert.py").resolve()
cases = mism = web_mism = certs = bad_certs = 0
for trial in range(60):
    s = rand_system()
    sat = [[list(pt[:2]) for pt in frontier(s, p, True)] for p in s.policies]
    br = [[list(pt) for pt in brute(s, p, True)] for p in s.policies]
    cases += len(s.policies)
    mism += sum(a != b for a, b in zip(sat, br))
    if shutil.which("node"):
        f = Path(tempfile.mkdtemp()) / "s.json"
        f.write_text(json.dumps(export(s)))
        out = subprocess.run(["node", "-e", f"""
const E=require('{engine}'),fs=require('fs');const d=JSON.parse(fs.readFileSync('{f}'));const m=E.load(d);
const fr=E.search(m,true).front.map(x=>x.map(p=>[p.t,p.h]));
const certs=[];m.policies.forEach((p,k)=>{{for(const [t,h] of [[0,0],[1,0],[0,1],[1,1]]){{const c=E.certificate(d,m,k,t,h);if(c)certs.push(c);}}}});
console.log(JSON.stringify({{fr,certs}}));"""], capture_output=True, text=True)
        got = json.loads(out.stdout)
        web_mism += sum(a != b for a, b in zip(got["fr"], sat))
        for c in got["certs"]:
            certs += 1
            r = subprocess.run([sys.executable, str(verify)], input=json.dumps(c), capture_output=True, text=True)
            bad_certs += r.returncode != 0
print(f"trust: {cases} cases, SAT/brute mismatches {mism}, web mismatches {web_mism}, "
      f"certificates {certs} ({bad_certs} rejected)")
sys.exit(1 if mism or web_mism or bad_certs else 0)
