"""Tests for the Llama Stack importer and the shield what-if:
  * the reader on the hand-made example deployment,
  * SAT frontier == brute force on randomized deployments,
  * whatif() is monotone -- trusting a shield never makes an attack cheaper --
    and on the example it is strictly worth something, cross-checked with analyze.

Runs with no llama_stack package installed; the deployments are hand-made files
and plain dicts, never a live SDK."""
import itertools
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from collusion import analyze, gates, violated
from llamastack import load_llamastack
from sat import frontier
from shield_whatif import shield_system, whatif
from test_sat import brute

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


# --- the example deployment --------------------------------------------------
s = load_llamastack("examples/llamastack/deployment.yaml")
A = s.agents
R = s.resources

expect(set(A) == {"assistant", "publisher"}, "two agents")
expect(R["vdb:pii_store"].labels == {"customer_pii"} and not R["vdb:pii_store"].untrusted,
       "the PII store carries a label and is curated (not attacker-ingestible)")
expect(R["vdb:reports"].untrusted, "an unlabelled vector DB is attacker-ingestible")
expect(R["net:crm.example.com"].untrusted and R["net:crm.example.com"].sink,
       "the external MCP host is both attacker-writable and a way out")
expect(R["acct:crm.example.com"].protected, "a credentialed MCP endpoint adds a protected account")
expect(R["session:assistant"].controls == ["assistant"],
       "session persistence gives a resource the agent obeys")
expect("vdb:pii_store" in A["assistant"].read, "the RAG agent reads its bound store")
expect("vdb:pii_store" not in A["publisher"].read, "the publisher is not bound to the PII store")
expect("net:crm.example.com" in A["publisher"].write and "acct:crm.example.com" in A["publisher"].write,
       "the MCP tool reaches its endpoint and acts as you")
expect(not A["publisher"].injectable, "a deterministic step is not steerable by what it reads")
expect(A["assistant"].injectable, "an LLM agent is steerable")
expect(getattr(s, "shielded") == ["publisher"], "the shielded set is the agents with a shield")
expect({p.name for p in s.policies} ==
       {"customer_pii never leaves the deployment",
        "web content never acts through your crm.example.com account"},
       "one no_flow policy per label, one integrity policy per account")

# unknown tool groups are assumed able to do anything (conservative, like openshell)
d = Path(tempfile.mkdtemp())
(d / "u.json").write_text(json.dumps({"agents": {"x": {"toolgroups": ["builtin::mystery_tool"]}}}))
su = load_llamastack(str(d / "u.json"))
expect("web" in su.agents["x"].read and "net" in su.agents["x"].write,
       "an unrecognized tool group is assumed able to do anything")

# a malformed file names itself
try:
    (d / "bad.json").write_text(json.dumps({"toolgroups": []}))
    load_llamastack(str(d / "bad.json"))
    expect(False, "a deployment with no agents should be refused")
except ValueError:
    pass


# --- the hand-written policy file compiles and checks against the system -----
from policy import compile_file, parse  # noqa: E402

pf = parse(Path("examples/llamastack/deployment.policy").read_text())
compiled = {c.title: c for c in compile_file(s, pf, lambda p: p if p in s.resources else None)}
expect(set(compiled) == {"Customer PII never leaves the deployment",
                         "Web content never acts through the CRM account",
                         "The publisher is never steered"},
       "the example policy file compiles against the built system")
pts = frontier(s, compiled["Customer PII never leaves the deployment"].goal, True)
expect(pts and pts[0][:2] == (0, 0), "PII leaks for free without the shield (via the publisher)")
pub = frontier(s, compiled["The publisher is never steered"].goal, True)
expect(pub and pub[0][0] >= 1, "the deterministic publisher cannot be steered with no hacked agent")


# --- whatif on the example: the shield is strictly worth something -----------
wi = whatif(s, s.shielded, injection=True)
expect(wi.shielded == ["publisher"], "whatif uses the shielded agents")
expect("customer_pii" in wi.stripped and "attacker" in wi.stripped,
       "a shield strips attacker influence and the secret labels")
expect(wi.helps, "on the example the shield strictly raises the cheapest attack")
for r in wi.results:
    expect(r.without == [(0, 0)], f"without the shield, {r.policy} breaks for free")
    expect(r.with_ == [(1, 0)], f"with the shield, {r.policy} needs one hacked agent")


def cost(points):
    return min(points, default=(1 << 30, 1 << 30))


# whatif's WITH frontier is never cheaper than WITHOUT, cross-checked with analyze:
# every coalition that breaks a policy WITH the shield also breaks it WITHOUT.
def monotone_ok(sys_, shielded, inj):
    guarded = shield_system(sys_, shielded)
    G, names = gates(sys_), sorted(sys_.agents)
    ok = True
    for p in sys_.policies:
        for k in range(len(names) + 1):
            for c in itertools.combinations(names, k):
                for h in range(len(G) + 1):
                    for g in itertools.combinations(G, h):
                        bad_guarded = violated(guarded, p, analyze(guarded, frozenset(c), inj, frozenset(g)))
                        if bad_guarded:
                            bad_base = violated(sys_, p, analyze(sys_, frozenset(c), inj, frozenset(g)))
                            ok = ok and bool(bad_base)
    return ok


expect(monotone_ok(s, s.shielded, True),
       "every attack that survives the shield also exists without it (example, agentic)")
expect(monotone_ok(s, s.shielded, False),
       "every attack that survives the shield also exists without it (example, traditional)")


# --- SAT vs brute on randomized deployments; whatif monotone on each ---------
def rand_deployment(rng):
    vdbs = []
    # bias toward a secret store so more systems exercise a no_flow policy
    pick = rng.sample(["kb", "pii", "cases"], rng.randint(1, 3))
    if rng.random() < 0.6 and "pii" not in pick:
        pick.append("pii")
    for v in pick:
        if v == "pii":
            vdbs.append({"vector_db_id": v, "label": "secret", "untrusted": False})
        else:
            vdbs.append({"vector_db_id": v})
    all_vids = [v["vector_db_id"] for v in vdbs]
    hosts = ["crm.example.com", "svc.internal.example.com", "api.example.com"]
    agents = {}
    shielded = []
    for i in range(rng.randint(2, 3)):
        name = f"a{i}"
        tgs = []
        pool = ["rag", "websearch", "code", "mcp", "mcp", "send"]
        for kind in rng.sample(pool, rng.randint(1, 3)):
            if kind == "rag":
                tgs.append({"name": "builtin::rag",
                            "args": {"vector_db_ids": rng.sample(all_vids, rng.randint(1, len(all_vids)))}})
            elif kind == "websearch":
                tgs.append("builtin::websearch")
            elif kind == "code":
                tgs.append("builtin::code_interpreter")
            elif kind == "send":
                tgs.append("builtin::send_email")
            elif kind == "mcp":
                h = rng.choice(hosts)
                tgs.append({"toolgroup_id": f"mcp::{name}", "provider_id": "model-context-protocol",
                            "mcp_endpoint": {"uri": f"https://{h}/sse"},
                            "requires_auth": rng.random() < 0.5})
        cfg = {"toolgroups": tgs}
        if rng.random() < 0.4:
            cfg["deterministic"] = True
        if rng.random() < 0.4:
            cfg["enable_session_persistence"] = True
        if rng.random() < 0.5:
            cfg["output_shields"] = ["llama_guard"]
            shielded.append(name)
        agents[name] = cfg
    return {"vector_dbs": vdbs, "internal_hosts": ["svc.internal.example.com"],
            "trusted_users": rng.random() < 0.5, "agents": agents}, shielded


rng = random.Random(11)
cases = mism = mono = checked = 0
for trial in range(60):
    spec, shielded = rand_deployment(rng)
    (d / "dep.json").write_text(json.dumps(spec))
    ds = load_llamastack(str(d / "dep.json"))
    if len(gates(ds)) > 4:          # keep brute force cheap
        continue
    guarded = shield_system(ds, shielded)
    for inj in (True, False):
        for p in ds.policies:
            cases += 1
            want = brute(ds, p, inj)
            got = [pt[:2] for pt in frontier(ds, p, inj)]
            if want != got:
                mism += 1
                print("SAT/BRUTE MISMATCH", trial, p.name, inj, want, got)
            # whatif WITH frontier is never cheaper than WITHOUT
            g_got = [pt[:2] for pt in frontier(guarded, p, inj)]
            checked += 1
            if cost(got) > cost(g_got):
                mono += 1
                print("MONOTONE VIOLATION", trial, p.name, inj, "without", got, "with", g_got)

# whatif() end-to-end on one random system agrees with the per-policy frontiers
spec, shielded = rand_deployment(random.Random(3))
(d / "dep.json").write_text(json.dumps(spec))
ds = load_llamastack(str(d / "dep.json"))
if len(gates(ds)) <= 4:
    wi2 = whatif(ds, shielded, injection=True)
    for r in wi2.results:
        expect(cost(r.without) <= cost(r.with_), f"whatif: WITH is never cheaper than WITHOUT ({r.policy})")

# --- an INLINE MCP tool (endpoint + auth on the tool, not in a top-level toolgroup) ----
# Regression: the host and credential used to vanish unless the toolgroup was also
# registered top-level, so the account integrity policy silently disappeared.
_yaml = """version: 2
secrets:
  - {resource: "vdb:notes", label: customer_pii}
agents:
  bot:
    instructions: "reads notes, posts to crm"
    toolgroups:
      - {name: "builtin::rag", args: {vector_db_ids: [notes]}}
      - name: "mcp::crm"
        mcp_endpoint: {uri: "https://crm.example.com/sse"}
        requires_auth: true
vector_dbs:
  - {vector_db_id: notes, label: customer_pii, untrusted: false}
"""
_di = Path(tempfile.mkdtemp())
(_di / "inline.yaml").write_text(_yaml)
si = load_llamastack(str(_di / "inline.yaml"))
expect("net:crm.example.com" in si.resources, "an inline MCP endpoint creates its host resource")
expect("acct:crm.example.com" in si.resources and si.resources["acct:crm.example.com"].protected,
       "an inline MCP tool with requires_auth creates the protected account")
expect(any(p.kind == "integrity" and p.resource == "acct:crm.example.com" for p in si.policies),
       "the account integrity policy is created for an inline MCP credential")

print(f"llamastack: {cases} SAT/brute cases, {mism} mismatches; "
      f"{checked} monotone checks, {mono} violations; {fails} unit failures")
sys.exit(1 if fails or mism or mono else 0)
