"""Tests for the Strands Agents integration, run WITHOUT the strands SDK.

The SDK is not installed here, so the integration must import on its own, and we
exercise it with duck-typed fakes that expose exactly the attributes the reader
inspects: an Agent's ``tool_registry.registry`` (name -> tool), a Swarm's
``nodes`` + ``entry_point``, and a Graph's ``nodes`` + ``edges`` (each edge with
``from_node`` / ``to_node``) + ``entry_points``. These mirror the real SDK
objects (strands/agent/agent.py, strands/multiagent/swarm.py and graph.py), but
agreement with a live install still needs checking there.

As in tests/test_openshell.py, we also cross-check the built System against brute
force: sat.frontier must equal the exhaustive search for every policy on many
randomized fake apps."""
import random
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

import integrations.strands as st  # noqa: E402
from collusion import Policy  # noqa: E402
from sat import frontier  # noqa: E402
from test_sat import brute  # noqa: E402

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


# --------------------------------------------------------------- fake SDK objects

class FakeTool:
    """A Strands AgentTool: name via .tool_name, spec via .tool_spec.
    mcp=True makes it look like an MCPAgentTool; meta attaches sherlock metadata."""
    def __init__(self, name, mcp=False, meta=None):
        self.tool_name = name
        self.tool_spec = {"name": name, "description": f"does {name}", "inputSchema": {"json": {}}}
        if mcp:
            self.mcp_client = object()
            self.mcp_tool = object()
        if meta is not None:
            self.metadata = meta


class FakeRegistry:
    def __init__(self, tools):
        self.registry = {}
        for t in tools:
            tool = FakeTool(t) if isinstance(t, str) else t
            self.registry[tool.tool_name] = tool


class FakeAgent:
    def __init__(self, name, tools=()):
        self.name = name
        self.tool_registry = FakeRegistry(tools)


class FakeNode:
    def __init__(self, node_id, executor):
        self.node_id = node_id
        self.executor = executor


class FakeSwarm:
    """nodes keyed by id, a shared context, NO edges -> recognized as a Swarm."""
    def __init__(self, agents, entry_point=None, id="swarm"):
        self.id = id
        self.entry_point = entry_point
        self.shared_context = object()
        self.nodes = {a.name: FakeNode(a.name, a) for a in agents}


class FakeEdge:
    def __init__(self, u, v):
        self.from_node = u
        self.to_node = v


class FakeGraph:
    """nodes + edges -> recognized as a Graph. `nodes` is [(id, executor), ...]."""
    def __init__(self, nodes, edges, entry=()):
        self.nodes = {nid: FakeNode(nid, ex) for nid, ex in nodes}
        self.edges = {FakeEdge(self.nodes[a], self.nodes[b]) for a, b in edges}
        self.entry_points = {self.nodes[e] for e in entry}


# --------------------------------------------------------------- tool recognition

expect(st.tool_reach("mystery_tool", None, {})[1].startswith("unrecognized"),
       "an unknown tool is assumed able to do anything")
expect("MCP" in st.tool_reach("srv_tool", FakeTool("srv_tool", mcp=True), {})[1],
       "an MCP tool is recognized and assumed able to do anything")
expect(st.tool_reach("srv_tool", FakeTool("srv_tool", mcp=True), {})[0]["write"] == ["net", "*"],
       "an MCP tool is unrestricted")
expect(st.tool_reach("web_search", None, {})[0] == {"read": ["web"], "write": ["net"]},
       "web_search reads the web and its queries leave")
expect(st.tool_reach("python_repl", None, {})[0] == st.UNRESTRICTED, "python_repl runs code: unrestricted")
expect(st.tool_reach("file_read", None, {})[0] == {"read": ["*"], "write": []}, "file_read reads local files")
expect(st.tool_reach("think", None, {})[0] == {"read": [], "write": []}, "think has no outside effect")
expect(st.tool_reach("send_email", None, {})[0] == {"read": ["web"], "write": ["net"]},
       "send_email acts on an outside service")
expect(st.tool_reach("x", FakeTool("x", meta={"sherlock": {"read": ["data:db"]}}), {})[0]["read"] == ["data:db"],
       "a tool's sherlock metadata is honored")
expect(st.tool_reach("web_search", None, {"web_search": {"read": ["only"], "write": []}})[1] == "as you declared",
       "an explicit override wins over the catalog")
# a word-boundary false positive is avoided (as in the LangGraph catalog)
expect(st.tool_reach("research_notes", None, {})[1].startswith("unrecognized"),
       "'research_notes' does not match 'search'")


# --------------------------------------------------------------- a single Agent

researcher = FakeAgent("researcher", ["web_search"])
s = st.to_system(researcher)
expect(set(s.agents) == {"researcher"}, "a lone Agent becomes one agent")
expect("input" in s.agents["researcher"].read and "web" in s.agents["researcher"].read,
       "it reads the task input and the web")
expect("net" in s.agents["researcher"].write, "a web tool writes the net sink")
expect(s.resources["input"].untrusted, "the task input is attacker-written by default")
expect(s.agents["researcher"].injectable, "a Strands agent is an AI model")
expect(not st.to_system(researcher, untrusted_input=False).resources["input"].untrusted,
       "untrusted_input=False opts out")
expect(not st.to_system(researcher, deterministic=["researcher"]).agents["researcher"].injectable,
       "deterministic marks an agent non-AI")

# declared tool rights, a secret store, and the generated policy
account = FakeAgent("account", ["lookup_customer"])
s = st.to_system(account, tools={"lookup_customer": {"read": ["data:crm"]}},
                 secrets={"data:crm": "customer_pii"})
expect("data:crm" in s.agents["account"].read, "a declared tool right is placed")
expect(s.resources["data:crm"].labels == {"customer_pii"}, "the secret label is attached")
expect(any(p.kind == "no_flow" and p.label == "customer_pii" for p in s.policies),
       "a no_flow policy is generated for the secret")

# an approval tool becomes a gate, not an open right
emailer = FakeAgent("emailer", ["send_email"])
s = st.to_system(emailer, approval_tools=["send_email"])
expect("tool:send_email" in s.agents["emailer"].ask, "approval_tools makes the tool a gate")
expect("net" not in s.agents["emailer"].write, "a gated tool's rights are not open")
expect("net" in s.agents["emailer"].ask["tool:send_email"]["write"], "the gate carries the tool's rights")

# trusted / strips
s = st.to_system(researcher, trusted=["researcher"])
expect(s.agents["researcher"].trusted and not s.agents["researcher"].injectable,
       "a trusted agent cannot be hacked or steered")


# --------------------------------------------------------------- a Swarm

r = FakeAgent("researcher", ["web_search"])
acct = FakeAgent("account", ["lookup_customer"])
wr = FakeAgent("writer", [])
sw = FakeSwarm([r, acct, wr], entry_point=r)
s = st.to_system(sw, tools={"lookup_customer": {"read": ["data:crm"]}}, secrets={"data:crm": "customer_pii"})
expect("state:shared" in s.resources, "the swarm has a shared-memory resource")
for a in ("researcher", "account", "writer"):
    expect("state:shared" in s.agents[a].read and "state:shared" in s.agents[a].write,
           f"{a} reads and writes the swarm's shared memory")
expect("input" in s.agents["researcher"].read, "the entry agent reads the task")
expect("input" not in s.agents["account"].read, "a non-entry agent does not read the task directly")
# the naive swarm leaks the CRM: account -> shared -> researcher's web tool -> net, no hack needed
pts = frontier(s, [p for p in s.policies if p.label == "customer_pii"][0], True)
expect(pts and pts[0][:2] == (0, 0), "customer data leaks through shared memory with no agent hacked")


# --------------------------------------------------------------- a Graph

r = FakeAgent("researcher", ["web_search"])
acct = FakeAgent("account", ["lookup_customer"])
wr = FakeAgent("writer", [])
em = FakeAgent("emailer", ["send_email"])
g = FakeGraph([("researcher", r), ("account", acct), ("writer", wr), ("emailer", em)],
              edges=[("researcher", "writer"), ("account", "writer"), ("writer", "emailer")],
              entry=["researcher", "account"])
s = st.to_system(g, tools={"lookup_customer": {"read": ["data:crm"]}}, secrets={"data:crm": "customer_pii"},
                 approval_tools=["send_email"])
for nid in ("researcher", "account", "writer", "emailer"):
    expect(f"msg:{nid}" in s.resources, f"node {nid} has an output channel")
expect("msg:researcher" in s.agents["writer"].read and "msg:account" in s.agents["writer"].read,
       "the writer reads both predecessors' outputs")
expect("msg:writer" in s.agents["emailer"].read, "the emailer reads the writer's output")
expect("msg:researcher" in s.agents["researcher"].write, "a node writes its own output channel")
expect("input" in s.agents["researcher"].read and "input" in s.agents["account"].read,
       "entry nodes read the task")
expect("input" not in s.agents["writer"].read, "a non-entry node does not read the task")
expect("input" not in s.agents["emailer"].read, "a non-entry node does not read the task")
expect("tool:send_email" in s.agents["emailer"].ask, "the email tool is a gate in the graph too")


# --------------------------------------------------------------- nesting

# a Graph node whose executor is itself a Swarm
a1 = FakeAgent("a", ["web_search"])
b1 = FakeAgent("b", [])
team = FakeSwarm([a1, b1], entry_point=a1, id="team")
final = FakeAgent("final", ["send_email"])
nested = FakeGraph([("team", team), ("final", final)], edges=[("team", "final")], entry=["team"])
s = st.to_system(nested)
expect("team/a" in s.agents and "team/b" in s.agents and "final" in s.agents,
       "a nested swarm's agents are expanded with a path prefix")
expect("state:team/shared" in s.resources, "the nested swarm gets its own shared memory")
expect("msg:team" in s.agents["team/a"].write and "msg:team" in s.agents["team/b"].write,
       "the nested swarm's agents produce the graph node's output")
expect("msg:team" in s.agents["final"].read, "the downstream node reads the nested unit's output")
expect("input" in s.agents["team/a"].read, "the nested entry agent reads the task")


# --------------------------------------------------------------- check / export

RULES = '''
policy "Customer data never leaves the app"
  never customer_pii -> internet
'''
out = st.check(sw, RULES, tools={"lookup_customer": {"read": ["data:crm"]}},
               secrets={"data:crm": "customer_pii"})
expect("FAIL" in out, "the naive swarm fails the no-leak rule")
d = st.export(sw, tools={"lookup_customer": {"read": ["data:crm"]}}, secrets={"data:crm": "customer_pii"})
expect(d["format"] == "sherlock-scan/1" and d["generated"] == "Strands app", "export has the scan format")
expect(set(d["agents"]) == set(s0 for s0 in st.to_system(sw).agents), "export lists every agent")
expect(d["policies"] and d["policies"][0]["kind"] == "no_flow", "export carries the policies")


# --------------------------------------------------------------- SAT vs brute force

TOOL_POOL = ["web_search", "send_email", "file_read", "file_write", "python_repl",
             "lookup_customer", "think", "remember", "retrieve", "mystery_tool"]


def rand_agent(rng, name):
    return FakeAgent(name, rng.sample(TOOL_POOL, rng.randint(1, 2)))


def rand_app(rng):
    names = [f"n{i}" for i in range(rng.randint(2, 3))]
    agents = [rand_agent(rng, n) for n in names]
    shape = rng.choice(["agent", "swarm", "graph"])
    if shape == "agent":
        obj = agents[0]
    elif shape == "swarm":
        obj = FakeSwarm(agents, entry_point=rng.choice(agents))
    else:
        edges = []
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                if rng.random() < 0.6:
                    edges.append((names[i], names[j]))
        obj = FakeGraph([(n, a) for n, a in zip(names, agents)], edges,
                        entry=[names[0]] if rng.random() < 0.7 else [])
    kw = dict(tools={"lookup_customer": {"read": ["data:crm"]}}, secrets={"data:crm": "customer_pii"},
              untrusted_input=rng.random() < 0.8)
    gated = [t for t in TOOL_POOL if rng.random() < 0.25]
    if gated:
        kw["approval_tools"] = gated
    if rng.random() < 0.3:
        kw["deterministic"] = rng.sample(names, 1)
    return obj, kw, names


rng = random.Random(11)
cases = mism = 0
for trial in range(40):
    obj, kw, names = rand_app(rng)
    s = st.to_system(obj, **kw)
    if len(st.gates(s)) > 6:          # keep the brute-force search small, as test_sat does
        continue
    extra = [Policy("crm integrity", "integrity", resource="data:crm")]
    extra += [Policy(f"{a} hijacked", "hijack", agent=a) for a in list(s.agents)[:1]]
    for p in s.policies + extra:
        cases += 1
        want = brute(s, p, True)
        got = [pt[:2] for pt in frontier(s, p, True)]
        if want != got:
            mism += 1
            print("MISMATCH", trial, p.name, "brute", want, "sat", got)

# --- effectful tool names must not silently map to zero reach (soundness) ------------
from integrations.strands import tool_reach
for nm in ("stop_instance", "stop_task", "run_task", "delete_everything_xyz"):
    r, _ = tool_reach(nm, object(), {})
    expect(r["read"] or r["write"], f"{nm}: an unrecognized/effectful tool is not modeled inert")
# a tool that both reads data and reaches the web keeps BOTH (union, not first-match)
r, _ = tool_reach("search_customer", object(), {})
expect("*" in r["read"] and "net" in r["write"], f"search_customer keeps its data read and net sink: {r}")
# a genuinely inert control-flow tool stays inert
r, _ = tool_reach("final_answer", object(), {})
expect(r["read"] == [] and r["write"] == [], f"final_answer is inert: {r}")

print(f"strands: {cases} random cases, {mism} mismatches; {fails} unit failures")
sys.exit(1 if fails or mism else 0)
