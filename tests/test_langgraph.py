"""Tests for the LangGraph integration (skipped when langgraph is not installed)."""
import importlib.util
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, ".")
if importlib.util.find_spec("langgraph") is None:
    print("langgraph: skipped (pip install langgraph)")
    sys.exit(0)

from typing import TypedDict  # noqa: E402

from langchain_core.tools import tool  # noqa: E402
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402

import integrations.langgraph as lg  # noqa: E402
from examples.langgraph.support_bot import COMMON, HARDENED, hardened_app, naive_app  # noqa: E402
from sat import frontier  # noqa: E402

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


# --- reading a graph -----------------------------------------------------------
s = lg.to_system(naive_app(), **COMMON)
expect(set(s.agents) == {"router", "researcher", "account", "writer"}, "ToolNodes are not agents")
expect("web" in s.agents["researcher"].read and "net" in s.agents["researcher"].write, "web_search reads the web")
expect("data:crm" in s.agents["account"].read, "declared tool rights")
expect("net" in s.agents["writer"].write, "a tool reached through a conditional edge")
expect(not s.agents["router"].injectable, "deterministic nodes are not AI")
expect("state:messages" in s.agents["account"].read, "without input_schema a node reads all state")
h = lg.to_system(hardened_app(), **HARDENED)
expect(h.agents["account"].read == sorted(["state:customer_id", "data:crm"]), "input_schema limits reads")
expect("tool:send_email" in h.agents["writer"].ask and "net" not in h.agents["writer"].write,
       "interrupt_before makes the tool an approval")
expect(lg.tool_reach("mystery", None, {})[1].startswith("unrecognized"), "unknown tools are unrestricted")

# --- automatic detection: outside input, long-term Store, tool metadata -----------
from typing import Annotated  # noqa: E402
from langgraph.prebuilt import InjectedStore  # noqa: E402
from langgraph.store.base import BaseStore  # noqa: E402
from langgraph.store.memory import InMemoryStore  # noqa: E402


@tool
def remember(fact: str, store: Annotated[BaseStore, InjectedStore()]) -> str:
    """Save a fact for later conversations."""
    return ""


@tool
def crm(cid: str) -> str:
    """Look up a customer."""
    return ""


crm.metadata = {"sherlock": {"read": ["data:crm"]}}


def recall(state, *, store: BaseStore):
    return {}


mg = StateGraph(MessagesState)
mg.add_node("recall", recall)
mg.add_node("agent", lambda s: {})
mg.add_node("plain", lambda s: {})
mg.add_node("tools", ToolNode([remember, crm]))
mg.add_edge(START, "recall")
mg.add_edge("recall", "agent")
mg.add_conditional_edges("agent", lambda s: END, ["tools", END])
mg.add_edge("tools", "agent")
ms = lg.to_system(mg.compile(store=InMemoryStore()))
expect(ms.resources["state:messages"].untrusted, "the app's input keys are attacker-written by default")
expect(not lg.to_system(mg.compile(), untrusted_inputs=[]).resources["state:messages"].untrusted, "untrusted_inputs=[] opts out")
expect(lg.MEMORY in ms.agents["recall"].read and lg.MEMORY in ms.agents["recall"].write, "a node asking for store uses memory")
expect(lg.MEMORY in ms.agents["agent"].write, "an InjectedStore tool uses memory")
expect(lg.MEMORY not in ms.agents["plain"].read, "a plain node does not")
expect("data:crm" in ms.agents["agent"].read, "tool metadata declares what it touches")
expect("net" not in ms.agents["agent"].write, "a memory tool is not unrestricted")

# --- SAT vs the exhaustive fallback, on the examples and random graphs ----------
TOOLS = []
for name, doc in [("web_search", "Search the web."), ("send_email", "Send an email."),
                  ("lookup_customer", "Look up a customer."), ("python_repl", "Run Python code."),
                  ("read_file", "Read a local file.")]:
    TOOLS.append(tool(name, description=doc)(lambda x="": ""))


def random_app(rng):
    keys = ["messages", "a", "b", "c"]
    S = TypedDict("S", {k: (list if k == "messages" else str) for k in keys})
    g = StateGraph(S)
    names = [f"n{i}" for i in range(rng.randint(2, 3))]
    interrupts = []
    for n in names:
        sub = {k: str for k in rng.sample(keys[1:], rng.randint(1, 2))}
        g.add_node(n, lambda s: {}, **({"input_schema": TypedDict(f"I{n}", sub)} if rng.random() < .6 else {}))
        if rng.random() < .7:
            g.add_node(f"{n}_tools", ToolNode(rng.sample(TOOLS, rng.randint(1, 2))))
            g.add_conditional_edges(n, lambda s: END, [f"{n}_tools", END])
            g.add_edge(f"{n}_tools", n)
            if rng.random() < .4:
                interrupts.append(f"{n}_tools")
    g.add_edge(START, names[0])
    for x, y in zip(names, names[1:]):
        g.add_edge(x, y)
    app = g.compile(interrupt_before=interrupts)
    kw = dict(tools={"lookup_customer": {"read": ["data:crm"]}}, secrets={"data:crm": "pii"},
              deterministic=[n for n in names if rng.random() < .3],
              writes={n: rng.sample(keys, rng.randint(1, 2)) for n in names if rng.random() < .5})
    return app, kw


cases = mism = 0
apps = [(naive_app(), COMMON), (hardened_app(), HARDENED)] + [random_app(random.Random(i)) for i in range(25)]
for app, kw in apps:
    s = lg.to_system(app, **kw)
    for p in s.policies + [lg.Policy("crm integrity", "integrity", resource="data:crm")]:
        cases += 1
        sat = [pt[:2] for pt in frontier(s, p, True)]
        real = shutil.which
        lg.shutil.which = lambda _: None          # force the exhaustive fallback
        try:
            brute = [pt[:2] for pt in lg._frontier(s, p)]
        finally:
            lg.shutil.which = real
        if sat != brute:
            mism += 1
            print("mismatch", p.name, sat, brute)

# --- the exported JSON gives the same answers in the web page's engine ------------
site_engine = Path("web/engine.js")
web_agree = "skipped (web/engine.js or node missing)"
if site_engine.exists() and shutil.which("node"):
    d = lg.export(hardened_app(), **HARDENED)
    Path("/tmp/lg_export.json").write_text(json.dumps(d))
    out = subprocess.run(["node", "-e", f"""
const E=require('{site_engine.resolve()}');const d=require('/tmp/lg_export.json');const m=E.load(d);
console.log(JSON.stringify(E.search(m,true).front.map(f=>f.map(x=>[x.t,x.h]))));"""], capture_output=True, text=True)
    s = lg.to_system(hardened_app(), **HARDENED)
    web_agree = json.loads(out.stdout) == [[list(pt[:2]) for pt in frontier(s, p, True)] for p in s.policies]
    expect(web_agree, "web engine agrees on the exported app")

print(f"langgraph: {cases} cases, {mism} SAT/exhaustive mismatches, web engine agrees: {web_agree}, {fails} unit failures")
sys.exit(1 if fails or mism else 0)
