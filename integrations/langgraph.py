"""Check a LangGraph application with Sherlock.

LangGraph builds multi-agent apps as graphs: nodes (agents or plain code),
tools they call through ToolNode, and shared state that every node can read.
This module reads a *compiled* graph, without running it or calling any
model, and turns it into a Sherlock system:

  LangGraph                          Sherlock
  --------------------------------   ----------------------------------------
  node                               agent; an AI model (steerable by what it
                                     reads) unless listed in `deterministic`
  subgraph node (e.g. a ReAct agent) one agent with the tools of its ToolNodes
  ToolNode reached from a node       that node's rights, via the tool catalog
  interrupt_before / _after on a     an approval gate: those tools need you
    ToolNode, or `approval_tools`
  state key (e.g. `messages`)        resource `state:KEY`
  what a node does                   even an honest node passes everything it
                                     reads to everything it writes
  node input_schema                  the state keys the node reads (else all)
  `writes={node: [keys]}`            the keys the node writes (else all)

Unknown tools are modeled as able to do anything. Override with `tools=`.

    from integrations.langgraph import check
    print(check(app, '''
        policy "Customer data never leaves"
          never customer_pii -> internet
    ''', tools={"lookup_customer": {"read": ["data:crm"]}},
         secrets={"data:crm": "customer_pii"}))

`export(app, ...)` gives the same JSON the Sherlock web page reads, so the
result can also be checked, and certified, at https://sherlocksec.org.
"""
from __future__ import annotations

import inspect
import itertools
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from collusion import Agent, Policy, Resource, System, analyze, gates, violated  # noqa: E402

UNRESTRICTED = {"read": ["web", "*"], "write": ["net", "*"]}
TOOL_CATALOG = [   # (words matched against the tool's NAME, reach, plain description); first match wins
    (("transfer_to_", "handoff", "think", "reflect", "plan_", "todo", "write_todos", "final_answer", "respond",
      "done", "question", "ask_user", "finish", "complete", "clarify"),
     {"read": [], "write": []}, "no outside effect (planning, handoff or answer)"),
    (("remember", "memory", "recall", "save_fact", "save_note"),
     {"read": [], "write": []}, "keeps notes in memory"),
    (("shell", "bash", "terminal", "execute", "exec", "python", "repl", "code_interpreter", "run_code", "task"),
     UNRESTRICTED, "runs code, or starts a sub-agent that can"),
    (("write_file", "save_file", "create_file", "edit_file", "delete_file", "delete", "move_file", "patch"),
     {"read": [], "write": ["*"]}, "writes local files"),
    (("read_file", "load_file", "open_file", "list_files", "file_search", "ls", "glob", "grep", "list_dir"),
     {"read": ["*"], "write": []}, "reads local files"),
    (("sql", "query_db", "database", "db_", "crm", "lookup", "customer", "account", "order", "invoice"),
     {"read": ["*"], "write": ["*"]}, "reads and writes app data"),
    (("email", "gmail", "slack", "send", "post", "tweet", "notify", "webhook", "upload", "publish", "sms",
      "create_issue", "comment", "reply", "schedule_meeting", "calendar"),
     {"read": ["web"], "write": ["net"]}, "acts on an outside service"),
    (("search", "browse", "fetch", "scrape", "crawl", "web", "url", "http", "wikipedia", "arxiv", "tavily",
      "duckduckgo", "serp", "exa", "perplexity", "doc"),
     {"read": ["web"], "write": ["net"]}, "reads the web (its queries leave the app)"),
]
LOCAL = "local"     # what "*" means for an app: its local files and data stores


def _tools_of(runnable) -> dict:
    return dict(getattr(runnable, "tools_by_name", {}) or {})


def _is_graph(x) -> bool:
    return hasattr(x, "builder") and hasattr(getattr(x, "builder"), "nodes")


def _inner(runnable):
    """The graph or ToolNode inside a node's runnable, if any."""
    for cand in (runnable, getattr(runnable, "bound", None), getattr(runnable, "afunc", None)):
        if cand is not None and (_is_graph(cand) or _tools_of(cand)):
            return cand
    return runnable


def tool_reach(name: str, tool, overrides: dict) -> tuple[dict, str]:
    meta = (getattr(tool, "metadata", None) or {}).get("sherlock") if tool is not None else None
    if name in overrides or meta:
        o = overrides.get(name) or meta
        return {"read": list(o.get("read", [])), "write": list(o.get("write", []))}, \
            "as you declared" if name in overrides else "as declared in the tool's metadata"
    text = name.lower()
    if text.split(".")[0] in HTTP_MODULES:
        return {"read": ["web"], "write": ["net"]}, "calls the network directly"
    for words, reach, desc in TOOL_CATALOG:
        if any(re.search(rf"(^|[^a-z]){re.escape(w)}", text) for w in words):
            return {"read": list(reach["read"]), "write": list(reach["write"])}, desc
    return {"read": list(UNRESTRICTED["read"]), "write": list(UNRESTRICTED["write"])}, \
        "unrecognized tool: assumed able to do anything"


MEMORY = "memory:store"     # LangGraph's long-term Store: shared across runs and threads


def _node_uses_store(runnable) -> bool:
    acc = getattr(runnable, "func_accepts", None) or {}
    if "store" in acc or "runtime" in acc:
        return True
    fn = getattr(runnable, "func", None) or getattr(runnable, "afunc", None)
    try:
        params = inspect.signature(fn).parameters if fn else {}
    except (TypeError, ValueError):
        params = {}
    return any(n in ("store", "runtime") or "BaseStore" in str(p.annotation) or "Runtime" in str(p.annotation)
               for n, p in params.items())


def _tool_uses_store(toolnode, name: str, tool) -> bool:
    inj = (getattr(toolnode, "_injected_args", None) or {}).get(name)
    if inj is not None and (getattr(inj, "store", None) or getattr(inj, "runtime", None)):
        return True
    fn = getattr(tool, "func", None) or getattr(tool, "coroutine", None)
    try:
        params = inspect.signature(fn).parameters if fn else {}
    except (TypeError, ValueError):
        params = {}
    return any("InjectedStore" in str(p.annotation) or "ToolRuntime" in str(p.annotation) for p in params.values())


def _graph_uses_store(g) -> bool:
    for spec in g.builder.nodes.values():
        r = _inner(spec.runnable)
        if _is_graph(r):
            if _graph_uses_store(r):
                return True
        elif not _tools_of(r) and _node_uses_store(r):
            return True
    return False


HTTP_MODULES = {"requests", "httpx", "aiohttp", "urllib", "urllib3", "http", "websockets", "smtplib", "boto3", "openai"}


def _is_tool(x) -> bool:
    return hasattr(x, "invoke") and hasattr(x, "name") and (hasattr(x, "args_schema") or type(x).__name__.endswith("Tool"))


def _project_code(fn) -> bool:
    try:
        f = inspect.getsourcefile(fn) or ""
    except TypeError:
        return False
    return bool(f) and "site-packages" not in f and "/lib/python" not in f


WEB_CALL_WORDS = ("search", "scrape", "crawl", "fetch", "tavily", "duckduckgo", "perplexity", "searx", "serp",
                  "exa_", "browse", "firecrawl")


def scan_code(fn, depth: int = 3, seen=None, graphs=None) -> tuple[dict, list[str], bool]:
    """What a plain node's code reaches: tools it references (directly, or in lists
    and dicts), HTTP libraries and helper functions it calls (followed into the
    project's own code), and whether it pauses for a person with interrupt()."""
    seen = seen if seen is not None else set()
    graphs = graphs if graphs is not None else []
    tools, calls, asks = {}, [], False
    fn = getattr(fn, "__wrapped__", fn)
    code = getattr(fn, "__code__", None)
    if code is None or id(code) in seen or depth < 0:
        return tools, calls, asks
    seen.add(id(code))
    names, stack = set(), [code]
    while stack:
        c = stack.pop()
        names |= set(c.co_names)
        stack += [k for k in c.co_consts if hasattr(k, "co_names")]
    g = getattr(fn, "__globals__", {}) or {}
    for n in names:
        obj = g.get(n)
        if obj is None:
            continue
        if _is_graph(obj):
            graphs.append(obj)                       # a sub-agent the node runs itself
        elif _is_tool(obj):
            tools[obj.name] = obj
        elif isinstance(obj, (list, tuple, set)) or isinstance(obj, dict):
            vals = obj.values() if isinstance(obj, dict) else obj
            for v in vals:
                if _is_tool(v):
                    tools[v.name] = v
        elif n == "interrupt" and "langgraph" in getattr(obj, "__module__", ""):
            asks = True
        elif inspect.ismodule(obj) and obj.__name__.split(".")[0] in HTTP_MODULES:
            calls.append(f"uses {obj.__name__}")
        elif "mcp" in n.lower() and "mcp" in (getattr(obj, "__module__", "") or "").lower():
            calls.append("loads MCP tools at run time (unknown tools: assumed able to do anything)")
        elif callable(obj) and not inspect.isclass(obj) and _project_code(obj):
            t2, c2, a2 = scan_code(obj, depth - 1, seen, graphs)
            tools.update(t2)
            calls += c2
            asks = asks or a2
        elif callable(obj) and not _project_code(obj) and not n.startswith("_") and \
                not (inspect.isclass(obj) and issubclass(obj, BaseException)) and \
                any(w in n.lower() for w in WEB_CALL_WORDS):
            calls.append(f"calls {n}")
    return tools, calls, asks


class _Reader:
    def __init__(self, tools, secrets, deterministic, writes, approval_tools, trusted=None, strips=None,
                 untrusted_inputs="auto", reads_as_data=None):
        self.untrusted_inputs = untrusted_inputs
        self.trusted, self.strips = set(trusted or []), dict(strips or {})
        self.reads_as_data = reads_as_data or {}
        self.tools, self.secrets = tools or {}, secrets or {}
        self.deterministic, self.writes = set(deterministic or []), writes or {}
        self.approval_tools = set(approval_tools or [])
        self.res: dict[str, Resource] = {"web": Resource("web", untrusted=True),
                                         "net": Resource("net", sink=True),
                                         LOCAL: Resource(LOCAL)}
        self.notes: list[str] = []

    def place(self, x: str) -> list[str]:
        if x == "*":
            return [r for r, v in self.res.items() if not v.untrusted and not v.sink and not r.startswith("state:")]
        if x not in self.res:
            self.res[x] = Resource(x, untrusted=x.startswith("web:"), sink=x.startswith("net:"))
        return [x]

    def graph_tools(self, g, gated: bool) -> dict[str, tuple]:
        """name -> (tool, behind approval?) for every ToolNode in g, recursively."""
        self._gt_seen = getattr(self, "_gt_seen", set())
        if (id(g), gated) in self._gt_seen:
            return {}
        self._gt_seen.add((id(g), gated))
        out = {}
        before = set(getattr(g, "interrupt_before_nodes", []) or [])
        after = set(getattr(g, "interrupt_after_nodes", []) or [])
        for n, spec in g.builder.nodes.items():
            r = _inner(spec.runnable)
            if _tools_of(r):
                for tn, t in _tools_of(r).items():
                    out[tn] = (t, gated or n in before or n in after or tn in self.approval_tools)
                    if _tool_uses_store(r, tn, t):
                        self.store_tools.add(tn)
            elif _is_graph(r):
                out.update(self.graph_tools(r, gated or n in before))
            else:                                    # plain code inside the subgraph
                subs = []
                ct, cc, ca = scan_code(getattr(r, "func", None) or getattr(r, "afunc", None), graphs=subs)
                for tn, t in ct.items():
                    out[tn] = (t, gated or ca or n in before or tn in self.approval_tools)
                for c in cc:
                    nm = "mcp tools" if c.startswith("loads MCP") else c.split(" ", 1)[1]
                    out.setdefault(nm, (None, gated or ca))
                for sg in subs:
                    if sg is not g:
                        out.update(self.graph_tools(sg, gated or ca))
        return out

    def read(self, app) -> System:
        b = app.builder
        self.store_tools = set()
        channels = [c for c in b.channels if not c.startswith("__")]
        # Whoever calls the app sets its input keys: by default they are attacker-written.
        if self.untrusted_inputs == "auto":
            schema = getattr(b, "input_schema", None)
            keys = list(getattr(schema, "__annotations__", {}) or {}) if schema is not None else channels
            outside = [k for k in keys if k in channels]
        else:
            outside = [k for k in (self.untrusted_inputs or []) if k in channels]
        for c in channels:
            self.res[f"state:{c}"] = Resource(f"state:{c}", untrusted=c in outside)
        if outside:
            self.notes.append(f"app input: {', '.join(outside)} set by whoever calls the app, treated as attacker-written"
                              " (untrusted_inputs=[] if only trusted people call it)")
        # which nodes route into which ToolNodes
        succ: dict[str, set] = {}
        for a, z in b.edges:
            succ.setdefault(a, set()).add(z)
        for a, brs in b.branches.items():
            for br in brs.values():
                ends = getattr(br, "ends", None)
                succ.setdefault(a, set()).update(ends.values() if isinstance(ends, dict) else (ends or b.nodes))
        before = set(getattr(app, "interrupt_before_nodes", []) or [])
        after = set(getattr(app, "interrupt_after_nodes", []) or [])
        toolnodes = {n for n, s in b.nodes.items() if _tools_of(_inner(s.runnable))}
        agents = {}
        for n, spec in b.nodes.items():
            if n in toolnodes:
                continue
            r = _inner(spec.runnable)
            schema = getattr(spec, "input_schema", None)
            keys = list(getattr(schema, "__annotations__", {}) or {}) if schema is not None else []
            reads = [f"state:{k}" for k in keys if k in channels] or [f"state:{c}" for c in channels]
            writes = [f"state:{k}" for k in self.writes.get(n, channels) if k in channels]
            tools = {}
            code_tools, code_calls, code_asks = ({}, [], False) if _is_graph(r) else \
                scan_code(getattr(r, "func", None) or getattr(r, "afunc", None), graphs=(code_graphs := []))
            if _is_graph(r):
                code_graphs = []
            for sub in code_graphs:
                tools.update(self.graph_tools(sub, code_asks))
            if _is_graph(r):
                tools.update(self.graph_tools(r, n in before))
            for tn, tool in code_tools.items():
                tools.setdefault(tn, (tool, code_asks or tn in self.approval_tools))
            for c in sorted(set(code_calls)):
                name = "mcp tools" if c.startswith("loads MCP") else c.split(" ", 1)[1]
                tools.setdefault(name, (None, code_asks))
                self.notes.append(f"{n}: its code {c}")
            if code_asks:
                self.notes.append(f"{n}: its code pauses for a person (interrupt); its tools count as needing approval")
            for t in succ.get(n, ()):
                if t in toolnodes:
                    tnode = _inner(b.nodes[t].runnable)
                    for tn, tool in _tools_of(tnode).items():
                        if _tool_uses_store(tnode, tn, tool):
                            self.store_tools.add(tn)
                        tools[tn] = (tool, t in before or t in after or tn in self.approval_tools)
            rd, wr, ask = set(reads), set(writes), {}
            uses_store = (_graph_uses_store(r) if _is_graph(r) else _node_uses_store(r))
            if uses_store:
                self.place(MEMORY)
                rd.add(MEMORY)
                wr.add(MEMORY)
                self.notes.append(f"{n}: reads and writes the long-term Store (memory shared across runs)")
            for tn, (tool, gated) in sorted(tools.items()):
                reach, desc = tool_reach(tn, tool, self.tools)
                tr = {p for x in reach["read"] for p in self.place(x)}
                tw = {p for x in reach["write"] for p in self.place(x)}
                if tn in self.store_tools:
                    self.place(MEMORY)
                    tr.add(MEMORY)
                    tw.add(MEMORY)
                    desc += "; uses the long-term Store"
                if gated:
                    ask[f"tool:{tn}"] = {"read": sorted(tr), "write": sorted(tw)}
                else:
                    rd |= tr
                    wr |= tw
                self.notes.append(f"{n}: tool {tn}: {desc}{' (needs your approval)' if gated else ''}")
            # A node's job is to turn what it reads into what it writes, so even an
            # honest node passes its inputs (including data its tools fetch) to its
            # outputs (including tools that need approval, once approved).
            all_r = rd | {x for g in ask.values() for x in g["read"]}
            all_w = wr | {x for g in ask.values() for x in g["write"]}
            flows = [(a, z) for a in sorted(all_r) for z in sorted(all_w) if a != z]
            meta = ((getattr(spec, "metadata", None) or {}).get("sherlock") or {})
            trusted = n in self.trusted or bool(meta.get("trusted"))
            strips = sorted(set(self.strips.get(n, [])) | set(meta.get("strips") or []))
            ai = n not in self.deterministic and not meta.get("deterministic") and not trusted
            rad_names = set(self.reads_as_data.get(n, [])) | set(meta.get("reads_as_data") or [])
            rad = sorted({(f"state:{x}" if x in channels else p)
                          for x in rad_names for p in ([x] if x in channels else self.place(x))})
            agents[n] = Agent(n, read=sorted(rd), write=sorted(wr), injectable=ai, ask=ask, flows=flows,
                              trusted=trusted, strips=strips, reads_as_data=rad)
            if trusted or strips:
                self.notes.append(f"{n}: " + ", ".join((["trusted: cannot be hacked or steered"] if trusted else []) +
                                                     ([f"its output carries no {', '.join(strips)}"] if strips else [])))
        for r, label in self.secrets.items():
            self.place(r)
            self.res[r].labels.add(label)
        policies = [Policy(f"{l} never leaves the app", "no_flow", label=l)
                    for l in sorted(set(self.secrets.values()))]
        return System(agents, self.res, policies)


def to_system(app, tools=None, secrets=None, deterministic=None, writes=None, approval_tools=None,
              trusted=None, strips=None, untrusted_inputs="auto", reads_as_data=None) -> System:
    """The Sherlock model of a compiled LangGraph app.

    trusted=[nodes]: the attacker can neither break into nor steer these nodes
    (reviewed code, a human step). strips={node: ["attacker", "customer_pii"]}:
    what a node's output never carries (a fixed-choice router, a redaction step).
    Both can also be set on the node: metadata={"sherlock": {"trusted": True, "strips": [...]}}."""
    rd = _Reader(tools, secrets, deterministic, writes, approval_tools, trusted, strips,
                 untrusted_inputs, reads_as_data)
    # create every declared data store first, so "*" (everything local) covers them
    for r in (secrets or {}):
        rd.place(r)
    for o in (tools or {}).values():
        for x in list(o.get("read", [])) + list(o.get("write", [])):
            if x != "*":
                rd.place(x)
    s = rd.read(app)
    s.notes = rd.notes  # type: ignore[attr-defined]
    return s


def export(app, **kw) -> dict:
    """The JSON the Sherlock web page reads (paste it at https://sherlocksec.org)."""
    s = to_system(app, **kw)
    return {"format": "sherlock-scan/1", "generated": "LangGraph app",
            "agents": {a: {"title": a, "read": x.read, "write": x.write, "injectable": x.injectable,
                           "ask": x.ask, "flows": [list(f) for f in x.flows],
                           "trusted": x.trusted, "strips": list(x.strips), "notes": [n.split(": ", 1)[1] for n in s.notes if n.startswith(a + ":")]}
                       for a, x in s.agents.items()},
            "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                                ("sink", x.sink)) if v} for r, x in s.resources.items()},
            "policies": [{k: v for k, v in p.__dict__.items() if v is not None} for p in s.policies],
            "coverage": {"read": sorted(s.agents), "assumed": [],
                         "worst": sorted({n.split(":", 1)[0] for n in s.notes if "unrecognized tool" in n}),
                         "not_checked": ["what each tool does beyond the catalog or what you declared",
                                         "which state keys a node writes, unless you list them in writes=",
                                         "tools that call interrupt() themselves, unless listed in approval_tools="]}}


def _frontier(s: System, goal) -> list[tuple[int, int, object]]:
    """Cheapest (agents hacked, approvals) attacks: SAT when CaDiCaL is installed, else exhaustive."""
    if shutil.which("cadical"):
        from sat import frontier
        return [(t, h, a) for t, h, a in frontier(s, goal, True)]
    from sat import as_goal
    goal = as_goal(goal)

    def bad(c, g):
        res = analyze(s, frozenset(c), True, frozenset(g), goal.sources)
        return any(violated(s, x, res) for x in goal.atoms)
    G, A, pts, best_h = gates(s), sorted(s.agents), [], len(gates(s)) + 1
    for t in range(len(A) + 1):
        for h in range(best_h):
            hit = next(((c, g) for c in itertools.combinations(A, t) for g in itertools.combinations(G, h)
                        if bad(c, g)), None)
            if hit:
                pts.append((t, h, hit))
                best_h = h
                break
    return pts


def check(app, rules: str = "", **kw) -> str:
    """Check rules (Sherlock's policy language) against a compiled LangGraph app."""
    from policy import compile_file, parse
    s = to_system(app, **kw)
    pf = parse(rules) if rules.strip() else None
    if pf:
        goals = compile_file(s, pf, lambda p: p if p in s.resources else None)
    else:
        from policy import Compiled
        goals = [Compiled(p.name, p, 0, 0, []) for p in s.policies]
    lines = []
    for g in goals:
        t_b = len(s.agents) if g.agents is None else g.agents
        h_b = len(gates(s)) if g.approvals is None else g.approvals
        pts = _frontier(s, g.goal)
        bad = [p for p in pts if p[0] <= t_b and p[1] <= h_b]
        cheapest = ", ".join(f"{t} hacked + {h} approvals" for t, h, _ in pts) or "none at any cost"
        lines.append(f"{'FAIL' if bad else 'PASS'}  {g.title}\n      cheapest attack: {cheapest}")
    return "\n".join(lines)
