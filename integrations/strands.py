"""Check an AWS Strands Agents application with Sherlock.

Strands (https://github.com/strands-agents/sdk-python) builds agents as an
`Agent(model, tools=[...])`, and composes them with two multi-agent
orchestrators: a `Swarm` (agents that share one working memory and hand off to
each other) and a `Graph` (agents wired by edges, each node's output fed to its
successors). This module reads a *constructed* Strands object -- an Agent, a
Swarm or a Graph -- without running it or calling any model, and turns it into a
Sherlock system:

  Strands                             Sherlock
  ----------------------------------  ----------------------------------------
  Agent                               an agent; an AI model (steerable by what
                                      it reads) unless listed in `deterministic`
  a tool on the agent                 that agent's rights, via the tool catalog
  Swarm node                          an agent; the Swarm's shared context is
                                      one resource every node reads and writes
  Graph node                          an agent; each node's output is a resource
                                      `msg:NODE` its successors read
  Swarm/Graph node that is itself a   expanded in place (its agents wired to the
    Swarm or Graph                    node's inbound/outbound channels)
  the task given to the app           resource `input`; set by whoever calls the
                                      app, so attacker-written by default
  an MCP tool (loaded from a server)  assumed able to do anything (the server
                                      could expose any tool), and noted
  what an agent does                  even an honest agent passes everything it
                                      reads to everything it writes

Unknown tools are modeled as able to do anything. Override with `tools=`.
Strands has no structural "this tool pauses for a human" flag the way LangGraph's
`interrupt_before` does, so mark human-confirmed tools with `approval_tools=`.

    from integrations.strands import check
    print(check(agent, '''
        policy "Customer data never leaves"
          never customer_pii -> internet
    ''', tools={"lookup_customer": {"read": ["data:crm"]}},
         secrets={"data:crm": "customer_pii"}))

`export(obj, ...)` gives the same JSON the Sherlock web page reads, so the
result can also be checked, and certified, at https://sherlocksec.org.

Validation note: the Strands->Sherlock mapping and the object introspection
(``agent.tool_registry.registry``, ``swarm.nodes``, ``graph.nodes``/``edges``
and their ``executor`` / ``node_id`` / ``from_node`` / ``to_node`` attributes)
are confirmed against the SDK source and exercised here with duck-typed fakes in
tests/test_strands.py. They have NOT been run against a live install of the
`strands-agents` package in this workspace; the tool catalog in particular is a
best-effort recognition of the `strands-agents-tools` names and should be
spot-checked against the version you deploy.
"""
from __future__ import annotations

import itertools
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from collusion import Agent, Policy, Resource, System, analyze, gates, violated  # noqa: E402

UNRESTRICTED = {"read": ["web", "*"], "write": ["net", "*"]}
LOCAL = "local"     # what "*" means for an app: its local files and data stores
INPUT = "input"     # the task/prompt handed to the app, set by whoever calls it

# (words matched against the tool's NAME, reach, plain description); first match wins.
# Names are from the open-source `strands-agents-tools` package plus the generic
# verbs LangGraph's catalog already recognizes, so custom tools are caught too.
TOOL_CATALOG = [
    # Only unambiguous control-flow / inert tool names: a match here alone means NO reach,
    # so a word that could name an effectful tool (stop_instance, respond_and_email, run_task)
    # must NOT be here -- it should fall through to the worst-case default instead.
    (("transfer_to_", "handoff", "final_answer", "ask_user", "think", "reflect", "plan_",
      "todo", "clarify", "calculator", "current_time"),
     {"read": [], "write": []}, "no outside effect (planning, reasoning, handoff or answer)"),
    (("memory", "mem0", "remember", "recall", "journal", "save_fact", "save_note"),
     {"read": [], "write": []}, "keeps notes in memory"),
    (("shell", "bash", "terminal", "python_repl", "code_interpreter", "execute", "exec", "repl",
      "use_aws", "workflow", "agent_graph", "swarm", "graph", "load_tool", "cron", "environment",
      "a2a_client", "use_computer", "run_code", "task"),
     UNRESTRICTED, "runs code, calls cloud APIs, or starts a sub-agent that can"),
    (("file_write", "fs_write", "editor", "write_file", "save_file", "create_file", "edit_file",
      "delete_file", "delete", "move_file", "patch"),
     {"read": [], "write": ["*"]}, "writes local files"),
    (("file_read", "fs_read", "read_file", "load_file", "open_file", "list_files", "image_reader",
      "ls", "glob", "grep", "list_dir"),
     {"read": ["*"], "write": []}, "reads local files"),
    (("retrieve", "knowledge_base", "rag", "sql", "query_db", "database", "db_", "crm", "lookup",
      "customer", "account", "order", "invoice"),
     {"read": ["*"], "write": ["*"]}, "reads and writes app data"),
    (("slack", "email", "gmail", "send", "post", "tweet", "notify", "webhook", "upload", "publish",
      "sms", "sns", "ses", "speak", "generate_image", "nova_reel", "nova_canvas", "create_issue",
      "comment", "reply", "schedule_meeting", "calendar"),
     {"read": ["web"], "write": ["net"]}, "acts on an outside service"),
    (("http_request", "http", "tavily", "exa", "bright_data", "browser", "rss", "search", "browse",
      "fetch", "scrape", "crawl", "web", "url", "wikipedia", "arxiv", "duckduckgo", "serp",
      "firecrawl", "doc"),
     {"read": ["web"], "write": ["net"]}, "reads the web (its queries leave the app)"),
]


# ------------------------------------------------------------- introspection

def _is_graph(x) -> bool:
    """A Graph (or GraphBuilder): nodes keyed by id, plus edges."""
    return hasattr(x, "nodes") and hasattr(x, "edges")


def _is_swarm(x) -> bool:
    """A Swarm: nodes keyed by id, shared working memory, no edges."""
    return hasattr(x, "nodes") and not hasattr(x, "edges")


def _is_mcp_tool(tool) -> bool:
    if tool is None:
        return False
    return type(tool).__name__ == "MCPAgentTool" or hasattr(tool, "mcp_client") or hasattr(tool, "mcp_tool")


def _node_id(n) -> str:
    return str(getattr(n, "node_id", None) or getattr(n, "name", None) or n)


def _tools_of(executor) -> dict:
    """name -> tool object for every tool on a Strands Agent.

    The SDK keeps them in ``agent.tool_registry.registry`` (name -> AgentTool);
    ``agent.tool_names`` is the name list. We fall back to a plain ``.tools``
    list of objects exposing ``.tool_name`` / ``.name`` for duck-typed inputs."""
    reg = getattr(getattr(executor, "tool_registry", None), "registry", None)
    if isinstance(reg, dict):
        return dict(reg)
    names = getattr(executor, "tool_names", None)
    if isinstance(names, (list, tuple, set)):
        return {str(n): None for n in names}
    out: dict[str, object] = {}
    tl = getattr(executor, "tools", None)
    if isinstance(tl, (list, tuple, set)):
        for t in tl:
            tn = getattr(t, "tool_name", None) or getattr(t, "name", None)
            if tn:
                out[str(tn)] = t
    return out


def tool_reach(name: str, tool, overrides: dict) -> tuple[dict, str]:
    """What a tool can read and write, and a one-line reason."""
    if name in overrides:
        o = overrides[name]
        return {"read": list(o.get("read", [])), "write": list(o.get("write", []))}, "as you declared"
    meta = getattr(tool, "metadata", None)
    meta = meta.get("sherlock") if isinstance(meta, dict) else None
    if meta:
        return {"read": list(meta.get("read", [])), "write": list(meta.get("write", []))}, \
            "as declared in the tool's metadata"
    if _is_mcp_tool(tool):
        return {"read": list(UNRESTRICTED["read"]), "write": list(UNRESTRICTED["write"])}, \
            "MCP tool: its server could expose anything (assumed able to do anything)"
    text = name.lower()
    # Union every catalog group the name matches (not first-match): a tool named
    # search_customer both reads app data and reaches the web, so it gets both -- never
    # losing a sink to an earlier group. A name that matches nothing is worst-case.
    r, w, descs = [], [], []
    for words, reach, desc in TOOL_CATALOG:
        if any(re.search(rf"(^|[^a-z]){re.escape(w)}", text) for w in words):
            r += [x for x in reach["read"] if x not in r]
            w += [x for x in reach["write"] if x not in w]
            descs.append(desc)
    if not descs:
        return {"read": list(UNRESTRICTED["read"]), "write": list(UNRESTRICTED["write"])}, \
            "unrecognized tool: assumed able to do anything"
    return {"read": r, "write": w}, "; ".join(dict.fromkeys(descs))


# ------------------------------------------------------------- channel names

def _msg(prefix: str, nid: str) -> str:
    """Resource carrying a Graph node's output to its successors."""
    return "msg:" + (f"{prefix}/{nid}" if prefix else str(nid))


def _shared(prefix: str) -> str:
    """Resource for a Swarm's shared working memory."""
    return "state:" + (f"{prefix}/shared" if prefix else "shared")


def _sub(prefix: str, nid: str) -> str:
    return f"{prefix}/{nid}" if prefix else str(nid)


# ------------------------------------------------------------- the reader

class _Reader:
    def __init__(self, tools=None, secrets=None, deterministic=None, approval_tools=None,
                 trusted=None, strips=None, untrusted_input=True):
        self.tools, self.secrets = tools or {}, secrets or {}
        self.deterministic = set(deterministic or [])
        self.approval_tools = set(approval_tools or [])
        self.trusted = set(trusted or [])
        self.strips = dict(strips or {})
        self.untrusted_input = bool(untrusted_input)
        self.res: dict[str, Resource] = {
            "web": Resource("web", untrusted=True),
            "net": Resource("net", sink=True),
            LOCAL: Resource(LOCAL),
            INPUT: Resource(INPUT, untrusted=self.untrusted_input),
        }
        self.channels: set[str] = {INPUT}   # resources not covered by "*"
        self.agents: dict[str, Agent] = {}
        self.notes: list[str] = []
        self._used: set[str] = set()

    def place(self, x: str) -> list[str]:
        if x == "*":
            return [r for r, v in self.res.items()
                    if not v.untrusted and not v.sink and r not in self.channels
                    and not r.startswith("state:") and not r.startswith("msg:")]
        if x not in self.res:
            self.res[x] = Resource(x, untrusted=x.startswith("web:"), sink=x.startswith("net:"))
        return [x]

    def channel(self, name: str) -> str:
        if name not in self.res:
            self.res[name] = Resource(name)
        self.channels.add(name)
        return name

    def _uname(self, base: str) -> str:
        n, i = str(base), 2
        while n in self._used:
            n = f"{base}#{i}"
            i += 1
        self._used.add(n)
        return n

    def make_agent(self, executor, node_id: str, reads_in, writes_out) -> str:
        """One Strands Agent -> one Sherlock agent. reads_in / writes_out are the
        inter-agent channels this agent consumes and produces."""
        name = self._uname(node_id)
        rd, wr, ask = set(reads_in), set(writes_out), {}
        for tn, tool in sorted(_tools_of(executor).items()):
            reach, desc = tool_reach(tn, tool, self.tools)
            tr = {p for x in reach["read"] for p in self.place(x)}
            tw = {p for x in reach["write"] for p in self.place(x)}
            gated = tn in self.approval_tools
            if gated:
                ask[f"tool:{tn}"] = {"read": sorted(tr), "write": sorted(tw)}
            else:
                rd |= tr
                wr |= tw
            self.notes.append(f"{name}: tool {tn}: {desc}{' (needs your approval)' if gated else ''}")
        # An agent's job is to turn what it reads into what it writes, so even an
        # honest agent passes its inputs (incl. what its tools fetch, and what it
        # reads from other agents) to its outputs (incl. approval-gated tools once
        # approved). Mirrors the LangGraph reader.
        all_r = rd | {x for g in ask.values() for x in g["read"]}
        all_w = wr | {x for g in ask.values() for x in g["write"]}
        flows = [(a, z) for a in sorted(all_r) for z in sorted(all_w) if a != z]
        trusted = node_id in self.trusted or name in self.trusted
        strips = sorted(set(self.strips.get(node_id, [])) | set(self.strips.get(name, [])))
        injectable = node_id not in self.deterministic and name not in self.deterministic and not trusted
        self.agents[name] = Agent(name, read=sorted(rd), write=sorted(wr), injectable=injectable,
                                  ask=ask, flows=flows, trusted=trusted, strips=strips)
        if trusted or strips:
            self.notes.append(f"{name}: " + ", ".join(
                (["trusted: cannot be hacked or steered"] if trusted else []) +
                ([f"its output carries no {', '.join(strips)}"] if strips else [])))
        return name

    def expand(self, obj, prefix: str, reads_in, writes_out, seen: set) -> None:
        if id(obj) in seen:
            self.notes.append(f"{prefix or 'root'}: a cycle of nested orchestrators, not followed again")
            return
        if _is_graph(obj):
            self.expand_graph(obj, prefix, reads_in, writes_out, seen | {id(obj)})
        elif _is_swarm(obj):
            self.expand_swarm(obj, prefix, reads_in, writes_out, seen | {id(obj)})
        else:
            self.make_agent(obj, prefix, reads_in, writes_out)

    def expand_graph(self, g, prefix: str, reads_in, writes_out, seen: set) -> None:
        nodes = dict(getattr(g, "nodes", {}) or {})
        preds: dict[str, list[str]] = {nid: [] for nid in nodes}
        succ: dict[str, list[str]] = {nid: [] for nid in nodes}
        for e in (getattr(g, "edges", None) or []):
            u, v = _node_id(getattr(e, "from_node", None)), _node_id(getattr(e, "to_node", None))
            if u in succ:
                succ[u].append(v)
            if v in preds:
                preds[v].append(u)
        entry = {_node_id(n) for n in (getattr(g, "entry_points", None) or [])}
        if not entry:
            entry = {nid for nid in nodes if not preds[nid]} or set(nodes)
        chan = {nid: self.channel(_msg(prefix, nid)) for nid in nodes}
        exits = [nid for nid in nodes if not succ[nid]]
        for nid, node in nodes.items():
            executor = getattr(node, "executor", node)
            rin = [chan[u] for u in preds[nid]] + (list(reads_in) if nid in entry else [])
            wout = [chan[nid]] + (list(writes_out) if nid in exits else [])
            self.expand(executor, _sub(prefix, nid), rin, wout, seen)

    def expand_swarm(self, sw, prefix: str, reads_in, writes_out, seen: set) -> None:
        nodes = dict(getattr(sw, "nodes", {}) or {})
        shared = self.channel(_shared(prefix))
        entry = self._swarm_entry(sw, nodes)
        for nid, node in nodes.items():
            executor = getattr(node, "executor", node)
            rin = [shared] + (list(reads_in) if nid in entry else [])
            # Agents share one memory, and any of them may produce the final answer,
            # so each reads and writes the shared context and the unit's own output.
            wout = [shared] + list(writes_out)
            self.expand(executor, _sub(prefix, nid), rin, wout, seen)

    def _swarm_entry(self, sw, nodes: dict) -> set:
        ep = getattr(sw, "entry_point", None)
        if ep is not None:
            for nid, node in nodes.items():
                if getattr(node, "executor", None) is ep:
                    return {nid}
            nm = getattr(ep, "name", None)
            if nm in nodes:
                return {nm}
        return {next(iter(nodes))} if nodes else set()

    def read(self, obj) -> System:
        if self.untrusted_input:
            self.notes.append("app input: the task given to the app is set by whoever calls it, "
                              "treated as attacker-written (untrusted_input=False if only trusted callers)")
        root = str(getattr(obj, "name", None) or getattr(obj, "id", None)
                   or ("graph" if _is_graph(obj) else "swarm" if _is_swarm(obj) else "agent"))
        if _is_graph(obj) or _is_swarm(obj):
            self.expand(obj, "", [INPUT], [], set())
        else:
            self.make_agent(obj, root, [INPUT], [])
        for r, label in self.secrets.items():
            self.place(r)
            self.res[r].labels.add(label)
        policies = [Policy(f"{l} never leaves the app", "no_flow", label=l)
                    for l in sorted(set(self.secrets.values()))]
        return System(self.agents, self.res, policies)


def to_system(obj, tools=None, secrets=None, deterministic=None, approval_tools=None,
              trusted=None, strips=None, untrusted_input=True) -> System:
    """The Sherlock model of a constructed Strands Agent, Swarm or Graph.

    tools={name: {"read": [...], "write": [...]}}: declare what a tool touches
    (overrides the catalog). secrets={resource: label}: a data store and the label
    it holds. deterministic=[names]: agents that are not AI (never steered by what
    they read). approval_tools=[names]: tools a person confirms before they run
    (their rights become an approval gate). trusted=[names] / strips={name: [...]}:
    as in the LangGraph integration. untrusted_input=False: the task is only ever
    supplied by trusted callers."""
    rd = _Reader(tools, secrets, deterministic, approval_tools, trusted, strips, untrusted_input)
    for r in (secrets or {}):              # create declared stores first, so "*" covers them
        rd.place(r)
    for o in (tools or {}).values():
        for x in list(o.get("read", [])) + list(o.get("write", [])):
            if x != "*":
                rd.place(x)
    s = rd.read(obj)
    s.notes = rd.notes  # type: ignore[attr-defined]
    return s


def export(obj, **kw) -> dict:
    """The JSON the Sherlock web page reads (paste it at https://sherlocksec.org)."""
    s = to_system(obj, **kw)
    return {"format": "sherlock-scan/1", "generated": "Strands app",
            "agents": {a: {"title": a, "read": x.read, "write": x.write, "injectable": x.injectable,
                           "ask": x.ask, "flows": [list(f) for f in x.flows],
                           "trusted": x.trusted, "strips": list(x.strips),
                           "notes": [n.split(": ", 1)[1] for n in s.notes if n.startswith(a + ":")]}
                       for a, x in s.agents.items()},
            "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                                ("sink", x.sink)) if v} for r, x in s.resources.items()},
            "policies": [{k: v for k, v in p.__dict__.items() if v is not None} for p in s.policies],
            "coverage": {"read": sorted(s.agents), "assumed": [],
                         "worst": sorted({n.split(":", 1)[0] for n in s.notes if "unrecognized tool" in n}),
                         "not_checked": ["what each tool does beyond the catalog or what you declared",
                                         "which tools pause for a human, unless you list them in approval_tools=",
                                         "MCP tools, which are assumed able to do anything"]}}


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


def check(agent, rules: str = "", **kw) -> str:
    """Check rules (Sherlock's policy language) against a constructed Strands object."""
    from policy import compile_file, parse
    s = to_system(agent, **kw)
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
