#!/usr/bin/env python3
"""Import a Meta Llama Stack deployment into Sherlock.

Llama Stack (https://github.com/meta-llama/llama-stack) runs agents behind one
API. A deployment registers *tool groups* (built-in ones such as
``builtin::websearch`` / ``builtin::rag`` / ``builtin::code_interpreter``, and
remote ones served over MCP), *shields* (Llama Guard, Prompt Guard, ...), and
*vector DBs*. Each agent is an ``AgentConfig``: a model, instructions, the
``toolgroups`` it may call, and its ``input_shields`` / ``output_shields``.
Llama Stack's own safety check runs one shield at a time on one turn. This
module turns a whole deployment into one Sherlock system, so the solver can
find attacks that pass through several agents and the stores they share.

Format
------
A single file (YAML or JSON) describing the deployment. The fields that are
real Llama Stack config are marked [LS]; the rest are Sherlock annotations
([S]) for what the config alone cannot say (which store holds a secret, whether
an MCP endpoint carries a credential, which hosts are internal):

    toolgroups:                               # [LS] the stack's registered tool groups
      - {toolgroup_id: builtin::websearch, provider_id: tavily-search}
      - {toolgroup_id: builtin::rag,        provider_id: rag-runtime}
      - {toolgroup_id: builtin::code_interpreter, provider_id: code-interpreter}
      - toolgroup_id: mcp::crm               # [LS] a remote MCP tool group
        provider_id: model-context-protocol
        mcp_endpoint: {uri: "https://crm.example.com/sse"}   # [LS]
        requires_auth: true                  # [S] carries an auth header / credential
    shields:                                  # [LS] registered shields
      - {shield_id: prompt_guard, provider_id: prompt-guard}
      - {shield_id: llama_guard,  provider_id: llama-guard}
    vector_dbs:                               # [LS] registered vector DBs (RAG stores)
      - {vector_db_id: cases}                 #      attacker-ingestible by default
      - {vector_db_id: pii_store, label: customer_pii, untrusted: false}  # label is [S]
    secrets:                                  # [S] attach a confidential label to any resource
      - {resource: "vdb:pii_store", label: customer_pii}
    internal_hosts: [crm.internal.example.com]   # [S] hosts the attacker cannot write
    trusted_users: false                      # [S] is the end-user's turn attacker-controllable?
    agents:                                   # [LS] one AgentConfig each
      intake:
        model: meta-llama/Llama-3.1-8B-Instruct
        instructions: "Triage inbound cases."
        toolgroups:
          - builtin::websearch
          - {name: builtin::rag, args: {vector_db_ids: [cases]}}
        input_shields: [prompt_guard]
        output_shields: [llama_guard]
        enable_session_persistence: true
      publisher:
        instructions: "Post the triage summary."
        toolgroups: [mcp::crm]
        deterministic: true                   # [S] a fixed (non-LLM) step; not steerable by what it reads

Model
-----
- Each agent is one Sherlock agent, injectable (an LLM, steerable by what it
  reads) unless ``deterministic: true``. Its tool groups are not told apart.
- Tool groups become rights through a catalog (see TOOL_CATALOG):
    web search / browser / wolfram  -> reads the web (untrusted), its queries
                                        leave the machine (net sink).
    rag / memory / knowledge_search -> reads and writes the vector DBs it is
                                        bound to (knowledge_search reads, insert
                                        writes); ingested documents are untrusted.
    code_interpreter                -> broad: runs code, so reaches the web, the
                                        local filesystem and the network.
    an MCP tool group               -> reaches its endpoint host, and, because
                                        the tools it serves are discovered at run
                                        time, is assumed able to do anything
                                        locally too (conservative, noted).
    anything unrecognized           -> assumed able to do anything (noted).
- A vector DB is a resource ``vdb:<id>``; documents ingested into it come from
  outside, so it is attacker-writable (untrusted) unless it is a curated secret
  store. An MCP endpoint host is a resource: ``net:<host>`` (external: the
  attacker can post to it and data in a request leaves) or ``svc:<host>`` (an
  internal host: neither). A credentialed endpoint adds ``acct:<host>``
  (protected) -- acting there acts as you.
- ``enable_session_persistence`` gives the agent a ``session:<agent>`` resource
  it reads, writes and *obeys* (controls): attacker content that lands in it
  steers the agent on the next turn.
- The end-user's turn is a shared ``user_turn`` resource, attacker-controllable
  by default (set ``trusted_users: true`` if only trusted people call the stack).

Shields are NOT trusted here. The system this reader builds assumes every
shield can be bypassed; that is the sound guarantee. ``shield_whatif.whatif``
re-runs the analysis under the explicit, conditional assumption that named
shields hold, so you can see what each one is worth. A shield is never silently
believed.

Verified here vs. not
----------------------
The field names (``toolgroups``/``tools``, ``input_shields``/``output_shields``,
``shields`` with ``shield_id``/``provider_id``, ``tool_groups`` with
``toolgroup_id``/``mcp_endpoint``, ``enable_session_persistence``) were taken
from the Llama Stack docs and distribution ``run.yaml`` templates (see the
report), not from a running SDK -- llama_stack is not imported and need not be
installed. The tool-group -> rights catalog is a conservative reading of what
each built-in does; an unrecognized group is assumed able to do anything. The
mapping should be re-checked against the Llama Stack release you deploy.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from collusion import Agent, Policy, Resource, System, literal

# Global resource names.
WEB = "web"            # the public web (untrusted input)
NET = "net"            # generic outbound (data leaving the machine)
FILES = "files"        # the local filesystem / host, reachable by code execution
TURN = "user_turn"     # the end-user's message for this turn

UNRESTRICTED = ({WEB, FILES}, {NET, FILES})   # (reads, writes) for "can do anything"

# (substrings matched against the tool-group id and provider id; reads; writes; note).
# First match wins. "rag"/"mcp"/"unknown" are handled specially in tool_rights.
TOOL_CATALOG = [
    (("code_interpreter", "code-interpreter", "code_exec", "python", "interpreter", "bash", "shell"),
     {WEB, FILES}, {NET, FILES}, "runs code (reaches the web, the filesystem and the network)"),
    (("websearch", "web_search", "web-search", "tavily", "brave", "bing", "google", "serp",
      "browser", "browse", "fetch_url", "url"),
     {WEB}, {NET}, "searches or reads the web (its queries leave the machine)"),
    (("wolfram",), {WEB}, {NET}, "calls an outside service"),
    (("send", "post", "email", "slack", "notify", "webhook", "publish", "sms", "message"),
     set(), {NET}, "sends to an outside service"),
    (("files", "filesystem", "file_io", "read_file", "write_file"),
     {FILES}, {FILES}, "reads and writes local files"),
]
RAG_WORDS = ("rag", "memory", "knowledge", "vector", "vector_io", "retriev")


def _host(uri: str) -> str:
    """The host part of an MCP endpoint URI (bare host, or host:port)."""
    if not uri:
        return ""
    p = urlparse(uri if "://" in uri else "//" + uri)
    return (p.hostname or "").lower() or uri.strip().lower()


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _names(x) -> bool:
    return isinstance(x, list) and all(isinstance(y, str) for y in x)


def load_yaml(path: Path):
    """Read a deployment file: JSON directly, YAML via PyYAML or the bundled
    MiniYaml subset (no third-party dependency needed)."""
    text = Path(path).read_text()
    if path.suffix == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        from miniyaml import MiniYaml
        return MiniYaml(text).parse()


class Deployment:
    def __init__(self, path: str):
        self.path = Path(path)
        self.spec = load_yaml(self.path) or {}
        self._check_shape()
        self.notes: list[str] = []
        self.files: list[Path] = [self.path]
        self.res: dict[str, Resource] = {}
        self.shielded: set[str] = set()
        self.shield_detail: dict[str, dict[str, list[str]]] = {}
        internal = [h.lower() for h in self.spec.get("internal_hosts") or []]
        self.internal = set(internal)
        self.trusted_users = bool(self.spec.get("trusted_users", False))
        # registries built from the top-level sections
        self.toolgroups: dict[str, dict] = {}     # toolgroup_id -> its registration
        self.vdbs: dict[str, str] = {}            # vector_db_id -> resource name

    # -- shape -------------------------------------------------------------
    def _check_shape(self) -> None:
        raw, p = self.spec, str(self.path)
        if not isinstance(raw, dict) or not isinstance(raw.get("agents"), dict):
            raise ValueError(f'{p}: expected a mapping with an "agents" mapping')
        if not raw["agents"]:
            raise ValueError(f"{p}: the deployment lists no agents")
        for key in ("toolgroups", "tool_groups", "shields", "vector_dbs", "secrets"):
            if key in raw and not isinstance(raw[key], list):
                raise ValueError(f"{p}: {key} must be a list")
        for name, cfg in raw["agents"].items():
            if not isinstance(cfg, dict):
                raise ValueError(f"{p}: agent {name} must be a mapping")
            for k in ("toolgroups", "tools", "input_shields", "output_shields"):
                if k not in cfg:
                    continue
                if not isinstance(cfg[k], list):
                    raise ValueError(f"{p}: agent {name}: {k} must be a list")
                ok = all(isinstance(t, (str, dict)) for t in cfg[k]) if k.endswith("groups") or k == "tools" \
                    else _names(cfg[k])
                if not ok:
                    raise ValueError(f"{p}: agent {name}: {k} must be a list of "
                                     f"{'tool groups' if k in ('toolgroups', 'tools') else 'shield ids'}")

    # -- resources ---------------------------------------------------------
    def res_(self, name: str, **kw) -> str:
        r = self.res.get(name)
        if r is None:
            r = self.res[name] = Resource(name)
        for k, v in kw.items():
            if k == "labels":
                r.labels |= set(v)
            elif v:
                setattr(r, k, v)
        return name

    def host_resource(self, host: str, credentialed: bool) -> tuple[set[str], set[str]]:
        """Resources an MCP endpoint reaches: (read+write hosts, write-only accounts).
        An external host is attacker-writable and a way out; an internal one is
        neither. A credentialed endpoint can act as you at the service (write only)."""
        if host in self.internal:
            reach = {self.res_(f"svc:{host}")}
        else:
            reach = {self.res_(f"net:{host}", untrusted=True, sink=True)}
        write_only = {self.res_(f"acct:{host}", protected=True)} if credentialed else set()
        return reach, write_only

    def vdb_resource(self, vid: str) -> str:
        return self.vdbs.get(vid) or self.res_(f"vdb:{vid}", untrusted=True)

    # -- tool groups -> rights --------------------------------------------
    def tool_rights(self, tg_id: str, args: dict, spec: dict | None = None) -> tuple[set[str], set[str], str]:
        # an inline tool dict carries its own mcp_endpoint/requires_auth/provider_id;
        # merge it over the top-level registry so an inline MCP endpoint is not lost.
        reg = {**self.toolgroups.get(tg_id, {}), **(spec or {})}
        provider = str(reg.get("provider_id", "")).lower()
        text = (tg_id + " " + provider).lower()
        is_mcp = tg_id.startswith("mcp::") or provider == "model-context-protocol" \
            or "model_context_protocol" in provider or bool(reg.get("mcp_endpoint"))
        if is_mcp:
            host = _host((reg.get("mcp_endpoint") or {}).get("uri", "")) if isinstance(reg.get("mcp_endpoint"), dict) \
                else _host(reg.get("mcp_endpoint") or "")
            cred = bool(reg.get("requires_auth") or reg.get("credentialed"))
            reach, write_only = self.host_resource(host, cred) if host else (set(), set())
            # the served tools are discovered at run time: assume they can do anything locally too
            reads = set(UNRESTRICTED[0]) | reach
            writes = set(UNRESTRICTED[1]) | reach | write_only
            where = f" at {host}" if host else ""
            return reads, writes, f"remote MCP tool group{where}: tools discovered at run time, assumed able to do anything"
        if any(w in text for w in RAG_WORDS):
            vids = args.get("vector_db_ids") or args.get("vector_db_id") or list(self.vdbs)
            targets = {self.vdb_resource(v) for v in _as_list(vids)} or set()
            if not targets:          # a RAG group with no store registered: note it, no reach
                return set(), set(), "retrieval over the registered vector DBs (none registered)"
            return set(targets), set(targets), "reads and writes its vector DB(s) (ingested documents are untrusted)"
        for words, reads, writes, note in TOOL_CATALOG:
            if any(re.search(rf"(^|[^a-z]){re.escape(w)}", text) for w in words):
                return set(reads), set(writes), note
        return set(UNRESTRICTED[0]), set(UNRESTRICTED[1]), "unrecognized tool group: assumed to read the web and local files and send data out (worst case for an unknown tool)"

    # -- build -------------------------------------------------------------
    def load(self) -> System:
        self.res_(WEB, untrusted=True)
        self.res_(NET, sink=True)
        self.res_(FILES)
        if not self.trusted_users:
            self.res_(TURN, untrusted=True)
        else:
            self.res_(TURN)

        # register tool groups, shields, vector DBs, secrets first
        for tg in (self.spec.get("toolgroups") or []) + (self.spec.get("tool_groups") or []):
            if isinstance(tg, str):
                tg = {"toolgroup_id": tg}
            tid = tg.get("toolgroup_id") or tg.get("name")
            if tid:
                self.toolgroups[tid] = tg
        for v in self.spec.get("vector_dbs") or []:
            if isinstance(v, str):
                v = {"vector_db_id": v}
            vid = v.get("vector_db_id") or v.get("identifier") or v.get("name")
            if not vid:
                continue
            label = v.get("label")
            # a curated secret store is not attacker-ingestible unless marked so
            untrusted = v.get("untrusted", not bool(label))
            name = self.res_(f"vdb:{vid}", untrusted=bool(untrusted),
                             labels=[label] if label else [])
            self.vdbs[vid] = name
        for sec in self.spec.get("secrets") or []:
            self.res_(sec["resource"], labels=[sec["label"]])

        lit = lambda names: [literal(r) for r in sorted(names)]
        agents: dict[str, Agent] = {}
        for name, cfg in self.spec["agents"].items():
            cfg = cfg or {}
            reads: set[str] = {TURN}
            writes: set[str] = set()
            tool_specs = _as_list(cfg.get("toolgroups") if cfg.get("toolgroups") is not None else cfg.get("tools"))
            for t in tool_specs:
                if isinstance(t, dict):
                    tid = t.get("name") or t.get("toolgroup_id") or ""
                    args = t.get("args") or {}
                else:
                    tid, args = str(t), {}
                tr, tw, note = self.tool_rights(tid, args, t if isinstance(t, dict) else None)
                reads |= tr
                writes |= tw
                self.notes.append(f"{name}: tool group {tid}: {note}")
            if cfg.get("enable_session_persistence"):
                sess = self.res_(f"session:{name}", controls=[name])
                reads.add(sess)
                writes.add(sess)
                self.notes.append(f"{name}: keeps session state across turns (obeys it: attacker content there steers it)")
            inp = _as_list(cfg.get("input_shields"))
            outp = _as_list(cfg.get("output_shields"))
            if inp or outp:
                self.shielded.add(name)
                self.shield_detail[name] = {"input": inp, "output": outp}
                self.notes.append(f"{name}: shields input={inp or '[]'} output={outp or '[]'} "
                                  f"(NOT trusted in the base model; see shield_whatif.whatif)")
            injectable = not bool(cfg.get("deterministic")) and cfg.get("ai", True) is not False
            if not injectable:
                self.notes.append(f"{name}: a fixed (non-LLM) step; not steerable by what it reads")
            # an agent's job is to turn what it reads into what it writes: honestly it
            # passes every input through to every output (its tools included).
            flows = [(literal(r), literal(w)) for r in sorted(reads) for w in sorted(writes) if r != w]
            agents[name] = Agent(name, read=lit(reads), write=lit(writes),
                                 injectable=injectable, flows=flows)

        policies: list[Policy] = []
        for label in sorted({l for r in self.res.values() for l in r.labels}):
            policies.append(Policy(f"{label} never leaves the deployment", "no_flow", label=label))
        for r in sorted(self.res):
            if r.startswith("acct:"):
                policies.append(Policy(f"web content never acts through your {r[5:]} account",
                                       "integrity", resource=r))
            elif r.startswith("svc:"):
                policies.append(Policy(f"web content never changes {r[4:]}", "integrity", resource=r))
            elif self.res[r].protected:
                policies.append(Policy(f"{r} stays trustworthy", "integrity", resource=r))
        return System(agents, self.res, policies)


def load_llamastack(path: str) -> System:
    """Read a Llama Stack deployment file into a Sherlock system.

    The returned system carries, as attributes: ``notes`` (how each tool group
    was read), ``files`` (every file the deployment was read from), ``shielded``
    (the agents with an input or output shield) and ``shield_detail`` (the shield
    ids per agent). Shields are not trusted by the model itself."""
    d = Deployment(path)
    s = d.load()
    s.notes = d.notes            # type: ignore[attr-defined]
    s.files = d.files            # type: ignore[attr-defined]
    s.shielded = sorted(d.shielded)   # type: ignore[attr-defined]
    s.shield_detail = d.shield_detail  # type: ignore[attr-defined]
    return s


if __name__ == "__main__":
    s = load_llamastack(sys.argv[1])
    print(json.dumps({
        "agents": {a: {"read": x.read, "write": x.write, "injectable": x.injectable,
                       **({"flows": [list(f) for f in x.flows]} if x.flows else {})}
                   for a, x in s.agents.items()},
        "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                            ("sink", x.sink), ("protected", x.protected),
                                            ("controls", x.controls)) if v}
                      for r, x in s.resources.items()},
        "policies": [{k: v for k, v in p.__dict__.items() if v is not None} for p in s.policies],
        "shielded": getattr(s, "shielded", []),
        "notes": getattr(s, "notes", []),
    }, indent=1))
