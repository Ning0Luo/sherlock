#!/usr/bin/env python3
"""Import an AWS Bedrock Agents deployment into Sherlock.

AWS Bedrock Agents (https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html)
builds an assistant out of one or more *agents*. A supervisor agent can call
*collaborator* agents (multi-agent collaboration); each agent reaches the
outside world through *action groups* (a Lambda, or RETURN_CONTROL) and reads
*knowledge bases* (vector stores filled by data sources). Each of those pieces
is configured on its own; the question Sherlock asks is what they can do
*together* -- whether web text a researcher crawls can end up acting through a
payments account another agent holds, through the messages they exchange.

This is a FILE-BASED reader, like openshell.py: it reads a directory of JSON
that was exported from the Bedrock control-plane API (``aws bedrock-agent
get-agent`` / ``list-agent-action-groups`` / ``list-agent-collaborators`` /
``get-knowledge-base`` ...). It never calls AWS and needs no boto3.

Export layout (every subdirectory optional; files are globbed)::

    <dir>/
      agents/*.json              GetAgent output: {"agent": {agentId, agentName,
                                   agentCollaboration, memoryConfiguration,
                                   guardrailConfiguration, ...}}  (or the bare agent)
      action-groups/*.json       {"agentId": "...", "actionGroups": [ <agentActionGroup>, ... ]}
                                   each group: actionGroupName, actionGroupState,
                                   actionGroupExecutor{lambda|customControl},
                                   parentActionGroupSignature, apiSchema,
                                   functionSchema{functions:[{name, requireConfirmation, ...}]}
      collaborators/*.json       {"agentId": "<supervisor>", "agentCollaborators":
                                   [{collaboratorName, agentDescriptor:{aliasArn}, ...}]}
      knowledge-bases/*.json     {"knowledgeBase": {knowledgeBaseId, name},
                                   "dataSources": [{dataSourceConfiguration:{type}}]}
      agent-knowledge-bases/*.json {"agentId": "...", "agentKnowledgeBases":
                                   [{"knowledgeBaseId": "..."}]}
      rights.json                SUPPLEMENTAL, not a Bedrock API output -- see below.

The field names above were taken from the Bedrock API reference (see the
module tests and the project report for the exact pages). What Bedrock's
control plane does NOT tell you is what a given action group's Lambda is
actually allowed to touch -- that lives in the Lambda's IAM role, outside the
agent config. So ``rights.json`` carries the one thing we cannot read from the
agent export: each action group's *effect* on resources. Start simple::

    {
      "stores": {                         # resources and their sensitivity
        "store:customer_db": {"labels": ["customer_pii"]},
        "store:uploads":     {"untrusted": true},   # a bucket outsiders can write
        "kb:support_wiki":   {"untrusted": true}    # (also inferred from a WEB data source)
      },
      "actionGroups": {                   # <agentName>/<actionGroup>[/<function>] -> effect
        "researcher/lookup_customer": {"reads": ["store:customer_db"], "writes": []},
        "assistant/comms/send_email": {"reads": [], "writes": ["sink:ses"]}
      }
    }

Model mapping (follows openshell.py's conventions)
--------------------------------------------------
- Each agent, supervisor and collaborator alike, is one ``Agent`` (injectable:
  Bedrock agents are LLM-driven, so what they read can steer them).
- A supervisor and a collaborator share a message channel ``msg:SUP__COLLAB``
  that both read and write (the dispatch and the reply).
- User input is attacker-written: an agent that takes user turns directly (a
  supervisor, or a standalone agent -- anyone that is not a collaborator) reads
  an untrusted ``input:AGENT``.
- An action group function with ``requireConfirmation: ENABLED`` puts that
  function's rights behind an ask gate (one approval from you); ``DISABLED`` (or
  an apiSchema group, which has no per-op confirmation) grants them directly.
- A knowledge base with a ``WEB`` (web crawler) data source, or an S3 bucket
  outsiders can write, is ``untrusted``. SES / SNS / outbound HTTP is a ``sink``.
  An outbound account/credential is ``acct:HOST`` (protected). Session-summary
  memory is ``mem:AGENT`` with ``controls=[AGENT]`` (it steers the agent, and a
  corrupted agent can poison it).
- A Guardrail / prompt-attack filter is recorded as a NOTE only. It is a model,
  so a PASS must never depend on it; it is never a ``strips``.

Resource-name prefixes carry their sensitivity, so a policy file (and the
``--bedrock`` path map) can name them directly: ``store:`` a data store,
``kb:`` a knowledge base, ``sink:`` an egress (SES/SNS/HTTP), ``net:`` an
external host (untrusted AND a sink), ``acct:`` an outbound account (protected),
``mem:`` agent memory, ``input:`` a user-input channel, ``msg:`` an agent-to-
agent channel.

Honest, and what is NOT verified here
-------------------------------------
Verified in this repo: the reader builds a valid ``collusion.System`` from
hand-made exports, and ``tests/test_bedrock.py`` cross-checks the solver
against brute force on randomized Bedrock-shaped exports. NOT verified here: the
field names against a live Bedrock account (they come from the public API docs,
January 2026), and the mapping from a real Lambda IAM role to ``rights.json``
(that is left to whoever produces the export; an action group with no declared
rights is modeled conservatively as able to read every store and reach every
sink, like an unrecognized tool in the LangGraph reader).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from collusion import Agent, Policy, Resource, System, literal

# action-group executor / parent signatures that mean "runs arbitrary code"
CODE_SIGNATURES = {"AMAZON.CodeInterpreter", "ANTHROPIC.Computer", "ANTHROPIC.Bash",
                   "ANTHROPIC.TextEditor"}
# the built-in "ask the user a question" action group
USER_INPUT_SIGNATURE = "AMAZON.UserInput"

# resource-name prefix -> default (untrusted, sink, protected)
PREFIX_DEFAULTS = {
    "net": (True, True, False),     # an external host: attacker can post to it, and it carries data out
    "sink": (False, True, False),   # SES / SNS / outbound HTTP: leaves the deployment
    "acct": (False, False, True),   # an outbound account/credential: integrity-critical
    "input": (True, False, False),  # a user-input channel: attacker-written
    "store": (False, False, False),
    "kb": (False, False, False),
    "mem": (False, False, False),
    "msg": (False, False, False),
}


def _prefix(name: str) -> str:
    return name.split(":", 1)[0] if ":" in name else ""


def _alias_agent_id(arn: str) -> str | None:
    """The collaborator agent's id out of an alias ARN
    (arn:aws:bedrock:...:agent-alias/<agentId>/<aliasId>)."""
    m = re.search(r"agent-alias/([0-9a-zA-Z]{10})/", arn or "")
    return m.group(1) if m else None


class Bedrock:
    def __init__(self, path: str):
        self.root = Path(path)
        if not self.root.is_dir():
            raise ValueError(f"{path} is not a directory of exported Bedrock JSON")
        self.notes: list[str] = []
        self.files: list[Path] = []
        self.res: dict[str, Resource] = {}
        self.store_meta: dict[str, dict] = {}       # name -> {labels, untrusted, sink, protected}
        self.rights: dict[str, dict] = {}           # "<agent>/<ag>[/<fn>]" -> {reads, writes}
        self.agents_raw: dict[str, dict] = {}        # agentId -> agent object
        self.name_of: dict[str, str] = {}            # agentId -> agentName
        self.action_groups: dict[str, list] = {}     # agentId -> [actionGroup, ...]
        self.collab: list[tuple[str, str, str]] = [] # (supervisorId, collaboratorId, label)
        self.kbs: dict[str, dict] = {}               # kbId -> {"name":..., "untrusted":bool}
        self.agent_kbs: dict[str, set[str]] = {}     # agentId -> {kbId, ...}
        self._load_files()

    # ---------------------------------------------------------------- file i/o
    def _read(self, p: Path):
        self.files.append(p)
        with open(p) as f:
            return json.load(f)

    def _glob(self, sub: str):
        d = self.root / sub
        return sorted(d.glob("*.json")) if d.is_dir() else []

    def _load_files(self) -> None:
        rj = self.root / "rights.json"
        if rj.is_file():
            data = self._read(rj)
            self.store_meta = dict(data.get("stores") or {})
            self.rights = dict(data.get("actionGroups") or {})

        for p in self._glob("agents"):
            data = self._read(p)
            ag = data.get("agent", data)
            aid = ag.get("agentId")
            if not aid:
                raise ValueError(f"{p}: agent has no agentId")
            name = ag.get("agentName") or f"agent:{aid}"
            self.agents_raw[aid] = ag
            self.name_of[aid] = name

        for p in self._glob("action-groups"):
            data = self._read(p)
            aid = data.get("agentId")
            if not aid:
                raise ValueError(f"{p}: action-groups file has no agentId")
            groups = data.get("actionGroups") or data.get("actionGroupSummaries") or []
            self.action_groups.setdefault(aid, []).extend(groups)

        for p in self._glob("collaborators"):
            data = self._read(p)
            sup = data.get("agentId")
            if not sup:
                raise ValueError(f"{p}: collaborators file has no agentId")
            for c in data.get("agentCollaborators") or data.get("agentCollaboratorSummaries") or []:
                arn = (c.get("agentDescriptor") or {}).get("aliasArn", "")
                cid = _alias_agent_id(arn) or c.get("collaboratorId")
                label = c.get("collaboratorName") or (cid or "collaborator")
                if not cid:
                    raise ValueError(f"{p}: collaborator {label} has no resolvable agent id")
                self.collab.append((sup, cid, label))

        for p in self._glob("knowledge-bases"):
            data = self._read(p)
            kb = data.get("knowledgeBase", data)
            kid = kb.get("knowledgeBaseId")
            if not kid:
                raise ValueError(f"{p}: knowledge base has no knowledgeBaseId")
            sources = data.get("dataSources") or data.get("dataSourceSummaries") or []
            # a KB ingests documents; anything but a provably-internal source can carry
            # attacker-influenced content, so treat any data source as untrusted. Summaries
            # omit the type, which is handled conservatively (untrusted).
            types = sorted({(ds.get("dataSourceConfiguration") or {}).get("type") or "UNKNOWN"
                            for ds in sources})
            self.kbs[kid] = {"name": kb.get("name") or kid, "untrusted": bool(sources), "types": types}

        for p in self._glob("agent-knowledge-bases"):
            data = self._read(p)
            aid = data.get("agentId")
            if not aid:
                raise ValueError(f"{p}: agent-knowledge-bases file has no agentId")
            for a in data.get("agentKnowledgeBases") or data.get("agentKnowledgeBaseSummaries") or []:
                kid = a.get("knowledgeBaseId")
                if kid:
                    self.agent_kbs.setdefault(aid, set()).add(kid)

        if not self.agents_raw:
            raise ValueError("the export has no agents/ directory with any agent file")

    # ---------------------------------------------------------------- resources
    def reg(self, name: str) -> str:
        """Register a resource (idempotent), applying the prefix's default sensitivity."""
        if name not in self.res:
            u, s, p = PREFIX_DEFAULTS.get(_prefix(name), (False, False, False))
            self.res[name] = Resource(name, untrusted=u, sink=s, protected=p)
        return name

    def _apply_store_meta(self) -> None:
        for name, meta in self.store_meta.items():
            r = self.res.get(name) or self.res[self.reg(name)]
            r.labels |= set(meta.get("labels") or [])
            for attr in ("untrusted", "sink", "protected"):
                if attr in meta:
                    setattr(r, attr, bool(meta[attr]))

    def _all_stores(self) -> set[str]:
        return {r for r in self.res if _prefix(r) in ("store", "kb")}

    def _all_sinks(self) -> set[str]:
        return {r for r, x in self.res.items()
                if x.sink or _prefix(r) in ("sink", "net", "acct")}

    def _effect(self, *keys: str):
        """The declared (reads, writes) for the first matching rights key, or None."""
        for k in keys:
            if k in self.rights:
                e = self.rights[k]
                return list(e.get("reads") or []), list(e.get("writes") or [])
        return None

    # ---------------------------------------------------------------- assembly
    def load(self) -> System:
        # pre-register every resource named in a rights effect, so an undeclared
        # action group's "read every store / reach every sink" sees them all.
        for e in self.rights.values():
            for name in list(e.get("reads") or []) + list(e.get("writes") or []):
                self.reg(name)
        for name in self.store_meta:
            self.reg(name)

        collab_ids = {cid for _, cid, _ in self.collab}
        # knowledge bases
        for kid, kb in self.kbs.items():
            r = self.reg(f"kb:{kb['name']}")
            if kb["untrusted"]:
                self.res[r].untrusted = True
                self.notes.append(f"kb:{kb['name']}: data source(s) {', '.join(kb.get('types') or ['?'])}; "
                                  "its contents can be attacker-influenced, so treated as attacker-written")
        self._apply_store_meta()

        reads: dict[str, set[str]] = {a: set() for a in self.agents_raw}
        writes: dict[str, set[str]] = {a: set() for a in self.agents_raw}
        asks: dict[str, dict] = {a: {} for a in self.agents_raw}
        unknown: dict[str, bool] = {a: False for a in self.agents_raw}

        # user input: anyone who is not a collaborator takes user turns directly
        for aid, ag in self.agents_raw.items():
            if aid not in collab_ids:
                reads[aid].add(self.reg(f"input:{self.name_of[aid]}"))

        # supervisor <-> collaborator message channels
        for sup, cid, label in self.collab:
            if cid not in self.agents_raw:          # a collaborator not in agents/: a stub
                self.name_of.setdefault(cid, label)
                self.agents_raw[cid] = {"agentId": cid, "agentName": self.name_of[cid]}
                reads.setdefault(cid, set())
                writes.setdefault(cid, set())
                asks.setdefault(cid, {})
                unknown[cid] = True
                self.notes.append(f"{self.name_of[cid]}: a collaborator not in the export; "
                                  "its own rights are unknown")
            chan = self.reg(f"msg:{self.name_of[sup]}__{self.name_of[cid]}")
            for a in (sup, cid):
                reads[a].add(chan)
                writes[a].add(chan)

        # knowledge bases the agent may read
        for aid, kids in self.agent_kbs.items():
            if aid not in reads:
                continue
            for kid in kids:
                if kid in self.kbs:
                    reads[aid].add(self.reg(f"kb:{self.kbs[kid]['name']}"))

        # memory, guardrails, action groups
        for aid, ag in list(self.agents_raw.items()):
            name = self.name_of[aid]
            mem = ag.get("memoryConfiguration") or {}
            if mem.get("enabledMemoryTypes"):
                r = self.reg(f"mem:{name}")
                self.res[r].controls = sorted(set(self.res[r].controls) | {name})
                reads[aid].add(r)
                writes[aid].add(r)
                self.notes.append(f"{name}: has session memory ({', '.join(mem['enabledMemoryTypes'])}); "
                                  "it steers the agent and a corrupted agent can poison it")
            g = ag.get("guardrailConfiguration") or {}
            if g.get("guardrailIdentifier"):
                self.notes.append(f"{name}: guardrail {g['guardrailIdentifier']} is a model-based "
                                  "filter; it is noted but never relied on for a PASS")
            if ag.get("agentCollaboration") in ("SUPERVISOR", "SUPERVISOR_ROUTER"):
                self.notes.append(f"{name}: multi-agent supervisor ({ag['agentCollaboration']})")

            for grp in self.action_groups.get(aid, []):
                self._apply_action_group(aid, name, grp, reads, writes, asks, unknown)

        # undeclared / code-interpreter action groups: conservatively able to read
        # every store and knowledge base and to reach every sink and account.
        all_stores, all_sinks = self._all_stores(), self._all_sinks()
        for aid in list(self.agents_raw):
            if unknown[aid]:
                reads[aid] |= all_stores
                writes[aid] |= all_sinks

        # an agent that takes user input also answers that user, and the same untrusted
        # user reads the reply -- so the response is a sink: anything the agent can read
        # can leave through it. Without this, a bot that reads a secret store and serves
        # users would show a vacuous PASS for "secret never leaves".
        for aid in list(self.agents_raw):
            if any(_prefix(r) == "input" for r in reads[aid]):
                out = self.reg(f"reply:{self.name_of[aid]}")
                self.res[out].sink = True
                writes[aid].add(out)
                self.notes.append(f"{self.name_of[aid]}: answers the user; its reply is a sink the "
                                  "(untrusted) user reads, so secrets it can read can leave here")

        # build the agents
        agents = {}
        for aid in self.agents_raw:
            name = self.name_of[aid]
            rd, wr, ask = reads[aid], writes[aid], asks[aid]
            all_r = rd | {x for g in ask.values() for x in g["read"]}
            all_w = wr | {x for g in ask.values() for x in g["write"]}
            flows = [(literal(r), literal(w)) for r in sorted(all_r) for w in sorted(all_w) if r != w]
            agents[name] = Agent(
                name,
                read=[literal(r) for r in sorted(rd)],
                write=[literal(r) for r in sorted(wr)],
                injectable=True,
                flows=flows,
                ask={g: {"read": [literal(x) for x in sorted(v["read"])],
                         "write": [literal(x) for x in sorted(v["write"])]}
                     for g, v in ask.items()},
                unknown=unknown[aid],
            )

        policies = self._policies()
        return System(agents, self.res, policies)

    def _apply_action_group(self, aid: str, name: str, grp: dict,
                            reads, writes, asks, unknown) -> None:
        gname = grp.get("actionGroupName", "action_group")
        if grp.get("actionGroupState", "ENABLED") == "DISABLED":
            return
        sig = grp.get("parentActionGroupSignature") or grp.get("parentActionSignature")
        if sig in CODE_SIGNATURES:
            unknown[aid] = True
            self.notes.append(f"{name}: action group {gname} runs arbitrary code ({sig}); "
                              "assumed able to read any store and reach any sink")
            return
        if sig == USER_INPUT_SIGNATURE:
            reads[aid].add(self.reg(f"input:{name}"))
            self.notes.append(f"{name}: action group {gname} asks the user for input (untrusted)")
            return

        functions = (grp.get("functionSchema") or {}).get("functions")
        group_eff = self._effect(f"{name}/{gname}")
        if functions:
            for fn in functions:
                fname = fn.get("name", "fn")
                eff = self._effect(f"{name}/{gname}/{fname}") or group_eff
                if eff is None:                       # nothing declared: conservative
                    unknown[aid] = True
                    self.notes.append(f"{name}: action group {gname}.{fname} has no declared "
                                      "rights; assumed able to read any store and reach any sink")
                    continue
                r_names = {self.reg(x) for x in eff[0]}
                w_names = {self.reg(x) for x in eff[1]}
                if fn.get("requireConfirmation") == "ENABLED":
                    asks[aid][f"confirm:{gname}.{fname}"] = {"read": r_names, "write": w_names}
                    self.notes.append(f"{name}: {gname}.{fname} needs your confirmation "
                                      "(requireConfirmation ENABLED)")
                else:
                    reads[aid] |= r_names
                    writes[aid] |= w_names
        else:
            # apiSchema / RETURN_CONTROL with no function list: no per-op confirmation
            if group_eff is None:
                unknown[aid] = True
                self.notes.append(f"{name}: action group {gname} has no declared rights; "
                                  "assumed able to read any store and reach any sink")
                return
            reads[aid] |= {self.reg(x) for x in group_eff[0]}
            writes[aid] |= {self.reg(x) for x in group_eff[1]}
            if grp.get("apiSchema"):
                self.notes.append(f"{name}: action group {gname} uses an OpenAPI schema; its "
                                  "operations have no per-operation confirmation (granted directly)")

    def _policies(self) -> list[Policy]:
        policies = []
        for label in sorted({l for r in self.res.values() for l in r.labels}):
            policies.append(Policy(f"{label} never leaves the fleet", "no_flow", label=label))
        for r in sorted(self.res):
            if self.res[r].protected:
                who = r.split(":", 1)[1] if ":" in r else r
                policies.append(Policy(f"web content never acts through {who}",
                                       "integrity", resource=r))
        return policies


def load_bedrock(path: str) -> System:
    """Build a Sherlock System from a directory of exported Bedrock Agents JSON."""
    b = Bedrock(path)
    s = b.load()
    s.notes = b.notes          # type: ignore[attr-defined]
    s.files = b.files          # type: ignore[attr-defined]
    return s


if __name__ == "__main__":
    s = load_bedrock(sys.argv[1])
    print(json.dumps(
        {"agents": {a: {"read": x.read, "write": x.write, "injectable": x.injectable,
                        **({"ask": x.ask} if x.ask else {}),
                        **({"flows": [list(f) for f in x.flows]} if x.flows else {}),
                        **({"unknown": True} if x.unknown else {})}
                    for a, x in s.agents.items()},
         "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                             ("sink", x.sink), ("protected", x.protected),
                                             ("controls", x.controls)) if v}
                       for r, x in s.resources.items()},
         "policies": [{k: v for k, v in p.__dict__.items() if v is not None} for p in s.policies],
         "notes": getattr(s, "notes", [])}, indent=1))
