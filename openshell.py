#!/usr/bin/env python3
"""Import NVIDIA OpenShell sandbox policies into Sherlock.

OpenShell (https://github.com/NVIDIA/OpenShell) gives each agent sandbox a
YAML policy: the paths it can read or write, and the network endpoints each
binary can reach, optionally down to HTTP methods and MCP tools. Its prover
checks one policy at a time against a boundary. This module turns a *fleet*
of sandboxes into one Sherlock system, so the solver can find attacks that
pass through several sandboxes, each of which is within its own boundary.

A fleet file (YAML or JSON) names the sandboxes and says what their policies
cannot: which storage they share, where secrets live, which hosts are
internal, and which policy-advisor proposals are pending.

    sandboxes:
      researcher: {policy: researcher.yaml}             # an AI agent (default)
      deployer:   {policy: deployer.yaml, ai: false,     # a fixed pipeline
                   relays: [[/workspace, api.internal.example.com]]}
      coder:
        policy: coder.yaml
        workdir: /sandbox                                # used by include_workdir
        proposals: [coder-wants-npm.yaml]                # each is one approval
    shared:                                              # same storage, several sandboxes
      - {name: workspace, mounts: {researcher: /workspace, coder: /workspace}}
    secrets:
      - {sandbox: coder, path: /home/sandbox/.ssh, label: ssh_key}
    internal_hosts: [api.internal.example.com]

Model
-----
- Each sandbox is one agent. Its binaries are not separated: an agent that
  can run one allowed binary is assumed to be able to run the others.
- A path a sandbox can read or write reaches every resource whose path is
  inside it or contains it (conservative), in that sandbox's own filesystem,
  or in shared storage mounted there.
- Each network host is a resource. An external host is attacker-writable
  (anyone can put text on a public site, issue tracker or package) and a sink
  (any request, even a GET, can carry data out in its URL). A sandbox that can
  reach a host reads it and writes to it. An internal host is neither; a
  sandbox writes to it only through write-capable access (any method other
  than GET/HEAD/OPTIONS, a GraphQL mutation, an MCP tools/call, a raw TCP or
  uninspected endpoint, or an endpoint in audit mode, which does not block).
- An endpoint that carries provider credentials adds an account resource
  (acct:HOST). Write-capable access to it acts as you at that service.
- Provider credentials themselves are injected by the proxy and never enter
  the sandbox, so they are not secrets the agent can read.
"""
from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path

from collusion import Agent, Policy, Resource, System, literal

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "*", "WEBSOCKET_TEXT"}


from miniyaml import MiniYaml, YamlError, _flow, _flow_token, _scalar, _strip_comment  # noqa: F401,E402


def load_yaml(path: Path):
    text = Path(path).read_text()
    if path.suffix == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        return MiniYaml(text).parse()


# ------------------------------------------------------------- the importer

def _under(a: str, b: str) -> bool:
    a, b = a.rstrip("/") or "/", b.rstrip("/") or "/"
    return a == b or b == "/" or a.startswith(b + "/")


def _related(a: str, b: str) -> bool:
    return _under(a, b) or _under(b, a)


def _host_overlap(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    return a == b or fnmatch.fnmatchcase(a, b.replace("**", "*")) or fnmatch.fnmatchcase(b, a.replace("**", "*"))


def endpoint_writes(ep: dict) -> bool:
    """Can requests to this endpoint change state at the other end?"""
    proto = ep.get("protocol")
    if proto in (None, "tcp") or ep.get("tls") == "skip":
        return True
    if ep.get("enforcement", "audit") != "enforce":
        return True
    access = ep.get("access")
    if access in ("full", "read-write"):
        return True
    if access == "read-only":
        return False
    for r in ep.get("rules") or []:
        allow = r.get("allow", r) if isinstance(r, dict) else {}
        if str(allow.get("method", "")).upper() in WRITE_METHODS:
            return True
        if allow.get("operation_type") in ("mutation", "subscription"):
            return True
        if str(allow.get("method", "")).startswith("tools/call") or allow.get("tool"):
            return True
    mcp = ep.get("mcp") or {}
    return bool(mcp.get("allow_all_known_mcp_methods"))


class Fleet:
    def __init__(self, path: str):
        self.path = Path(path)
        self.base = self.path.parent
        self.spec = load_yaml(self.path) or {}
        self.notes: list[str] = []
        self.files: list[Path] = [self.path]            # every file the fleet is read from
        self.res: dict[str, Resource] = {}
        self.paths: dict[str, dict[str, str]] = {}      # sandbox -> path -> resource
        self.shares: list[tuple[str, str, str]] = []    # (resource, sandbox, mount)
        self.hosts: dict[str, str] = {}                 # host pattern -> resource
        internal = [h.lower() for h in self.spec.get("internal_hosts") or []]
        self.internal = lambda h: any(_host_overlap(h, x) for x in internal)

    # resources --------------------------------------------------------
    def fs_resource(self, sb: str, p: str, labels=()) -> str:
        for name, s2, mount in self.shares:
            if s2 == sb and _under(p, mount):
                if labels:
                    self.res[name].labels |= set(labels)
                return name
        r = self.paths.setdefault(sb, {}).get(p)
        if r is None:
            r = f"fs:{sb}:{p}"
            self.paths[sb][p] = r
            self.res[r] = Resource(r)
        self.res[r].labels |= set(labels)
        return r

    def fs_reach(self, sb: str, p: str) -> set[str]:
        out = {r for q, r in self.paths.get(sb, {}).items() if _related(p, q)}
        out |= {name for name, s2, mount in self.shares if s2 == sb and _related(p, mount)}
        return out

    def host_resource(self, host: str) -> str:
        h = host.lower()
        if h not in self.hosts:
            if self.internal(h):
                r = f"svc:{h}"
                self.res[r] = Resource(r)
            else:
                r = f"net:{h}"
                self.res[r] = Resource(r, untrusted=True, sink=True)
            self.hosts[h] = r
        return self.hosts[h]

    def host_reach(self, host: str) -> set[str]:
        return {r for h, r in self.hosts.items() if _host_overlap(host, h)}

    # sandboxes --------------------------------------------------------
    def policy_paths(self, sb: str, pol: dict, workdir: str) -> tuple[list[str], list[str]]:
        fsp = pol.get("filesystem_policy")
        ro = list((fsp or {}).get("read_only") or [])
        rw = list((fsp or {}).get("read_write") or [])
        if (fsp is None) or fsp.get("include_workdir"):
            rw.append(workdir)
        if (pol.get("landlock") or {}).get("compatibility", "best_effort") == "best_effort":
            self.notes.append(f"{sb}: landlock is best_effort, so if the kernel cannot enforce it the "
                              f"sandbox runs without its filesystem rules (not modeled)")
        return ro, rw

    def endpoints(self, pol: dict):
        for rname, rule in (pol.get("network_policies") or {}).items():
            for ep in (rule or {}).get("endpoints") or []:
                hosts = [ep["host"]] if ep.get("host") else [f"ip:{x}" for x in ep.get("allowed_ips") or []]
                for h in hosts:
                    yield rname, h, ep

    def load(self) -> System:
        sandboxes = self.spec.get("sandboxes") or {}
        if not sandboxes:
            raise ValueError("the fleet file lists no sandboxes")
        pols, props = {}, {}
        for sb, cfg in sandboxes.items():
            cfg = cfg or {}
            if "policy" not in cfg:
                raise ValueError(f"sandbox {sb} has no policy file")
            self.files.append(self.base / cfg["policy"])
            pols[sb] = load_yaml(self.base / cfg["policy"]) or {}
            if pols[sb].get("version") not in (1, None):
                raise ValueError(f"{sb}: OpenShell policy version {pols[sb].get('version')} is not supported")
            self.files += [self.base / f for f in cfg.get("proposals") or []]
            props[sb] = {Path(f).stem: load_yaml(self.base / f) or {} for f in cfg.get("proposals") or []}
        for sh in self.spec.get("shared") or []:
            name = f"share:{sh['name']}"
            self.res[name] = Resource(name)
            for sb, mount in (sh.get("mounts") or {}).items():
                self.shares.append((name, sb, mount))
        for sec in self.spec.get("secrets") or []:
            self.fs_resource(sec["sandbox"], sec["path"], [sec["label"]])
        # register every path and host first, so reach() sees them all
        for sb, pol in pols.items():
            ro, rw = self.policy_paths(sb, pol, (sandboxes[sb] or {}).get("workdir", "/sandbox"))
            for p in ro + rw:
                self.fs_resource(sb, p)
            for p in [pol] + list(props[sb].values()):
                for _, h, ep in self.endpoints(p):
                    self.host_resource(h)
                    if (ep.get("credential_binding") or {}).get("provider") or ep.get("credential_signing") \
                            or ep.get("request_body_credential_rewrite") or ep.get("websocket_credential_rewrite"):
                        a = f"acct:{h.lower()}"
                        self.res.setdefault(a, Resource(a, protected=True))

        lit = lambda names: [literal(r) for r in sorted(names)]   # names such as net:*.example.com
        agents = {}
        for sb, pol in pols.items():
            cfg = sandboxes[sb] or {}
            ro, rw = self.policy_paths(sb, pol, cfg.get("workdir", "/sandbox"))
            read = set().union(*[self.fs_reach(sb, p) for p in ro + rw]) if ro + rw else set()
            write = set().union(*[self.fs_reach(sb, p) for p in rw]) if rw else set()
            nr, nw = self.net_rights(pol)
            ask = {}
            for gname, prop in props[sb].items():
                pr, pw = self.net_rights(prop)
                ask[f"proposal:{gname}"] = {"read": lit(pr - read - nr), "write": lit(pw - write - nw)}
            flows = []
            for src, dst in cfg.get("relays") or []:
                for s in self.place(sb, src):
                    for d in self.place(sb, dst):
                        flows.append((literal(s), literal(d)))
            agents[sb] = Agent(sb, read=lit(read | nr), write=lit(write | nw),
                               injectable=cfg.get("ai", True) is not False, flows=flows, ask=ask)
        policies = []
        for label in sorted({l for r in self.res.values() for l in r.labels}):
            policies.append(Policy(f"{label} never leaves the fleet", "no_flow", label=label))
        for r in sorted(self.res):
            if r.startswith("acct:"):
                policies.append(Policy(f"web content never acts through your {r[5:]} account", "integrity", resource=r))
            if r.startswith("svc:"):
                policies.append(Policy(f"web content never changes {r[4:]}", "integrity", resource=r))
        return System(agents, self.res, policies)

    def place(self, sb: str, x: str) -> list[str]:
        if x.startswith("/"):
            return sorted(self.fs_reach(sb, x)) or [self.fs_resource(sb, x)]
        return sorted(self.host_reach(x))

    def net_rights(self, pol: dict) -> tuple[set[str], set[str]]:
        read, write = set(), set()
        for _, h, ep in self.endpoints(pol):
            reach = self.host_reach(h)
            read |= reach
            for r in reach:
                if self.res[r].sink or endpoint_writes(ep):
                    write.add(r)
            acct = f"acct:{h.lower()}"
            if acct in self.res and endpoint_writes(ep):
                write.add(acct)
        return read, write


def load_fleet(path: str) -> System:
    f = Fleet(path)
    s = f.load()
    s.notes = f.notes  # type: ignore[attr-defined]
    s.files = f.files  # type: ignore[attr-defined]
    return s


if __name__ == "__main__":
    s = load_fleet(sys.argv[1])
    print(json.dumps({"agents": {a: {"read": x.read, "write": x.write, "injectable": x.injectable,
                                     **({"ask": x.ask} if x.ask else {}),
                                     **({"flows": [list(f) for f in x.flows]} if x.flows else {})}
                                 for a, x in s.agents.items()},
                      "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)), ("untrusted", x.untrusted),
                                                          ("sink", x.sink), ("protected", x.protected),
                                                          ("controls", x.controls)) if v}
                                    for r, x in s.resources.items()},
                      "policies": [{k: v for k, v in p.__dict__.items() if v is not None} for p in s.policies],
                      "notes": s.notes}, indent=1))
