"""Tests for the NVIDIA OpenShell importer: the YAML reader, how endpoints and
paths become rights, the example fleet, and SAT vs brute force on random fleets."""
import json, random, sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
sys.path.insert(0, "tests")
from openshell import MiniYaml, YamlError, endpoint_writes, load_fleet
from sat import frontier
from test_sat import brute

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


# --- YAML reader -------------------------------------------------------------
doc = MiniYaml('''
version: 1
filesystem_policy:
  read_only: [/usr, "/etc"]   # comment
  read_write:
    - /tmp
network_policies:
  gh:
    endpoints:
      - host: api.github.com
        port: 443
        rules:
          - allow:
              method: GET
              path: "/repos/**"
        credential_binding: {provider: work-github}
    binaries:
      - path: /usr/bin/gh
''').parse()
expect(doc["filesystem_policy"] == {"read_only": ["/usr", "/etc"], "read_write": ["/tmp"]}, "fs block")
ep = doc["network_policies"]["gh"]["endpoints"][0]
expect(ep["port"] == 443 and ep["rules"][0]["allow"]["path"] == "/repos/**", "nested list of maps")
expect(ep["credential_binding"] == {"provider": "work-github"}, "flow map")
expect(doc["network_policies"]["gh"]["binaries"] == [{"path": "/usr/bin/gh"}], "list after nested map")
try:
    MiniYaml("a: |\n  text\n").parse()
    expect(False, "block scalar should be refused")
except YamlError:
    pass

# --- endpoint rights ---------------------------------------------------------
E = lambda **k: {"host": "h", "port": 443, **k}
expect(endpoint_writes(E()), "uninspected endpoint can write")
expect(endpoint_writes(E(protocol="tcp")), "raw TCP can write")
expect(endpoint_writes(E(protocol="rest", access="read-only")), "audit mode does not block")
expect(not endpoint_writes(E(protocol="rest", enforcement="enforce", access="read-only")), "enforced read-only")
expect(endpoint_writes(E(protocol="rest", enforcement="enforce", access="read-write")), "read-write")
expect(not endpoint_writes(E(protocol="rest", enforcement="enforce", rules=[{"allow": {"method": "GET", "path": "/**"}}])), "GET rule")
expect(endpoint_writes(E(protocol="rest", enforcement="enforce", rules=[{"allow": {"method": "POST", "path": "/x"}}])), "POST rule")
expect(endpoint_writes(E(protocol="mcp", enforcement="enforce", rules=[{"allow": {"method": "tools/call", "tool": "x"}}])), "MCP tool call")
expect(not endpoint_writes(E(protocol="graphql", enforcement="enforce", rules=[{"allow": {"operation_type": "query"}}])), "GraphQL query")

# --- the example fleet -------------------------------------------------------
s = load_fleet("examples/openshell/fleet.yaml")
expect("fs:coder:/home/sandbox/.ssh" in s.agents["coder"].read, "secret under a read-write path is readable")
expect("fs:coder:/home/sandbox/.ssh" not in s.agents["researcher"].read, "other sandboxes do not see it")
expect("share:workspace" in s.agents["researcher"].write and "share:workspace" in s.agents["deployer"].read, "shared volume")
expect("acct:api.github.com" in s.agents["coder"].write, "credentialed read-write endpoint acts as you")
expect(not s.agents["deployer"].injectable and s.agents["deployer"].flows, "the CI job relays but is not an AI")
expect("proposal:coder-wants-pypi" in s.agents["coder"].ask, "a pending proposal is an approval gate")
expect(not s.resources["svc:api.internal.example.com"].untrusted, "internal host is not attacker-written")
from policy import compile_file, parse  # noqa: E402
pf = parse(Path("examples/openshell/fleet.policy").read_text())
from agentcheck import load_system  # noqa: E402
got = {}
for c in compile_file(s, pf, lambda p: p if p in s.resources else None):
    pts = frontier(s, c.goal, True)
    got[c.title] = pts[0][:2] if pts else None
expect(got.get("Web content never ships to production") == (0, 0), "prod is reachable through the CI job")
expect(got.get("The deploy job is never steered") == (1, 0), "the CI job itself cannot be steered")

# --- SAT vs brute force on random fleets ------------------------------------
rng = random.Random(5)
hosts = ["api.github.com", "*.wikipedia.org", "api.internal.example.com", "pypi.org"]
paths = ["/workspace", "/workspace/build", "/home/sandbox", "/tmp"]
cases = mism = 0
d = Path(tempfile.mkdtemp())
for trial in range(25):
    sbs = {}
    for sb in "abc":
        eps = [{"host": h, "port": 443, "protocol": "rest", "enforcement": rng.choice(["enforce", "audit"]),
                "access": rng.choice(["read-only", "read-write"]),
                **({"credential_binding": {"provider": "p"}} if h == "api.github.com" and rng.random() < .5 else {})}
               for h in rng.sample(hosts, rng.randint(0, 2))]
        pol = {"version": 1, "filesystem_policy": {"read_only": rng.sample(paths, 1), "read_write": rng.sample(paths, rng.randint(0, 2))}}
        if eps:
            pol["network_policies"] = {"r": {"endpoints": eps, "binaries": [{"path": "/usr/bin/curl"}]}}
        (d / f"{sb}.json").write_text(json.dumps(pol))
        sbs[sb] = {"policy": f"{sb}.json", "ai": rng.random() < .8}
        if rng.random() < .3:
            (d / f"{sb}-p.json").write_text(json.dumps({"version": 1, "network_policies": {"p": {"endpoints": [{"host": rng.choice(hosts), "port": 443}]}}}))
            sbs[sb]["proposals"] = [f"{sb}-p.json"]
    (d / "fleet.json").write_text(json.dumps({"sandboxes": sbs, "internal_hosts": ["api.internal.example.com"],
        "shared": [{"name": "ws", "mounts": {x: "/workspace" for x in rng.sample("abc", 2)}}],
        "secrets": [{"sandbox": "a", "path": "/home/sandbox/.ssh", "label": "ssh_key"}]}))
    fs = load_fleet(str(d / "fleet.json"))
    for p in fs.policies:
        cases += 1
        if [pt[:2] for pt in frontier(fs, p, True)] != brute(fs, p, True):
            mism += 1
print(f"openshell: {cases} random cases, {mism} mismatches; {fails} unit failures")
sys.exit(1 if fails or mism else 0)
