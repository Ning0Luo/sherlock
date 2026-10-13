"""Tests for the AWS Bedrock Agents reader: how agents, action groups (with and
without requireConfirmation), collaborators, knowledge bases and memory become
the Sherlock model; the example deployment; and SAT vs brute force on random
Bedrock-shaped exports. Runs with no boto3/AWS: everything is hand-made JSON."""
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")
sys.path.insert(0, "tests")
from bedrock import load_bedrock
from sat import frontier
from test_sat import brute

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


def write_export(base: Path, agents=(), action_groups=(), collaborators=None,
                 knowledge_bases=(), agent_kbs=None, rights=None):
    """Write a directory of Bedrock JSON exports from plain Python structures."""
    for sub in ("agents", "action-groups", "collaborators", "knowledge-bases",
                "agent-knowledge-bases"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    for ag in agents:
        (base / "agents" / f"{ag['agentName']}.json").write_text(json.dumps({"agent": ag}))
    for aid, groups in (action_groups or {}).items() if isinstance(action_groups, dict) else action_groups:
        (base / "action-groups" / f"{aid}.json").write_text(
            json.dumps({"agentId": aid, "actionGroups": groups}))
    if collaborators:
        for sup, collabs in collaborators.items():
            (base / "collaborators" / f"{sup}.json").write_text(
                json.dumps({"agentId": sup, "agentCollaborators": collabs}))
    for kb in knowledge_bases:
        (base / "knowledge-bases" / f"{kb['knowledgeBase']['knowledgeBaseId']}.json").write_text(json.dumps(kb))
    for aid, kids in (agent_kbs or {}).items():
        (base / "agent-knowledge-bases" / f"{aid}.json").write_text(json.dumps(
            {"agentId": aid, "agentKnowledgeBases": [{"knowledgeBaseId": k} for k in kids]}))
    if rights is not None:
        (base / "rights.json").write_text(json.dumps(rights))


def alias(agent_id: str) -> str:
    return f"arn:aws:bedrock:us-east-1:123456789012:agent-alias/{agent_id}/ALIASZZZZ1"


# --- a user-facing agent that reads a secret leaks it to the asker (reply is a sink) ---
# This is the composition a per-resource IAM review misses: no egress action group, yet
# the bot hands the secret back to the (untrusted) user who asked.
import tempfile as _tf
from collusion import Policy
from policy import Goal
_d = Path(_tf.mkdtemp())
write_export(_d,
    agents=[{"agentId": "helpdesk", "agentName": "helpdesk"}],
    action_groups={"helpdesk": [{"actionGroupName": "lookup", "actionGroupState": "ENABLED",
        "functionSchema": {"functions": [{"name": "get_customer", "requireConfirmation": "DISABLED"}]}}]},
    rights={"stores": {"store:customer_db": {"labels": ["customer_pii"]}},
            "actionGroups": {"helpdesk/lookup/get_customer": {"reads": ["store:customer_db"], "writes": []}}})
hs = load_bedrock(str(_d))
expect("reply:helpdesk" in hs.agents["helpdesk"].write, "a user-facing agent writes a reply sink")
expect(hs.resources["reply:helpdesk"].sink, "the reply channel is a sink")
_g = Goal("pii", [Policy("pii", "no_flow", label="customer_pii")])
expect([pt[:2] for pt in frontier(hs, _g, True)] == [(0, 0)],
       "a bot that reads PII and answers an untrusted user leaks it for free (no vacuous PASS)")

# --- knowledge bases: any data source makes a KB untrusted (not just WEB) ---------------
def _kb(kid, ds_type):
    return {"knowledgeBase": {"knowledgeBaseId": kid, "name": kid},
            "dataSources": [{"dataSourceConfiguration": {"type": ds_type}}]}
_d2 = Path(_tf.mkdtemp())
write_export(_d2, agents=[{"agentId": "a", "agentName": "a"}],
             knowledge_bases=[_kb("conf", "CONFLUENCE"), _kb("s3", "S3")],
             agent_kbs={"a": ["conf", "s3"]})
ks = load_bedrock(str(_d2))
expect(ks.resources["kb:conf"].untrusted, "a Confluence-backed KB is untrusted")
expect(ks.resources["kb:s3"].untrusted, "an S3-backed KB is untrusted (buckets can be written)")
# a data-source-less summary export: conservative untrusted, not silently trusted
_d3 = Path(_tf.mkdtemp())
write_export(_d3, agents=[{"agentId": "a", "agentName": "a"}],
             knowledge_bases=[{"knowledgeBase": {"knowledgeBaseId": "sumkb", "name": "sumkb"},
                               "dataSourceSummaries": [{"name": "ds1"}]}],
             agent_kbs={"a": ["sumkb"]})
expect(load_bedrock(str(_d3)).resources["kb:sumkb"].untrusted,
       "a KB known only by summaries (no type) is treated as untrusted, not trusted")


# --- the example deployment --------------------------------------------------
s = load_bedrock("examples/bedrock")
expect(set(s.agents) == {"supervisor", "researcher", "assistant"}, "the three agents are read")
expect(s.resources["kb:support_wiki"].untrusted, "a WEB (web-crawler) knowledge base is untrusted")
expect("customer_pii" in s.resources["store:customer_db"].labels, "a secret store carries its label")
expect("store:customer_db" in s.agents["researcher"].read, "the action group without confirmation reads directly")
expect("sink:ses" in s.agents["assistant"].write, "SES is an outbound sink the assistant can reach directly")
expect("confirm:account_actions.issue_refund" in s.agents["assistant"].ask,
       "a requireConfirmation=ENABLED function becomes an ask gate")
expect("acct:api.payments.example.com" in s.agents["assistant"].ask["confirm:account_actions.issue_refund"]["write"],
       "the gated function's rights act through the payments account")
expect("acct:api.payments.example.com" not in s.agents["assistant"].write,
       "the payments account is NOT reachable without the confirmation")
expect(s.resources["acct:api.payments.example.com"].protected, "an outbound account is integrity-critical")
expect(s.resources["mem:supervisor"].controls == ["supervisor"], "session memory is controlled by its agent")
expect("input:supervisor" in s.agents["supervisor"].read and s.resources["input:supervisor"].untrusted,
       "the supervisor takes untrusted user input")
expect(all("input:" + a not in s.agents[a].read for a in ("researcher", "assistant")),
       "collaborators do not take user input directly (only via the supervisor)")
expect("msg:supervisor__researcher" in s.agents["supervisor"].write
       and "msg:supervisor__researcher" in s.agents["researcher"].read,
       "supervisor and collaborator share a message channel (resolved via the alias ARN)")
expect(not any(s.agents[a].strips for a in s.agents), "a guardrail is never modeled as strips")
expect(any("guardrail" in n for n in s.notes), "the guardrail is recorded as a note")
expect({p.kind for p in s.policies} == {"no_flow", "integrity"}, "per-label and per-account policies are built")

# --- policy outcomes on the example (the path the --bedrock CLI will take) ---
from policy import compile_file, parse  # noqa: E402
pf = parse(Path("examples/bedrock/fleet.policy").read_text())
pm = lambda p: p if p in s.resources else None
got = {}
for c in compile_file(s, pf, pm):
    pts = frontier(s, c.goal, True)
    got[c.title] = pts[0][:2] if pts else None
expect(got.get("Customer PII never leaves the deployment") == (0, 0),
       "customer PII leaks with no compromise, through the honest email path")
expect(got.get("Web content never acts through the payments account") == (0, 1),
       "web content reaches the payments account only with one confirmation")
expect(got.get("The supervisor's session memory is never attacker-controlled") == (0, 0),
       "untrusted user input poisons the supervisor's session memory")

# --- requireConfirmation split: one gated function, one direct ---------------
d = Path(tempfile.mkdtemp())
write_export(d,
    agents=[{"agentId": "AAAAAAAAAA", "agentName": "solo", "agentCollaboration": "DISABLED"}],
    action_groups={"AAAAAAAAAA": [{
        "actionGroupName": "ops", "actionGroupState": "ENABLED",
        "actionGroupExecutor": {"lambda": "arn:aws:lambda:us-east-1:1:function:ops"},
        "functionSchema": {"functions": [
            {"name": "read_notes", "requireConfirmation": "DISABLED"},
            {"name": "wire_money", "requireConfirmation": "ENABLED"}]}}]},
    rights={"stores": {"store:notes": {"labels": ["secret"]}},
            "actionGroups": {"solo/ops/read_notes": {"reads": ["store:notes"], "writes": []},
                             "solo/ops/wire_money": {"reads": [], "writes": ["acct:bank"]}}})
s2 = load_bedrock(str(d))
expect("store:notes" in s2.agents["solo"].read, "the DISABLED function's read is direct")
expect("acct:bank" not in s2.agents["solo"].write, "the ENABLED function's write is not direct")
expect("confirm:ops.wire_money" in s2.agents["solo"].ask, "the ENABLED function is an ask gate")
expect("input:solo" in s2.agents["solo"].read, "a standalone (non-collaborator) agent takes user input")

# --- an undeclared action group is conservatively unrestricted ----------------
d = Path(tempfile.mkdtemp())
write_export(d,
    agents=[{"agentId": "BBBBBBBBBB", "agentName": "mystery", "agentCollaboration": "DISABLED"}],
    action_groups={"BBBBBBBBBB": [{
        "actionGroupName": "blackbox", "actionGroupState": "ENABLED",
        "actionGroupExecutor": {"lambda": "arn:aws:lambda:us-east-1:1:function:bb"},
        "functionSchema": {"functions": [{"name": "do_thing", "requireConfirmation": "DISABLED"}]}}]},
    rights={"stores": {"store:a": {"labels": ["x"]}, "sink:out": {}, "acct:p": {}}})
s3 = load_bedrock(str(d))
expect(s3.agents["mystery"].unknown, "an action group with no declared rights is flagged unknown")
expect("store:a" in s3.agents["mystery"].read, "an undeclared Lambda is assumed able to read any store")
expect("sink:out" in s3.agents["mystery"].write and "acct:p" in s3.agents["mystery"].write,
       "an undeclared Lambda is assumed able to reach any sink and account")

# --- built-in action-group signatures ----------------------------------------
d = Path(tempfile.mkdtemp())
write_export(d,
    agents=[{"agentId": "CCCCCCCCCC", "agentName": "coder", "agentCollaboration": "DISABLED"}],
    action_groups={"CCCCCCCCCC": [
        {"actionGroupName": "ci", "actionGroupState": "ENABLED",
         "parentActionGroupSignature": "AMAZON.CodeInterpreter"},
        {"actionGroupName": "ask", "actionGroupState": "ENABLED",
         "parentActionGroupSignature": "AMAZON.UserInput"}]},
    rights={"stores": {"store:z": {"labels": ["y"]}, "sink:q": {}}})
s4 = load_bedrock(str(d))
expect(s4.agents["coder"].unknown, "a code-interpreter action group is unrestricted (unknown)")
expect("store:z" in s4.agents["coder"].read and "sink:q" in s4.agents["coder"].write,
       "code interpreter reaches every store and sink")
expect("input:coder" in s4.agents["coder"].read, "AMAZON.UserInput adds an untrusted user-input channel")

# --- a collaborator missing from the export becomes an unknown stub -----------
d = Path(tempfile.mkdtemp())
write_export(d,
    agents=[{"agentId": "DDDDDDDDDD", "agentName": "boss", "agentCollaboration": "SUPERVISOR"}],
    collaborators={"DDDDDDDDDD": [
        {"collaboratorId": "CLBX000001", "collaboratorName": "ghost",
         "agentDescriptor": {"aliasArn": alias("EEEEEEEEEE")}}]})
s5 = load_bedrock(str(d))
expect("ghost" in s5.agents and s5.agents["ghost"].unknown,
       "a collaborator not in the export is added as an unknown stub")

# --- SAT vs brute force on random Bedrock-shaped exports ----------------------
rng = random.Random(11)
STORES = ["store:db1", "store:db2"]
SINKS = ["sink:ses"]
ACCTS = ["acct:pay"]
cases = mism = 0
base = Path(tempfile.mkdtemp())
for trial in range(40):
    d = base / f"t{trial}"
    ids = [f"{chr(65 + i)}" * 10 for i in range(rng.randint(1, 3))]  # AAAAAAAAAA, ...
    names = {ids[0]: "sup", **{ids[i]: f"c{i}" for i in range(1, len(ids))}}
    agents = [{"agentId": ids[0], "agentName": "sup",
               "agentCollaboration": "SUPERVISOR",
               **({"memoryConfiguration": {"enabledMemoryTypes": ["SESSION_SUMMARY"]}}
                  if rng.random() < .4 else {})}]
    for i in range(1, len(ids)):
        agents.append({"agentId": ids[i], "agentName": names[ids[i]], "agentCollaboration": "DISABLED"})
    collaborators = {ids[0]: [{"collaboratorId": f"CLB000000{i}", "collaboratorName": names[ids[i]],
                               "agentDescriptor": {"aliasArn": alias(ids[i])}}
                              for i in range(1, len(ids))]} if len(ids) > 1 else None
    rights_ag, groups = {}, {}
    for aid in ids:
        ags = []
        for gi in range(rng.randint(0, 2)):
            gname = f"g{gi}"
            funcs = []
            for fi in range(rng.randint(1, 2)):
                fname = f"f{fi}"
                reads = rng.sample(STORES, rng.randint(0, 2))
                if rng.random() < .3:
                    reads.append("kb:wiki")
                writes = rng.sample(SINKS + ACCTS, rng.randint(0, 1))
                conf = "ENABLED" if rng.random() < .4 else "DISABLED"
                funcs.append({"name": fname, "requireConfirmation": conf})
                rights_ag[f"{names[aid]}/{gname}/{fname}"] = {"reads": reads, "writes": writes}
            ags.append({"actionGroupName": gname, "actionGroupState": "ENABLED",
                        "actionGroupExecutor": {"lambda": "arn:aws:lambda:us-east-1:1:function:x"},
                        "functionSchema": {"functions": funcs}})
        if ags:
            groups[aid] = ags
    kbs, akbs = [], {}
    if rng.random() < .5 and len(ids) > 1:
        kbs = [{"knowledgeBase": {"knowledgeBaseId": "KB00000001", "name": "wiki"},
                "dataSources": [{"dataSourceId": "DS1", "dataSourceConfiguration": {"type": "WEB"}}]}]
        akbs = {ids[1]: ["KB00000001"]}
    rights = {"stores": {"store:db1": {"labels": ["secret"]},
                         "store:db2": {"labels": ["pii"]} if rng.random() < .5 else {}},
              "actionGroups": rights_ag}
    write_export(d, agents=agents, action_groups=groups, collaborators=collaborators,
                 knowledge_bases=kbs, agent_kbs=akbs, rights=rights)
    sys_ = load_bedrock(str(d))
    from collusion import gates  # noqa: E402
    if len(gates(sys_)) > 6:
        continue
    for p in sys_.policies:
        cases += 1
        if [pt[:2] for pt in frontier(sys_, p, True)] != brute(sys_, p, True):
            mism += 1
            print("MISMATCH", trial, p.name)

print(f"bedrock: {cases} random cases, {mism} mismatches; {fails} unit failures")
sys.exit(1 if fails or mism else 0)
