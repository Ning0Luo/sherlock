"""scaffold: a `check --json` report -> a validate scenarios module. We build a
fake findings list (in the shape `check --json` writes), scaffold it, exec the
generated module, and check that each Scenario carries the finding's roles and
that an un-wired stub reports ERROR (so `agentcheck validate` flags work left to
do rather than a false result)."""
import sys

sys.path.insert(0, ".")
from validate import ERROR, Scenario, run, shape
from validate.scaffold import _slug, scaffold

fails = 0


def expect(cond, what):
    global fails
    if not cond:
        fails += 1
        print("FAIL:", what)


# a `check --json` report: two FAIL rows (one pure-injection, one with a broken
# agent) and one PASS that must NOT become a stub.
findings = [
    {"policy": "PII stays internal", "pass": False,
     "attack": {"path": ["resource inbox: untrusted source",
                         "label customer_pii originates in crm",
                         "agent analyst: initial coalition",
                         "crm -> draft",
                         "draft -> mail"]}},
    {"policy": "Creds never leave", "pass": False,
     "attack": {"path": ["resource web: untrusted source",
                         "label ssh originates in keystore",
                         "keystore -> net"]}},
    {"policy": "Something safe", "pass": True, "cheapest_attacks": []},
]

# --- the finding parser pulls the roles out of the path --------------------
sh0 = shape(findings[0])
expect(sh0.label == "customer_pii" and sh0.source == "crm", "shape: label/source")
expect(sh0.sink == "mail", "shape: sink is the last outward hop")
expect(sh0.untrusted == ["inbox"], "shape: untrusted input")
expect(sh0.broken == ["analyst"] and not sh0.pure_injection, "shape: broken coalition")
expect(shape(findings[1]).pure_injection, "shape: finding 2 is a pure injection")

# --- scaffold -> a module that imports and builds scenarios ----------------
src = scaffold(findings, thisfile="scn.py")
expect(src.count("def scenario_") == 2, "one stub per FAIL (the PASS is skipped)")

ns: dict = {}
exec(compile(src, "<scaffold>", "exec"), ns)          # runs `from validate import ...`
expect(callable(ns.get("scenarios")), "generated module defines scenarios()")
scns = ns["scenarios"]()
expect(set(scns) == {"pii_stays_internal", "creds_never_leave"}, f"slugs: {sorted(scns)}")
expect(all(isinstance(v, Scenario) for v in scns.values()), "values are Scenarios")

a = scns["pii_stays_internal"]
expect("customer_pii" in a.canaries, "canary at the leaking label")
expect("mail" in a.sinks, "sink at the outward hop")
expect("inbox" in a.untrusted, "marker at the untrusted input")
expect(a.expect == ("customer_pii", "mail"), f"expect predicts the path, got {a.expect}")

b = scns["creds_never_leave"]
expect(b.expect == ("ssh", "net"), f"expect for finding 2, got {b.expect}")

# --- an un-wired stub runs to ERROR (not a false pass/fail) ----------------
o = run(a, guard=False)
expect(o.status == ERROR, f"un-wired run_app -> ERROR, got {o.status}")

# --- slugs stay unique even when policy names collide ----------------------
used: set = set()
expect(_slug("Same name", used) == "same_name", "first slug")
expect(_slug("Same name", used) == "same_name_2", "colliding slug is suffixed")
expect(_slug("", used) == "finding", "empty name falls back")

print("scaffold: parser, stub generation, exec, ERROR-on-unwired, slug uniqueness"
      if not fails else f"{fails} failures")
sys.exit(1 if fails else 0)
