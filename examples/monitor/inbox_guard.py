#!/usr/bin/env python3
"""A runtime monitor guarding the inbox support bot, step by step.

Each agent is within Meta's Rule of Two, but chained they leak customer data.
The Monitor watches the real events and blocks the step that would let the
secret leave -- the enforcement a per-agent review cannot do. Run:

    python3 examples/monitor/inbox_guard.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from collusion import Agent, Policy, Resource, System   # noqa: E402
from monitor import Monitor                              # noqa: E402

res = {"inbox": Resource("inbox", untrusted=True), "notes": Resource("notes"),
       "crm": Resource("crm", labels={"customer_pii"}), "draft": Resource("draft"),
       "mail": Resource("mail", sink=True)}
fleet = System({
    "triage":  Agent("triage",  read=["inbox"], write=["notes"]),
    "analyst": Agent("analyst", read=["notes", "crm"], write=["draft"]),
    "sender":  Agent("sender",  read=["draft"], write=["mail"]),
}, res, [Policy("Customer PII never leaves", "no_flow", label="customer_pii")])

# budget (0,0,0): block any action that lets a violation happen with no further
# attacker effort -- the tightest preventive gate.
mon = Monitor(fleet, budget=(0, 0, 0))

# the stream of observed actions, in order. A real hook feeds these from the
# tool calls it sees; `injected=True` where you observe (or assume) a steering.
events = [
    ("triage",  ["inbox"],         ["notes"]),   # reads the (poisoned) email, writes notes
    ("analyst", ["notes", "crm"],  ["draft"]),   # pulls the customer record into the draft
    ("sender",  ["draft"],         ["mail"]),     # would email the draft out
]

print(f"Monitoring the support fleet (budget {mon.t},{mon.h},{mon.m}); each step is gated before it runs.\n")
for agent, reads, writes in events:
    v = mon.probe(agent, reads=reads, writes=writes)
    act = f"{agent}: read {reads} -> write {writes}"
    if v:
        print(f"  BLOCK  {act}")
        print(f"         why: {v.why}")
        for line in v.hits[0][1].witness or []:
            print("           " + line.strip())
        print("\n  The monitor stopped the leak at the last hop. (A real hook would deny this tool call.)")
        break
    mon.apply(agent, reads=reads, writes=writes)
    print(f"  allow  {act}")
