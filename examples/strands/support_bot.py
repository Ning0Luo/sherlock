"""A customer-support team in Strands Agents, written two ways, checked by Sherlock.

  researcher  searches the web to answer product questions
  account     looks up the customer's record (personal data)
  writer      drafts the reply
  emailer     sends it

`naive_swarm()` is the easy way: a Strands `Swarm` where every agent shares one
working memory and the email tool runs without asking. `hardened_graph()` is a
`Graph` that wires each agent to only the next, and marks the email tool as one
a person confirms.

    python3 examples/strands/support_bot.py     # needs: pip install strands-agents

This is an example we built, not a real app. The Strands objects are only
constructed, never run, so no model is called and no AWS credentials are needed;
but the SDK must be importable. Without it, this prints a skip.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from integrations.strands import check, export  # noqa: E402,F401

try:
    from strands import Agent, tool
    from strands.multiagent import GraphBuilder, Swarm
    HAVE_STRANDS = True
except Exception:
    HAVE_STRANDS = False


if HAVE_STRANDS:

    @tool
    def web_search(query: str) -> str:
        """Search the web."""
        return ""

    @tool
    def lookup_customer(customer_id: str) -> str:
        """Look up a customer's record in the CRM."""
        return ""

    @tool
    def send_email(to: str, body: str) -> str:
        """Send an email to the customer."""
        return ""

    def _agents():
        # model="…" is a Bedrock model id; the agent is never run, so it is not resolved.
        researcher = Agent(name="researcher", model="us.anthropic.claude-sonnet-4-20250514-v1:0",
                           tools=[web_search], system_prompt="Answer product questions.")
        account = Agent(name="account", model="us.anthropic.claude-sonnet-4-20250514-v1:0",
                        tools=[lookup_customer], system_prompt="Look up the customer record.")
        writer = Agent(name="writer", model="us.anthropic.claude-sonnet-4-20250514-v1:0",
                       tools=[], system_prompt="Draft the reply.")
        emailer = Agent(name="emailer", model="us.anthropic.claude-sonnet-4-20250514-v1:0",
                        tools=[send_email], system_prompt="Send the reply.")
        return researcher, account, writer, emailer

    def naive_swarm():
        """Every agent shares the swarm's working memory; email just sends."""
        researcher, account, writer, emailer = _agents()
        return Swarm([researcher, account, writer, emailer], entry_point=researcher)

    def hardened_graph():
        """Each agent feeds only the next; email waits for a person (approval_tools)."""
        researcher, account, writer, emailer = _agents()
        b = GraphBuilder()
        for a in (researcher, account, writer, emailer):
            b.add_node(a, a.name)
        b.add_edge("researcher", "writer")
        b.add_edge("account", "writer")
        b.add_edge("writer", "emailer")
        b.set_entry_point("researcher")
        b.set_entry_point("account")
        return b.build()


RULES = '''
policy "Customer data never leaves the app"
  never customer_pii -> internet

policy "Customer data never leaves, even if I approve one email"
  never customer_pii -> internet
  tolerate 0 agents, 1 approval

policy "Web content never steers the account agent"
  attacker controls web
  never hijack account
'''
COMMON = dict(tools={"lookup_customer": {"read": ["data:crm"]}},
              secrets={"data:crm": "customer_pii"})
HARDENED = dict(COMMON, approval_tools=["send_email"])

if __name__ == "__main__":
    if not HAVE_STRANDS:
        print("strands: skipped (pip install strands-agents)")
        sys.exit(0)
    print("== naive swarm ==")
    print(check(naive_swarm(), RULES, **COMMON))
    print("\n== hardened graph ==")
    print(check(hardened_graph(), RULES, **HARDENED))
