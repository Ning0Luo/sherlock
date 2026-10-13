"""A customer-support app in LangGraph, written two ways, checked by Sherlock.

  researcher  searches the web to answer product questions
  account     looks up the customer's record (personal data)
  writer      drafts the reply
  email       sends it

`naive_app()` is how most LangGraph apps are written: every agent shares the
`messages` list and its tools run without asking. `hardened_app()` gives each
agent only the state it needs and asks before sending email.

    python3 examples/langgraph/support_bot.py     # needs: pip install langgraph
"""
import sys
from pathlib import Path
from typing import TypedDict

from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from integrations.langgraph import check, export  # noqa: E402


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


def react_agent(tools):
    """A ReAct-style agent: a model node that calls its tools until done."""
    g = StateGraph(MessagesState)
    g.add_node("model", lambda s: {})
    g.add_node("tools", ToolNode(tools))
    g.add_edge(START, "model")
    g.add_conditional_edges("model", lambda s: END, ["tools", END])
    g.add_edge("tools", "model")
    return g.compile()


class Support(MessagesState):
    question: str
    customer_id: str
    research: str
    account_summary: str
    reply: str


def naive_app():
    g = StateGraph(Support)
    g.add_node("router", lambda s: {})
    g.add_node("researcher", react_agent([web_search]))
    g.add_node("account", react_agent([lookup_customer]))
    g.add_node("writer", lambda s: {})
    g.add_node("email", ToolNode([send_email]))
    g.add_edge(START, "router")
    g.add_conditional_edges("router", lambda s: "researcher", ["researcher", "account", "writer"])
    for n in ("researcher", "account"):
        g.add_edge(n, "router")
    g.add_conditional_edges("writer", lambda s: END, ["email", END])
    g.add_edge("email", END)
    return g.compile()


class RouterIn(TypedDict):
    messages: list


class ResearchIn(TypedDict):
    question: str


class AccountIn(TypedDict):
    customer_id: str


class WriterIn(TypedDict):
    research: str
    account_summary: str


def hardened_app():
    g = StateGraph(Support)
    g.add_node("router", lambda s: {}, input_schema=RouterIn)
    g.add_node("researcher", react_agent([web_search]), input_schema=ResearchIn)
    g.add_node("account", react_agent([lookup_customer]), input_schema=AccountIn)
    g.add_node("writer", lambda s: {}, input_schema=WriterIn)
    g.add_node("email", ToolNode([send_email]))
    g.add_edge(START, "router")
    g.add_conditional_edges("router", lambda s: "researcher", ["researcher", "account", "writer"])
    for n in ("researcher", "account"):
        g.add_edge(n, "router")
    g.add_conditional_edges("writer", lambda s: END, ["email", END])
    g.add_edge("email", END)
    return g.compile(interrupt_before=["email"])      # a person approves every email


RULES = '''
policy "Customer data never leaves the app"
  never customer_pii -> internet

policy "Customer data never leaves, even if I approve one email"
  never customer_pii -> internet
  tolerate 0 agents, 1 approval

policy "Web content never steers the account agent"
  attacker controls web
  never hijack account

policy "A customer's message never steers the account agent"
  attacker controls state:messages
  never hijack account
'''
COMMON = dict(tools={"lookup_customer": {"read": ["data:crm"]}},
              secrets={"data:crm": "customer_pii"},
              deterministic=["router"])
HARDENED = dict(COMMON, writes={"router": ["question", "customer_id"], "researcher": ["research"],
                                "account": ["account_summary"], "writer": ["reply"]})

if __name__ == "__main__":
    print("== naive app ==")
    print(check(naive_app(), RULES, **COMMON))
    print("\n== hardened app ==")
    print(check(hardened_app(), RULES, **HARDENED))
