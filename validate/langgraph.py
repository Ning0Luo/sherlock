"""Adapters for building a validation Scenario from a LangGraph app.

langchain / langgraph need not be installed to use validate.core; these helpers
import them lazily, only when you call one. The pattern:

  - put a `canary_tool` where the fleet reads a secret (the CRM lookup, a file
    read), so that source returns a canary token instead of a real secret;
  - put a `sink_tool` where the fleet acts outward (send_email, an HTTP post),
    so the canary is caught and recorded instead of sent;
  - run the model nodes with your real LLM, so the result reflects real
    behavior (prompt following, refusals, any guard model you added);
  - wrap the compiled app with `langgraph_runner` as the Scenario.run_app.

Because the model nodes call a real LLM, a Scenario here needs network to that
provider. Point the provider at your own key, keep every *tool* a canary_tool,
sink_tool or other local stub, and the EgressGuard still blocks the fleet's own
tools from reaching anything but the model endpoint — which you allow by
running those nodes outside `run(..., guard=True)` if needed (see README).
"""

from __future__ import annotations

from typing import Callable

from .core import Canary, LocalSink


def canary_tool(name: str, canary: Canary, description: str = "Look up a record."):
    """A tool that returns the canary token. Give it the same name and argument
    shape as the real source tool it replaces."""
    from langchain_core.tools import tool

    @tool
    def _t(query: str = "") -> str:
        return canary.token

    _t.name = name
    _t.description = description
    return _t


def sink_tool(name: str, sink: LocalSink, description: str = "Send a message."):
    """A tool that records its arguments in `sink` and returns ''. Give it the
    same name and argument shape as the real outward tool it replaces."""
    from langchain_core.tools import tool

    @tool
    def _t(to: str = "", body: str = "") -> str:
        return sink.record(to, body)

    _t.name = name
    _t.description = description
    return _t


def langgraph_runner(app, input_keys: list[str] | None = None) -> Callable[[dict], object]:
    """Wrap a compiled LangGraph app as a Scenario.run_app. input_keys restricts
    which marker inputs are passed in (default: all)."""
    def run(inputs: dict):
        payload = inputs if input_keys is None else {k: inputs[k] for k in input_keys if k in inputs}
        return app.invoke(payload)

    return run
