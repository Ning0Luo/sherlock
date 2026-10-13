"""validate: check whether a Sherlock finding reproduces as real behavior.

A detector-evaluation harness, not an attack tool. See core.py for the safety
envelope (canary tokens, local sinks, egress guard, neutral markers).

    from validate import Scenario, Canary, LocalSink, MarkerInput, run
    from validate.langgraph import canary_tool, sink_tool, langgraph_runner
    from validate.finding import shape, failing
"""

from .core import (BLOCKED, ERROR, REPRODUCED, Canary, LocalSink, MarkerInput,
                   Outcome, Scenario, run)
from .egress import BlockedEgress, EgressGuard
from .finding import FindingShape, failing, shape

__all__ = ["Scenario", "Canary", "LocalSink", "MarkerInput", "Outcome", "run",
           "REPRODUCED", "BLOCKED", "ERROR", "EgressGuard", "BlockedEgress",
           "FindingShape", "shape", "failing"]
