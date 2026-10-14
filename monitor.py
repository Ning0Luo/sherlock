"""Event-level runtime monitor: a live SAT reachability query from observed state.

The static checker asks "could these agents ever break a policy?". At runtime we
know more: which resources already hold attacker-influenced content, where secrets
have actually flowed, which agents have already been steered. A Monitor keeps that
observed state and, before an agent acts, asks the solver:

    from where we are now, does this action make a policy violation reachable
    within the tolerated budget (t more hacks, h approvals, m more injections)?

If yes, the action is blocked (or sent for approval). Seed the current state as
the SAT encoding's round-0 facts (see sat.encode's seed_*), so the question is
asked from the present, not from scratch. Default budget (0, 0, 0): block an
action that would let a violation happen with no further attacker effort.

Wire `probe` into an enforcement point -- a Claude Code PreToolUse hook, a
LangGraph guard, an MCP proxy -- and `apply` to the events you observe. It is
only as good as what you can observe: treat an opaque action (a shell command)
conservatively, e.g. as reading and writing everything it could.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from collusion import Policy, System
from sat import n_injectable, solve


@dataclass
class Verdict:
    block: bool
    hits: list[tuple[str, object]] = field(default_factory=list)   # (policy name, attack Answer)

    def __bool__(self) -> bool:
        return self.block

    @property
    def why(self) -> str:
        return "; ".join(f"{name}: {a.violated}" for name, a in self.hits)


class Monitor:
    def __init__(self, s: System, policies: list[Policy] | None = None,
                 budget: tuple[int, int, int] = (0, 0, 0), injection: bool = True):
        self.s = s
        self.policies = list(policies if policies is not None else s.policies)
        self.t, self.h, self.m = budget
        self.injection = injection
        self.tainted: set[str] = set()                 # resources observed holding attacker content
        self.labels: dict[str, set[str]] = {}          # label -> resources it has reached (observed)
        self.corrupt: set[str] = set()                 # agents observed working for the attacker

    # -- observed state -----------------------------------------------------
    def _baseline_tainted(self) -> set[str]:
        return {r for r, x in self.s.resources.items() if x.untrusted}

    def _labels_at(self, r: str) -> set[str]:
        at = set(self.s.resources[r].labels) if r in self.s.resources else set()
        return at | {l for l, rs in self.labels.items() if r in rs}

    def _delta(self, agent: str, reads, writes):
        """What this action would add to the state, without mutating."""
        reads, writes = set(reads), set(writes)
        ag = self.s.agents.get(agent)
        tainted_now = self.tainted | self._baseline_tainted()
        data_only = self.s.matches(ag.reads_as_data) if ag else set()
        hit_taint = bool((reads & tainted_now) - data_only)
        d_corrupt = set()
        if ag and ag.injectable and not ag.trusted and hit_taint:
            d_corrupt.add(agent)                        # steered by what it read
        d_tainted = set(writes) if (reads & tainted_now) else set()
        d_labels: dict[str, set[str]] = {}
        read_labels = set().union(*[self._labels_at(r) for r in reads]) if reads else set()
        for l in read_labels:
            d_labels[l] = set(writes)
        return d_tainted, d_labels, d_corrupt

    def apply(self, agent: str, reads=(), writes=(), injected: bool = False) -> None:
        """Record that `agent` actually read `reads` and wrote `writes` (injected=True
        if you observed it being prompt-injected). Updates the observed state."""
        dt, dl, dc = self._delta(agent, reads, writes)
        self.tainted |= dt
        for l, rs in dl.items():
            self.labels.setdefault(l, set()).update(rs)
        self.corrupt |= dc
        if injected and agent in self.s.agents and not self.s.agents[agent].trusted:
            self.corrupt.add(agent)

    # -- the live query -----------------------------------------------------
    def _reachable(self, extra_t=frozenset(), extra_l=None, extra_c=frozenset()) -> list:
        extra_l = extra_l or {}
        seed_t = frozenset(self.tainted | set(extra_t))
        keys = set(self.labels) | set(extra_l)
        seed_l = {l: (self.labels.get(l, set()) | extra_l.get(l, set())) for l in keys}
        seed_c = frozenset(self.corrupt | set(extra_c))
        hits = []
        for p in self.policies:
            ans = solve(self.s, p, self.injection, self.t, self.h, max_inj=self.m,
                        seed_tainted=seed_t, seed_labels=seed_l, seed_corrupt=seed_c)
            if ans.sat:
                hits.append((p.name, ans))
        return hits

    def status(self) -> Verdict:
        """Is any policy already reachable from the current observed state?"""
        return Verdict(bool(h := self._reachable()), h)

    def probe(self, agent: str, reads=(), writes=()) -> Verdict:
        """Would `agent` doing this (reading `reads`, writing `writes`) make a policy
        violation reachable within budget? Use before allowing the action."""
        dt, dl, dc = self._delta(agent, reads, writes)
        return Verdict(bool(h := self._reachable(dt, dl, dc)), h)

    def allow(self, agent: str, reads=(), writes=()) -> bool:
        """Convenience gate: probe, and if safe, record it. Returns True if allowed."""
        if self.probe(agent, reads, writes):
            return False
        self.apply(agent, reads, writes)
        return True
