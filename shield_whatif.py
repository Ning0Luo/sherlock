#!/usr/bin/env python3
"""A LlamaFirewall / shield "what-if" for Sherlock.

Llama Stack agents can carry input and output shields -- PromptGuard (catches
prompt injection and jailbreaks on the way in), Llama Guard (content safety on
the way in and out), AlignmentCheck (watches the agent's reasoning). Meta's
LlamaFirewall bundles these. A shield is a *defense*: if it is effective, it
removes attacker-controlled content, and/or a secret, from what passes through
the agent it guards.

The problem with trusting a shield is that none of them is perfect, and a
checker that assumes they work will certify systems that a bypass breaks. So
Sherlock's base model (see ``llamastack.load_llamastack``) does NOT trust any
shield. This module answers the separate, conditional question: *if* the named
shields do hold, how much cheaper does that make the defender's life? It
computes the cheapest-attack frontier two ways and shows both:

  * WITHOUT -- the real guarantee. No shield is believed. This is what
    ``sat.frontier`` reports on the system as loaded.
  * WITH    -- the same, but each shielded agent is assumed to strip
    attacker influence (and, for confidentiality, the secret labels) from
    what it forwards. Modeled by adding those tokens to the agent's
    ``strips`` set. This result is only as true as the shields are.

Adding to ``strips`` only ever *removes* ways for taint or a label to travel
(it blocks an honest relay; it never blocks anything else), so every attack
that survives WITH the shields also exists WITHOUT them. The WITH frontier is
therefore always at least as expensive as the WITHOUT frontier -- assuming a
shield can only remove attacks, never add one. That is what keeps this sound:
the guarantee you ship is WITHOUT; WITH only tells you the upside, clearly
labeled as conditional.

A shield modeled this way blocks an agent's *honest relay* of attacker content
or a secret. It does not pretend to stop the guarded agent from being taken
over in the first place (a corrupted agent ignores its own shield), so the
numbers never over-credit an input shield on the very agent an injection
targets.

    from llamastack import load_llamastack
    from shield_whatif import whatif
    s = load_llamastack("examples/llamastack/deployment.yaml")
    print(whatif(s, s.shielded))          # s.shielded: the agents that declare a shield
"""
from __future__ import annotations

from dataclasses import dataclass, field

from collusion import Agent, Policy, System
from sat import Goal, as_goal, frontier


def _strip_tokens(system: System, labels) -> list[str]:
    """What a shielded agent is assumed to strip: 'attacker' always, plus the
    confidentiality labels (every label in the system, or the ones given)."""
    if labels is None:
        labels = sorted({l for r in system.resources.values() for l in r.labels})
    return sorted({"attacker", *labels})


def shield_system(system: System, shielded_agents, labels=None) -> System:
    """A copy of ``system`` in which each named agent is assumed effective: it
    strips attacker influence and the secret labels from what it forwards.
    Resources and policies are shared (never mutated); only agents are rebuilt."""
    shielded = set(shielded_agents) & set(system.agents)
    tokens = _strip_tokens(system, labels)
    agents = {}
    for name, ag in system.agents.items():
        strips = sorted(set(ag.strips) | set(tokens)) if name in shielded else list(ag.strips)
        agents[name] = Agent(name, read=list(ag.read), write=list(ag.write),
                             injectable=ag.injectable, flows=list(ag.flows),
                             ask={g: {k: list(v) for k, v in r.items()} for g, r in ag.ask.items()},
                             trusted=ag.trusted, strips=strips, unknown=ag.unknown,
                             maybe={k: list(v) for k, v in ag.maybe.items()})
    out = System(agents, system.resources, system.policies)
    out.notes = getattr(system, "notes", [])   # type: ignore[attr-defined]
    return out


@dataclass
class ShieldResult:
    policy: str
    without: list[tuple[int, int]]   # Pareto-minimal (agents hacked, approvals), no shield trusted
    with_: list[tuple[int, int]]     # ... assuming the shields hold
    without_ans: list = field(default_factory=list)   # the matching sat.Answer objects
    with_ans: list = field(default_factory=list)

    @property
    def helps(self) -> bool:
        """The shields make at least one policy strictly harder to break."""
        return _cost(self.with_) > _cost(self.without)


@dataclass
class WhatIf:
    shielded: list[str]
    stripped: list[str]
    results: list[ShieldResult]
    injection: bool

    @property
    def helps(self) -> bool:
        return any(r.helps for r in self.results)

    def summary(self) -> str:
        who = ", ".join(self.shielded) or "(none)"
        mode = "agentic (reading attacker data can take an agent over)" if self.injection \
            else "traditional (only a coalition or a control file takes an agent over)"
        out = [f"shield what-if  -- mode: {mode}",
               f"  shielded agents: {who}",
               f"  assumed to strip from what they forward: {', '.join(self.stripped)}",
               "  WITHOUT = the guarantee (no shield trusted) | WITH = only if the shields hold",
               ""]
        for r in self.results:
            w0, w1 = _fmt(r.without), _fmt(r.with_)
            if r.helps:
                verdict = f"shield worth it: cheapest attack rises from [{w0}] to [{w1}]"
            elif _cost(r.without) == _INF:
                verdict = "already safe without any shield"
            else:
                verdict = f"shield does not help here: still [{w0}] (the guarded agent is not an honest relay on this path)"
            out.append(f"  {r.policy}")
            out.append(f"      WITHOUT: [{w0}]   WITH: [{w1}]   -> {verdict}")
        return "\n".join(out)

    def __str__(self) -> str:
        return self.summary()


_INF = (1 << 30, 1 << 30)


def _cost(points: list[tuple[int, int]]) -> tuple[int, int]:
    """The cheapest attack (fewest agents, then fewest approvals); huge if none."""
    return min((p for p in points), default=_INF)


def _fmt(points: list[tuple[int, int]]) -> str:
    if not points:
        return "no attack at any cost"
    return " | ".join(f"{t} hacked + {h} approvals" for t, h in points)


def whatif(system: System, shielded_agents, injection: bool = True,
           labels=None, goals=None) -> WhatIf:
    """Compute the cheapest-attack frontier with and without trusting the shields.

    system          a Sherlock System (e.g. from llamastack.load_llamastack).
    shielded_agents the agents whose shields to assume effective (names; a set,
                    list, or None -> use system.shielded if present, else none).
    injection       True: an agent that reads attacker data can be taken over
                    (the agentic threat model). False: the traditional model.
    labels          which confidentiality labels a shield strips, besides
                    "attacker" (default: every label in the system).
    goals           the policies/goals to check (default: system.policies).

    Returns a WhatIf: per policy, the WITHOUT frontier (the real guarantee) and
    the WITH frontier (conditional on the shields). WITH is always >= WITHOUT.
    """
    if shielded_agents is None:
        shielded_agents = getattr(system, "shielded", [])
    shielded = sorted(set(shielded_agents) & set(system.agents))
    tokens = _strip_tokens(system, labels)
    guarded = shield_system(system, shielded, labels)
    atoms = list(goals) if goals is not None else list(system.policies)
    results = []
    for g in atoms:
        g = as_goal(g)
        f0 = frontier(system, g, injection)
        f1 = frontier(guarded, g, injection)
        results.append(ShieldResult(
            policy=g.name,
            without=[(t, h) for t, h, _ in f0],
            with_=[(t, h) for t, h, _ in f1],
            without_ans=[a for _, _, a in f0],
            with_ans=[a for _, _, a in f1],
        ))
    return WhatIf(shielded=shielded, stripped=tokens, results=results, injection=injection)


if __name__ == "__main__":
    import sys

    from llamastack import load_llamastack
    s = load_llamastack(sys.argv[1])
    print(whatif(s, getattr(s, "shielded", []), injection="--traditional" not in sys.argv))
