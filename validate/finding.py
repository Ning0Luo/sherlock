"""Read a Sherlock finding (the JSON that `agentcheck check --json` and
`conditions --json` write) into the few names a Scenario needs: the secret's
source, the sink it reaches, the untrusted inputs, and any agents the model
assumed were already malicious. You still supply the real agent code; this only
templates which resource plays which role so you do not transcribe it by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FindingShape:
    policy: str
    label: str | None = None            # the secret that leaks (None for integrity findings)
    source: str | None = None           # resource the label originates in
    sink: str | None = None             # resource the label (or attacker content) reaches
    untrusted: list[str] = field(default_factory=list)   # resources marked "untrusted source"
    broken: list[str] = field(default_factory=list)      # agents the model put in the coalition
    path: list[str] = field(default_factory=list)

    @property
    def pure_injection(self) -> bool:
        """True if the model reached this with nobody broken into: a flow driven by
        untrusted text alone, which is what this harness is built to reproduce."""
        return not self.broken


def _path_of(finding: dict) -> list[str]:
    a = finding.get("attack") or {}
    return a.get("path") or finding.get("path") or []


def shape(finding: dict) -> FindingShape:
    """One finding dict -> FindingShape. Accepts a `check` row (with 'attack')
    or a bare object carrying a 'path'."""
    path = [str(l).strip() for l in _path_of(finding)]
    sh = FindingShape(policy=finding.get("policy") or finding.get("violates") or "", path=path)
    for line in path:
        if line.startswith("label ") and " originates in " in line:
            lbl, _, src = line[len("label "):].partition(" originates in ")
            sh.label, sh.source = lbl.strip(), src.strip()
        elif line.endswith(": untrusted source"):
            sh.untrusted.append(line.split(":", 1)[0].replace("resource ", "").strip())
        elif line.startswith("agent ") and line.endswith(": initial coalition"):
            sh.broken.append(line[len("agent "):].split(":", 1)[0].strip())
        if " -> " in line:                       # last arrow is the outward step
            sh.sink = line.rsplit(" -> ", 1)[1].strip()
    if sh.sink is None:                          # integrity finding: the reached resource
        reached = [l for l in path if l.startswith("resource ") and ":" in l]
        if reached:
            sh.sink = reached[-1].split(":", 1)[0].replace("resource ", "").strip()
    return sh


def failing(findings: list[dict]) -> list[FindingShape]:
    """The FAIL rows of a `check --json` report, as shapes."""
    return [shape(f) for f in findings
            if f.get("pass") is False or f.get("status") == "FAIL" or f.get("attack")]
