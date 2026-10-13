#!/usr/bin/env python3
"""agentcheck: check safety policies, written in a small language, against a
multi-agent configuration, with a SAT solver.

  python3 agentcheck.py check POLICY --scan            # the agents on this Mac
  python3 agentcheck.py check POLICY --config FILE     # a configuration file
  python3 agentcheck.py check POLICY --openshell FLEET # NVIDIA OpenShell sandboxes
  python3 agentcheck.py check POLICY --bedrock DIR     # AWS Bedrock Agents (exported JSON)
  python3 agentcheck.py check POLICY --llamastack FILE # Llama Stack (run.yaml)
  python3 agentcheck.py names --scan                   # names a policy can use
  python3 agentcheck.py explain POLICY --scan          # what each policy compiles to
  python3 agentcheck.py ruleoftwo --scan               # Meta's Agents Rule of Two, per agent and fleet
  python3 agentcheck.py conditions POLICY --scan       # what unknown agents must not be able to do
  python3 agentcheck.py validate SCENARIOS.py          # do findings reproduce as real behavior?
  python3 agentcheck.py diff POLICY --config OLD --to NEW   # does a configuration change add attacks?
  python3 agentcheck.py watch POLICY --scan            # alarm when a change adds attacks

--guard-access (check, ruleoftwo, conditions; always on for diff and watch) sets
aside attacks that need an edit to access settings (permission rules, MCP configs,
approval lists): such an edit is itself a configuration change, checked when it
happens. On this Mac, watch also reports (REVIEW) a change to a file that a
set-aside attack edits, even when no verdict changes.

Each policy passes when the solver proves (UNSAT, with a DRAT proof) that no
attack exists within its tolerated budget of broken-into agents and approved
prompts. A failing policy comes with the cheapest attacks and a step-by-step
path. Exit code: 0 if every policy passes, 1 if any fails, 2 on errors.
See policy.py for the language.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "agentwatch"))

from collusion import System, freeze, gates, load  # noqa: E402
from policy import PolicyError, PolicyFile, compile_file, parse  # noqa: E402
from sat import coalitions, encode, frontier, frontier3, n_injectable, solve  # noqa: E402

# what a configuration that cannot be read raises (a missing file is an OSError)
BAD_CONFIG = (ValueError, KeyError, TypeError, AttributeError)


class ConfigError(Exception):
    """A configuration that cannot be read: exit code 2, never 1 (a failing policy)."""


def load_system(args, pf) -> tuple[System, callable]:
    if getattr(args, "openshell", None):
        import openshell
        try:
            s = openshell.load_fleet(args.openshell)
        except BAD_CONFIG + (openshell.YamlError,) as e:
            raise ConfigError(f"cannot read the OpenShell fleet {args.openshell}: {e}")
        for n in getattr(s, "notes", []):
            print(f"note: {n}", file=sys.stderr)
        return s, lambda p: p if p in s.resources else None
    for _src, _mod, _fn, _what in (("bedrock", "bedrock", "load_bedrock", "AWS Bedrock export"),
                                   ("llamastack", "llamastack", "load_llamastack", "Llama Stack deployment")):
        if getattr(args, _src, None):
            import importlib
            m = importlib.import_module(_mod)
            try:
                s = getattr(m, _fn)(getattr(args, _src))
            except BAD_CONFIG as e:
                raise ConfigError(f"cannot read the {_what} {getattr(args, _src)}: {e}")
            for n in getattr(s, "notes", []):
                print(f"note: {n}", file=sys.stderr)
            return s, lambda p: p if p in s.resources else None
    if args.config:
        try:
            s = load(args.config)
        except ValueError as e:      # names the file
            raise ConfigError(str(e))
        except BAD_CONFIG as e:
            raise ConfigError(f"cannot read {args.config}: {e}")

        def path_map(p: str) -> str | None:
            q = p.replace("~/", "home/", 1).lstrip("/")
            return q if q in s.resources else None
        return s, path_map
    import agentwatch as aw
    found, secrets = aw.discover(args.claude_mode, None, args.ignore)
    # A `secret NAME = PATH` line for a path no known store covers becomes a new store.
    extra, mapped = [], {}
    for name, (_, target) in pf.secrets.items():
        if target.startswith(("~", "/")) and aw.path_to_resource(found, target) is None:
            rel = target.replace("~/", "", 1)
            extra.append((f"secret:{name}", name, [rel]))
            mapped[target] = f"secret:{name}"
    s = aw.build_system(found, secrets + extra)
    s.found = found  # type: ignore[attr-defined]
    return s, lambda p: mapped.get(p) or aw.path_to_resource(found, p)


FROZEN_BANNER = ("access settings frozen: attacks that need a permission edit are set aside "
                 "(run 'agentcheck watch' to check such edits when they happen)\n")


def set_aside(lines: list[str], old: str, new: str, extra: list[str]) -> None:
    """Relabel a rendered PASS row as GUARDED: the line that is `old`, or `old: ...`,
    starts with `new` instead, and `extra` follows the row (its more indented lines).
    A row not found is added at the end."""
    indent = lambda l: len(l) - len(l.lstrip())
    for i, l in enumerate(lines):
        if l == old or l.startswith(old + ": "):
            lines[i] = new + l[len(old) + 1:]
            j = i + 1
            while j < len(lines) and lines[j].strip() and indent(lines[j]) > indent(l):
                j += 1
            lines[j:j] = extra
            return
    lines += [new.rstrip(",")] + extra


def budget(n: int | None, cap: int) -> int:
    return cap if n is None else min(n, cap)


def fmt_budget(n: int | None, unit: str) -> str:
    return f"any number of {unit}s" if n is None else f"{n} {unit}{'s' if n != 1 else ''}"


def describe(points) -> str:
    return " | or | ".join(
        f"{t} agent{'s' if t != 1 else ''} broken + {h} approval{'s' if h != 1 else ''}"
        for t, h, _ in points)


def describe3(points) -> str:
    return " | or | ".join(
        f"{t} agent{'s' if t != 1 else ''} broken + {h} approval{'s' if h != 1 else ''}"
        f" + {m} injection{'s' if m != 1 else ''}"
        for t, h, m, _ in points)


def attack_inj(ans) -> str:
    return f"; prompt-inject {', '.join(ans.injections)}" if getattr(ans, "injections", None) else ""


def cmd_check(args) -> int:
    pf = parse(Path(args.policy).read_text())
    s, path_map = load_system(args, pf)
    compiled = compile_file(s, pf, path_map)
    inj = not args.traditional
    proofs = Path(args.proofs).expanduser() if args.proofs else None
    n_agents, n_gates, n_inj = len(s.agents), len(gates(s)), n_injectable(s)
    want_inj = getattr(args, "injections", False)
    sf = freeze(s) if args.guard_access else s
    if sf is not s:
        print(FROZEN_BANNER)
    results, failed = [], 0
    for c in compiled:
        t, h = budget(c.agents, n_agents), budget(c.approvals, n_gates)
        m = budget(c.injections, n_inj)
        ans = solve(sf, c.goal, inj, t, h, proofs, max_inj=m)
        guarded = solve(s, c.goal, inj, t, h, max_inj=m) if not ans.sat and sf is not s else None
        guarded = guarded if guarded and guarded.sat else None
        need = f"{fmt_budget(c.agents, 'agent')} broken, {fmt_budget(c.approvals, 'approval')}"
        if c.injections is not None:
            need += f", {fmt_budget(c.injections, 'injection')}"
        if args.fast and not ans.sat:
            pts = []
        elif want_inj:
            pts = frontier3(sf, c.goal, inj)
        else:
            pts = frontier(sf, c.goal, inj)
        # the proof and the cheapest attacks are about the frozen system: say so
        frozen = "with access settings frozen, " if sf is not s else ""
        row = {"policy": c.title, "pass": not ans.sat, "guarded": guarded is not None, "tolerates": need,
               "access_frozen": sf is not s,
               "cheapest_attacks": [{"agents_broken": pt[0], "approvals": pt[1],
                                     **({"injections": pt[2]} if want_inj else {}),
                                     "broken": pt[-1].agents, "approved": pt[-1].approvals,
                                     "inject": pt[-1].injections, "path": pt[-1].witness,
                                     "violates": pt[-1].violated} for pt in pts],
               "proof": ans.proof}
        if ans.sat:
            failed += 1
            row["attack"] = {"broken": ans.agents, "approved": ans.approvals,
                             "inject": ans.injections, "violates": ans.violated, "path": ans.witness}
        results.append(row)

        print(f"{'FAIL' if ans.sat else 'GUARDED' if guarded else 'PASS'}  {c.title}")
        print(f"      must survive: {need}")
        for n in c.notes:
            print(f"      note: {n}")
        if guarded:
            print("      every attack needs an access-settings edit, set aside; e.g. "
                  f"break into {', '.join(guarded.agents) or 'no agent'}; "
                  f"you approve {', '.join(guarded.approvals) or 'nothing'}:")
            for line in guarded.witness or []:
                print("         " + line.strip())
            row["needs_access_edit"] = {"broken": guarded.agents, "approved": guarded.approvals,
                                        "path": guarded.witness}
        if not ans.sat:
            if ans.proof:
                print(f"      proof that no attack fits{' with access settings frozen' if frozen else ''}: "
                      f"{ans.proof}")
            if pts:
                print(f"      {frozen}cheapest attacks: {(describe3 if want_inj else describe)(pts)}")
            elif not args.fast:
                print(f"      {frozen + 'it ' if frozen else ''}cannot be broken at all, "
                      "even with every agent and every approval")
        else:
            best = pts[0][-1] if pts else ans
            if pts:
                print(f"      {frozen}cheapest attacks: {(describe3 if want_inj else describe)(pts)}")
            print(f"      e.g. break into {', '.join(best.agents) or 'no agent'}; "
                  f"you approve {', '.join(best.approvals) or 'nothing'}"
                  f"{attack_inj(best)}; result: {best.violated}")
            for line in best.witness or []:
                print("         " + line.strip())
        print()
    n_guarded = sum(r["guarded"] for r in results)
    print(f"{len(compiled) - failed}/{len(compiled)} policies pass"
          + (f" ({n_guarded} only with access settings frozen)" if n_guarded else "") + " "
          f"({'agentic' if inj else 'traditional'} model, {n_agents} agents, {n_gates} approval gates)")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
    return 1 if failed else 0


def contribution(s: System, agent: str, ans) -> str:
    """One line on what this member brings, read off the attack path."""
    acts = [l.strip() for l in ans.witness or [] if l.strip().startswith(agent + " ")]
    return acts[0] if acts else "needed: without it no attack exists (minimality)"


def cmd_collude(args) -> int:
    pf = parse(Path(args.policy).read_text())
    s, path_map = load_system(args, pf)
    compiled = compile_file(s, pf, path_map)
    print("Malicious agents that cooperate on purpose: nobody is tricked by text"
          + ("" if not args.with_injection else " (except: injection on)")
          + ", nobody is taken over through files" + (" (except: recruitment on)" if args.with_recruit else "")
          + f"; up to {args.approvals} approval(s) from you.\n")
    any_collusion = False
    for c in compiled:
        found, last = coalitions(s, c.goal, h=args.approvals, max_size=args.max,
                                 injection=args.with_injection, recruit=args.with_recruit)
        if found and not found[0].agents:
            print(f"{c.title}\n  broken without any malicious agent: {found[0].violated}\n")
            continue
        alone = [a for a in found if len(a.agents) == 1]
        together = [a for a in found if len(a.agents) > 1]
        any_collusion |= bool(together)
        print(f"{c.title}")
        if alone:
            print("  can do it alone: " + ", ".join(a.agents[0] for a in alone))
        if not together:
            print("  no collusion needed or possible" if alone else
                  "  safe: no group of agents can break it")
        for a in together:
            print(f"  COLLUSION {{{', '.join(a.agents)}}}"
                  + (f", with your approval of {', '.join(a.approvals)}" if a.approvals else ""))
            for m in a.agents:
                print(f"     {m}: {contribution(s, m, a)}")
            for line in a.witness or []:
                print("        " + line.strip())
        print()
    return 1 if any_collusion else 0


def cmd_export(args) -> int:
    """Write the configuration (e.g. the scanned Mac) as an editable JSON file."""
    s, _ = load_system(args, parse(""))
    # every field collusion.load reads, so the file loads back as the same system
    out = {
        "agents": {a: {"read": x.read, "write": x.write, "injectable": x.injectable,
                       **{k: v for k, v in (("ask", x.ask), ("flows", [list(f) for f in x.flows]),
                                            ("trusted", x.trusted), ("strips", x.strips),
                                            ("unknown", x.unknown), ("maybe", x.maybe)) if v}}
                   for a, x in sorted(s.agents.items())},
        "resources": {r: {k: v for k, v in (("labels", sorted(x.labels)),
                                             ("untrusted", x.untrusted), ("sink", x.sink),
                                             ("protected", x.protected),
                                             ("controls", x.controls), ("access", x.access)) if v}
                      for r, x in sorted(s.resources.items())},
        **({"policies": [{k: v for k, v in vars(p).items() if v is not None} for p in s.policies]}
           if s.policies else {}),
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {args.out}: {len(s.agents)} agents, {len(s.resources)} resources")
    return 0


def cmd_formula(args) -> int:
    """Write one policy's SAT formula: DIMACS, a name table, and a readable copy."""
    pf = parse(Path(args.policy).read_text())
    s, path_map = load_system(args, pf)
    compiled = compile_file(s, pf, path_map)
    pick = [c for c in compiled if args.title is None or c.title == args.title]
    if not pick:
        print("no policy titled " + repr(args.title) + "; titles: "
              + "; ".join(c.title for c in compiled), file=sys.stderr)
        return 2
    c = pick[0]
    t = budget(c.agents if args.agents is None else args.agents, len(s.agents))
    h = budget(c.approvals if args.approvals is None else args.approvals, len(gates(s)))
    cnf = encode(s, c.goal, not args.traditional, t, h).cnf
    out = Path(args.out)
    out.write_text(f"c policy: {c.title}\nc budget: {t} agents, {h} approvals\n" + cnf.dimacs())
    names = {i: (f"z{i}" if n == "aux" else f"c{i}" if n == "cnt" else n)
             for i, n in cnf.names.items()}
    Path(str(out) + ".names").write_text("".join(f"{i} {n}\n" for i, n in names.items()))
    lit = lambda l: ("¬" if l < 0 else "") + names[abs(l)]
    Path(str(out) + ".readable.txt").write_text(
        f"policy: {c.title}\nbudget: {t} agents, {h} approvals\n"
        f"{cnf.n} variables, {len(cnf.clauses)} clauses; every line is one clause (OR)\n\n"
        + "".join(" ∨ ".join(lit(x) for x in cl) + "\n" for cl in cnf.clauses))
    print(f"{c.title}: {cnf.n} variables, {len(cnf.clauses)} clauses (budget {t} agents, {h} approvals)")
    print(f"  {out}  (DIMACS, give it to any SAT solver)")
    print(f"  {out}.names  (variable number -> meaning)")
    print(f"  {out}.readable.txt  (same clauses with names)")
    return 0


def cmd_names(args) -> int:
    pf = parse(Path(args.policy).read_text()) if args.policy else parse("")
    s, path_map = load_system(args, pf)
    from policy import Resolver, short
    rv = Resolver(s, pf, path_map)
    print("Agents:      " + ", ".join(sorted(s.agents)))
    print("Secrets:     " + ", ".join(f"{l} ({short(l)})" if short(l) != l else l
                                      for l in sorted(rv.labels)))
    print("Untrusted:   " + ", ".join(sorted(r for r, x in s.resources.items() if x.untrusted)))
    print("Internet:    " + ", ".join(sorted(r for r, x in s.resources.items() if x.sink)))
    print("Resources:   " + ", ".join(sorted(s.resources)))
    print("Built-ins:   secrets, internet, agents, settings(AGENT), instructions(AGENT)")
    if pf.groups:
        print("Groups:      " + ", ".join(sorted(pf.groups)))
    print("Gates:       " + (", ".join(gates(s)) or "none"))
    return 0


def cmd_explain(args) -> int:
    pf = parse(Path(args.policy).read_text())
    s, path_map = load_system(args, pf)
    for c in compile_file(s, pf, path_map):
        print(f"{c.title}")
        print(f"  attacker writes: {sorted(c.goal.sources) if c.goal.sources else 'every untrusted input'}")
        for line in c.stmts:
            print(f"  require: {line}")
        print(f"  tolerate: {fmt_budget(c.agents, 'agent')}, {fmt_budget(c.approvals, 'approval')}")
        print(f"  SAT atoms ({len(c.goal.atoms)}): " + "; ".join(a.name for a in c.goal.atoms[:6])
              + (" ..." if len(c.goal.atoms) > 6 else ""))
    return 0


def cmd_ruleoftwo(args) -> int:
    """Meta's Agents Rule of Two for every agent, then for the fleet as a whole."""
    import ruleoftwo
    s, _ = load_system(args, parse(""))
    sf = freeze(s) if args.guard_access else s
    if sf is not s:
        print(FROZEN_BANNER)
    r = ruleoftwo.check(sf, Path(args.proofs).expanduser() if args.proofs else None)
    lines = ruleoftwo.render(r).split("\n")
    if sf is not s:   # a fleet goal that the frozen system passes but s does not is only GUARDED
        for f, g in zip(r["fleet"], ruleoftwo.check(s)["fleet"]):
            if (f["status"], f.get("approvals_needed")) == (g["status"], g.get("approvals_needed")):
                continue
            f["guarded"] = {k: g.get(k) for k in ("status", "approvals_needed", "path")}
            how = ("no approval" if g["status"] == "FAIL" else
                   f"{g['approvals_needed']} approval{'s' if g['approvals_needed'] != 1 else ''}")
            set_aside(lines, f"  PASS  {f['title']}", f"  GUARDED  {f['title']}: with access settings frozen,",
                      [f"        set aside: with an access-settings edit it happens with {how}:"]
                      + ["          " + x.strip() for x in g.get("path") or []])
    print("\n".join(lines))
    if args.why:
        print("\nWhy each letter:")
        print(ruleoftwo.explain(r))
    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2))
    return 1 if any(f["status"] == "FAIL" for f in r["fleet"]) else 0


def cmd_conditions(args) -> int:
    """Conditions on the rights nobody could read: when an attack exists, and what rules it out."""
    import synth
    pf = parse(Path(args.policy).read_text())
    s, path_map = load_system(args, pf)
    compiled = compile_file(s, pf, path_map)
    inj = not args.traditional
    sf = freeze(s) if args.guard_access else s
    if sf is not s:
        print(FROZEN_BANNER)
    out = synth.check(sf, compiled, budget, inj,
                      Path(args.proofs).expanduser() if args.proofs else None,
                      args.max_size, args.max_sets)
    if sf is not s:
        # what freezing set aside: for a PASS, any attack at all without freezing; for a
        # DEPENDS, an attack that gets past 'holds if' once access files can be edited
        unfrozen = synth.Synth(s, inj)
        for c, r in zip(compiled, out["results"]):
            t, h = budget(c.agents, len(s.agents)), budget(c.approvals, len(gates(s)))
            if r.status == "PASS":
                g = solve(s, c.goal, inj, t, h)
            elif r.status == "DEPENDS":
                g = unfrozen.holds_without(c.goal, t, h, frozenset(r.rule_out) & unfrozen.U)
            else:
                continue
            r.guarded = g if g.sat else None
    print(synth.render(out, args.show))
    if args.json:
        Path(args.json).write_text(json.dumps(synth.to_json(out), indent=2))
    # only a PASS is proved safe; DEPENDS holds only under conditions someone must check
    return 0 if all(r.status == "PASS" for r in out["results"]) else 1


def verdicts(s: System, pf, path_map, inj: bool = True, errors: dict | None = None,
             goals: dict | None = None) -> dict[str, tuple[str, object]]:
    """policy title -> (FAIL | GUARDED | PASS, attack) with access settings frozen.
    errors: if given, a policy that does not compile is left out and its message put
    here (title -> message), so the others are still checked; otherwise PolicyError.
    goals: if given, gets title -> (goal, agent budget, approval budget)."""
    if errors is None:
        compiled = compile_file(s, pf, path_map)
    else:
        rest = dict(secrets=pf.secrets, groups=pf.groups, sources=pf.sources)
        compile_file(s, PolicyFile(**rest), path_map)   # secret and attacker lines: all or nothing
        compiled = []
        for p in pf.policies:
            try:
                compiled += compile_file(s, PolicyFile(**rest, policies=[p]), path_map)
            except PolicyError as e:
                errors[p.title] = str(e)
    sf = freeze(s)
    out = {}
    for c in compiled:
        t, h = budget(c.agents, len(s.agents)), budget(c.approvals, len(gates(s)))
        if goals is not None:
            goals[c.title] = (c.goal, t, h)
        ans = solve(sf, c.goal, inj, t, h)
        if ans.sat:
            out[c.title] = ("FAIL", ans)
        elif sf is not s and (g := solve(s, c.goal, inj, t, h)).sat:
            out[c.title] = ("GUARDED", g)
        else:
            out[c.title] = ("PASS", None)
    return out


def compare(before: dict, after: dict) -> list[dict]:
    """What a change did. 'alarm': a policy that held now has an attack that needs no
    further access edit. 'guarded': new attacks, all needing an access edit. Removing
    rights never adds attacks (the model is monotone), so only additions alarm."""
    rank = {"PASS": 0, "GUARDED": 1, "FAIL": 2}
    out = []
    for title, (st, ans) in after.items():
        old = before.get(title, ("new policy", None))[0]
        if old == st:
            continue
        kind = ("alarm" if st == "FAIL" else "guarded" if st == "GUARDED" and rank.get(old, 0) < 1
                else "resolved")
        out.append({"policy": title, "before": old, "after": st, "kind": kind,
                    "broken": getattr(ans, "agents", None), "approved": getattr(ans, "approvals", None),
                    "path": getattr(ans, "witness", None)})
    return out


def print_changes(changes: list[dict]) -> None:
    if not changes:
        print("no change in any policy")
    for ch in changes:
        tag = {"alarm": "ALARM", "guarded": "NOTE", "resolved": "FIXED"}[ch["kind"]]
        print(f"{tag}  {ch['policy']}: {ch['before']} -> {ch['after']}")
        if ch["kind"] == "alarm":
            print("      this change brings an attack: break into "
                  f"{', '.join(ch['broken']) or 'no agent'}; you approve {', '.join(ch['approved']) or 'nothing'}")
        elif ch["kind"] == "guarded":
            print("      new attacks, but each needs a further access-settings edit, which is checked when it happens")
        for line in (ch["path"] or []) if ch["kind"] != "resolved" else []:
            print("         " + line.strip())


def cmd_diff(args) -> int:
    """Check a configuration change before it is made (CI, a proposed edit)."""
    if args.scan:
        print("diff compares two files; for this Mac use 'agentcheck watch'", file=sys.stderr)
        return 2
    text = Path(args.policy).read_text()
    s0, m0 = load_system(args, parse(text))
    new = argparse.Namespace(**vars(args))
    for _a in ("config", "openshell", "bedrock", "llamastack"):
        if getattr(args, _a, None):
            setattr(new, _a, args.to)
            break
    s1, m1 = load_system(new, parse(text))
    changes = compare(verdicts(s0, parse(text), m0), verdicts(s1, parse(text), m1))
    print_changes(changes)
    if args.json:
        Path(args.json).write_text(json.dumps(changes, indent=2))
    return 1 if any(ch["kind"] == "alarm" for ch in changes) else 0


def expand(p: str, home: Path) -> list[Path]:
    """A path from the scan (~/..., absolute, maybe a glob or a folder) as files, kept
    even when missing, so that creating one is seen as a change."""
    q = str(home) + p[1:] if p.startswith("~/") else p
    if any(c in q for c in "*?["):
        anchor = Path(q).anchor
        ps = sorted(Path(anchor or ".").glob(q[len(anchor):]))
    else:
        ps = [Path(q)]
    out = []
    for x in ps:
        out += sorted(y for y in x.rglob("*") if y.is_file()) if x.is_dir() else [x]
    return out


def watched_files(args, s: System) -> list[Path]:
    """The files the configuration is read from, each once (by resolved path)."""
    if args.config:
        files = [Path(args.config)]
    elif args.openshell:   # the fleet file and every sandbox policy and proposal it names
        files = list(getattr(s, "files", [])) or [Path(args.openshell)]
    elif getattr(args, "bedrock", None):
        files = list(getattr(s, "files", [])) or [Path(args.bedrock)]
    elif getattr(args, "llamastack", None):
        files = list(getattr(s, "files", [])) or [Path(args.llamastack)]
    else:
        import agentwatch as aw
        found = getattr(s, "found", [])
        files = aw.control_files({"guard": {"control_paths": {f.name: f.control_paths for f in found},
                                            "shell_rc": [f"~/{p}" for p in aw.SHELL_RC]}})
        # and every other file the scan reads (project settings, .mcp.json, managed settings).
        # These are literal paths: a project folder named 'app[1]' is not a glob.
        shallow = set(getattr(aw, "shallow_dirs", lambda: [])())
        for p in getattr(aw, "watch_paths", lambda f: [])(found):
            q = Path(str(aw.HOME) + p[1:] if p.startswith("~/") else p)
            if q in shallow or not q.is_dir():
                files.append(q)
            else:
                files += [q] + sorted(y for y in q.rglob("*") if y.is_file())
    out: dict[Path, Path] = {}
    for p in files:
        out.setdefault(p.resolve(), p)
    return list(out.values())


def snapshot(files: list[Path]) -> dict[str, str]:
    """Modification time and size of each file; a missing one (or one deleted meanwhile)
    is left out. ~/.claude.json counts only by what the scan reads from it."""
    key = lambda p: None
    if any(p.name == ".claude.json" for p in files):
        import agentwatch as aw
        key = getattr(aw, "content_key", key)
    out = {}
    for p in files:
        try:
            st = p.stat()
        except OSError:
            continue
        out[str(p)] = key(p) or f"{st.st_mtime_ns}:{st.st_size}"
    return out


def alert(args, msg: str) -> None:
    """Print msg; on this Mac (scan mode) also show it as a notification."""
    if not getattr(args, "scan", False):
        print(msg, flush=True)
    else:
        import agentwatch as aw
        aw.notify(msg)


def writes(witness: list[str] | None, r: str) -> bool:
    """Does an attack path write resource r (attacker content, or a copied secret)?"""
    return any(l.strip().startswith(f"resource {r}: ") or l.strip().endswith(f"-> {r}")
               for l in witness or [])


def review(args, s: System, goals: dict, now: dict, changed: list[str]) -> None:
    """Scan mode: report a changed file that a GUARDED policy's set-aside attack edits,
    even when no verdict changes. Writing an access file steers the agent it controls
    without granting rights, and the scan does not parse every setting (hooks, env),
    so the re-check alone may not see such an edit."""
    if args.config or args.openshell:
        return
    import agentwatch as aw
    for path in changed:
        r = aw.path_to_resource(getattr(s, "found", []), path)
        if r not in s.resources:
            continue
        for title, (st, ans) in now.items():
            if st != "GUARDED":
                continue
            goal, t, h = goals.get(title, (None, 0, 0))
            # the shown attack edits it, or some attack does with every other access file frozen
            if writes(getattr(ans, "witness", None), r) or (
                    goal is not None and s.resources[r].access and solve(freeze(s, {r}), goal, True, t, h).sat):
                alert(args, f"REVIEW {path.replace(str(aw.HOME), '~', 1)} changed: {title} has a "
                            "set-aside attack that edits this file")


def cmd_watch(args) -> int:
    """Re-check after every configuration change; alarm when one adds an attack."""
    import time
    text = Path(args.policy).read_text()
    s, pm = load_system(args, parse(text))
    goals: dict = {}
    base = verdicts(s, parse(text), pm, goals=goals)
    for title, (st, _) in base.items():
        print(f"{st:8} {title}")
    prev = snapshot(watched_files(args, s))
    print(f"\nwatching {len(prev)} files every {args.every}s (Ctrl-C to stop)")
    rounds = 0
    try:
        while args.rounds is None or rounds < args.rounds:
            rounds += 1
            time.sleep(args.every)
            cur = snapshot(watched_files(args, s))
            if cur == prev:
                continue
            changed = sorted({p for p, _ in set(cur.items()) ^ set(prev.items())})
            prev = cur
            print(time.strftime("[%H:%M:%S] ") + f"{len(changed)} file(s) changed: " + ", ".join(changed[:3]))
            now, errors = base, {}
            try:
                s2, pm2 = load_system(args, parse(text))
                g2: dict = {}
                v = verdicts(s2, parse(text), pm2, errors=errors, goals=g2)
            except Exception as e:   # a half-written or broken file: keep watching
                why = str(e) if isinstance(e, (ConfigError, PolicyError, OSError)) else f"{type(e).__name__}: {e}"
                alert(args, f"cannot re-check: {why}")
            else:
                s, goals = s2, g2
                now = {**base, **v}   # a policy that cannot be compiled keeps its last verdict
                for title, msg in errors.items():
                    alert(args, f"cannot re-check {title}: {msg}")
                changes = compare(base, now)
                print_changes(changes)
                alarms = [ch["policy"] for ch in changes if ch["kind"] == "alarm"]
                if alarms and getattr(args, "scan", False):
                    alert(args, f"ALARM: a settings change brings an attack on: {'; '.join(alarms[:2])}")
            review(args, s, goals, now, changed)
            base = now
    except KeyboardInterrupt:
        print()
    return 0


def cmd_validate(args) -> int:
    """Run validation scenarios you wrote (a Python module) and report, per
    scenario, whether a Sherlock finding reproduces as real behavior. This runs
    real agents on a test fleet you own; see validate/README.md for the rules."""
    import importlib.util
    import validate
    spec = importlib.util.spec_from_file_location("_scenarios", args.scenarios)
    if spec is None or spec.loader is None:
        print(f"error: cannot load {args.scenarios}", file=sys.stderr)
        return 2
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        print(f"error: cannot import {args.scenarios}: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    try:
        scns = getattr(mod, "SCENARIOS", None)
        if scns is None and callable(getattr(mod, "scenarios", None)):
            scns = mod.scenarios()
    except Exception as e:
        print(f"error: {args.scenarios} could not build its scenarios: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 2
    if not isinstance(scns, dict) or not scns:
        print(f"error: {args.scenarios} must define SCENARIOS (a dict name -> validate.Scenario) "
              "or scenarios() returning one", file=sys.stderr)
        return 2
    repro = blocked = errored = 0
    for name, sc in scns.items():
        o = validate.run(sc, guard=not args.no_guard)
        note = "  (not the predicted path)" if o.status == validate.REPRODUCED and not o.predicted else ""
        print(f"{o.status:11} {name}{note}")
        print(f"            {o.detail}")
        repro += o.status == validate.REPRODUCED
        blocked += o.status == validate.BLOCKED
        errored += o.status == validate.ERROR
    judged = repro + blocked
    print()
    print(f"precision: {repro}/{judged} findings reproduced as real behavior"
          + (f"; {errored} could not be run" if errored else "") if judged
          else f"nothing judged ({errored} errored)")
    return 2 if errored else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "names", "explain", "collude", "export", "formula", "ruleoftwo", "diff", "watch",
                 "conditions"):
        sp = sub.add_parser(name)
        if name == "names":
            sp.add_argument("policy", nargs="?")
        elif name == "export":
            sp.add_argument("out", help="JSON file to write")
        elif name == "ruleoftwo":
            sp.add_argument("--guard-access", action="store_true",
                            help="set aside attacks that need an access-settings edit")
            sp.add_argument("--why", action="store_true", help="explain each letter")
            sp.add_argument("--proofs", help="directory for DRAT proofs of passing goals")
            sp.add_argument("--json", help="write results as JSON")
        elif name == "formula":
            sp.add_argument("policy")
            sp.add_argument("out", help="DIMACS file to write")
            sp.add_argument("--title", help="which policy (default: the first)")
            sp.add_argument("--agents", type=int, help="override the agent budget")
            sp.add_argument("--approvals", type=int, help="override the approval budget")
            sp.add_argument("--traditional", action="store_true")
        elif name != "ruleoftwo":
            sp.add_argument("policy")
        if name == "conditions":
            sp.add_argument("--guard-access", action="store_true",
                            help="set aside attacks that need an access-settings edit")
            sp.add_argument("--max-size", type=int, default=4, help="largest set of unknown rights to list")
            sp.add_argument("--max-sets", type=int, default=50, help="most sets to list per policy")
            sp.add_argument("--show", type=int, default=8, help="sets to print per policy")
            sp.add_argument("--traditional", action="store_true")
            sp.add_argument("--proofs", help="directory for DRAT proofs")
            sp.add_argument("--json", help="write results as JSON")
        if name == "diff":
            sp.add_argument("--to", required=True, help="the changed configuration (same kind as the source)")
            sp.add_argument("--json", help="write the changes as JSON")
        if name == "watch":
            sp.add_argument("--every", type=int, default=10, help="seconds between checks")
            sp.add_argument("--rounds", type=int, help=argparse.SUPPRESS)   # for tests
        src = sp.add_mutually_exclusive_group(required=True)
        src.add_argument("--config", help="configuration file (JSON, see examples/)")
        src.add_argument("--scan", action="store_true", help="discover the agents on this Mac")
        src.add_argument("--openshell", metavar="FLEET",
                         help="NVIDIA OpenShell sandboxes: a fleet file naming each sandbox's policy")
        src.add_argument("--bedrock", metavar="DIR",
                         help="AWS Bedrock Agents: a directory of exported JSON")
        src.add_argument("--llamastack", metavar="FILE",
                         help="Llama Stack: a run.yaml deployment file")
        sp.add_argument("--ignore", action="append", help="skip this agent (scan mode)")
        sp.add_argument("--claude-mode",
                        choices=["default", "acceptEdits", "plan", "auto", "bypassPermissions"])
        if name == "collude":
            sp.add_argument("--approvals", type=int, default=0,
                            help="approvals you might give (default 0)")
            sp.add_argument("--max", type=int, help="largest group to consider")
            sp.add_argument("--with-injection", action="store_true",
                            help="also let honest agents be tricked by what they read")
            sp.add_argument("--with-recruit", action="store_true",
                            help="also let colluders take over agents through settings files")
        if name == "check":
            sp.add_argument("--traditional", action="store_true",
                            help="textbook model: reading never corrupts an agent")
            sp.add_argument("--fast", action="store_true",
                            help="skip the cheapest-attack search for passing policies")
            sp.add_argument("--proofs", help="directory for DRAT proofs of passing policies")
            sp.add_argument("--json", help="write results as JSON")
            sp.add_argument("--guard-access", action="store_true",
                            help="set aside attacks that need an access-settings edit")
            sp.add_argument("--injections", action="store_true",
                            help="count prompt injections as a third budget axis in the attack list")
    vp = sub.add_parser("validate")
    vp.add_argument("scenarios", help="a Python module defining SCENARIOS (name -> validate.Scenario)")
    vp.add_argument("--no-guard", action="store_true",
                    help="do not block real network during runs (unsafe; off by default)")

    args = ap.parse_args()
    try:
        code = {"check": cmd_check, "names": cmd_names, "explain": cmd_explain,
                "collude": cmd_collude, "export": cmd_export,
                "formula": cmd_formula, "ruleoftwo": cmd_ruleoftwo,
                "diff": cmd_diff, "watch": cmd_watch, "conditions": cmd_conditions,
                "validate": cmd_validate}[args.cmd](args)
    except PolicyError as e:
        print(f"policy error, {e}", file=sys.stderr)
        code = 2
    except (ConfigError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        code = 2
    except Exception:   # exit code 1 means a policy fails, so a crash must not end with it
        import traceback
        traceback.print_exc()
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
