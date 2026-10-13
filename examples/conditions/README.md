# Conditions on rights the scan could not confirm

```bash
python3 agentcheck.py conditions examples/conditions/home.policy --config examples/conditions/home.json
python3 agentcheck.py conditions policies/mac.policy --scan
```

`check` gives every right it could not confirm to the agent, which keeps it sound but makes most policies fail. `conditions` turns each such right into an open question and asks the solver when an attack exists.

Two kinds of rights count as uncertain:
- every open right of an agent whose settings the scan could not read (`"unknown": true`; the scan sets it for agents with coverage "worst")
- open rights that come only from an assumption (`"maybe": {"read": [...], "write": [...]}`): for example a pre-approved, unrecognized MCP server, or Codex's browser plugin

| Result | Meaning |
|---|---|
| FAIL | broken even if every uncertain right is absent; the attack is printed, with whom it breaks into and which prompts you approve |
| PASS | holds even if every uncertain right is present (DRAT proof with `--proofs`) |
| DEPENDS | an attack exists exactly when one of the listed sets of rights is present. Each set is minimal, and is printed with what else its attack needs (`e.g. break into X; you approve Y`) when that is not nothing. A final UNSAT call proves the list complete (but see below for a list cut off). **holds if** gives the smallest set of rights whose absence rules out every attack, with a proof. |

At the end, one checklist covers every DEPENDS policy at once, and each policy is re-proved under it.

### When the list is cut off

`--max-size` (largest set listed, default 4) and `--max-sets` (most sets listed, default 50) bound the smallest-first list. When either stops it, **holds if** is still exact: each attack that slips past a candidate rule-out set is shrunk to a minimal set and added. Those sets are printed under *also found while working out 'holds if'*. They lie beyond the limit and are not necessarily smallest. Completeness is then checked again with every set found:
- If no attack avoids all of them, the output says *exactly when one of these holds*, with a proof.
- Otherwise it says *at least when one of these holds*, with the limit that stopped the list:
  - `--max-sets`: *other sets, possibly of the same size, may exist*
  - `--max-size`: *sets larger than --max-size were not searched*

In `--json`, `attack_sets` is the smallest-first list and `extra_sets` holds the others. `stopped` is `max_size`, `max_sets` or `null`, and `complete` says whether the two lists together are every minimal set. Each set comes with an example `path`, plus `broken` and `approved` when its attack needs them. That path uses only the rights in its set.

### Checking the proofs

With `--proofs DIR`, each proof `P.drat` is written next to the exact formula it refutes, `P.drat.cnf`, and the output prints both paths. That formula is not the one `agentcheck formula` writes. It encodes the system with each uncertain right as its own switch, plus the clauses for the sets blocked and the rights ruled out. Check a pair without trusting the solver:

```bash
python3 drat_check.py P.drat.cnf P.drat
```

`check --proofs` keeps its formulas the same way.

## Why this is exact

More rights never remove an attack, because the model is monotone. So the attacks are described exactly by their minimal sets of uncertain rights:
- Sets are listed smallest first. Each one found is blocked, along with every superset.
- A set found at size k is minimal: a smaller working set would have been found at an earlier size.
- `tests/test_synth.py` compares the statuses, the sets and the size of the rule-out set against all subsets of uncertain rights on 300 random systems. It runs each system a second time with small `--max-size`/`--max-sets` values, and checks the listed sets, the extra sets, the stop reason and the wording. It also runs `drat_check.py` on the PASS, *complete*, *holds if* and checklist proofs.

## `home.json`

- `helper`'s settings could not be read.
- `coder`'s web access comes only from an MCP server that might not fetch web pages.

Both policies are DEPENDS, and the checklist has two items: *coder cannot read web*, and *helper cannot read web*. If both are true, both policies hold, with proofs.

## Limits

- **Uncertainty is tracked only for open rights.** A right behind an approval gate that comes from an unrecognized MCP server stays worst-case. That is sound, but coarser.
- **Agents with coverage "assumed"** (documented defaults, such as Cursor) are modeled from those defaults, not as open questions. The defaults could also be looser than modeled, for example if the user turned on auto-run.
- **A checklist item is only useful if someone can check it.** "ChatGPT cannot read ~/.ssh" might be settled through macOS privacy settings or the app's sandbox. Some items will stay a judgment call.
