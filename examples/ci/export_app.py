#!/usr/bin/env python3
"""Export a compiled LangGraph app to a sherlock-scan JSON config.

    python export_app.py my_app:app fleet.json
    python export_app.py my_app:app fleet.json --secrets customer_db,api_key

`my_app:app` is an import path (module:attribute) to a compiled StateGraph. The
output loads with `agentcheck check --config fleet.json` and pastes into
https://sherlocksec.org. For the full set of knobs (writes=, approval_tools=,
reads_as_data=, trusted=, ...), write the three-line export() call yourself; see
../langgraph/README.md. This helper covers the common case.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys


def _load(ref: str):
    mod, _, attr = ref.partition(":")
    if not attr:
        sys.exit("give the app as module:attribute, e.g. my_app:app")
    try:
        m = importlib.import_module(mod)
    except Exception as e:  # noqa: BLE001 - surface the import error plainly
        sys.exit(f"could not import {mod!r}: {type(e).__name__}: {e}")
    try:
        return getattr(m, attr)
    except AttributeError:
        sys.exit(f"{mod!r} has no attribute {attr!r}")


def _csv(v: str) -> list[str]:
    return [x.strip() for x in v.split(",") if x.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("app", help="module:attribute of a compiled LangGraph app")
    ap.add_argument("out", help="path to write the JSON config to")
    ap.add_argument("--secrets", type=_csv, default=[],
                    help="comma-separated state keys / tool names that hold secrets")
    ap.add_argument("--writes", type=_csv, default=[],
                    help="comma-separated state keys a node writes (if the catalog can't tell)")
    args = ap.parse_args()

    try:
        from integrations.langgraph import export
    except Exception as e:  # noqa: BLE001
        sys.exit(f"sherlock is not importable: {type(e).__name__}: {e}\n"
                 "install it: pip install 'git+https://github.com/Ning0Luo/sherlock.git@main'")

    kw: dict = {}
    if args.secrets:
        kw["secrets"] = args.secrets
    if args.writes:
        kw["writes"] = args.writes

    cfg = export(_load(args.app), **kw)
    with open(args.out, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"wrote {args.out}: {len(cfg['agents'])} agents, {len(cfg['resources'])} resources")


if __name__ == "__main__":
    main()
