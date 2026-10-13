#!/usr/bin/env bash
# Install Sherlock for LangGraph users: makes `from integrations.langgraph import check`
# importable in your Python environment, and installs the CaDiCaL solver if it can.
#
#   ./install-langgraph.sh            # into the active venv, or a new ./.venv
#   WITH_LANGGRAPH=1 ./install-langgraph.sh   # also pip-install langgraph + langchain-core
#   PYTHON=python3.12 ./install-langgraph.sh  # pick the interpreter
#
# The Sherlock core is standard-library only, so this adds no Python dependencies
# of its own; it reads the LangGraph app you already have. CaDiCaL is optional
# (there is a slower pure-Python fallback).
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Python 3.9+
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || die "no '$PY' on PATH (set PYTHON=... to choose one)"
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "Python 3.9+ required (found $("$PY" -V 2>&1))"
say "Python: $("$PY" -V 2>&1)"

# 2. Pick the environment to install into: the active venv, else a local ./.venv
if [ -n "${VIRTUAL_ENV:-}" ]; then
  VENV_PY="$VIRTUAL_ENV/bin/python"
  say "Installing into the active virtualenv: $VIRTUAL_ENV"
  ACTIVATE=""
else
  VENV="$SRC/.venv"
  if [ ! -x "$VENV/bin/python" ]; then
    say "No virtualenv active; creating one at $VENV"
    "$PY" -m venv "$VENV"
  else
    say "Using existing virtualenv: $VENV"
  fi
  VENV_PY="$VENV/bin/python"
  ACTIVATE="source $VENV/bin/activate"
  warn "to use Sherlock alongside YOUR LangGraph app, run this from your project's"
  warn "activated venv instead, so both live in the same environment."
fi

# 3. Install Sherlock (editable, so edits to the repo take effect immediately)
say "Installing Sherlock (editable)"
"$VENV_PY" -m pip install --quiet --upgrade pip
"$VENV_PY" -m pip install --quiet -e "$SRC"

# 4. CaDiCaL: optional, faster solver (pure-Python fallback otherwise)
if command -v cadical >/dev/null 2>&1; then
  say "CaDiCaL: $(command -v cadical)"
elif command -v brew >/dev/null 2>&1; then
  say "Installing CaDiCaL with Homebrew"
  brew install cadical || warn "brew install failed; the slower built-in search will be used"
elif command -v apt-get >/dev/null 2>&1; then
  say "Installing CaDiCaL with apt"
  sudo apt-get install -y cadical || warn "apt install failed; the slower built-in search will be used"
else
  warn "no brew/apt found; skipping CaDiCaL. A slower built-in search is used instead."
  warn "install CaDiCaL yourself for speed/scale: https://github.com/arminbiere/cadical"
fi

# 5. Optionally install LangGraph itself (you probably already have it)
if [ "${WITH_LANGGRAPH:-0}" = "1" ]; then
  say "Installing langgraph + langchain-core"
  "$VENV_PY" -m pip install --quiet langgraph langchain-core
fi

# 6. Self-test: the import works with no LangGraph needed
say "Self-test"
"$VENV_PY" - <<'PYEOF'
import shutil
from integrations.langgraph import check, export   # standard-library-only import
print("  import integrations.langgraph: ok")
try:
    import langgraph  # noqa: F401
    print("  langgraph: installed (you can run check() on a real app)")
except ImportError:
    print("  langgraph: not in this env (install it, or run from your project's venv)")
print("  CaDiCaL:", "found (fast path)" if shutil.which("cadical") else "absent (slower fallback)")
PYEOF

say "Done."
[ -n "$ACTIVATE" ] && echo "    First: $ACTIVATE"
cat <<'EOF'
    Then, in your code:

      from integrations.langgraph import check
      print(check(app, '''
      policy "Customer data never leaves the app"
        never customer_pii -> internet
      ''', secrets={"data:crm": "customer_pii"}))

    Or export the model for the CLI / website:
      from integrations.langgraph import export; import json
      json.dump(export(app, secrets={"data:crm": "customer_pii"}), open("app.json", "w"))
      agentcheck ruleoftwo --config app.json
EOF
