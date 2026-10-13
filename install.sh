#!/usr/bin/env bash
# Install agentcheck (policy checker), agentwatch (agent scanner) and
# drat-check (independent proof checker) for the current user.
#
#   ./install.sh                 # installs into ~/.local
#   PREFIX=/opt/agentcheck ./install.sh
#   NO_SOLVER_INSTALL=1 ./install.sh   # never run brew/apt; just report
#
# Needs: Python 3.9+, and the CaDiCaL SAT solver (installed for you via
# Homebrew or apt when available). Changes nothing outside PREFIX except that
# package-manager install; it does not edit your shell startup files.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
DEST="$PREFIX/share/agentcheck"
BIN="$PREFIX/bin"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Python ---------------------------------------------------------------
PY=""
for c in python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if command -v "$c" >/dev/null 2>&1 &&
     "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    PY="$(command -v "$c")"; break
  fi
done
[ -n "$PY" ] || die "Python 3.9 or newer is required (macOS: xcode-select --install, or brew install python)."
say "Python: $PY ($("$PY" -c 'import platform; print(platform.python_version())'))"

# 2. CaDiCaL --------------------------------------------------------------
SOLVER="$(command -v cadical || true)"
if [ -z "$SOLVER" ] && [ -z "${NO_SOLVER_INSTALL:-}" ]; then
  if command -v brew >/dev/null 2>&1; then
    say "Installing the CaDiCaL SAT solver with Homebrew"
    brew install cadical || warn "brew install cadical failed"
  elif command -v apt-get >/dev/null 2>&1; then
    say "Installing the CaDiCaL SAT solver with apt (may ask for your password)"
    sudo apt-get install -y cadical || warn "apt-get install cadical failed"
  fi
  SOLVER="$(command -v cadical || true)"
fi
if [ -z "$SOLVER" ]; then
  warn "CaDiCaL not found. Install it, then re-run this script:"
  warn "  git clone https://github.com/arminbiere/cadical && cd cadical && ./configure && make"
  warn "  and put build/cadical on your PATH (or set CADICAL=/path/to/cadical)."
else
  say "CaDiCaL: $SOLVER"
fi

# 3. Files ----------------------------------------------------------------
say "Installing into $DEST"
rm -rf "$DEST"
mkdir -p "$DEST/agentwatch" "$DEST/policies" "$DEST/examples" "$DEST/tests" "$BIN"
cp "$SRC"/collusion.py "$SRC"/sat.py "$SRC"/policy.py "$SRC"/agentcheck.py "$SRC"/drat_check.py \
   "$SRC"/ruleoftwo.py "$SRC"/openshell.py "$SRC"/miniyaml.py "$SRC"/synth.py \
   "$SRC"/bedrock.py "$SRC"/llamastack.py "$SRC"/shield_whatif.py "$DEST/"
cp "$SRC"/agentwatch/agentwatch.py "$DEST/agentwatch/"
mkdir -p "$DEST/validate"
cp "$SRC"/validate/*.py "$DEST/validate/"
mkdir -p "$DEST/integrations"
cp "$SRC"/integrations/*.py "$DEST/integrations/"
cp "$SRC"/policies/*.policy "$DEST/policies/"
cp "$SRC"/examples/*.json "$SRC"/examples/__init__.py "$DEST/examples/"
for d in openshell ruleoftwo access conditions langgraph validate bedrock llamastack strands; do
  [ -d "$SRC/examples/$d" ] && cp -R "$SRC/examples/$d" "$DEST/examples/"
done
# only the tests that run here: test_parsers and test_trust need web/ (not installed),
# test_langgraph needs the langgraph package
for t in "$SRC"/tests/*.py; do
  case "$(basename "$t")" in
    test_parsers.py|test_trust.py|test_langgraph.py) ;;
    *) cp "$t" "$DEST/tests/" ;;
  esac
done
for f in POLICY.md README.md; do [ -f "$SRC/$f" ] && cp "$SRC/$f" "$DEST/"; done
[ -f "$SRC/agentwatch/README.md" ] && cp "$SRC/agentwatch/README.md" "$DEST/agentwatch/"

# 4. Commands -------------------------------------------------------------
make_cmd() {   # name, script
  cat > "$BIN/$1" <<EOF
#!/usr/bin/env bash
${SOLVER:+export CADICAL="\${CADICAL:-$SOLVER}"}
exec "$PY" "$DEST/$2" "\$@"
EOF
  chmod +x "$BIN/$1"
}
make_cmd agentcheck agentcheck.py
make_cmd agentwatch agentwatch/agentwatch.py
make_cmd drat-check drat_check.py
say "Commands: $BIN/agentcheck, $BIN/agentwatch, $BIN/drat-check"

# 5. Self-test ------------------------------------------------------------
if [ -n "$SOLVER" ]; then
  say "Self-test"
  out="$("$BIN/agentcheck" check "$DEST/policies/devbox_hardened.policy" \
           --config "$DEST/examples/devbox_hardened.json" --fast 2>&1 || true)"
  echo "$out" | tail -1
  echo "$out" | grep -q "3/4 policies pass" || die "self-test gave an unexpected result"
  # every installed module must import (the scan, OpenShell and Rule-of-Two paths load lazily)
  (cd "$DEST" && "$PY" -c "import sys; sys.path[:0] = ['.', 'agentwatch']
import agentwatch, openshell, ruleoftwo, synth, validate, bedrock, llamastack, shield_whatif, integrations.langgraph, integrations.strands") || die "self-test: an installed module does not import"
  out="$("$BIN/agentcheck" ruleoftwo --config "$DEST/examples/ruleoftwo/inbox.json" 2>&1 || true)"
  echo "$out" | grep -q "COMPOSITION" || die "self-test: ruleoftwo gave an unexpected result"
  rc=0   # exit 1 = some policy fails, which is fine here; 2 = could not run
  "$BIN/agentcheck" check "$DEST/examples/openshell/fleet.policy" \
    --openshell "$DEST/examples/openshell/fleet.yaml" --fast >/dev/null 2>&1 || rc=$?
  [ "$rc" -le 1 ] || die "self-test: --openshell failed (exit $rc)"
  say "Self-test passed"
fi

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) warn "$BIN is not on your PATH. Add this line to ~/.zshrc (or ~/.bashrc):"
     printf '    export PATH="%s:$PATH"\n' "$BIN" ;;
esac
cat <<EOF

Try:
  agentcheck names --scan                                   # what's on this Mac
  agentcheck check $DEST/policies/mac.policy --scan         # your policies
  agentcheck collude $DEST/policies/mac.policy --scan       # colluding groups
Docs: $DEST/POLICY.md      Uninstall: PREFIX=$PREFIX $SRC/uninstall.sh
EOF
