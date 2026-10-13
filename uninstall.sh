#!/usr/bin/env bash
# Remove what install.sh installed. Leaves CaDiCaL and your policy files alone.
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
rm -rf "$PREFIX/share/agentcheck"
rm -f "$PREFIX/bin/agentcheck" "$PREFIX/bin/agentwatch" "$PREFIX/bin/drat-check"
echo "Removed agentcheck from $PREFIX"
