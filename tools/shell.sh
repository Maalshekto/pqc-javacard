#!/usr/bin/env bash
# shell.sh — Terminal APDU interactif pour l'applet.
#
#   ./tools/shell.sh                    simulateur, PIN de laboratoire 1234
#   ./tools/shell.sh --pin 246810       simulateur, PIN initial fourni à l'installation
#   ./tools/shell.sh < tools/demo.apdu  rejouer un scénario commenté
#   ./tools/shell.sh --pcsc             carte réelle sur le premier lecteur PC/SC (applet déjà chargée)
set -euo pipefail
cd "$(dirname "$0")/.."
exec mvn -q -B test-compile exec:java -Dexec.args="$*"
