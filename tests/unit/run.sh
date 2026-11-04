#!/usr/bin/env bash
# Runs the unit tests (no cluster, no network) inside the shieldwaf image, or with a local Python that has `cryptography` and `flask`:
#   bash tests/unit/run.sh            (needs Docker and the image shieldwaf:2.4 or shieldwaf:2.3)
#   PYTHON=python bash tests/unit/run.sh   (local interpreter)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$(dirname "$HERE")")"
if [ -n "${PYTHON:-}" ]; then cd "$HERE" && "$PYTHON" -m unittest discover -s "$HERE" -p 'test_*.py' -v; exit $?; fi
IMG="${IMAGE:-shieldwaf:2.4-dev}"
MSYS_NO_PATHCONV=1 docker run --rm -e SHIELD_DATA=/tmp/d -v "$ROOT/panel:/panel:ro" -v "$HERE:/unit:ro" --entrypoint python3 "$IMG" -m unittest discover -s /unit -p 'test_*.py' -v
