#!/usr/bin/env bash
# Malicious-prover test on the real backend: for every witness k of one execution the prover adds 1
# to witness k; every run must be rejected (or give exactly the honest output).
#   ./soundness.sh <lut|poly|naive> <func>...     e.g. ./soundness.sh lut sin log60
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
podman run --rm -v "$HERE:/ext:z" -v "$HERE/build:/build:z" zkmath-ext:latest \
    bash /ext/scripts/container_soundness.sh "$@"
