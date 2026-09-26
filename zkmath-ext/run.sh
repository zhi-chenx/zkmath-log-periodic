#!/usr/bin/env bash
# Run a two-party (prover=1/ALICE, verifier=2/BOB) binary inside the container over localhost.
#   ./run.sh <binary> [args...]        e.g. ./run.sh hao_exp   |   ./run.sh bench_ext log lut 100000
# Set BW=<rate> (e.g. BW=500mbit) to shape the loopback link with tc (needs sch_tbf on the host).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1; shift
PORT=${PORT:-$((20000 + RANDOM % 20000))}
podman run --rm --cap-add=NET_ADMIN -e BW="${BW:-}" -e EXT_CHEAT -v "$HERE:/ext:z" -v "$HERE/build:/build:z" \
    zkmath-ext:latest bash /ext/scripts/container_run.sh "$BIN" "$PORT" "$@"
