#!/usr/bin/env bash
# Inside the container: optional bandwidth shaping, then prover and verifier over 127.0.0.1.
set -uo pipefail
BIN=/build/emp-zk/bin/$1; PORT=$2; shift 2
cd /tmp && mkdir -p data   # emp-ot stores pre-OT data in ./data
if [ -n "${BW:-}" ]; then
    tc qdisc replace dev lo root tbf rate "$BW" burst 1mbit latency 50ms
fi
"$BIN" 1 "$PORT" "$@" > /tmp/prover.log 2>&1 &
PID=$!
"$BIN" 2 "$PORT" "$@" > /tmp/verifier.log 2>&1
VS=$?
wait $PID
PS=$?
sed 's/^/[P] /' /tmp/prover.log
sed 's/^/[V] /' /tmp/verifier.log
[ $PS -eq 0 ] && [ $VS -eq 0 ] || { echo "EXIT prover=$PS verifier=$VS"; exit 1; }
