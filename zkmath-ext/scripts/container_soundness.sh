#!/usr/bin/env bash
# Inside the container: malicious-prover test on the real emp-zk backend. For every witness k
# of one protocol execution, the prover adds 1 to witness k (EXT_CHEAT=k). Each run must either
# be rejected by the verifier or produce exactly the honest output.
#   container_soundness.sh <mode> <func>...
set -uo pipefail
cd /tmp && mkdir -p data
BIN=/build/emp-zk/bin/bench_ext
MODE=$1; shift
PORT=31000
run() {  # run <func> <dump>  -> prints verifier status
    "$BIN" 1 $PORT "$1" "$MODE" 1 3 "$2" > p.log 2>&1 &
    local pid=$!
    timeout 20 "$BIN" 2 $PORT "$1" "$MODE" 1 3 > v.log 2>&1
    local vs=$?
    sleep 0.05; kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null
    PORT=$((PORT + 1))
    if [ $vs -ne 0 ] || grep -q "verify=FAIL" v.log; then echo REJECT; else echo ACCEPT; fi
}
for f in "$@"; do
    [ "$(run "$f" honest.csv)" = ACCEPT ] || { echo "$f: honest run rejected"; exit 1; }
    W=$(grep -o 'witnesses=[0-9]*' p.log | cut -d= -f2)
    rej=0; same=0; diff=0
    for ((k = 0; k < W; k++)); do
        r=$(EXT_CHEAT=$k run "$f" cheat.csv)
        if [ "$r" = REJECT ]; then rej=$((rej + 1))
        elif cmp -s honest.csv cheat.csv; then same=$((same + 1))
        else diff=$((diff + 1)); echo "  $f: witness $k accepted with a WRONG output"; fi
    done
    echo "SOUNDNESS mode=$MODE func=$f witnesses=$W rejected=$rej accepted_same_output=$same accepted_wrong_output=$diff"
done
