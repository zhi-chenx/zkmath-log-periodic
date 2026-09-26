#!/usr/bin/env python3
"""Bit-exact cross-check: the C++ protocols (LUT mode, real emp-zk proof) must output exactly the
field elements computed by the Python executable specification (spec/zkml).

    python3 scripts/crosscheck.py [n] [seed]      (runs ./run.sh bench_ext ... in the container)
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parent / "spec"))
from zkml import FZK, pi_sin, pi_log, pi_exp_neg, pi_snake, pi_softplus, pi_log_softmax  # noqa: E402

SPEC = {
    "sin": lambda f, x: pi_sin(f, x, x_bits=24),
    "log60": lambda f, x: pi_log(f, x, n=60),
    "log20": lambda f, x: pi_log(f, x, n=20),
    "exp": lambda f, x: pi_exp_neg(f, x, n=24),
    "snake": lambda f, x: pi_snake(f, x, a=1.0, x_bits=24),
    "softplus": lambda f, x: pi_softplus(f, x, x_bits=24),
}
LSM = 10


def run_cpp(func, n, seed):
    raw = HERE / "results" / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    dump = raw / f"dump_{func}.csv"
    out = subprocess.run([str(HERE / "run.sh"), "bench_ext", func, "lut", str(n), str(seed),
                          f"/ext/results/raw/{dump.name}"], capture_output=True, text=True)
    if out.returncode or "verify=OK" not in out.stdout:
        sys.exit(f"{func}: C++ run failed\n{out.stdout}\n{out.stderr}")
    return [tuple(map(int, line.split(","))) for line in dump.read_text().split()]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 7
    bad_total = 0
    for func in list(SPEC) + ["logsoftmax"]:
        rows = run_cpp(func, n // LSM if func == "logsoftmax" else n, seed)
        bad = 0
        if func == "logsoftmax":
            for i in range(0, len(rows), LSM):
                f = FZK()
                ys = pi_log_softmax(f, [f.public(x) for x, _ in rows[i:i + LSM]])
                bad += sum(y.v != yc for y, (_, yc) in zip(ys, rows[i:i + LSM]))
        else:
            for x, yc in rows:
                f = FZK()
                bad += SPEC[func](f, f.public(x)).v != yc
        print(f"{func:11s} {len(rows):6d} outputs  mismatches={bad}")
        bad_total += bad
    sys.exit(1 if bad_total else 0)


if __name__ == "__main__":
    main()
