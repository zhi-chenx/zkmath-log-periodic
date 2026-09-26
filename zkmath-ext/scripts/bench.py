#!/usr/bin/env python3
"""Runtime / communication benchmark in the style of Hao et al. (USENIX Sec '24, Tables 2, 4, 5).

    python3 scripts/bench.py [--quick] [--out results/bench.csv]

* scaling: 10^3, 10^4, 10^5 instances on the unshaped loopback (3 repetitions, median reported)
* bandwidth: 10^5 instances with the loopback shaped to 200 Mbps, 500 Mbps and 1 Gbps (tc tbf)
* hao: Hao et al.'s own binaries (exp, div, sigmoid, gelu, softmax; 10^5 instances) for calibration
Every run is a full two-party execution of the proof in the container (see run.sh).
"""
import argparse
import csv
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
FUNCS = ["sin", "log60", "log20", "exp", "snake", "softplus", "logsoftmax"]
MODES = ["lut", "poly", "naive"]
BWS = ["200mbit", "500mbit", "1000mbit"]
HAO = ["exp", "div", "sigmoid", "gelu", "softmax"]
FIELDS = ["kind", "func", "mode", "dim", "bw", "rep", "time_p", "time_v", "comm_p_mb", "comm_v_mb",
          "max_err_ulp", "mean_err_ulp", "verify"]


def run(args, bw=""):
    env = {"BW": bw} if bw else {}
    for attempt in range(3):
        out = subprocess.run([str(HERE / "run.sh")] + args, capture_output=True, text=True,
                             env={**__import__("os").environ, **env})
        if out.returncode == 0:
            return out.stdout
        time.sleep(1)
    sys.exit(f"run failed: {args} {bw}\n{out.stdout}\n{out.stderr}")


def parse_ext(text):
    res = {}
    for line in text.splitlines():
        if "RESULT" in line:
            kv = dict(re.findall(r"(\w+)=(\S+)", line))
            res[int(kv["party"])] = kv
    return res


def parse_hao(text):
    t = {1: None, 2: None}
    comm = {1: 0.0, 2: 0.0}
    for line in text.splitlines():
        p = 1 if line.startswith("[P]") else 2
        m = re.search(r"time - \w+(?: \(ms\))?: ([\d.]+) (m?s)", line)
        if m:
            t[p] = float(m.group(1)) / (1000 if m.group(2) == "ms" else 1)
        m = re.search(r"communication - \w+ \(KB\): ([\d.]+)", line)
        if m:
            comm[p] = float(m.group(1)) / 1024
    return t, comm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="small sizes, 1 repetition")
    ap.add_argument("--out", default=str(HERE / "results" / "bench.csv"))
    ap.add_argument("--parts", default="scaling,bandwidth,hao")
    a = ap.parse_args()
    dims = [1000, 3000] if a.quick else [1000, 10000, 100000]
    big = dims[-1]
    reps = 1 if a.quick else 3
    parts = a.parts.split(",")
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    new = not out.exists()
    with out.open("a", newline="") as fh:
        w = csv.DictWriter(fh, FIELDS)
        if new:
            w.writeheader()

        def emit(**row):
            w.writerow(row)
            fh.flush()
            print(" ".join(f"{k}={row[k]}" for k in FIELDS if k in row), flush=True)

        if "scaling" in parts:
            for f in FUNCS:
                for d in dims:
                    r = parse_ext(run(["bench_ext", f, "plain", str(d)]))[1]
                    emit(kind="scaling", func=f, mode="plain", dim=d, bw="", rep=0,
                         time_p=r["time_s"], time_v=0, comm_p_mb=0, comm_v_mb=0,
                         max_err_ulp=0, mean_err_ulp=0, verify="NA")
                    for m in MODES:
                        for rep in range(reps):
                            r = parse_ext(run(["bench_ext", f, m, str(d), str(rep + 1)]))
                            emit(kind="scaling", func=f, mode=m, dim=d, bw="", rep=rep,
                                 time_p=r[1]["time_s"], time_v=r[2]["time_s"],
                                 comm_p_mb=r[1]["comm_mb"], comm_v_mb=r[2]["comm_mb"],
                                 max_err_ulp=r[1]["max_err_ulp"], mean_err_ulp=r[1]["mean_err_ulp"],
                                 verify=r[2]["verify"])
        if "bandwidth" in parts:
            for bw in BWS:
                for f in FUNCS:
                    for m in MODES:
                        r = parse_ext(run(["bench_ext", f, m, str(big)], bw))
                        emit(kind="bandwidth", func=f, mode=m, dim=big, bw=bw, rep=0,
                             time_p=r[1]["time_s"], time_v=r[2]["time_s"],
                             comm_p_mb=r[1]["comm_mb"], comm_v_mb=r[2]["comm_mb"],
                             max_err_ulp=r[1]["max_err_ulp"], mean_err_ulp=r[1]["mean_err_ulp"],
                             verify=r[2]["verify"])
        if "hao" in parts and not a.quick:
            for bw in [""] + BWS:
                for h in HAO:
                    t, c = parse_hao(run([f"hao_{h}"], bw))
                    emit(kind="hao", func=h, mode="hao", dim=100000, bw=bw, rep=0,
                         time_p=t[1], time_v=t[2], comm_p_mb=c[1], comm_v_mb=c[2],
                         max_err_ulp="", mean_err_ulp="", verify="NA")


if __name__ == "__main__":
    main()
