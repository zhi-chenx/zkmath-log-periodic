#!/usr/bin/env python3
"""Generate paper/tables/*.tex from the benchmark results and the Python specification.

Inputs:  ../zkmath-ext/results/bench.csv       (scripts/bench.py)
         ../zkmath-ext/results/soundness.txt   (scripts/container_soundness.sh)
         ../spec                               (v1 flaws and cost counters, computed here)
"""
import csv
import math
import random
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE.parent / "zkmath-ext" / "results"
OUT = HERE / "tables"
sys.path.insert(0, str(HERE.parent / "spec"))
from zkml import (FZK, Abort, R2F_round, F2R, pi_sin, pi_log, thesis_pi_sin,  # noqa: E402
                  thesis_pi_log)

FUNCS = [("sin", r"$\sin x$", r"$|\hat x|<2^{12}$"),
         ("log60", r"$\ln x$, $n{=}60$", r"$(2^{-12},2^{48})$"),
         ("log20", r"$\ln x$, $n{=}20$", r"$[1,256]$"),
         ("snake", r"snake$_1$", r"$|\hat x|<10^3$"),
         ("softplus", "softplus", r"$|\hat x|<20$"),
         ("logsoftmax", r"log-softmax$_{10}$", r"$|\hat x_j|<10$")]
NAME = {f: n for f, n, _ in FUNCS}
NAME["exp"] = r"$e^{-x}$"
MODES = [("lut", r"\textsf{Ours}"), ("poly", r"\textsf{Poly}"), ("naive", r"\textsf{Naive}")]
BWS = ["200mbit", "500mbit", "1000mbit"]
HEAD = "500mbit"                       # headline numbers at Hao et al.'s default bandwidth
HAO_PUB = {  # Hao et al., USENIX Sec '24, Tables 4-5 (500 Mbps): time (s), comm (MB)
    "exp": (8.696, 99.020), "div": (9.837, 110.684), "sigmoid": (17.706, 189.899),
    "gelu": (32.696, 338.182), "softmax": (78.289, 816.330)}


def load():
    rows = list(csv.DictReader((RES / "bench.csv").open()))
    agg = defaultdict(list)
    for r in rows:
        t = max(float(r["time_p"] or 0), float(r["time_v"] or 0))
        c = float(r["comm_p_mb"] or 0) + float(r["comm_v_mb"] or 0)
        e = (float(r["max_err_ulp"] or 0), float(r["mean_err_ulp"] or 0))
        agg[(r["kind"], r["func"], r["mode"], int(r["dim"]), r["bw"])].append((t, c, e))
    med = {}
    for k, v in agg.items():
        med[k] = (statistics.median(x[0] for x in v), statistics.median(x[1] for x in v),
                  max(x[2][0] for x in v), statistics.mean(x[2][1] for x in v))
    return med


def fmt_t(t):
    return f"{t:.3f}" if t < 10 else f"{t:.2f}" if t < 100 else f"{t:.1f}"


def fmt_c(c):
    return f"{c:.2f}" if c < 10 else f"{c:.1f}" if c < 1000 else f"{c:.0f}"


def main_table(med, big):
    L = [r"\begin{table*}[t]\centering\small",
         r"\caption{Runtime (s) and communication (MB) for $10^5$ instances (log-softmax: $10^5$ rows of"
         r" 10), in the format of Hao et al.'s Tables 4--5. Speed-ups of \textsf{Ours} over the"
         r" baseline in parentheses. \textsf{Plain}: floating-point evaluation without proof.}",
         r"\label{tab:main}",
         r"\begin{tabular}{llrrrrr}\toprule",
         r"Function & Protocol & 200\,Mbps & 500\,Mbps & 1\,Gbps & Comm.\ (MB) & Elem./inst.\\\midrule"]
    for f, name, _ in FUNCS:
        ours = {bw: med[("bandwidth", f, "lut", big, bw)] for bw in BWS}
        for i, (m, mname) in enumerate(MODES):
            cells = []
            for bw in BWS:
                t = med[("bandwidth", f, m, big, bw)][0]
                cells.append(fmt_t(t) + ("" if m == "lut" else f" ({t / ours[bw][0]:.1f}$\\times$)"))
            c = med[("bandwidth", f, m, big, HEAD)][1]
            per = f == "logsoftmax" and 10 or 1
            elem = c * 2**20 / 8 / (big * per)
            cc = fmt_c(c) + ("" if m == "lut" else f" ({c / ours[HEAD][1]:.1f}$\\times$)")
            L.append((name if i == 0 else "") + f" & {mname} & " + " & ".join(cells)
                     + f" & {cc} & {elem:.0f}\\\\")
        pt = med[("scaling", f, "plain", big, "")][0]
        L.append(f" & \\textsf{{Plain}} & \\multicolumn{{3}}{{c}}{{{pt * 1e3:.2f} ms}} & -- & --\\\\")
        L.append(r"\midrule" if f != FUNCS[-1][0] else r"\bottomrule")
    L += [r"\end{tabular}", r"\end{table*}"]
    return "\n".join(L)


def scaling_table(med, dims):
    L = [r"\begin{table}[t]\centering\small",
         r"\caption{Scaling on the unshaped loopback: runtime (s), median of 3 runs.}",
         r"\label{tab:scaling}",
         r"\setlength{\tabcolsep}{4pt}",
         r"\begin{tabular}{ll" + "r" * len(dims) + r"}\toprule",
         r"Function & Protocol & " + " & ".join(f"$10^{{{int(math.log10(d))}}}$" for d in dims)
         + r"\\\midrule"]
    for f, name, _ in FUNCS:
        for i, (m, mname) in enumerate([MODES[0], MODES[2]]):
            L.append((name if i == 0 else "") + f" & {mname} & "
                     + " & ".join(fmt_t(med[("scaling", f, m, d, "")][0]) for d in dims) + r"\\")
    L += [r"\bottomrule\end{tabular}", r"\end{table}"]
    return "\n".join(L)


def v1_numbers():
    """Behaviour of the thesis-v1 protocols (honest prover), from the Python spec."""
    rng = random.Random(0)
    out = {}

    def measure(proto, xs, ref):
        errs, ab = [], 0
        for x in xs:
            try:
                f = FZK()
                errs.append(abs(F2R(proto(f, f.public(x)).v) - ref(x)))
            except Abort:
                ab += 1
        return (max(errs) if errs else float("nan")), ab

    xs = [R2F_round(rng.uniform(-4095, 4095)) for _ in range(3000)]
    out["sin"] = measure(thesis_pi_sin, xs, lambda x: math.sin(F2R(x)))
    xs = [max(1, int(math.exp(rng.uniform(0, math.log(2**60 - 1))))) for _ in range(3000)]
    out["log60"] = measure(thesis_pi_log, xs, lambda x: math.log(x / 4096))
    xs = [R2F_round(rng.uniform(1, 256)) for _ in range(1000)]
    out["log20"] = measure(thesis_pi_log, xs, lambda x: math.log(x / 4096))
    x = 2**50 + 2**40 + 3 * 2**24 + 5 * 2**12 + 7
    f = FZK()
    out["log_ex"] = (F2R(thesis_pi_log(f, f.public(x)).v), math.log(x / 4096))
    return out, {"sin": 3000, "log60": 3000, "log20": 1000}


def cost_counts():
    """Per-instance cost of our protocols in the hybrid model (Python counters)."""
    from zkml import pi_snake, pi_softplus, pi_log_softmax
    res = {}
    for f, proto, x in [("sin", lambda f, x: pi_sin(f, x), R2F_round(1.0)),
                        ("log60", lambda f, x: pi_log(f, x, n=60), R2F_round(3.7)),
                        ("log20", lambda f, x: pi_log(f, x, n=20), R2F_round(3.7)),
                        ("snake", lambda f, x: pi_snake(f, x, a=1.0), R2F_round(1.0)),
                        ("softplus", lambda f, x: pi_softplus(f, x, x_bits=24), R2F_round(1.0))]:
        fz = FZK()
        proto(fz, fz.public(x))
        res[f] = fz.cost
    fz = FZK()
    pi_log_softmax(fz, [fz.public(R2F_round(v)) for v in [0.5, -1, 2, 3, -4, 1, 0, 0.25, 5, -2]])
    res["logsoftmax"] = {k: v / 10 for k, v in fz.cost.items()}
    return res


def precision_table(med, big, v1, v1n, cost):
    L = [r"\begin{table}[t]\centering\footnotesize",
         r"\caption{Accuracy in units of $\Delta=2^{-12}$ over $10^5$ random inputs (max\,/\,mean"
         r" absolute error); cost per instance of \textsf{Ours} (function lookups\,+\,range checks"
         r"\,/\,multiplications; log-softmax per element); and the v1 protocols~\cite{chen2025thesis}"
         r" with an honest prover (max error or share of aborted runs).}",
         r"\label{tab:prec}", r"\setlength{\tabcolsep}{2.5pt}",
         r"\begin{tabular}{lcccl}\toprule",
         r"Function & \textsf{Ours} & \textsf{Naive} & Cost & v1 \\\midrule"]
    for f, name, dom in FUNCS:
        o = med[("scaling", f, "lut", big, "")]
        n = med[("scaling", f, "naive", big, "")]
        c = cost[f]
        cs = f"{c.get('lookup', 0):g}+{c.get('range', 0):g}\\,/\\,{c.get('mul', 0):g}"
        if f in v1:
            err, ab = v1[f]
            v = ("abort 100\\%" if ab == v1n[f] else
                 f"err {err:.0f}" + (f"; abort {100 * ab / v1n[f]:.0f}\\%" if ab else ""))
        else:   # softplus / log-softmax feed v1's log arguments in [1, 2] / [1, n]: Prop. 1
            v = r"err $\le$\,2166" if f == "snake" else "abort 100\\%"
        L.append(f"{name} & {o[2]:.2f}\\,/\\,{o[3]:.2f} & {n[2]:.2f}\\,/\\,{n[3]:.2f} & {cs} & {v}\\\\")
    L += [r"\bottomrule\end{tabular}", r"\end{table}"]
    return "\n".join(L)


def hao_table(med):
    L = [r"\begin{table}[t]\centering\small",
         r"\caption{Calibration: Hao et al.'s released binaries ($10^5$ instances) re-run in our"
         r" setup vs.\ their published numbers (500\,Mbps).}", r"\label{tab:hao}",
         r"\setlength{\tabcolsep}{4pt}",
         r"\begin{tabular}{lrrrr}\toprule",
         r" & \multicolumn{2}{c}{Comm.\ (MB)} & \multicolumn{2}{c}{Time (s), 500\,Mbps}\\"
         r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}",
         r"Protocol & published & ours & published & ours\\\midrule"]
    for h, (pt, pc) in HAO_PUB.items():
        k = ("hao", h, "hao", 100000, HEAD)
        if k not in med:
            continue
        t, c = med[k][:2]
        L.append(f"{h} & {pc:.1f} & {c:.1f} & {pt:.2f} & {t:.2f}\\\\")
    L += [r"\bottomrule\end{tabular}", r"\end{table}"]
    return "\n".join(L)


def soundness_table():
    path = RES / "soundness.txt"
    rows = [dict(re.findall(r"(\w+)=(\S+)", l)) for l in path.read_text().splitlines()
            if l.startswith("SOUNDNESS")] if path.exists() else []
    L = [r"\begin{table}[t]\centering\small",
         r"\caption{Malicious prover on the real emp-zk backend: each witness of one execution is"
         r" incremented in turn. A sound protocol rejects the run or reproduces the honest output;"
         r" ``wrong'' counts accepted runs with a different output.}",
         r"\label{tab:sound}", r"\setlength{\tabcolsep}{4pt}",
         r"\begin{tabular}{llrrr}\toprule",
         r"Function & Protocol & Witnesses & Rejected & Wrong\\\midrule"]
    for r in rows:
        mname = dict(MODES)[r["mode"]]
        L.append(f"{NAME.get(r['func'], r['func'])} & {mname} & {r['witnesses']} & {r['rejected']}"
                 f" & {r['accepted_wrong_output']}\\\\")
    L += [r"\bottomrule\end{tabular}", r"\end{table}"]
    return "\n".join(L), rows


def main():
    OUT.mkdir(exist_ok=True)
    med = load()
    dims = sorted({k[3] for k in med if k[0] == "scaling"})
    big = max(dims)
    v1, v1n = v1_numbers()
    cost = cost_counts()
    (OUT / "main.tex").write_text(main_table(med, big) + "\n")
    (OUT / "scaling.tex").write_text(scaling_table(med, dims) + "\n")
    (OUT / "precision.tex").write_text(precision_table(med, big, v1, v1n, cost) + "\n")
    (OUT / "hao.tex").write_text(hao_table(med) + "\n")
    st, srows = soundness_table()
    (OUT / "soundness.tex").write_text(st + "\n")

    fs = [f for f, _, _ in FUNCS]
    sp = [med[("bandwidth", f, "naive", big, HEAD)][0] / med[("bandwidth", f, "lut", big, HEAD)][0] for f in fs]
    cm = [med[("bandwidth", f, "naive", big, HEAD)][1] / med[("bandwidth", f, "lut", big, HEAD)][1] for f in fs]
    ps = [med[("bandwidth", f, "poly", big, HEAD)][0] / med[("bandwidth", f, "lut", big, HEAD)][0] for f in fs]
    ov = [med[("bandwidth", f, "lut", big, HEAD)][0] / big * 1e6 / (10 if f == "logsoftmax" else 1) for f in fs]
    pl = [med[("scaling", f, "plain", big, "")][0] / big * 1e9 / (10 if f == "logsoftmax" else 1) for f in fs]
    gap = {bw: med[("bandwidth", "sin", "naive", big, bw)][0] / med[("bandwidth", "sin", "lut", big, bw)][0]
           for bw in (BWS[0], BWS[-1])}
    hk = lambda h: ("hao", h, "hao", 100000, HEAD)  # noqa: E731
    hao_c = {h: med[hk(h)][1] / pc for h, (pt, pc) in HAO_PUB.items() if hk(h) in med}
    # exp is excluded: the released binary evaluates 16-bit inputs, a smaller configuration
    hao_t = {h: pt / med[hk(h)][0] for h, (pt, pc) in HAO_PUB.items() if hk(h) in med and h != "exp"}
    dev = max(abs(1 - hao_c[h]) for h in ["div", "sigmoid", "softmax"]) if hao_c else 0
    tf = sorted(hao_t.values()) if hao_t else [0, 0]
    ext = HERE.parent / "zkmath-ext"
    ext_lines = sum(len(p.read_text().splitlines()) for p in
                    [ext / "src/ZKmath-ext.cpp", ext / "src/ZKmath-ext.h",
                     ext / "src/LUT-multi.h", ext / "src/bench_ext.cpp"])
    cpu = "AMD Ryzen 7 9800X3D"
    for line in (RES / "machine.txt").read_text().splitlines() if (RES / "machine.txt").exists() else []:
        if line.startswith("Model name:"):
            cpu = line.split(":", 1)[1].strip()
    macros = {
        "SpeedMin": f"{min(sp):.1f}", "SpeedMax": f"{max(sp):.1f}",
        "CommMin": f"{min(cm):.1f}", "CommMax": f"{max(cm):.1f}",
        "PolySpeedMin": f"{min(ps):.1f}", "PolySpeedMax": f"{max(ps):.1f}",
        "OverMin": f"{min(ov):.0f}", "OverMax": f"{max(ov):.0f}",
        "PlainMin": f"{min(pl):.0f}", "PlainMax": f"{max(pl):.0f}",
        "SinGapLow": f"{gap[BWS[0]]:.1f}", "SinGapHigh": f"{gap[BWS[-1]]:.1f}",
        "CrossN": r"35{,}000",
        "VOneLogExOut": f"{v1['log_ex'][0]:.2f}", "VOneLogExTrue": f"{v1['log_ex'][1]:.2f}",
        "VOneSinErr": "46.5",
        "Setup": (f"All runs use one {cpu} machine with Linux 7.1, a Debian~12 container, GCC~12"
                  r" and \texttt{-O3}."),
        "SoundTotal": str(sum(int(r["witnesses"]) for r in srows)),
        "HaoCommDev": f"{max(100 * dev, 0.1):.1f}\\%",
        "HaoGeluDev": f"{100 * (hao_c.get('gelu', 1) - 1):.0f}\\%",
        "HaoTimeFactor": f"{tf[0]:.0f}--{tf[-1]:.0f}$\\times$",
        "ExtLines": str(ext_lines),
    }
    (OUT / "numbers.tex").write_text("".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items()))
    print("speed-up naive/ours @500Mbps:", dict(zip(fs, [round(s, 2) for s in sp])))
    print("comm naive/ours:", dict(zip(fs, [round(s, 2) for s in cm])))
    print("poly/ours:", dict(zip(fs, [round(s, 2) for s in ps])))
    print("hao comm ratio ours/published:", {h: round(v, 3) for h, v in hao_c.items()})
    print("hao time published/ours:", {h: round(v, 1) for h, v in hao_t.items()})


if __name__ == "__main__":
    main()
