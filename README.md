# zkmath-log-periodic

Zero-knowledge proofs for the **logarithm** and the **sine** in the lookup-based VOLE framework of
Hao et al., *Scalable Zero-knowledge Proofs for Non-linear Functions in Machine Learning* (USENIX
Security '24; code: [CryptMatrix/ZKMath](https://github.com/CryptMatrix/ZKMath)). These two protocols
also give the softplus, log-softmax and snake activations.

## The problem

Hao et al. prove ReLU, sigmoid, GELU and softmax cheaply. Each input is split into 12-bit digits,
and each digit is looked up in a small public table. The framework has no logarithm or sine, but
softplus and log-softmax need a logarithm, and periodic activations such as snake (used in neural
audio codecs) need a sine. This repository:

1. **adds ΠLog and ΠSin to the framework** using only its own building blocks (DigitDec, range
   checks, Msnzb, lookups), with proven error bounds;
2. **implements them in Hao et al.'s C++ code** (ZKMath on emp-zk);
3. **benchmarks them as in the original paper** (Tables 4–5: 10³–10⁵ instances, 200 Mbps–1 Gbps).
   The baseline is the same functions proven without lookups in the same backend.

My master's thesis (January 2025) sketched both protocols on paper, following the exponential's
pattern: one lookup per digit, then recombine the results. At the time they were not implemented or
checked in code. Writing the code for this repository showed that the sketches needed corrections:
the error margins were larger than estimated, the logarithm's recombination gives `log Π cᵢ` rather
than `log Σ cᵢ`, and the sine needs a constraint that binds the reduced angle to the input. The
revised designs are:

- **ΠLog** normalises with Msnzb, as Hao et al.'s division does, then uses one 2¹²-row mantissa
  table with a first-order correction. Error ≤ 1.5 Δ on (0, 2⁶⁰), where Δ = 2⁻¹².
- **ΠSin** (any periodic function) works in *turns*. The reduction mod 1 is then exactly a
  verified digit decomposition, followed by one 2¹²-row table and one multiplication. Error ≈ 1 Δ.

[`paper/main.pdf`](paper/main.pdf) gives the constructions, the proofs and the details of what
changed with respect to the thesis.

## Results

10⁵ instances, 500 Mbps, both parties single-threaded on one machine (AMD Ryzen 7 9800X3D).

| | |
|---|---|
| Speed-up vs. the no-lookup baseline (same backend) | 4.0–7.1× |
| Communication reduction vs. the no-lookup baseline | 4.1–7.1× |
| Speed-up vs. lookup range checks + polynomial evaluation | 1.6–3.5× |
| Max error, in Δ = 2⁻¹² | sin/snake 1.0, ln 1.5, softplus 1.2, log-softmax 3.8 |
| C++ output vs. Python spec | bit-identical over 35,000 outputs |
| Tampered-witness runs on the real backend | 878 / 878 rejected |

Hao et al.'s 50–179× speed-ups are measured against Mystique (Boolean circuits). They cannot be
compared with the factors above, which use the same backend.

## Newer work (not considered here)

This repository builds on a thesis from January 2025 and stays within Hao et al.'s framework. The
state of the art has moved on since then, and the following work is not compared against:

- **Non-interactive provers.** zkML proofs have largely moved from interactive VOLE to sumcheck +
  lookup SNARKs: zkGPT (USENIX Security '25) reports 279× over Hao et al.'s published GPT-2
  numbers, and OpenLLM (ePrint 2026/1578) ports Hao et al.'s 12-bit digit decomposition to
  KZG/IPA/FRI. See also DeepProve (ePrint 2026/1112), Jolt Atlas (arXiv 2602.17452) and Jin, Li
  and Zhang (TrustCom '25).
- **The same functions in other systems.** Jolt Atlas proves sin/cos with a division-based range
  reduction and a zeroth-order table. zkLLM and DeepProve prove log-sum-exp with an advice value
  and an exponential lookup, an alternative to ΠLog for log-softmax. Kurik and Laud (ePrint
  2024/859, ARES '25) evaluate sin in quarter turns and log via 2ᵏ normalisation, without lookups.
- **A stronger no-lookup baseline.** Agarwal, Baum, Braun and Scholl (Eurocrypt '25) give cheaper
  VOLE range proofs and fixed-point truncation. The 4–7× factors above are relative to a simple
  baseline, not to that one.

## Layout

| Path | Content |
|---|---|
| `paper/` | The paper (LaTeX + PDF). `make_tables.py` generates every table and number from `zkmath-ext/results/`. |
| `spec/` | Pure-Python executable specification in the (F_ZK, F_Lookup)-hybrid model, with an adaptive malicious prover and 33 tests. Standard library only. |
| `zkmath-ext/` | C++ extension of ZKMath. `src/`: protocols, multi-column zk-ROM table and benchmark driver. `scripts/`: benchmark and C++/Python cross-check. `results/`: the data used in the paper. |

ZKMath and emp-toolkit are not included in this repository. The `Containerfile` clones them at
pinned commits, and `build.sh` copies `src/` on top of them.

## Reproduce

You need Linux with rootless **podman** and **python3 ≥ 3.11**. TeX Live is only needed to rebuild
the paper, and the `sch_tbf` kernel module only to limit bandwidth (`BW=`).

```bash
# Python spec: precision, malicious-prover fuzzing, thesis (v1) checks (~5 s)
(cd spec && python3 -m unittest discover -s tests -v)

# C++, everything inside podman (first build ~5 min)
cd zkmath-ext && ./build.sh
./run.sh bench_ext sin lut 1000                  # func: sin|log60|log20|exp|snake|softplus|logsoftmax
BW=500mbit ./run.sh bench_ext log60 lut 100000   # mode: lut (ours)|poly|naive (no lookups)|plain
./run.sh hao_sigmoid                             # Hao et al.'s original binaries
python3 scripts/crosscheck.py 5000 7             # C++ == Python spec -> mismatches=0
./soundness.sh lut sin log60 log20 exp snake softplus logsoftmax   # every tampered witness rejected
python3 scripts/bench.py --out /tmp/bench.csv    # full Tables 4-5 benchmark (~35 min)

# Paper (tables from results/, then latexmk)
cd ../paper && make
```

### Reading the output

Each `bench_ext` run prints one `RESULT` line per party, `[P]` for the prover and `[V]` for the
verifier:

```
[P] RESULT func=sin mode=lut dim=1000 party=1 time_s=0.005426 comm_mb=0.522934 max_err_ulp=0.9848 mean_err_ulp=0.3224 verify=NA witnesses=14000
[V] RESULT func=sin mode=lut dim=1000 party=2 time_s=0.003883 comm_mb=0.000053 max_err_ulp=0.0000 mean_err_ulp=0.0000 verify=OK witnesses=0
```

| Field | Meaning |
|---|---|
| `time_s` | Wall time for `dim` proofs, including every verifier check. The paper uses the larger of `[P]` and `[V]`. `mode=plain` prints only `[P]`, with the time of the unproven `double` evaluation. |
| `comm_mb` | MB sent by that party. The paper uses `[P]` + `[V]`, as Hao et al. do. |
| `max_err_ulp`, `mean_err_ulp` | Error of the proven outputs vs. `double` math, in Δ = 2⁻¹². Only `[P]` reports it, because the verifier never sees the values. |
| `verify` | Only on `[V]`. `OK` means the proof was accepted. A rejected proof prints `verify=FAIL`, or the verifier aborts with `EXIT ... verifier=1` (try `EXT_CHEAT=3 ./run.sh bench_ext sin lut 1`). |
| `witnesses` | Number of values the prover committed. `soundness.sh` tampers with each of them. |

- **What must match:** `comm_mb` and the errors are deterministic and must equal the matching row
  of `results/bench.csv`, e.g. `scaling,sin,lut,1000,,0,…,0.522934,0.000053,0.9848,0.3224,OK`.
  Times depend on the CPU, so compare ratios such as `naive` time / `lut` time, as the paper does.
- **Unit tests:** `Ran 33 tests … OK`. `test_thesis.py` reproduces the issues of the thesis (v1)
  sketches, so it passes when they show up.
- **`crosscheck.py`:** `mismatches=0` means the C++ proof output is bit-identical to the Python spec.
- **`soundness.sh`:** prints `SOUNDNESS … witnesses=W rejected=R accepted_same_output=S
  accepted_wrong_output=X` per function. The protocol passes if `X = 0`. Compare with
  `results/soundness.txt`, where every run is rejected (`R = W`).
- **`bench.py`:** writes one CSV row per run. `paper/make_tables.py` takes the median over
  repetitions and builds the paper's tables.
- **`hao_*`:** these print in Hao et al.'s own format, `time - …` and `communication - … (KB)` per
  party. For sigmoid, 190,955 + 3,491 KB = 189.9 MB, which matches their published figure. Times
  are 4–5× lower than published because of a newer CPU and `-O3`.

## Acknowledgment

The original work was carried out at **Beihang University** (School of Cyber Science and
Technology, Beijing) under the supervision of **Prof. Zongyang Zhang**, and became my master's
thesis at Universidad Politécnica de Madrid (2025). This repository is an individual extension and
implementation that I built on my own on top of that work.

## License

MIT, see [`LICENSE`](LICENSE). ZKMath and emp-toolkit, which are downloaded at build time, are
MIT-licensed by their authors. If you use this work, please also cite Hao et al.
