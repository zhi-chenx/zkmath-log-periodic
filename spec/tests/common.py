import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zkml import FZK, Prover, Abort, R2F_round, F2R, P, S  # noqa: E402

DELTA = 2.0**-S
TAMPERS = [1, -1, 2, -2, 3, 1 << 11, -(1 << 12), 1 << 12, 1 << 24, 1 << 40, (P - 1) // 2]


def run(proto, x_field: int, prover: Prover = None, **kw):
    """Run proto on an authenticated input; returns (output field element, FZK)."""
    f = FZK(prover or Prover())
    x = f.public(x_field)
    return proto(f, x, **kw).v, f


def fx(xhat: float) -> int:
    return R2F_round(xhat)


def xr(x_field: int) -> float:
    return F2R(x_field)


def _digit_pairs(labels):
    """Consecutive digits of the same decomposition: '<tag>.d<i>' and '<tag>.d<i+1>'."""
    s = set(labels)
    for lab in labels:
        head, _, idx = lab.rpartition(".d")
        if idx.isdigit() and f"{head}.d{int(idx) + 1}" in s:
            yield lab, f"{head}.d{int(idx) + 1}"


def fuzz_soundness(tc, proto, x_field, rng=None, n_random=40, **kw):
    """Adaptive malicious prover. Tries
      * every single witness shifted by each delta in TAMPERS and by random field elements;
      * carry attacks on every pair of adjacent digits, (+2^w, -1) and (-2^w, +1) for all w,
        which keep the digit sum and so only CheckRange can catch them;
      * random coordinated pairs of witnesses.
    Every accepted run must return the honest output. Returns (#accepted, #aborted)."""
    rng = rng or random.Random(0)
    rec = Prover()
    honest, _ = run(proto, x_field, rec, **kw)
    labels = list(dict.fromkeys(rec.labels))
    cheats = [{lab: d} for lab in labels for d in TAMPERS]
    cheats += [{rng.choice(labels): rng.randrange(1, P)} for _ in range(n_random)]
    for lo, hi in _digit_pairs(labels):
        for w in range(1, 61):
            cheats += [{lo: 1 << w, hi: -1}, {lo: -(1 << w), hi: 1}]
    for _ in range(n_random):
        a, b = rng.sample(labels, 2)
        cheats.append({a: rng.choice(TAMPERS), b: rng.choice(TAMPERS)})
    acc = ab = 0
    for c in cheats:
        prover = Prover({lab: (lambda v, d=d: (v + d) % P) for lab, d in c.items()})
        try:
            out, _ = run(proto, x_field, prover, **kw)
        except Abort:
            ab += 1
            continue
        acc += 1
        tc.assertEqual(out, honest, f"accepted wrong output under tampering {c}")
    return acc, ab
