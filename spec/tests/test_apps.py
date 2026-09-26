import math
import random
import unittest

from common import FZK, Abort, P, DELTA, run, fx, xr, fuzz_soundness
from zkml import pi_snake, pi_softplus, pi_exp_neg, pi_log_softmax, F2R

SIN_BOUND = DELTA + (2 * math.pi / 4096) ** 2 / 2
LSM_OFFSETS = [0, -7000, 12000, 300, -25000, 4096, 1, -1, 30000, -40000]   # field units


def lsm_proto(k):
    """log-softmax of a row derived from one authenticated input (public offsets), output k."""
    return lambda f, x: pi_log_softmax(f, [x + d for d in LSM_OFFSETS])[k]


class TestApps(unittest.TestCase):
    def test_exp(self):
        rng = random.Random(11)
        worst = 0.0
        for _ in range(2000):
            x = rng.randrange(0, 2**32)
            y, _ = run(pi_exp_neg, x)
            worst = max(worst, abs(F2R(y) - math.exp(-x / 4096)))
        for x in range(0, 40000, 7):
            y, _ = run(pi_exp_neg, x)
            worst = max(worst, abs(F2R(y) - math.exp(-x / 4096)))
        self.assertLessEqual(worst, 1.5 * DELTA)

    def test_snake(self):
        rng = random.Random(12)
        for a in [0.25, 0.5, 1.0, 1.7, 4.0]:
            worst = 0.0
            for _ in range(600):
                x = fx(rng.uniform(-1000, 1000))
                y, _ = run(pi_snake, x, a=a)
                t = xr(x)
                worst = max(worst, abs(F2R(y) - (t + math.sin(a * t) ** 2 / a)))
            self.assertLessEqual(worst, (SIN_BOUND + 1e-6) / a + DELTA / 2, f"a={a}")

    def test_softplus(self):
        rng = random.Random(13)
        worst = 0.0
        pts = [rng.uniform(-30, 30) for _ in range(2000)] + [0.0, DELTA, -DELTA, 1e5, -1e5]
        for xh in pts:
            x = fx(xh)
            y, _ = run(pi_softplus, x)
            t = xr(x)
            ref = max(t, 0) + math.log1p(math.exp(-abs(t)))
            worst = max(worst, abs(F2R(y) - ref))
        self.assertLessEqual(worst, 3 * DELTA)

    def test_soundness(self):
        rng = random.Random(14)
        for xh in [-3.0, 0.0, 2.5]:
            fuzz_soundness(self, pi_softplus, fx(xh), rng, n_random=20)
            fuzz_soundness(self, pi_snake, fx(xh), rng, n_random=20, a=1.3)

    def test_softplus_domain(self):
        with self.assertRaises(Abort):
            run(pi_softplus, 2**33)

    def test_log_softmax(self):
        rng = random.Random(16)
        worst = 0.0
        for _ in range(300):
            n = rng.choice([2, 3, 10, 16])
            row = [rng.uniform(-10, 10) for _ in range(n)]
            f = FZK()
            ys = pi_log_softmax(f, [f.public(fx(v)) for v in row])
            ts = [xr(fx(v)) for v in row]
            m = max(ts)
            lse = m + math.log(sum(math.exp(t - m) for t in ts))
            worst = max(worst, max(abs(F2R(y.v) - (t - lse)) for y, t in zip(ys, ts)))
        self.assertLessEqual(worst, 16 * 1.5 * DELTA + 1.5 * DELTA)

    def test_log_softmax_soundness(self):
        rng = random.Random(17)
        for xh in [-3.0, 2.5]:
            for k in [0, 4]:
                fuzz_soundness(self, lsm_proto(k), fx(xh), rng, n_random=20)

    def test_log_softmax_domain(self):
        f = FZK()
        with self.assertRaises(Abort):                 # |x| >= 2^23: difference overflows
            pi_log_softmax(f, [f.public(0), f.public(2**24)])


if __name__ == "__main__":
    unittest.main()
