import math
import random
import unittest

from common import Abort, P, DELTA, run, fx, xr, fuzz_soundness
from zkml import pi_sin_turns, pi_sin, pi_periodic, sin_drift_bound, F2R

INTERP = (2 * math.pi / 4096) ** 2 / 2          # first-order interpolation error
BOUND = DELTA + INTERP                          # 2^-13 (table) + 2^-13 (Trunc) + interp


class TestSin(unittest.TestCase):
    def test_turns_exhaustive_exact_grid(self):
        """F = s: tau is on the table grid, so the error is only the output rounding (2^-13)."""
        worst = 0.0
        for u in range(-3 * 4096, 3 * 4096 + 1):
            y, _ = run(pi_sin_turns, u % P)
            worst = max(worst, abs(F2R(y) - math.sin(2 * math.pi * u / 4096)))
        self.assertLessEqual(worst, DELTA / 2 + 1e-12)

    def test_turns_interpolated(self):
        rng = random.Random(4)
        worst = 0.0
        for _ in range(3000):
            F = rng.randrange(13, 49)
            u = rng.randrange(-2**57, 2**57)
            y, _ = run(pi_sin_turns, u % P, F=F)
            tau = (u % 2**F) / 2**F                 # exact fractional part
            worst = max(worst, abs(F2R(y) - math.sin(2 * math.pi * tau)))
        self.assertLessEqual(worst, BOUND)

    def test_radians_accuracy(self):
        rng = random.Random(5)
        pts = [rng.uniform(-4095, 4095) for _ in range(3000)]
        pts += [k * math.pi + e for k in range(-40, 41) for e in (-1e-3, 0, 1e-3)]
        pts += [0.0, DELTA, -DELTA, 2 * math.pi, 1.0, 4095.99]
        drift = sin_drift_bound(4096, 24)
        worst = 0.0
        for xh in pts:
            x = fx(xh)
            y, _ = run(pi_sin, x)
            worst = max(worst, abs(F2R(y) - math.sin(xr(x))))
        self.assertLess(drift, 1e-6)
        self.assertLessEqual(worst, BOUND + drift)
        self.assertLess(worst, 1.01 * DELTA)        # quantisation-limited

    def test_cos_and_sin2(self):
        rng = random.Random(6)
        for _ in range(500):
            x = fx(rng.uniform(-100, 100))
            c, _ = run(pi_sin, x, kind="cos")
            s2, _ = run(pi_sin, x, kind="sin2")
            self.assertLessEqual(abs(F2R(c) - math.cos(xr(x))), BOUND + 1e-6)
            self.assertLessEqual(abs(F2R(s2) - math.sin(xr(x)) ** 2), BOUND + 1e-6)

    def test_domain_edge(self):
        """The verified domain is |x * A| < 2^58, i.e. |x| < 2^24.65 for x_bits = 24."""
        for x in [2**24, -(2**24)]:
            y, _ = run(pi_sin, x % P, x_bits=24)
            self.assertLessEqual(abs(F2R(y) - math.sin(xr(x % P))),
                                 BOUND + sin_drift_bound(2**12, 24))
        for x in [2**25, -(2**25), 2**40]:
            with self.assertRaises(Abort):
                run(pi_sin, x % P, x_bits=24)

    def test_soundness(self):
        rng = random.Random(7)
        for xh in [0.0, 1.0, -2.5, 3.14159, 1234.5, -4000.0]:
            acc, ab = fuzz_soundness(self, pi_sin, fx(xh), rng)
            self.assertGreater(ab, 0)
        for u in [0, 5, -(2**50)]:
            fuzz_soundness(self, pi_sin_turns, u % P, rng)

    def test_cost(self):
        _, f = run(pi_sin, fx(1.0))
        self.assertEqual(f.cost["lookup"], 1)
        self.assertEqual(f.cost["mul"], 1)


if __name__ == "__main__":
    unittest.main()
