import math
import random
import unittest

from common import Abort, P, DELTA, run, fx, xr, fuzz_soundness
from zkml import pi_log, F2R

BOUND = 3 * DELTA / 2 + 2.0**-25 + 2.0**-25     # 3 roundings + interpolation + b rounding


class TestLog(unittest.TestCase):
    def check(self, xs, n=60):
        worst = 0.0
        for x in xs:
            y, _ = run(pi_log, x, n=n)
            worst = max(worst, abs(F2R(y) - math.log(x / 4096)))
        self.assertLessEqual(worst, BOUND)
        return worst

    def test_full_domain(self):
        rng = random.Random(8)
        xs = [int(math.exp(rng.uniform(0, math.log(2**60 - 1)))) for _ in range(3000)]
        xs += [rng.randrange(1, 2**60) for _ in range(1000)]
        xs += list(range(1, 3000))
        xs += [2**k + d for k in range(60) for d in (-1, 0, 1) if 0 < 2**k + d < 2**60]
        self.check([x for x in xs if 0 < x < 2**60])

    def test_ml_ranges(self):
        rng = random.Random(9)
        probs = [fx(rng.uniform(DELTA, 1)) for _ in range(1000)]
        self.check([x for x in probs if x > 0])
        sums = [fx(rng.uniform(1, 256)) for _ in range(1000)]
        self.check(sums, n=20)                       # log-softmax: sum in [1, 256]

    def test_rejects_non_positive_and_overflow(self):
        for x in [0, P - 1, P - 4096, 2**60]:
            with self.assertRaises(Abort):
                run(pi_log, x)
        with self.assertRaises(Abort):
            run(pi_log, 2**20, n=20)

    def test_soundness(self):
        rng = random.Random(10)
        for x in [1, 4096, fx(3.7), 2**47 + 999, 2**60 - 1]:
            acc, ab = fuzz_soundness(self, pi_log, x, rng)
            self.assertGreater(ab, 0)

    def test_cost(self):
        _, f = run(pi_log, fx(3.7))
        self.assertEqual((f.cost["lookup"], f.cost["mul"]), (2, 2))


if __name__ == "__main__":
    unittest.main()
