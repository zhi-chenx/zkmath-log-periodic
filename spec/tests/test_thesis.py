"""Demonstrates the flaws of the original thesis protocols (these tests PASS when the
flaw is present)."""
import math
import random
import unittest

from common import Abort, Prover, P, run, fx, xr
from zkml import thesis_pi_sin, thesis_pi_log, F2R, R2F


class TestThesisSin(unittest.TestCase):
    def test_unsound_any_output_accepted(self):
        """A malicious prover replaces x_mod and the verifier still accepts."""
        x = fx(0.0)                                   # sin(0) = 0
        target = R2F(math.pi / 2)                     # claim x_mod = pi/2  ->  y ~ 1
        y, _ = run(thesis_pi_sin, x, Prover({"tsin.xmod": lambda v: target}))
        self.assertGreater(F2R(y), 0.99)              # accepted: "sin(0) = 1.0045"

    def test_many_wrong_outputs_accepted(self):
        rng = random.Random(15)
        accepted_wrong = 0
        for _ in range(200):
            x = fx(rng.uniform(-10, 10))
            forged = rng.randrange(0, 25736)
            y, _ = run(thesis_pi_sin, x, Prover({"tsin.xmod": lambda v, g=forged: g}))
            accepted_wrong += abs(F2R(y) - math.sin(xr(x))) > 0.1
        self.assertGreater(accepted_wrong, 150)

    def test_honest_precision(self):
        y, _ = run(thesis_pi_sin, fx(2 * math.pi - 0.001))
        self.assertGreater(F2R(y), 40)                # T5 near 2 pi: ~46 instead of ~0


class TestThesisLog(unittest.TestCase):
    def test_undefined_on_realistic_inputs(self):
        for xh in [0.5, 1.0, 3.7, 200.0, 1e6]:
            with self.assertRaises(Abort):          # top digits are 0 -> log 0 missing
                run(thesis_pi_log, fx(xh))

    def test_wrong_value_when_defined(self):
        x = 2**50 + 2**40 + 3 * 2**24 + 5 * 2**12 + 7
        y, _ = run(thesis_pi_log, x)
        self.assertGreater(abs(F2R(y) - math.log(x / 4096)), 20)   # 50.40 vs 26.34


if __name__ == "__main__":
    unittest.main()
