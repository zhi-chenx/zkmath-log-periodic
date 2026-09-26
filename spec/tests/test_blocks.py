import random
import unittest

from common import FZK, Prover, Abort, P, fuzz_soundness
from zkml.blocks import digit_dec, pos_trunc, trunc_signed, msnzb, sign_abs, range_check
from zkml.protocols import log_k_table


class TestBlocks(unittest.TestCase):
    def test_digit_dec_roundtrip_and_range(self):
        rng = random.Random(1)
        for _ in range(300):
            x = rng.randrange(0, 2**60)
            f = FZK()
            parts = digit_dec(f, f.public(x), [12, 12, 12, 12, 12], "dd")
            self.assertEqual(sum(p.v << (12 * i) for i, p in enumerate(parts)), x)
        for bad in [2**60, P - 1, P - 2**30]:
            with self.assertRaises(Abort):
                digit_dec(FZK(), FZK().public(bad), [12] * 5, "dd")

    def test_digit_dec_sound(self):
        proto = lambda f, x: digit_dec(f, x, [7, 12, 20], "dd")[1]
        for x in [0, 5, 2**38 + 12345, 2**39 - 1]:
            acc, ab = fuzz_soundness(self, proto, x)
            self.assertGreater(ab, 0)

    def test_range_check_large(self):
        range_check(FZK(), FZK().public(2**45 - 1), 45, "r")
        with self.assertRaises(Abort):
            range_check(FZK(), FZK().public(2**45), 45, "r")

    def test_pos_trunc(self):
        rng = random.Random(2)
        for _ in range(300):
            x, t = rng.randrange(0, 2**40), rng.randrange(1, 30)
            self.assertEqual(pos_trunc(FZK(), FZK().public(x), t, 40, "t").v, x >> t)
            self.assertEqual(pos_trunc(FZK(), FZK().public(x), t, 40, "t", rnd=True).v,
                             (x + (1 << (t - 1))) >> t)

    def test_trunc_signed(self):
        rng = random.Random(3)
        for _ in range(300):
            x, t = rng.randrange(-2**40, 2**40), rng.randrange(1, 30)
            got = trunc_signed(FZK(), FZK().public(x % P), t, 41, "t", rnd=False)
            self.assertEqual(got.signed, x >> t)          # python >> is floor
        proto = lambda f, x: trunc_signed(f, x, 13, 41, "t")
        for x in [-(2**40) + 1, -12345, 0, 777, 2**40 - 1]:
            fuzz_soundness(self, proto, x % P)

    def test_msnzb(self):
        tab = log_k_table(60)
        for x in [1, 2, 3, 4095, 4096, 2**59, 2**60 - 1, 123456789]:
            k, _ = msnzb(FZK(), FZK().public(x), 60, tab, "m")
            self.assertEqual(k.v, x.bit_length() - 1)
        for bad in [0, 2**60, P - 1]:
            with self.assertRaises(Abort):
                msnzb(FZK(), FZK().public(bad), 60, tab, "m")
        proto = lambda f, x: msnzb(f, x, 60, tab, "m")[0]
        for x in [1, 4096, 2**45 + 3]:
            acc, ab = fuzz_soundness(self, proto, x)
            self.assertGreater(ab, 0)

    def test_sign_abs(self):
        for x in [-(2**30), -1, 0, 1, 2**30]:
            b, ax, bx = sign_abs(FZK(), FZK().public(x % P), 32, "s")
            self.assertEqual((b.v, ax.v, bx.signed), (int(x < 0), abs(x), x if x < 0 else 0))
        proto = lambda f, x: sign_abs(f, x, 32, "s")[1]
        for x in [-(2**30), -5, 0, 9]:
            fuzz_soundness(self, proto, x % P)


if __name__ == "__main__":
    unittest.main()
