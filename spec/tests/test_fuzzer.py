"""Mutation tests for the soundness fuzzer: if any verifier check is disabled, the fuzzer
must find an accepted wrong output. Without this, 'fuzz passes' would prove nothing."""
import unittest
from unittest import mock

from common import fuzz_soundness, fx, Abort
import zkml.fzk as fzk
from zkml import pi_log, pi_sin, pi_softplus


def _lookup_key_only(self, table, key, *outs):
    if key.v not in table.rows:
        raise Abort("key")


MUTANTS = {
    "check_zero": lambda self, a: None,
    "range": lambda self, bits, a: None,
    "lookup": _lookup_key_only,
}


class TestFuzzerDetectsBrokenVerifier(unittest.TestCase):
    def test_mutants_are_caught(self):
        cases = [(pi_log, fx(3.7)), (pi_sin, fx(1.0)), (pi_softplus, fx(-2.0))]
        for attr, fn in MUTANTS.items():
            for proto, x in cases:
                with self.subTest(mutant=attr, proto=proto.__name__), \
                        mock.patch.object(fzk.FZK, attr, fn):
                    with self.assertRaises(AssertionError):
                        fuzz_soundness(self, proto, x)


if __name__ == "__main__":
    unittest.main()
