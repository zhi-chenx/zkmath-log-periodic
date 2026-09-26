"""Ideal functionalities F_ZK / F_ZK^Lookup of Hao et al. (USENIX Sec '24, Fig. 2-3).

Protocols in the thesis and in Hao et al. are specified and proven in the
(F_ZK, F_ZK^Lookup)-hybrid model, so they are simulated here at exactly that level:

* ``Auth`` is an authenticated value [x]_p. In the real system it is an IT-MAC; here the
  functionality stores the value. Linear operations with public constants are local.
* The prover commits witnesses through ``FZK.input``. Every witness goes through
  ``Prover.w``, so a test can replace any witness with an arbitrary value (a malicious prover).
* The verifier's checks (CheckZero, CheckLookup, CheckRange) raise ``Abort``.
  Soundness then means: if the verifier accepts, the output equals the honest output.
"""
from collections import Counter
from dataclasses import dataclass
import math

P = 2**61 - 1
S = 12
RANGE_BITS = 12          # largest public range table (Hao: 12-bit digits)


class Abort(Exception):
    pass


def enc(v: int) -> int:
    return v % P


def dec(v: int) -> int:
    v %= P
    return v if v <= (P - 1) // 2 else v - P


def R2F(x: float, s: int = S) -> int:
    """Hao et al.: floor(x * 2^s) mod p."""
    return math.floor(x * 2**s) % P


def R2F_round(x: float, s: int = S) -> int:
    """Nearest rounding, used for public table entries."""
    return math.floor(x * 2**s + 0.5) % P


def F2R(v: int, s: int = S) -> float:
    return dec(v) / 2**s


class Auth:
    __slots__ = ("v",)

    def __init__(self, v: int):
        self.v = v % P

    def _c(self, o):
        return o.v if isinstance(o, Auth) else o

    def __add__(self, o): return Auth(self.v + self._c(o))
    __radd__ = __add__
    def __sub__(self, o): return Auth(self.v - self._c(o))
    def __rsub__(self, o): return Auth(self._c(o) - self.v)
    def __neg__(self): return Auth(-self.v)

    def __mul__(self, c: int):
        assert isinstance(c, int), "use FZK.mul for [x]*[y]"
        return Auth(self.v * c)
    __rmul__ = __mul__

    @property
    def signed(self) -> int:
        return dec(self.v)


class Prover:
    """Honest by default. ``cheat`` maps a witness label to ``f(honest_value) -> value``."""

    def __init__(self, cheat=None):
        self.cheat = dict(cheat or {})
        self.labels = []

    def w(self, label: str, value: int) -> int:
        self.labels.append(label)
        f = self.cheat.get(label)
        return value if f is None else f(value)


@dataclass(frozen=True)
class Table:
    """Public lookup table: key -> tuple of output columns (field elements)."""
    name: str
    rows: dict

    def __len__(self):
        return len(self.rows)


class FZK:
    def __init__(self, prover: Prover = None):
        self.prover = prover or Prover()
        self.cost = Counter()

    def input(self, label: str, value: int) -> Auth:
        self.cost["input"] += 1
        return Auth(self.prover.w(label, value))

    def public(self, value: int) -> Auth:
        return Auth(value)

    def mul(self, a: Auth, b: Auth) -> Auth:
        self.cost["mul"] += 1
        return Auth(a.v * b.v)

    def check_zero(self, a: Auth):
        self.cost["check_zero"] += 1
        if a.v % P:
            raise Abort("CheckZero")

    def lookup(self, table: Table, key: Auth, *outs: Auth):
        self.cost["lookup"] += 1
        row = table.rows.get(key.v)
        if row is None or row != tuple(o.v for o in outs):
            raise Abort(f"CheckLookup[{table.name}]")

    def range(self, bits: int, a: Auth):
        assert bits <= RANGE_BITS
        self.cost["range"] += 1
        if not 0 <= a.v < 2**bits:
            raise Abort(f"CheckRange[{bits}]")
