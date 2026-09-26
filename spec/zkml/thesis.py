"""The original thesis protocols (Fig. 4.1 / 4.2), implemented literally, for comparison.
The one unspecified step (snapping x_mod to the fixed-point grid) is filled in with R2F."""
import math
from functools import lru_cache

from .fzk import FZK, Auth, Table, S, R2F, F2R
from .blocks import digit_dec


def taylor5(x: float) -> float:
    return x - x**3 / 6 + x**5 / 120


@lru_cache(None)
def thesis_sin_table() -> Table:
    n = math.ceil(2 * math.pi * 2**S)
    return Table("thesis-sin", {xm: (R2F(taylor5(xm / 2**S)),) for xm in range(n)})


def thesis_pi_sin(f: FZK, x: Auth, tag: str = "tsin") -> Auth:
    """Fig. 4.2. Step 1 commits x_mod, but nothing relates [x_mod] to [x]."""
    xhat = F2R(x.v)
    x_mod = xhat - 2 * math.pi * math.floor(xhat / (2 * math.pi))
    xm = f.input(f"{tag}.xmod", R2F(x_mod))
    y = f.input(f"{tag}.y", R2F(taylor5(F2R(xm.v))))
    f.lookup(thesis_sin_table(), xm, y)
    return y


@lru_cache(None)
def thesis_log_table(shift: int, d: int) -> Table:
    """L_i = {x_i, R2F(log(2^shift * x_hat_i))}. The entry x_i = 0 would be log 0,
    so it cannot be built and is missing."""
    return Table(f"thesis-log/{shift}",
                 {v: (R2F(math.log((v << shift) / 2**S)),) for v in range(1, 2**d)})


def thesis_pi_log(f: FZK, x: Auth, d: int = 12, k: int = 5, tag: str = "tlog") -> Auth:
    """Fig. 4.1 with Hao's 12-bit digits (k = 5 covers the 60-bit domain)."""
    digits = digit_dec(f, x, [d] * k, f"{tag}.dd")
    z = Auth(0)
    for i, xi in enumerate(digits):
        tab = thesis_log_table(i * d, d)
        yi = f.input(f"{tag}.y{i}", tab.rows.get(xi.v, (0,))[0])
        f.lookup(tab, xi, yi)
        z = z + yi
    return z
