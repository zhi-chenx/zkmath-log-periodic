"""Corrected protocols: PiPeriodic / PiSin / PiSnake and PiLog / PiExp / PiSoftplus.

Error bounds are in real units; Delta = 2^-s = 2.44e-4 (s = 12).
"""
import math
from functools import lru_cache

from .fzk import FZK, Auth, Table, S, R2F_round, P
from .blocks import digit_dec, pos_trunc, trunc_signed, msnzb, sign_abs, range_check

TWO_PI = 2 * math.pi
IDX_BITS = 12          # table index bits per period -> 4096-entry tables
U_BITS = 58            # |u| < 2^58 for the periodic reduction
F_MAX = 48             # fraction bits of u (Trunc of g1*delta needs S+3+F-12+2 <= 60)

# --------------------------------------------------------------------------- periodic
PERIODIC = {  # g(tau) with period 1, and g'(tau)
    "sin":  (lambda t: math.sin(TWO_PI * t),      lambda t: TWO_PI * math.cos(TWO_PI * t)),
    "cos":  (lambda t: math.cos(TWO_PI * t),      lambda t: -TWO_PI * math.sin(TWO_PI * t)),
    "sin2": (lambda t: math.sin(TWO_PI * t) ** 2, lambda t: TWO_PI * math.sin(2 * TWO_PI * t)),
}


@lru_cache(None)
def periodic_table(kind: str, b: int) -> Table:
    g, dg = PERIODIC[kind]
    return Table(f"{kind}/{b}", {i: (R2F_round(g(i / 2**b)), R2F_round(dg(i / 2**b)))
                                 for i in range(2**b)})


def pi_periodic(f: FZK, u: Auth, F: int, kind: str, tag: str = "per") -> Auth:
    """[y] = R2F(g(u / 2^F)) for a 1-periodic g, with u signed and |u| < 2^58, F <= 48.

    1. u' = u + 2^58 >= 0. 2^58 is a multiple of 2^F, so frac(u'/2^F) = frac(u/2^F).
    2. DigitDec(u') = hi || idx || delta. The reduction mod 1 is exact and verified:
       tau = idx/2^b + delta/2^F. (This fixes the thesis' unconstrained x_mod.)
    3. Lookup (idx -> g(idx/2^b), g'(idx/2^b)) in one 2^b-entry table.
    4. y = g0 + Trunc(g1 * delta, F): first-order interpolation.
    Error <= 2^-13 (g0) + 2^-13 (Trunc) + (2 pi 2^-b)^2 / 2 (= 1.2e-6 for b=12)."""
    assert 0 <= F <= F_MAX
    b = min(IDX_BITS, F)
    db = F - b
    sizes = ([db] if db else []) + [b, U_BITS + 1 - F]
    parts = digit_dec(f, u + (1 << U_BITS), sizes, f"{tag}.dd")
    delta, idx = (parts[0], parts[1]) if db else (None, parts[0])
    tab = periodic_table(kind, b)
    row = tab.rows.get(idx.v, (0, 0))
    g0, g1 = f.input(f"{tag}.g0", row[0]), f.input(f"{tag}.g1", row[1])
    f.lookup(tab, idx, g0, g1)
    if not db:
        return g0
    v = f.mul(g1, delta)                                  # |v| < 2^(s+3) * 2^db
    return g0 + trunc_signed(f, v, F, S + 3 + db, f"{tag}.tr")


def pi_sin_turns(f: FZK, u: Auth, F: int = S, tag: str = "sin") -> Auth:
    """sin(2 pi u/2^F). Recommended: fold 1/(2 pi) into the model parameter."""
    return pi_periodic(f, u, F, "sin", tag)


def radian_scale(x_bits: int):
    """Choose s_a and A = round(2^s_a / 2pi) so that |x*A| < 2^58 for |x| < 2^x_bits."""
    s_a = min(F_MAX - S, U_BITS - x_bits + 2)
    assert s_a >= 0, "input bound too large"
    return s_a, round(2**s_a / TWO_PI)


def sin_drift_bound(xhat_max: float, x_bits: int) -> float:
    """Worst-case angle error of the public constant A ~ 2^s_a / 2pi."""
    s_a, A = radian_scale(x_bits)
    return TWO_PI * xhat_max * abs(A / 2**s_a - 1 / TWO_PI)


def pi_sin(f: FZK, x: Auth, x_bits: int = 24, kind: str = "sin", tag: str = "sin") -> Auth:
    """sin(x_hat) for x_hat in radians, |x| < 2^x_bits (field units). Aborts outside.
    u = x * A (a local operation) turns radians into turns with F = s + s_a fraction bits."""
    s_a, A = radian_scale(x_bits)
    return pi_periodic(f, x * A, S + s_a, kind, tag)


def pi_snake(f: FZK, x: Auth, a: float, x_bits: int = 24, tag: str = "snake") -> Auth:
    """snake_a(x) = x + sin^2(a x)/a with public a > 0. Tabulates sin^2 directly, so no
    squaring multiplication is needed."""
    s_a = min(F_MAX - S, U_BITS - x_bits + 2 - max(0, math.ceil(math.log2(a))))
    A = round(a * 2**s_a / TWO_PI)
    s2 = pi_periodic(f, x * A, S + s_a, "sin2", f"{tag}.per")
    s_inv = 24
    inv = R2F_round(1 / a, s_inv)
    bound = S + 1 + s_inv + max(0, math.ceil(math.log2(1 / a))) + 1
    return x + trunc_signed(f, s2 * inv, s_inv, bound, f"{tag}.tr")


# --------------------------------------------------------------------------- log
@lru_cache(None)
def log_k_table(n: int) -> Table:
    """k -> (2^k, 2^(n-1-k), R2F((k - s) ln 2))."""
    return Table(f"logk/{n}", {k: (2**k, 2**(n - 1 - k), R2F_round((k - S) * math.log(2)))
                               for k in range(n)})


@lru_cache(None)
def log_mant_table(m: int) -> Table:
    """z1 in [2^m, 2^(m+1)) -> (R2F(ln(z1/2^m)), R2F(2^m/z1)). Leaving out z1 < 2^m
    enforces the normalisation."""
    return Table(f"logm/{m}", {z1: (R2F_round(math.log(z1 / 2**m)), R2F_round(2**m / z1))
                               for z1 in range(2**m, 2**(m + 1))})


def pi_log(f: FZK, x: Auth, n: int = 60, m: int = 12, tag: str = "log") -> Auth:
    """ln(x_hat) for x in (0, 2^n) (x_hat = x/2^s). Aborts for x <= 0 or x >= 2^n.

    1. Msnzb: k with 2^k <= x < 2^(k+1); look up 2^(n-1-k) and c_k = (k-s) ln 2.
    2. z = x * 2^(n-1-k) in [2^(n-1), 2^n)            (multiplicative normalisation)
    3. DigitDec(z) = z1 || z0, z1 = top m+1 bits; look up a = ln z1_hat, b = 1/z1_hat.
    4. y = c_k + a + Round(b * z0 / 2^(n-1))            (ln z_hat ~ ln z1_hat + r/z1_hat)
    Error <= 3 * 2^-13 + 2^-2m-1 + 2^-m-13  (= 3.66e-4 for m = 12)."""
    assert 2 <= n <= 60
    m = min(m, n - 1)
    k, (q, ck) = msnzb(f, x, n, log_k_table(n), f"{tag}.msnzb")
    z = f.mul(x, q)
    z0, z1 = digit_dec(f, z, [n - 1 - m, m + 1], f"{tag}.dd")
    tab = log_mant_table(m)
    row = tab.rows.get(z1.v, (0, 0))
    a, b = f.input(f"{tag}.a", row[0]), f.input(f"{tag}.b", row[1])
    f.lookup(tab, z1, a, b)
    t = pos_trunc(f, f.mul(b, z0), n - 1, S + n - 1 - m, f"{tag}.tr", rnd=True)   # b <= 2^s
    return ck + a + t


# --------------------------------------------------------------------------- exp / softplus
@lru_cache(None)
def exp_table(shift: int, d: int) -> Table:
    return Table(f"exp/{shift}", {v: (R2F_round(math.exp(-(v << shift) / 2**S)),)
                                  for v in range(2**d)})


def pi_exp_neg(f: FZK, x: Auth, n: int = 32, tag: str = "exp") -> Auth:
    """Hao et al. PiExp: e^(-x_hat) for x in [0, 2^n). Digits of 12 bits; the product of the
    per-digit lookups is correct because e^(-sum c_i) = prod e^(-c_i)."""
    sizes = [12] * (n // 12) + ([n % 12] if n % 12 else [])
    digits = digit_dec(f, x, sizes, f"{tag}.dd")
    z, sh = None, 0
    for i, (xi, d) in enumerate(zip(digits, sizes)):
        tab = exp_table(sh, d)
        yi = f.input(f"{tag}.y{i}", tab.rows.get(xi.v, (0,))[0])
        f.lookup(tab, xi, yi)
        z = yi if z is None else pos_trunc(f, f.mul(z, yi), S, 2 * S + 2, f"{tag}.tr{i}", rnd=True)
        sh += d
    return z


def pi_softplus(f: FZK, x: Auth, x_bits: int = 32, tag: str = "softplus") -> Auth:
    """softplus(x) = ReLU(x) + ln(1 + e^-|x|). The log argument lies in [1, 2], so PiLog
    runs with n = s + 2."""
    b, ax, bx = sign_abs(f, x, x_bits, f"{tag}.abs")
    e = pi_exp_neg(f, ax, x_bits, f"{tag}.exp")
    return (x - bx) + pi_log(f, e + (1 << S), S + 2, tag=f"{tag}.log")


# --------------------------------------------------------------------------- log-softmax
def pi_max(f: FZK, xs, bits: int, tag: str = "max") -> Auth:
    """Hao's max: P inputs m; V checks m - x_j in [0, 2^bits) for all j and prod_j (m - x_j) = 0."""
    m = f.input(f"{tag}.m", max(xs, key=lambda a: a.signed).v)
    prod = None
    for j, x in enumerate(xs):
        d = m - x
        range_check(f, d, bits, f"{tag}.r{j}")
        prod = d if prod is None else f.mul(prod, d)
    f.check_zero(prod)
    return m


def pi_log_softmax(f: FZK, xs, x_bits: int = 23, tag: str = "lsm"):
    """y_j = (x_j - m) - ln(sum_k e^(x_k - m)), m = max, |x_j| < 2^x_bits. The log argument lies
    in [1, n], i.e. below 2^(s + ceil(log2 n) + 1), so PiLog runs on few bits and no division
    is needed. Error <= n * 1.5 Delta (sum of PiExp errors) + 1.5 Delta (PiLog)."""
    m = pi_max(f, xs, x_bits + 1, f"{tag}.max")
    s = Auth(0)
    for j, x in enumerate(xs):
        s = s + pi_exp_neg(f, m - x, x_bits + 1, f"{tag}.exp{j}")
    lg = pi_log(f, s, S + math.ceil(math.log2(len(xs))) + 1, tag=f"{tag}.log")
    return [x - m - lg for x in xs]
