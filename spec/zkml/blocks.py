"""Building blocks of Hao et al. Sec. 4, realised on top of the ideal functionality.

All non-negativity arguments rely on p = 2^61 - 1 > 2^60: a field element that passes
a range check on at most 60 bits is a genuine integer in [0, 2^60). A "negative" value
p - |v| (with |v| < 2^60) never passes such a check.
"""
from .fzk import FZK, Auth, Table, RANGE_BITS

MAX_BITS = 60


def _chunks(bits: int):
    return [RANGE_BITS] * (bits // RANGE_BITS) + ([bits % RANGE_BITS] if bits % RANGE_BITS else [])


def range_check(f: FZK, a: Auth, bits: int, tag: str):
    """Prove a in [0, 2^bits)."""
    assert 0 <= bits <= MAX_BITS
    if bits == 0:
        f.check_zero(a)
    elif bits <= RANGE_BITS:
        f.range(bits, a)
    else:
        digit_dec(f, a, _chunks(bits), tag)


def digit_dec(f: FZK, x: Auth, sizes, tag: str):
    """Hao PiDigitDec (positive): x = x_{k-1}||...||x_0 with x_i in [0, 2^{d_i}).
    sum(sizes) <= 60 < log2 p, so an accepted decomposition is unique and proves x < 2^sum."""
    assert sum(sizes) <= MAX_BITS
    parts, acc, sh = [], Auth(0), 0
    for i, d in enumerate(sizes):
        # the top digit takes everything left, so an out-of-range x is caught by CheckRange
        top = i == len(sizes) - 1
        xi = f.input(f"{tag}.d{i}", (x.v >> sh) if top else (x.v >> sh) & ((1 << d) - 1))
        range_check(f, xi, d, f"{tag}.d{i}")
        parts.append(xi)
        acc = acc + xi * (1 << sh)
        sh += d
    f.check_zero(acc - x)
    return parts


def pos_trunc(f: FZK, x: Auth, t: int, nbits: int, tag: str, rnd: bool = False):
    """floor(x / 2^t) (or nearest if rnd) for x in [0, 2^nbits). Also proves that range."""
    if t == 0:
        range_check(f, x, nbits, tag)
        return x
    if rnd:
        x, nbits = x + (1 << (t - 1)), nbits + 1
    return digit_dec(f, x, [t, nbits - t], tag)[1]


def trunc_signed(f: FZK, x: Auth, t: int, bound_bits: int, tag: str, rnd: bool = True):
    """Signed truncation for |x| < 2^bound_bits: shift by 2^L (L >= t) into the positive range.
    floor((x + 2^L) / 2^t) = floor(x / 2^t) + 2^(L-t)."""
    L = max(bound_bits, t)
    hi = pos_trunc(f, x + (1 << L), t, L + 1, tag, rnd)
    return hi - (1 << (L - t))


def msnzb(f: FZK, x: Auth, n: int, table: Table, tag: str):
    """Most significant non-zero bit: k with 2^k <= x < 2^(k+1), for x in (0, 2^n).
    ``table`` maps k -> (2^k, *extra columns). Returns k and the authenticated columns.
    Proven with one lookup and two n-bit range checks (x - 2^k >= 0, 2^(k+1) - 1 - x >= 0).
    Aborts for x = 0 or x >= 2^n."""
    kv = max(x.v.bit_length() - 1, 0)
    k = f.input(f"{tag}.k", kv)
    row = table.rows.get(k.v, (0,) * len(next(iter(table.rows.values()))))
    cols = [f.input(f"{tag}.c{j}", c) for j, c in enumerate(row)]
    f.lookup(table, k, *cols)
    pk = cols[0]
    range_check(f, x - pk, n, f"{tag}.lo")
    range_check(f, pk * 2 - 1 - x, n, f"{tag}.hi")
    return k, cols[1:]


def sign_abs(f: FZK, x: Auth, bits: int, tag: str):
    """Returns ([b], [|x|], [b*x]) with b = 1{x < 0}. Proves |x| < 2^bits."""
    b = f.input(f"{tag}.b", 1 if x.signed < 0 else 0)
    f.range(1, b)
    bx = f.mul(b, x)
    ax = x - bx * 2
    range_check(f, ax, bits, f"{tag}.abs")
    return b, ax, bx
