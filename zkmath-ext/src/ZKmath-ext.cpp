#include "emp-zk/emp-zk-math/ZKmath-ext.h"
#include "emp-zk/emp-zk-math/ZKmath-ext-poly.h"
#include <cmath>
#include <functional>
#include <map>
#include <string>

static const int S = SCALE;           // fractional bits (12)
static const int RB = NUM_RANGE - 1;  // largest range table: 12 bits
static const int MAXB = 60;           // p = 2^61 - 1 > 2^60
static const int U_BITS = 58;         // periodic: |u| < 2^58
static const int F_MAX = 48;
static const int W = 20;              // working scale of the polynomial baselines
static const double TWO_PI = 2 * 3.14159265358979323846;

static int g_party = ALICE;
static long g_inputs = 0, g_cheat_at = -1;  // malicious-prover hook (env EXT_CHEAT=<k>)
typedef std::vector<std::vector<uint64_t> > Cols;
static std::map<std::string, LUTMultiIntFp *> g_tables;

// ------------------------------------------------------------------ field helpers
static inline uint64_t fe(int64_t v)
{
	int64_t r = v % (int64_t)PR;
	return r < 0 ? (uint64_t)(r + (int64_t)PR) : (uint64_t)r;
}
static inline int64_t sdec(uint64_t v)
{
	v %= PR;
	return v <= (PR - 1) / 2 ? (int64_t)v : (int64_t)v - (int64_t)PR;
}
static inline uint64_t pow2(int k) { return 1ULL << k; }
static inline IntFp pubc(int64_t v) { return IntFp(fe(v), PUBLIC); }
static inline IntFp addc(const IntFp &x, int64_t v) { return x + pubc(v); }
static inline IntFp mulc(const IntFp &x, int64_t v) { return x * fe(v); }
static inline IntFp neg(const IntFp &x) { IntFp t(x); return t.negate(); }
static inline IntFp sub(const IntFp &x, const IntFp &y) { return x + neg(y); }
static uint64_t inv_mod(uint64_t a)
{
	uint64_t r = 1, e = PR - 2;
	while (e) {
		if (e & 1) r = mult_mod(r, a);
		a = mult_mod(a, a);
		e >>= 1;
	}
	return r;
}
static inline int bits_for(double mag) { return (int)std::ceil(std::log2(mag)) + 1; }

uint64_t ext_R2F_round(double x, int s) { return fe((int64_t)std::floor(x * std::ldexp(1.0, s) + 0.5)); }
uint64_t ext_pv(const ZKX &c, const IntFp &x) { return c.party == ALICE ? (uint64_t)HIGH64(x.value) : 0; }
// With EXT_CHEAT=k the prover adds 1 to its k-th witness: a sound protocol must then reject.
IntFp ext_in(const ZKX &c, uint64_t v)
{
	if (c.party == ALICE && g_inputs++ == g_cheat_at)
		v = add_mod(v, 1);
	return IntFp(c.party == ALICE ? v : 0, ALICE);
}

long ext_num_inputs() { return g_inputs; }

// ------------------------------------------------------------------ degree-2 checks
// Batched QuickSilver check of x_i * y_i = 0 (booleanity b(1-b) = 0, is-zero gadget). Same
// algebra as emp-zk's FpPolyProof::zkp_inner_prdt, but with an unbounded buffer: one round trip
// per flush instead of one per 1024 constraints. No product is committed.
static std::vector<uint64_t> q_a0, q_a1, q_b;

static void quad_add(const IntFp &x, const IntFp &y)
{
	if (g_party == ALICE) {
		uint64_t w0 = HIGH64(x.value), m0 = LOW64(x.value);
		uint64_t w1 = HIGH64(y.value), m1 = LOW64(y.value);
		q_a0.push_back(mult_mod(m0, m1));
		q_a1.push_back(add_mod(mult_mod(m0, w1), mult_mod(m1, w0)));
	} else {
		q_b.push_back(mult_mod((uint64_t)LOW64(x.value), (uint64_t)LOW64(y.value)));
	}
}

static void quad_check()
{
	int n = g_party == ALICE ? q_a0.size() : q_b.size();
	if (n == 0)
		return;
	FpPolyProof<ExtIO> *pp = FpPolyProof<ExtIO>::fppolyproof;
	ExtIO *io = pp->io;
	std::vector<uint64_t> chi(n);
	uint64_t seed, cs[2];
	__uint128_t ope;
	io->flush();
	if (g_party == ALICE) {
		io->recv_data(&seed, sizeof(uint64_t));
		uni_hash_coeff_gen(chi.data(), seed, n);
		cs[0] = vector_inn_prdt_sum_red(chi.data(), q_a0.data(), n);
		cs[1] = vector_inn_prdt_sum_red(chi.data(), q_a1.data(), n);
		pp->ostriple->vole->extend(&ope, 1);
		cs[0] = add_mod(cs[0], (uint64_t)LOW64(ope));
		cs[1] = add_mod(cs[1], (uint64_t)HIGH64(ope));
		io->send_data(cs, 2 * sizeof(uint64_t));
		io->flush();
	} else {
		PRG prg;
		prg.random_data(&seed, sizeof(uint64_t));
		seed = mod(seed);
		io->send_data(&seed, sizeof(uint64_t));
		io->flush();
		uni_hash_coeff_gen(chi.data(), seed, n);
		uint64_t B = vector_inn_prdt_sum_red(chi.data(), q_b.data(), n);
		pp->ostriple->vole->extend(&ope, 1);
		B = add_mod(B, (uint64_t)LOW64(ope));
		io->recv_data(cs, 2 * sizeof(uint64_t));
		if (add_mod(B, mult_mod(cs[1], pp->delta)) != cs[0])
			CheatRecord::put("ext: degree-2 check fails");
	}
	q_a0.clear();
	q_a1.clear();
	q_b.clear();
}

void ZKX::flush()
{
	if (!zero.empty()) {
		batch_reveal_check_zero(zero.data(), zero.size());
		zero.clear();
	}
	quad_check();
}

void ext_start(int party)
{
	g_party = party;
	g_inputs = 0;
	const char *s = getenv("EXT_CHEAT");
	g_cheat_at = s ? atol(s) : -1;
}

void ext_end()
{
	for (std::map<std::string, LUTMultiIntFp *>::iterator it = g_tables.begin(); it != g_tables.end(); ++it)
		delete it->second;  // runs the final permutation check of every table
	g_tables.clear();
	quad_check();
}

void ext_finish_checks()
{
	FpOSTriple<ExtIO> *ot = g_party == ALICE ? ((ZKFpExecPrv<ExtIO> *)ZKFpExec::zk_exec)->ostriple
	                                         : ((ZKFpExecVer<ExtIO> *)ZKFpExec::zk_exec)->ostriple;
	if (ot->check_cnt != 0) {
		ot->andgate_correctness_check_manage();
		ot->check_cnt = 0;
	}
	ot->auth_helper->flush();
}

// ------------------------------------------------------------------ building blocks
void ext_bool(ZKX &c, const IntFp &b) { quad_add(b, addc(neg(b), 1)); }

static std::vector<int> chunks(int bits)
{
	std::vector<int> v(bits / RB, RB);
	if (bits % RB)
		v.push_back(bits % RB);
	return v;
}

// Commit the n bits of x (the top one takes everything that is left, so an out-of-range x fails
// its booleanity check), prove booleanity and x = sum b_j 2^j.
static std::vector<IntFp> commit_bits(ZKX &c, const IntFp &x, int n)
{
	uint64_t xv = ext_pv(c, x);
	std::vector<IntFp> b(n);
	IntFp acc(0, PUBLIC);
	for (int j = 0; j < n; j++) {
		b[j] = ext_in(c, j == n - 1 ? (xv >> j) : ((xv >> j) & 1));
		ext_bool(c, b[j]);
		acc = acc + b[j] * pow2(j);
	}
	c.zero.push_back(sub(acc, x));
	return b;
}

std::vector<IntFp> ext_digdec(ZKX &c, const IntFp &x, const std::vector<int> &sizes)
{
	int total = 0;
	for (size_t i = 0; i < sizes.size(); i++)
		total += sizes[i];
	assert(total <= MAXB);
	std::vector<IntFp> parts;
	if (!c.lut_range()) {  // no lookups: every digit is a linear combination of committed bits
		std::vector<IntFp> b = commit_bits(c, x, total);
		int sh = 0;
		for (size_t i = 0; i < sizes.size(); i++) {
			IntFp p(0, PUBLIC);
			for (int j = 0; j < sizes[i]; j++)
				p = p + b[sh + j] * pow2(j);
			parts.push_back(p);
			sh += sizes[i];
		}
		return parts;
	}
	// Hao's ΠDigitDec: commit digits, range-check each with a lookup, CheckZero on the sum
	uint64_t xv = ext_pv(c, x);
	IntFp acc(0, PUBLIC);
	int sh = 0;
	for (size_t i = 0; i < sizes.size(); i++) {
		int d = sizes[i];
		bool top = i + 1 == sizes.size();
		IntFp xi = ext_in(c, top ? (xv >> sh) : ((xv >> sh) & (pow2(d) - 1)));
		ext_range(c, xi, d);
		parts.push_back(xi);
		acc = acc + xi * pow2(sh);
		sh += d;
	}
	c.zero.push_back(sub(acc, x));
	return parts;
}

void ext_range(ZKX &c, const IntFp &a, int bits)
{
	assert(0 <= bits && bits <= MAXB);
	if (bits == 0) {
		c.zero.push_back(a);
	} else if (!c.lut_range()) {
		commit_bits(c, a, bits);
	} else if (bits == 1) {
		ext_bool(c, a);
	} else if (bits <= RB) {
		IntFp t(a);
		LUTRange[bits]->LUTRangeread(t);
	} else {
		ext_digdec(c, a, chunks(bits));
	}
}

IntFp ext_pos_trunc(ZKX &c, const IntFp &x, int t, int nbits, bool rnd)
{
	if (t == 0) {
		ext_range(c, x, nbits);
		return x;
	}
	IntFp y = x;
	if (rnd) {
		y = addc(x, (int64_t)pow2(t - 1));
		nbits += 1;
	}
	std::vector<int> s;
	s.push_back(t);
	s.push_back(nbits - t);
	return ext_digdec(c, y, s)[1];
}

IntFp ext_trunc_signed(ZKX &c, const IntFp &x, int t, int bound_bits, bool rnd)
{
	int L = std::max(bound_bits, t);
	IntFp hi = ext_pos_trunc(c, addc(x, (int64_t)pow2(L)), t, L + 1, rnd);
	return addc(hi, -(int64_t)pow2(L - t));
}

// Msnzb: k with 2^k <= x < 2^(k+1) for x in (0, 2^n); returns k and columns 1.. of row k of K
// (column 0 must be 2^k). With lookups: one lookup + two n-bit range checks. Without: the bits
// of x, a prefix-OR chain (n-1 multiplications) and the one-hot msb indicator e; every column is
// then the linear form sum_i e_i K[i].
static IntFp msnzb(ZKX &c, const IntFp &x, int n, LUTMultiIntFp *K, std::vector<IntFp> &extra)
{
	int nc = K->ncols;
	if (c.lut_range()) {
		uint64_t xv = ext_pv(c, x);
		uint64_t kv = xv ? 63 - __builtin_clzll(xv) : 0;
		IntFp k = ext_in(c, kv);
		std::vector<IntFp> cols(nc);
		for (int j = 0; j < nc; j++)
			cols[j] = ext_in(c, K->value(j, kv));
		K->read(k, cols.data());
		ext_range(c, sub(x, cols[0]), n);
		ext_range(c, addc(sub(cols[0] * (uint64_t)2, x), -1), n);
		extra.assign(cols.begin() + 1, cols.end());
		return k;
	}
	std::vector<IntFp> b = commit_bits(c, x, n);
	std::vector<IntFp> o(n);
	o[n - 1] = b[n - 1];
	for (int i = n - 2; i >= 0; i--)
		o[i] = sub(o[i + 1] + b[i], o[i + 1] * b[i]);
	c.zero.push_back(addc(o[0], -1));  // x > 0
	IntFp k(0, PUBLIC);
	extra.assign(nc - 1, IntFp(0, PUBLIC));
	for (int i = 0; i < n; i++) {
		IntFp e = i == n - 1 ? o[i] : sub(o[i], o[i + 1]);
		k = k + e * (uint64_t)i;
		for (int j = 1; j < nc; j++)
			extra[j - 1] = extra[j - 1] + e * K->cols[j][i];
	}
	return k;
}

static void sign_abs(ZKX &c, const IntFp &x, int bits, IntFp &b, IntFp &ax, IntFp &bx)
{
	b = ext_in(c, sdec(ext_pv(c, x)) < 0 ? 1 : 0);
	ext_bool(c, b);
	bx = b * x;
	ax = sub(x, bx * (uint64_t)2);
	ext_range(c, ax, bits);
}

// P(t) = sum_i cf[i] t^i at scale W, t at scale W with t/2^W in [0, tmax]. Horner with signed
// truncations; the truncation bounds follow from the coefficient magnitudes.
static IntFp horner(ZKX &c, const double *cf, int N, const IntFp &t, double tmax)
{
	std::vector<double> H(N);
	H[N - 1] = std::fabs(cf[N - 1]);
	for (int i = N - 2; i >= 0; i--)
		H[i] = std::fabs(cf[i]) + H[i + 1] * tmax;
	IntFp h = ext_trunc_signed(c, t * ext_R2F_round(cf[N - 1], W), W, bits_for(H[N - 1] * tmax) + 2 * W)
	          + IntFp(ext_R2F_round(cf[N - 2], W), PUBLIC);
	for (int i = N - 3; i >= 0; i--)
		h = ext_trunc_signed(c, h * t, W, bits_for(H[i + 1] * tmax) + 2 * W)
		    + IntFp(ext_R2F_round(cf[i], W), PUBLIC);
	return h;
}

// ------------------------------------------------------------------ public tables
static LUTMultiIntFp *get_table(const std::string &key, const std::function<Cols()> &build)
{
	std::map<std::string, LUTMultiIntFp *>::iterator it = g_tables.find(key);
	if (it != g_tables.end())
		return it->second;
	LUTMultiIntFp *t = new LUTMultiIntFp(g_party, build());
	g_tables[key] = t;
	return t;
}

static double per_g(int kind, double t)
{
	if (kind == KIND_SIN) return std::sin(TWO_PI * t);
	if (kind == KIND_COS) return std::cos(TWO_PI * t);
	double s = std::sin(TWO_PI * t);
	return s * s;
}

static double per_dg(int kind, double t)
{
	if (kind == KIND_SIN) return TWO_PI * std::cos(TWO_PI * t);
	if (kind == KIND_COS) return -TWO_PI * std::sin(TWO_PI * t);
	return TWO_PI * std::sin(2 * TWO_PI * t);
}

// i -> (g(i/2^b), g'(i/2^b)) for a 1-periodic g
static LUTMultiIntFp *periodic_table(int kind, int b)
{
	return get_table("per" + std::to_string(kind) + "/" + std::to_string(b), [kind, b]() {
		Cols cols(2, std::vector<uint64_t>(pow2(b)));
		for (uint64_t i = 0; i < pow2(b); i++) {
			double t = (double)i / (double)pow2(b);
			cols[0][i] = ext_R2F_round(per_g(kind, t));
			cols[1][i] = ext_R2F_round(per_dg(kind, t));
		}
		return cols;
	});
}

// k -> (2^k, 2^(n-1-k), (k - s) ln 2)
static LUTMultiIntFp *log_k_table(int n)
{
	return get_table("logk/" + std::to_string(n), [n]() {
		Cols cols(3, std::vector<uint64_t>(n));
		for (int k = 0; k < n; k++) {
			cols[0][k] = pow2(k);
			cols[1][k] = pow2(n - 1 - k);
			cols[2][k] = ext_R2F_round((double)(k - S) * std::log(2.0));
		}
		return cols;
	});
}

// i = z1 - 2^m for z1 in [2^m, 2^(m+1)) -> (ln(z1/2^m), 2^m/z1). No row exists for z1 < 2^m,
// which enforces the normalisation.
static LUTMultiIntFp *log_mant_table(int m)
{
	return get_table("logm/" + std::to_string(m), [m]() {
		Cols cols(2, std::vector<uint64_t>(pow2(m)));
		for (uint64_t i = 0; i < pow2(m); i++) {
			double z1 = (double)(pow2(m) + i);
			cols[0][i] = ext_R2F_round(std::log(z1 / (double)pow2(m)));
			cols[1][i] = ext_R2F_round((double)pow2(m) / z1);
		}
		return cols;
	});
}

// v -> e^(-(v << shift)/2^s)
static LUTMultiIntFp *exp_table(int shift, int d)
{
	return get_table("exp/" + std::to_string(shift) + "/" + std::to_string(d), [shift, d]() {
		Cols cols(1, std::vector<uint64_t>(pow2(d)));
		for (uint64_t v = 0; v < pow2(d); v++)
			cols[0][v] = ext_R2F_round(std::exp(-(double)(v << shift) / (double)pow2(S)));
		return cols;
	});
}

// ------------------------------------------------------------------ periodic functions
// No-LUT variant: the same verified reduction mod 1 (as bits), quadrant folding with two bits,
// and an odd degree-7 polynomial for sin(2 pi t) on [0, 1/4] (scripts/polyfit.py).
static IntFp periodic_poly(ZKX &c, const IntFp &u, int F, int kind)
{
	assert(F >= 3 && F <= F_MAX);
	int St = std::min(W, F), drop = F - St;
	int64_t shift = kind == KIND_COS ? (int64_t)pow2(F - 2) : 0;  // cos(2 pi t) = sin(2 pi (t + 1/4))
	std::vector<int> sz;
	if (drop)
		sz.push_back(drop);
	sz.push_back(St - 2);
	sz.push_back(1);
	sz.push_back(1);
	sz.push_back(U_BITS + 1 - F);
	std::vector<IntFp> p = ext_digdec(c, addc(u, (int64_t)pow2(U_BITS) + shift), sz);
	int o = drop ? 1 : 0;
	IntFp r = p[o], q0 = p[o + 1], q1 = p[o + 2];
	IntFp t = r + q0 * addc(mulc(r, -2), (int64_t)pow2(St - 2));  // fold into [0, 1/4]
	t = mulc(t, pow2(W - St));
	IntFp w = ext_pos_trunc(c, t * t, W, 2 * (W - 2) + 1, true);
	std::vector<double> H(SIN2PI_N);
	H[SIN2PI_N - 1] = std::fabs(SIN2PI_C[SIN2PI_N - 1]);
	for (int i = SIN2PI_N - 2; i >= 0; i--)
		H[i] = std::fabs(SIN2PI_C[i]) + H[i + 1] / 16;
	IntFp h = horner(c, SIN2PI_C, SIN2PI_N, w, 1.0 / 16);
	IntFp s2w = h * t;  // sin(2 pi t) at scale 2W
	int bound = bits_for(H[0] / 4) + 2 * W;
	if (kind == KIND_SIN2) {
		IntFp sw = ext_trunc_signed(c, s2w, W, bound);
		return ext_pos_trunc(c, sw * sw, 2 * W - S, 2 * W + 2, true);
	}
	IntFp y = ext_trunc_signed(c, s2w, 2 * W - S, bound);
	return sub(y, (q1 * y) * (uint64_t)2);  // (1 - 2 q1) y
}

// Our ΠPeriodic (spec: protocols.py pi_periodic): g(u / 2^F) for |u| < 2^58, F <= 48.
IntFp zk_periodic(ZKX &c, const IntFp &u, int F, int kind)
{
	assert(F >= 0 && F <= F_MAX);
	if (!c.lut_func())
		return periodic_poly(c, u, F, kind);
	int b = std::min(12, F), db = F - b;
	std::vector<int> sizes;
	if (db)
		sizes.push_back(db);
	sizes.push_back(b);
	sizes.push_back(U_BITS + 1 - F);
	std::vector<IntFp> parts = ext_digdec(c, addc(u, (int64_t)pow2(U_BITS)), sizes);
	IntFp idx = db ? parts[1] : parts[0];
	LUTMultiIntFp *T = periodic_table(kind, b);
	uint64_t iv = ext_pv(c, idx);
	IntFp g[2] = {ext_in(c, T->value(0, iv)), ext_in(c, T->value(1, iv))};
	T->read(idx, g);
	if (!db)
		return g[0];
	IntFp v = g[1] * parts[0];
	return g[0] + ext_trunc_signed(c, v, F, S + 3 + db);
}

static void radian_scale(int x_bits, int &s_a, int64_t &A)
{
	s_a = std::min(F_MAX - S, U_BITS - x_bits + 2);
	assert(s_a >= 0);
	A = llround(std::ldexp(1.0, s_a) / TWO_PI);
}

IntFp zk_sin(ZKX &c, const IntFp &x, int x_bits, int kind)
{
	int s_a;
	int64_t A;
	radian_scale(x_bits, s_a, A);
	return zk_periodic(c, x * (uint64_t)A, S + s_a, kind);
}

IntFp zk_snake(ZKX &c, const IntFp &x, double a, int x_bits)
{
	int s_a = std::min(F_MAX - S, U_BITS - x_bits + 2 - std::max(0, (int)std::ceil(std::log2(a))));
	int64_t A = llround(a * std::ldexp(1.0, s_a) / TWO_PI);
	IntFp s2 = zk_periodic(c, x * (uint64_t)A, S + s_a, KIND_SIN2);
	const int s_inv = 24;
	uint64_t inv = ext_R2F_round(1 / a, s_inv);
	int bound = S + 1 + s_inv + std::max(0, (int)std::ceil(std::log2(1 / a))) + 1;
	return x + ext_trunc_signed(c, s2 * inv, s_inv, bound);
}

// ------------------------------------------------------------------ logarithm
IntFp zk_log(ZKX &c, const IntFp &x, int n)
{
	assert(2 <= n && n <= 60);
	int m = std::min(12, n - 1);
	std::vector<IntFp> ex;
	msnzb(c, x, n, log_k_table(n), ex);
	IntFp q = ex[0], ck = ex[1];
	IntFp z = x * q;  // multiplicative normalisation: z in [2^(n-1), 2^n)
	std::vector<int> sz;
	if (c.lut_func()) {
		sz.push_back(n - 1 - m);
		sz.push_back(m + 1);
		std::vector<IntFp> p = ext_digdec(c, z, sz);
		LUTMultiIntFp *M = log_mant_table(m);
		IntFp idx = addc(p[1], -(int64_t)pow2(m));
		uint64_t iv = ext_pv(c, idx);
		IntFp ab[2] = {ext_in(c, M->value(0, iv)), ext_in(c, M->value(1, iv))};
		M->read(idx, ab);
		IntFp t = ext_pos_trunc(c, ab[1] * p[0], n - 1, S + n - 1 - m, true);
		return ck + ab[0] + t;
	}
	// no function table: t = z/2^(n-1) - 1 in [0, 1) at scale St, degree-5 polynomial ln(1 + t)
	int St = std::min(W, n - 1);
	if (n - 1 - St)
		sz.push_back(n - 1 - St);
	sz.push_back(St);
	std::vector<IntFp> p = ext_digdec(c, addc(z, -(int64_t)pow2(n - 1)), sz);
	IntFp t = mulc(p.back(), pow2(W - St));
	IntFp P = horner(c, LN1P_C, LN1P_N, t, 1.0);
	return ck + ext_trunc_signed(c, P, W - S, W + 2);
}

// ------------------------------------------------------------------ exponential
IntFp zk_exp_neg(ZKX &c, const IntFp &x, int n)
{
	if (c.lut_func()) {  // Hao's ΠExp: e^(-sum c_i) = prod e^(-c_i), one table per 12-bit digit
		std::vector<int> sizes(n / 12, 12);
		if (n % 12)
			sizes.push_back(n % 12);
		std::vector<IntFp> digits = ext_digdec(c, x, sizes);
		IntFp z;
		int sh = 0;
		for (size_t i = 0; i < sizes.size(); i++) {
			LUTMultiIntFp *T = exp_table(sh, sizes[i]);
			IntFp y = ext_in(c, T->value(0, ext_pv(c, digits[i])));
			T->read(digits[i], &y);
			z = i == 0 ? y : ext_pos_trunc(c, z * y, S, 2 * S + 2, true);
			sh += sizes[i];
		}
		return z;
	}
	// no function table: e^-x = 2^-(k + f) with k + f = x / ln 2 (verified split), 2^-k from the
	// bits of k (exact integer product), 2^-f by a degree-4 polynomial, k >= 32 by an is-zero test
	const int SL = 16;
	const int64_t L = llround(std::ldexp(1.0, SL) / std::log(2.0));
	IntFp V = x * (uint64_t)L;
	int vbits = n + SL + 1, fs = S + SL, drop = fs - W, kh = vbits - fs - 5;
	assert(drop > 0 && kh > 0);
	std::vector<int> sz;
	sz.push_back(drop);
	sz.push_back(W);
	for (int i = 0; i < 5; i++)
		sz.push_back(1);
	sz.push_back(kh);
	std::vector<IntFp> p = ext_digdec(c, V, sz);
	IntFp G;
	for (int i = 0; i < 5; i++) {  // G = prod_i (k_i ? 1 : 2^(2^i)) = 2^(31 - (k mod 32))
		IntFp fi = addc(mulc(p[2 + i], -(int64_t)(pow2(1 << i) - 1)), (int64_t)pow2(1 << i));
		G = i == 0 ? fi : G * fi;
	}
	IntFp P = horner(c, EXP2N_C, EXP2N_N, p[1], 1.0);
	IntFp y = ext_pos_trunc(c, G * P, 31 + W - S, 31 + W + 1, true);
	uint64_t kv = ext_pv(c, p[7]);
	IntFp inv = ext_in(c, kv ? inv_mod(kv) : 0);
	IntFp zf = addc(neg(p[7] * inv), 1);  // zf = 1{k_high = 0}
	quad_add(p[7], zf);
	return y * zf;
}

// ------------------------------------------------------------------ activations
IntFp zk_softplus(ZKX &c, const IntFp &x, int x_bits)
{
	IntFp b, ax, bx;
	sign_abs(c, x, x_bits, b, ax, bx);
	IntFp e = zk_exp_neg(c, ax, x_bits);
	return sub(x, bx) + zk_log(c, addc(e, (int64_t)pow2(S)), S + 2);
}

IntFp zk_max(ZKX &c, const IntFp *x, int len, int bits)
{
	int64_t best = sdec(ext_pv(c, x[0]));
	for (int j = 1; j < len; j++)
		best = std::max(best, sdec(ext_pv(c, x[j])));
	IntFp m = ext_in(c, fe(best));
	IntFp prod;
	for (int j = 0; j < len; j++) {
		IntFp d = sub(m, x[j]);
		ext_range(c, d, bits);
		prod = j == 0 ? d : prod * d;
	}
	c.zero.push_back(prod);
	return m;
}

void zk_log_softmax(ZKX &c, const IntFp *x, IntFp *y, int len, int x_bits)
{
	IntFp m = zk_max(c, x, len, x_bits + 1);
	IntFp s(0, PUBLIC);
	for (int j = 0; j < len; j++)
		s = s + zk_exp_neg(c, sub(m, x[j]), x_bits + 1);
	int lg = (int)std::ceil(std::log2((double)len));
	IntFp L = zk_log(c, s, S + lg + 1);
	for (int j = 0; j < len; j++)
		y[j] = sub(sub(x[j], m), L);
}
