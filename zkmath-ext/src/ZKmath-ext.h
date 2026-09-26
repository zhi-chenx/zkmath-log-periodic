#pragma once
// Extension of Hao et al.'s ZKMath with the thesis-v2 protocols:
//   ΠPeriodic / ΠSin (verified reduction mod 1 + one 2^12-row table + 1st-order interpolation),
//   ΠLog (Msnzb normalisation + mantissa table), and the activations snake, softplus, log-softmax.
// Every protocol runs in three modes so that the lookup-table technique can be measured:
//   EXT_LUT   : our protocols (range checks and function evaluation by table lookup),
//   EXT_POLY  : Hao's LUT building blocks, but the function tables replaced by polynomials,
//   EXT_NAIVE : no lookups at all (bit decomposition + polynomials / bitwise products).
// The LUT mode mirrors spec/zkml/protocols.py bit for bit (the executable spec).
#include "emp-zk/emp-zk-math/ZKmath-global.h"
#include "emp-zk/emp-zk-math/LUT-multi.h"
#include <vector>

enum ExtMode { EXT_LUT = 0, EXT_POLY = 1, EXT_NAIVE = 2 };
enum ExtKind { KIND_SIN = 0, KIND_COS = 1, KIND_SIN2 = 2 };

struct ZKX {
	int party;
	int mode;
	std::vector<IntFp> zero;   // deferred CheckZero
	ZKX(int _party, int _mode) : party(_party), mode(_mode) {}
	bool lut_range() const { return mode != EXT_NAIVE; }
	bool lut_func() const { return mode == EXT_LUT; }
	void flush();              // CheckZero + batched degree-2 (booleanity) checks
};

void ext_start(int party);     // call after startComputation()
void ext_end();                // final lookup checks of our tables
void ext_finish_checks();      // force the pending multiplication-triple / CheckZero checks

// ---- building blocks (one element) ----
uint64_t ext_pv(const ZKX &c, const IntFp &x);              // prover's clear value (0 for V)
IntFp ext_in(const ZKX &c, uint64_t v);                      // prover input (witness)
long ext_num_inputs();                                       // witnesses committed so far
void ext_bool(ZKX &c, const IntFp &b);                       // b in {0,1}
std::vector<IntFp> ext_digdec(ZKX &c, const IntFp &x, const std::vector<int> &sizes);
void ext_range(ZKX &c, const IntFp &a, int bits);            // a in [0, 2^bits)
IntFp ext_pos_trunc(ZKX &c, const IntFp &x, int t, int nbits, bool rnd);
IntFp ext_trunc_signed(ZKX &c, const IntFp &x, int t, int bound_bits, bool rnd = true);

// ---- protocols (one element) ----
IntFp zk_periodic(ZKX &c, const IntFp &u, int F, int kind);  // g(u / 2^F), g 1-periodic
IntFp zk_sin(ZKX &c, const IntFp &x, int x_bits = 24, int kind = KIND_SIN);  // radians
IntFp zk_log(ZKX &c, const IntFp &x, int n = 60);            // ln(x/2^s), x in (0, 2^n)
IntFp zk_exp_neg(ZKX &c, const IntFp &x, int n = 24);        // e^(-x/2^s), x in [0, 2^n)
IntFp zk_snake(ZKX &c, const IntFp &x, double a, int x_bits = 24);
IntFp zk_softplus(ZKX &c, const IntFp &x, int x_bits = 24);
IntFp zk_max(ZKX &c, const IntFp *x, int len, int bits);
void zk_log_softmax(ZKX &c, const IntFp *x, IntFp *y, int len, int x_bits = 23);

// Real-number reference of the fixed-point encoding (s = 12).
uint64_t ext_R2F_round(double x, int s = SCALE);
