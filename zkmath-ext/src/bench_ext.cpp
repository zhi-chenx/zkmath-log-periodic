// Benchmark driver for the thesis-v2 protocols on top of Hao et al.'s ZKMath (emp-zk).
//   bench_ext <party> <port> <func> <mode> <dim> [seed] [dump.csv]
//   func: sin | log60 | log20 | exp | snake | softplus | logsoftmax (rows of 10)
//   mode: lut (ours) | poly (LUT building blocks, polynomial functions) | naive (no LUT) | plain
// Prints one "RESULT ..." line per party. The measured time covers the protocol and ALL
// verifier checks (lookup permutation checks, multiplication triples, CheckZero, degree-2).
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include <cmath>
#include <fstream>
#include <random>
#include <string>

using namespace emp;
using namespace std;

static const int threads = 1;
static const int LSM = 10;  // log-softmax row length (Hao's softmax benchmark uses dim = 10)

static double F2R(uint64_t v)
{
	v %= PR;
	int64_t s = v <= (PR - 1) / 2 ? (int64_t)v : (int64_t)v - (int64_t)PR;
	return (double)s / 4096.0;
}

static double ref1(const string &f, double x)
{
	if (f == "sin") return sin(x);
	if (f == "log60" || f == "log20") return log(x);
	if (f == "exp") return exp(-x);
	if (f == "snake") return x + sin(x) * sin(x);
	if (f == "softplus") return max(x, 0.0) + log1p(exp(-fabs(x)));
	error("unknown function");
	return 0;
}

static void ref_lsm(const double *x, double *y)
{
	double m = x[0], s = 0;
	for (int j = 1; j < LSM; j++) m = max(m, x[j]);
	for (int j = 0; j < LSM; j++) s += exp(x[j] - m);
	for (int j = 0; j < LSM; j++) y[j] = x[j] - m - log(s);
}

static uint64_t gen_input(const string &f, mt19937_64 &rng)
{
	uniform_real_distribution<double> u01(0.0, 1.0);
	double r = u01(rng);
	if (f == "sin") return ext_R2F_round(-4095 + 8190 * r);
	if (f == "log60") return max<uint64_t>(1, (uint64_t)exp(r * log((double)((1ULL << 60) - 1))));
	if (f == "log20") return ext_R2F_round(1 + 255 * r);
	if (f == "exp") return ext_R2F_round(16 * r);
	if (f == "snake") return ext_R2F_round(-1000 + 2000 * r);
	if (f == "softplus") return ext_R2F_round(-20 + 40 * r);
	if (f == "logsoftmax") return ext_R2F_round(-10 + 20 * r);
	error("unknown function");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 6) {
		fprintf(stderr, "usage: %s <party> <port> <func> <mode> <dim> [seed] [dump]\n", argv[0]);
		return 1;
	}
	int party = atoi(argv[1]), port = atoi(argv[2]);
	string func = argv[3], mname = argv[4];
	int dim = atoi(argv[5]);
	uint64_t seed = argc > 6 ? strtoull(argv[6], nullptr, 10) : 1;
	string dump = argc > 7 ? argv[7] : "";
	int per = func == "logsoftmax" ? LSM : 1, n_in = dim * per;

	mt19937_64 rng(seed);
	vector<uint64_t> xs(n_in);
	for (int i = 0; i < n_in; i++)
		xs[i] = gen_input(func, rng);
	vector<double> ref(n_in);

	if (mname == "plain") {  // plaintext float evaluation, prover only
		if (party != ALICE) return 0;
		vector<double> xr(n_in);
		for (int i = 0; i < n_in; i++)
			xr[i] = func == "log60" ? (double)xs[i] / 4096.0 : F2R(xs[i]);
		auto t0 = clock_start();
		if (func == "logsoftmax")
			for (int i = 0; i < dim; i++) ref_lsm(&xr[i * LSM], &ref[i * LSM]);
		else
			for (int i = 0; i < n_in; i++) ref[i] = ref1(func, xr[i]);
		double t = time_from(t0) / 1e6;
		double chk = 0;
		for (int i = 0; i < n_in; i++) chk += ref[i];
		printf("RESULT func=%s mode=plain dim=%d party=1 time_s=%.6f comm_mb=0 max_err_ulp=0 "
		       "mean_err_ulp=0 verify=NA checksum=%.3f\n", func.c_str(), dim, t, chk);
		return 0;
	}
	int mode = mname == "lut" ? EXT_LUT : mname == "poly" ? EXT_POLY : mname == "naive" ? EXT_NAIVE : -1;
	if (mode < 0) error("unknown mode");

	BoolIO<NetIO> *ios[threads];
	for (int i = 0; i < threads; ++i)
		ios[i] = new BoolIO<NetIO>(new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i), party == ALICE);
	setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
	setup_zk_arith<BoolIO<NetIO>>(ios, threads, party, false);
	sync_zk_bool<BoolIO<NetIO>>();

	startComputation(party);
	ext_start(party);
	IntFp *x = new IntFp[n_in];
	IntFp *y = new IntFp[n_in];
	for (int i = 0; i < n_in; i++)
		x[i] = IntFp(party == ALICE ? xs[i] : 0, ALICE);

	uint64_t c0 = ios[0]->counter;
	auto t0 = clock_start();
	ZKX ctx(party, mode);
	for (int i = 0; i < dim; i++) {
		if (func == "sin") y[i] = zk_sin(ctx, x[i]);
		else if (func == "log60") y[i] = zk_log(ctx, x[i], 60);
		else if (func == "log20") y[i] = zk_log(ctx, x[i], 20);
		else if (func == "exp") y[i] = zk_exp_neg(ctx, x[i], 24);
		else if (func == "snake") y[i] = zk_snake(ctx, x[i], 1.0);
		else if (func == "softplus") y[i] = zk_softplus(ctx, x[i]);
		else if (func == "logsoftmax") zk_log_softmax(ctx, x + i * LSM, y + i * LSM, LSM);
		if ((i + 1) % 4096 == 0) ctx.flush();
	}
	ctx.flush();
	ext_end();
	endComputation(party);
	ext_finish_checks();
	double t = time_from(t0) / 1e6;
	double comm_mb = (ios[0]->counter - c0) / 1048576.0;

	double max_ulp = 0, sum_ulp = 0;
	if (party == ALICE) {
		vector<double> xr(n_in);
		for (int i = 0; i < n_in; i++)
			xr[i] = func == "log60" ? (double)xs[i] / 4096.0 : F2R(xs[i]);
		if (func == "logsoftmax")
			for (int i = 0; i < dim; i++) ref_lsm(&xr[i * LSM], &ref[i * LSM]);
		else
			for (int i = 0; i < n_in; i++) ref[i] = ref1(func, xr[i]);
		ofstream out;
		if (!dump.empty()) out.open(dump);
		for (int i = 0; i < n_in; i++) {
			uint64_t yv = (uint64_t)HIGH64(y[i].value);
			double e = fabs(F2R(yv) - ref[i]) * 4096.0;
			max_ulp = max(max_ulp, e);
			sum_ulp += e;
			if (out.is_open()) out << xs[i] << "," << yv << "\n";
		}
	}
	printf("RESULT func=%s mode=%s dim=%d party=%d time_s=%.6f comm_mb=%.6f max_err_ulp=%.4f "
	       "mean_err_ulp=%.4f verify=%s witnesses=%ld\n", func.c_str(), mname.c_str(), dim, party, t,
	       comm_mb, max_ulp, sum_ulp / n_in, party == BOB ? (CheatRecord::cheated() ? "FAIL" : "OK") : "NA",
	       ext_num_inputs());
	fflush(stdout);

	finalize_zk_arith<BoolIO<NetIO>>();
	finalize_zk_bool<BoolIO<NetIO>>();
	for (int i = 0; i < threads; i++) {
		delete ios[i]->io;
		delete ios[i];
	}
	delete[] x;
	delete[] y;
	return 0;
}
