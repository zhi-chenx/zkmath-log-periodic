#pragma once
// Public lookup table with any number of output columns, proven with the zk-ROM technique of
// Hao et al. (ZKMath LUT.h / LUT-twoValue.h): every read appends (index, values, version) to
// `reads` and (index, values, version+1) to `writes`; a batch check proves that reads is a
// permutation of writes with a grand-product identity, 2N + T multiplications for N reads.
//
// Difference to ZKMath: the packing/evaluation challenges are sampled by the verifier after the
// reads are committed (ZKMath derives them from a fixed PRG key, which is only acceptable for
// benchmarking). The coin toss costs one round trip per batch check.
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <vector>

typedef BoolIO<NetIO> ExtIO;

inline void ext_coin_toss(int party, uint64_t *out, int n)
{
	ExtIO *io = FpPolyProof<ExtIO>::fppolyproof->io;
	io->flush();
	if (party == BOB) {
		PRG prg;
		prg.random_data(out, n * sizeof(uint64_t));
		for (int i = 0; i < n; i++)
			out[i] = mod(out[i]);
		io->send_data(out, n * sizeof(uint64_t));
		io->flush();
	} else {
		io->recv_data(out, n * sizeof(uint64_t));
	}
}

class LUTMultiIntFp {
public:
	int party;
	int ncols;
	std::vector<std::vector<uint64_t> > cols;   // cols[j][i]: column j of row i
	std::vector<uint64_t> latest_version;       // prover only
	std::vector<IntFp> rd_idx, rd_ver, rd_val;  // rd_val holds ncols entries per read
	uint64_t batch_check_size = 100000;

	LUTMultiIntFp(int _party, const std::vector<std::vector<uint64_t> > &_cols)
		: party(_party), ncols(_cols.size()), cols(_cols)
	{
		latest_version.assign(size(), 0);
	}

	~LUTMultiIntFp()
	{
		if (!rd_idx.empty())
			check();
	}

	uint64_t size() const { return cols[0].size(); }

	// Row lookup for the prover's witness generation (0 outside the table).
	uint64_t value(int j, uint64_t i) const { return i < size() ? cols[j][i] : 0; }

	void read(const IntFp &index, const IntFp *vals)
	{
		uint64_t version = 0;
		if (party == ALICE) {
			uint64_t i = (uint64_t)HIGH64(index.value);
			if (i < size())
				version = latest_version[i]++;
		}
		rd_idx.push_back(index);
		rd_ver.push_back(IntFp(version, ALICE));
		for (int j = 0; j < ncols; j++)
			rd_val.push_back(vals[j]);
		if (rd_idx.size() == batch_check_size)
			check();
	}

	void check()
	{
		const uint64_t T = size(), N = rd_idx.size();
		std::vector<IntFp> fin_ver(T);
		for (uint64_t i = 0; i < T; i++)
			fin_ver[i] = IntFp(party == ALICE ? latest_version[i] : 0, ALICE);

		// a[0]: index, a[1..ncols]: values, a[ncols+1]: version, a[ncols+2]: evaluation point
		std::vector<uint64_t> a(ncols + 3);
		ext_coin_toss(party, a.data(), ncols + 3);
		const uint64_t av = a[ncols + 1], r = a[ncols + 2];

		IntFp prod_r(1, PUBLIC), prod_w(1, PUBLIC);
		bool first = true;
		for (uint64_t k = 0; k < N; k++) {
			IntFp base = rd_idx[k] * a[0];
			for (int j = 0; j < ncols; j++)
				base = base + rd_val[k * ncols + j] * a[j + 1];
			IntFp rd = base + rd_ver[k] * av + IntFp(r, PUBLIC);
			IntFp wr = base + rd_ver[k] * av + IntFp(add_mod(av, r), PUBLIC);  // version + 1
			prod_r = first ? rd : prod_r * rd;
			prod_w = first ? wr : prod_w * wr;
			first = false;
		}
		// final reads of every row (public index/values, committed latest version) and the
		// initial writes of every row (all public, version 0)
		uint64_t init = 1;
		for (uint64_t i = 0; i < T; i++) {
			uint64_t pub = mult_mod(i, a[0]);
			for (int j = 0; j < ncols; j++)
				pub = add_mod(pub, mult_mod(cols[j][i], a[j + 1]));
			pub = add_mod(pub, r);
			prod_r = prod_r * (fin_ver[i] * av + IntFp(pub, PUBLIC));
			init = mult_mod(init, pub);
		}
		IntFp diff = prod_r + (prod_w * init).negate();
		diff.reveal_zero();

		rd_idx.clear();
		rd_ver.clear();
		rd_val.clear();
		std::fill(latest_version.begin(), latest_version.end(), 0);
	}
};
