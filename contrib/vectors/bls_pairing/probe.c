/*
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * Runs the reference implementation's relic pairing (the librelic.a its
 * build links, with that build's relic_conf.h) against blst, for dash-pkc's
 * relic engine:
 *
 *   probe fe <count> <seed>     pp_exp_k12 against blst_final_exp on random
 *                               Fp12 elements: general, unitary, 0 and 1.
 *                               Prints the agreement on "is one" and the
 *                               relation between the two values.
 *   probe pairs <count> <seed>  pairing vectors on stdout as JSON5: points
 *                               of every class relic can hold (subgroup,
 *                               on the curve outside it, the G1 points of
 *                               order 3, off the curve, G2 with y = 0,
 *                               projective on and off the curve,
 *                               coordinates at the field's edge values,
 *                               infinity) and relic's pp_map_sim_oatep_k12
 *                               of them.
 *
 * The seed, at most 32 bytes, replaces relic's urandom seeding (SEED UDEV),
 * so a run is reproducible.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "relic.h"
#include "blst.h"

static __attribute__((noreturn)) void die(const char *what) {
	fprintf(stderr, "probe: %s\n", what);
	exit(2);
}

/* Seeds relic's HASHD generator from `s` alone: core_init has already
 * seeded it from urandom, and rand_seed mixes a new seed into an existing
 * state unless `seeded` is clear, as rand_init clears it
 * (relic_rand_hashd.c:176-215, relic_rand_core.c:179). */
static void seed(const char *s) {
	uint8_t buf[32] = { 0 };
	size_t n = strlen(s);
	if (n > sizeof(buf)) {
		die("seed longer than 32 bytes");
	}
	memcpy(buf, s, n);
	core_get()->seeded = 0;
	rand_seed(buf, sizeof(buf));
}

/* A relic fp12 as blst holds it: the same tower, slot by slot. */
static void to_blst(blst_fp12 *out, fp12_t a) {
	uint8_t b[RLC_FP_BYTES];
	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 3; j++) {
			for (int k = 0; k < 2; k++) {
				fp_write_bin(b, sizeof(b), a[i][j][k]);
				blst_fp_from_bendian(&out->fp6[i].fp2[j].fp[k], b);
			}
		}
	}
}

static int fe(long count) {
	fp12_t a, t, out;
	blst_fp12 x, fx, rx;
	long agree = 0, eq = 0, conj = 0, other = 0, ones = 0;

	fp12_new(a);
	fp12_new(t);
	fp12_new(out);
	for (long n = 0; n < count; n++) {
		switch (n % 8) {
			case 0:
				fp12_zero(a);
				break;
			case 1:
				fp12_set_dig(a, 1);
				break;
			case 2:
			case 3:
			case 4:
				/* Unitary: conj(f) / f. */
				fp12_rand(t);
				fp12_inv(a, t);
				fp12_inv_cyc(t, t);
				fp12_mul(a, a, t);
				break;
			default:
				fp12_rand(a);
		}
		pp_exp_k12(out, a);
		to_blst(&x, a);
		to_blst(&rx, out);
		blst_final_exp(&fx, &x);

		int r1 = fp12_cmp_dig(out, 1) == RLC_EQ;
		int b1 = blst_fp12_is_one(&fx);
		agree += r1 == b1;
		ones += r1;
		blst_fp12 fx_conj = fx;
		blst_fp12_conjugate(&fx_conj);
		if (blst_fp12_is_equal(&rx, &fx)) {
			eq++;
		} else if (blst_fp12_is_equal(&rx, &fx_conj)) {
			conj++;
		} else {
			other++;
		}
	}
	printf("fe count=%ld agree_is_one=%ld relic_one=%ld equal=%ld conjugate=%ld other=%ld\n",
		count, agree, ones, eq, conj, other);
	fp12_free(a);
	fp12_free(t);
	fp12_free(out);
	/* dash-pkc reads relic's value through blst's: equal, not only both one. */
	return agree == count && eq == count ? 0 : 1;
}

static void put_fp(const fp_t a) {
	uint8_t b[RLC_FP_BYTES];
	fp_write_bin(b, sizeof(b), a);
	putchar('"');
	for (size_t i = 0; i < sizeof(b); i++) {
		printf("%02x", b[i]);
	}
	putchar('"');
}

static void put_fp2(fp2_t a) {
	putchar('[');
	put_fp(a[0]);
	putchar(',');
	put_fp(a[1]);
	putchar(']');
}

/* Bounded draws: relic's rand_bytes over a byte. */
static int pick(int n) {
	uint8_t b;
	rand_bytes(&b, 1);
	return b % n;
}

/* A value at a boundary of relic's field arithmetic: 0, 1, 2, -1, -2,
 * (p - 1) / 2 = -1/2, (p + 1) / 2 = 1/2 or -4, or a random element. */
static void edge_fp(fp_t a) {
	switch (pick(9)) {
		case 0:
			fp_zero(a);
			break;
		case 1:
		case 2:
			fp_set_dig(a, 1 + pick(2));
			break;
		case 3:
		case 4:
			fp_set_dig(a, 1 + pick(2));
			fp_neg(a, a);
			break;
		case 5:
			fp_set_dig(a, 1);
			fp_neg(a, a);
			fp_hlv(a, a);
			break;
		case 6:
			fp_set_dig(a, 1);
			fp_hlv(a, a);
			break;
		case 7:
			fp_set_dig(a, 4);
			fp_neg(a, a);
			break;
		default:
			fp_rand(a);
	}
}

static void edge_fp2(fp2_t a) {
	edge_fp(a[0]);
	edge_fp(a[1]);
}

static const char *g1_class(ep_t p) {
	fp_t t;
	const char *name;

	fp_new(t);
	switch (pick(9)) {
		case 0:
		case 1:
			ep_rand(p);
			name = "subgroup";
			break;
		case 2:
			/* On the curve, outside the subgroup: x with a square rhs. */
			do {
				fp_rand(p->x);
				fp_sqr(t, p->x);
				fp_mul(t, t, p->x);
				fp_add_dig(t, t, 4);
			} while (!fp_srt(p->y, t));
			fp_set_dig(p->z, 1);
			p->coord = BASIC;
			name = ep_on_curve(p) && !g1_is_valid(p) ? "torsion" : "subgroup";
			break;
		case 3:
			fp_zero(p->x);
			fp_set_dig(p->y, 2);
			if (pick(2)) {
				fp_neg(p->y, p->y);
			}
			fp_set_dig(p->z, 1);
			p->coord = BASIC;
			name = "order3";
			break;
		case 4:
			fp_rand(p->x);
			fp_rand(p->y);
			fp_set_dig(p->z, 1);
			p->coord = BASIC;
			name = "offcurve";
			break;
		case 5:
			/* A projective representation of a subgroup point. */
			ep_rand(p);
			fp_rand(t);
			fp_mul(p->x, p->x, t);
			fp_mul(p->y, p->y, t);
			fp_copy(p->z, t);
			p->coord = PROJC;
			name = "projective";
			break;
		case 6:
			/* Homogeneous coordinates off the curve. */
			fp_rand(p->x);
			fp_rand(p->y);
			do {
				fp_rand(p->z);
			} while (fp_is_zero(p->z));
			p->coord = PROJC;
			name = "projective_offcurve";
			break;
		case 7:
			edge_fp(p->x);
			edge_fp(p->y);
			if (pick(2)) {
				fp_set_dig(p->z, 1);
				p->coord = BASIC;
			} else {
				do {
					edge_fp(p->z);
				} while (fp_is_zero(p->z));
				p->coord = PROJC;
			}
			name = "edge";
			break;
		default:
			ep_set_infty(p);
			name = "infinity";
	}
	fp_free(t);
	return name;
}

static const char *g2_class(ep2_t q) {
	fp2_t t, u;
	fp2_new(t);
	fp2_new(u);
	const char *name;
	switch (pick(9)) {
		case 0:
		case 1:
			ep2_rand(q);
			name = "subgroup";
			break;
		case 2:
			do {
				fp2_rand(q->x);
				fp2_set_dig(q->z, 1);
				q->coord = BASIC;
				ep2_rhs(t, q);
			} while (!fp2_srt(q->y, t));
			name = ep2_on_curve(q) && !g2_is_valid(q) ? "torsion" : "subgroup";
			break;
		case 3:
			fp2_rand(q->x);
			fp2_rand(q->y);
			fp2_set_dig(q->z, 1);
			q->coord = BASIC;
			name = "offcurve";
			break;
		case 4:
			fp2_rand(q->x);
			fp2_zero(q->y);
			fp2_set_dig(q->z, 1);
			q->coord = BASIC;
			name = "y0";
			break;
		case 5:
			/* Jacobian: (l^2 x, l^3 y, l). */
			ep2_rand(q);
			fp2_rand(t);
			fp2_sqr(u, t);
			fp2_mul(q->x, q->x, u);
			fp2_mul(u, u, t);
			fp2_mul(q->y, q->y, u);
			fp2_copy(q->z, t);
			q->coord = PROJC;
			name = "projective";
			break;
		case 6:
			/* Jacobian coordinates off the curve. */
			fp2_rand(q->x);
			fp2_rand(q->y);
			do {
				fp2_rand(q->z);
			} while (fp2_is_zero(q->z));
			q->coord = PROJC;
			name = "projective_offcurve";
			break;
		case 7:
			edge_fp2(q->x);
			edge_fp2(q->y);
			if (pick(2)) {
				fp2_set_dig(q->z, 1);
				q->coord = BASIC;
			} else {
				do {
					edge_fp2(q->z);
				} while (fp2_is_zero(q->z));
				q->coord = PROJC;
			}
			name = "edge";
			break;
		default:
			ep2_set_infty(q);
			name = "infinity";
	}
	fp2_free(t);
	fp2_free(u);
	return name;
}

/* The most pairs per pp_map_sim_oatep_k12 call. */
enum { MAX_PAIRS = 4 };

static void put_g1(const char *sep, const char *class, ep_t p) {
	printf("%s{\"class\": \"%s\", \"projc\": %s, \"x\": ", sep, class, p->coord == PROJC ? "true" : "false");
	put_fp(p->x);
	printf(", \"y\": ");
	put_fp(p->y);
	printf(", \"z\": ");
	put_fp(p->z);
	putchar('}');
}

static void put_g2(const char *sep, const char *class, ep2_t q) {
	printf("%s{\"class\": \"%s\", \"projc\": %s, \"x\": ", sep, class, q->coord == PROJC ? "true" : "false");
	put_fp2(q->x);
	printf(", \"y\": ");
	put_fp2(q->y);
	printf(", \"z\": ");
	put_fp2(q->z);
	putchar('}');
}

static int pairs(long count, const char *seed) {
	ep_t p[MAX_PAIRS];
	ep2_t q[MAX_PAIRS];
	fp12_t out;

	fp12_new(out);
	for (int i = 0; i < MAX_PAIRS; i++) {
		ep_new(p[i]);
		ep2_new(q[i]);
	}
	printf("// Generated by contrib/vectors/bls_pairing/probe.c: probe pairs %ld %s\n", count, seed);
	printf("{\n  \"twist_mtype\": %s,\n  \"pairs\": [\n", ep2_curve_is_twist() == RLC_EP_MTYPE ? "true" : "false");
	for (long n = 0; n < count; n++) {
		int m = 1 + pick(MAX_PAIRS);
		printf("    {\"g1\": [");
		for (int i = 0; i < m; i++) {
			put_g1(i ? ", " : "", g1_class(p[i]), p[i]);
		}
		printf("],\n     \"g2\": [");
		for (int i = 0; i < m; i++) {
			put_g2(i ? ", " : "", g2_class(q[i]), q[i]);
		}
		pp_map_sim_oatep_k12(out, p, q, m);
		if (err_get_code() != RLC_OK) {
			die("relic set its error code");
		}
		printf("],\n     \"out\": [");
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 3; j++) {
				printf("%s", i || j ? ", " : "");
				put_fp2(out[i][j]);
			}
		}
		printf("]}%s\n", n + 1 < count ? "," : "");
	}
	printf("  ]\n}\n");
	return 0;
}

int main(int argc, char **argv) {
	if (argc != 4) {
		die("usage: probe fe|pairs <count> <seed>");
	}
	if (core_init() != RLC_OK || ep_param_set_any_pairf() != RLC_OK) {
		die("relic init");
	}
	seed(argv[3]);
	long count = strtol(argv[2], NULL, 10);
	if (!strcmp(argv[1], "fe")) {
		return fe(count);
	}
	if (!strcmp(argv[1], "pairs")) {
		return pairs(count, argv[3]);
	}
	die("mode is fe or pairs");
}
