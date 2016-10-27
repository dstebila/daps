/********************************************************************************************
 * DAPS: double-authentication preventing signatures
 *
 * Based on the paper:
 *     Mihir Bellare, Bertram Poettering, and Douglas Stebila.
 *     Deterring Certificate Subversion: Efficient Double-Authentication-Preventing Signatures.
 *     IACR Cryptology ePrint Archive, Report 2016/1016. October, 2016.
 *     https://eprint.iacr.org/2016/1016
 *
 * Software originally developed by Douglas Stebila.
 *
 * Released into the public domain; see LICENSE.txt for details.
 *
 * BN_jacobi_priv function by Adam L. Young (see below).
 ********************************************************************************************/

/** \file bn_extra.c
 * Extra BIGNUM functions.
 */

#include <string.h>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "common.h"
#include "bn_extra.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

unsigned char *SHA256_arbitrary(const unsigned char *d, const int d_length, const int o_length) {
	int ok;
	unsigned char dgst[SHA256_DIGEST_LENGTH];
	unsigned char *output = NULL;
	CHECK_NONNULL(output = (unsigned char *) OPENSSL_malloc(sizeof(unsigned char) * o_length));
	for (int i = 0; i < o_length; i += SHA256_DIGEST_LENGTH) {
		SHA256_CTX ctx;
		CHECK_IS_ONE(SHA256_Init(&ctx));
		CHECK_IS_ONE(SHA256_Update(&ctx, (unsigned char *) &i, sizeof(int) / sizeof(unsigned char)));
		CHECK_IS_ONE(SHA256_Update(&ctx, d, d_length));
		CHECK_IS_ONE(SHA256_Final(dgst, &ctx));
		memcpy(&output[i], dgst, MIN(SHA256_DIGEST_LENGTH, o_length - i));
	}
	return output;
err:
	OPENSSL_free(output);
	return NULL;
}

BIGNUM *SHA256_mod(const unsigned char *d, const int d_length, BIGNUM *m, BN_CTX *bn_ctx) {
	int ok;
	unsigned char *dgst = NULL;
	int dgst_len;
	BIGNUM *r = NULL;
	dgst_len = 2 * BN_num_bytes(m);
	CHECK_NONNULL(dgst = SHA256_arbitrary(d, d_length, dgst_len));
	CHECK_NONNULL(r = BN_bin2bn(dgst, dgst_len, NULL));
	CHECK_IS_ONE(BN_mod(r, r, m, bn_ctx));
	goto cleanup;
err:
	r = NULL;
	BN_free(r);
cleanup:
	OPENSSL_free(dgst);
	return r;
}

// http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
int BN_extended_gcd(BIGNUM *r, BIGNUM *s, BIGNUM *t, const BIGNUM *a, const BIGNUM *b, BN_CTX *bn_ctx) {
	int ok, ret;
	int swapped = 0;
	BIGNUM *r2 = NULL, *r1 = NULL, *r0 = NULL;
	BIGNUM *s2 = NULL, *s1 = NULL, *s0 = NULL;
	BIGNUM *t2 = NULL, *t1 = NULL, *t0 = NULL;
	BIGNUM *q = NULL;
	CHECK_NONNULL(a);
	CHECK_NONNULL(b);
	CHECK_IS_ZERO(BN_is_zero(a));
	CHECK_IS_ZERO(BN_is_zero(b));
	CHECK_NONNULL(bn_ctx);
	if (BN_cmp(a, b) >= 0) {
		CHECK_NONNULL(r0 = BN_dup(a));
		CHECK_NONNULL(r1 = BN_dup(b));
	} else {
		CHECK_NONNULL(r0 = BN_dup(b));
		CHECK_NONNULL(r1 = BN_dup(a));
		swapped = 1;
	}
	CHECK_NONNULL(r2 = BN_new());
	CHECK_NONNULL(s2 = BN_new());
	CHECK_NONNULL(s1 = BN_new());
	CHECK_NONNULL(s0 = BN_new());
	CHECK_IS_ONE(BN_one(s0));
	CHECK_IS_ONE(BN_zero(s1));
	CHECK_NONNULL(t2 = BN_new());
	CHECK_NONNULL(t1 = BN_new());
	CHECK_NONNULL(t0 = BN_new());
	CHECK_IS_ONE(BN_zero(t0));
	CHECK_IS_ONE(BN_one(t1));
	CHECK_NONNULL(q = BN_new());
	while (1) {
		// r0 / r1 = quotient q + remainder r2
		CHECK_IS_ONE(BN_div(q, r2, r0, r1, bn_ctx));
		// s2 = s0 - q s1
		CHECK_IS_ONE(BN_mul(s2, q, s1, bn_ctx));
		CHECK_IS_ONE(BN_sub(s2, s0, s2));
		// t2 = t0 - q t1
		CHECK_IS_ONE(BN_mul(t2, q, t1, bn_ctx));
		CHECK_IS_ONE(BN_sub(t2, t0, t2));
		// stop if r2 = 0
		if (BN_is_zero(r2)) {
			break;
		}
		// update variables
		BN_free(r0);
		r0 = r1;
		r1 = r2;
		CHECK_NONNULL(r2 = BN_new());
		BN_free(s0);
		s0 = s1;
		s1 = s2;
		CHECK_NONNULL(s2 = BN_new());
		BN_free(t0);
		t0 = t1;
		t1 = t2;
		CHECK_NONNULL(t2 = BN_new());
	};
	if (r != NULL) {
		CHECK_NONNULL(BN_copy(r, r1));
	}
	if ((s != NULL) && (t != NULL)) {
		if (swapped) {
			CHECK_NONNULL(BN_copy(s, t1));
			CHECK_NONNULL(BN_copy(t, s1));
		} else {
			CHECK_NONNULL(BN_copy(s, s1));
			CHECK_NONNULL(BN_copy(t, t1));
		}
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(r2);
	BN_free(r1);
	BN_free(r0);
	BN_free(s2);
	BN_free(s1);
	BN_free(s0);
	BN_free(t2);
	BN_free(t1);
	BN_free(t0);
	BN_free(q);
	return ret;
}

// http://en.wikipedia.org/wiki/Chinese_remainder_theorem#Case_of_two_equations_.28k_.3D_2.29
int BN_crt(BIGNUM *x, const BIGNUM *a1, const BIGNUM *n1, const BIGNUM *a2, const BIGNUM *n2, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *n1inv_n2 = NULL, *n2inv_n1 = NULL;
	BIGNUM *n = NULL;
	BIGNUM *tmp = NULL, *tmp1 = NULL, *tmp2 = NULL;
	CHECK_NONNULL(n1inv_n2 = BN_new());
	CHECK_NONNULL(n2inv_n1 = BN_new());
	CHECK_NONNULL(n = BN_new());
	CHECK_NONNULL(tmp = BN_new());
	CHECK_NONNULL(tmp1 = BN_new());
	CHECK_NONNULL(tmp2 = BN_new());
	// n = n1 * n2
	CHECK_IS_ONE(BN_mul(n, n1, n2, bn_ctx));
	// used extended Euclidean algorithm to compute 1 = n1 * (n1^-1 mod n2) + n2 * (n2^-1 mod n1)
	CHECK_IS_ONE(BN_extended_gcd(NULL, n1inv_n2, n2inv_n1, n1, n2, bn_ctx));
	// x = a1 * n2 * (n2^-1 mod n1) + a2 * n1 * (n1^-1 mod n2) mod n
	CHECK_IS_ONE(BN_mod_mul(tmp, n2inv_n1, n2, n, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(tmp1, a1, tmp, n, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(tmp, n1inv_n2, n1, n, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(tmp2, a2, tmp, n, bn_ctx));
	CHECK_IS_ONE(BN_mod_add(x, tmp1, tmp2, n, bn_ctx));
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(n1inv_n2);
	BN_free(n2inv_n1);
	BN_free(n);
	BN_free(tmp);
	BN_free(tmp1);
	BN_free(tmp2);
	return ret;
}

// https://github.com/justmoon/node-bignum/blob/master/bignum.cc
/**
 * BN_jacobi_priv() computes the Jacobi symbol of A with respect to N.
 *
 * Hence, *jacobi = 1 when the jacobi symbol is unity and *jacobi = -1 when the
 * jacobi symbol is -1. N must be odd and >= 3. It is required that 0 <= A < N.
 *
 * When successful 0 is returned. -1 is returned on failure.
 *
 * This is an implementation of an iterative version of Algorithm 2.149 on page
 * 73 of the book "Handbook of Applied Cryptography" by Menezes, Oorshot,
 * Vanstone. Note that there is a typo in step 1. Step 1 should return the value
 * 1. The algorithm has a running time of O((lg N)^2) bit operations.
 *
 * @author Adam L. Young
 */
int BN_jacobi_priv(const BIGNUM *A, const BIGNUM *N, int *jacobi, BN_CTX *ctx) {
	int e, returnvalue = 0, s, bit0, bit1, bit2, a1bit0, a1bit1;
	BIGNUM *zero, *a1, *n1, *three, *tmp;

	if (!jacobi) {
		return -1;
	}
	*jacobi = 1;
	if ((!A) || (!N) || (!ctx)) {
		return -1;
	}
	if (!BN_is_odd(N)) {
		return -1;    /* ERROR: BN_jacobi() given an even N */
	}
	if (BN_cmp(A, N) >= 0) {
		return -1;
	}
	n1 = BN_new();
	zero = BN_new();
	a1 = BN_new();
	three = BN_new();
	tmp = BN_new();
	BN_set_word(zero, 0);
	BN_set_word(three, 3);
	if (BN_cmp(N, three) < 0) {
		/* This function was written by Adam L. Young */
		returnvalue = -1;
		goto endBN_jacobi;
	}
	if (BN_cmp(zero, A) > 0) {
		returnvalue = -1;
		goto endBN_jacobi;
	}
	BN_copy(a1, A);
	BN_copy(n1, N);
startjacobistep1:
	if (BN_is_zero(a1)) { /* step 1 */
		goto endBN_jacobi;    /* *jacobi = 1; */
	}
	if (BN_is_one(a1)) { /* step 2 */
		goto endBN_jacobi;    /* *jacobi = 1; */
	}
	for (e = 0;; e++) /*  step 3 */
		if (BN_is_odd(a1)) {
			break;
		} else {
			BN_rshift1(a1, a1);
		}
	s = 1; /* step 4 */
	bit0 = BN_is_odd(n1);
	bit1 = BN_is_bit_set(n1, 1);
	if (e % 2) {
		bit2 = BN_is_bit_set(n1, 2);
		if ((!bit2) && (bit1) && (bit0)) {
			s = -1;
		}
		if ((bit2) && (!bit1) && (bit0)) {
			s = -1;
		}
	}
	a1bit0 = BN_is_odd(a1);  /* step 5 */
	a1bit1 = BN_is_bit_set(a1, 1);
	if (((bit1) && (bit0)) && ((a1bit1) && (a1bit0))) {
		s = -s;
	}
	BN_mod(n1, n1, a1, ctx); /* step 6 */
	BN_copy(tmp, a1);
	BN_copy(a1, n1);
	BN_copy(n1, tmp);
	*jacobi *= s;  /*  step 7 */
	goto startjacobistep1;
endBN_jacobi:
	BN_clear_free(zero);
	BN_clear_free(tmp);
	BN_clear_free(a1);
	BN_clear_free(n1);
	BN_clear_free(three);
	return returnvalue;
}
