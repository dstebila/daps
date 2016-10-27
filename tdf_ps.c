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
 ********************************************************************************************/

/** \file tdf_ps.c
 * PS trapdoor function.
 */

#include <openssl/bn.h>

#include "common.h"
#include "tdf_ps.h"
#include "bn_extra.h"

void TDF_PS_PK_free(TDF_PS_PK *pk) {
	if (pk == NULL) {
		return;
	}
	BN_free(pk->n);
	BN_free(pk->halfn);
	OPENSSL_free(pk);
}

void TDF_PS_TDK_free(TDF_PS_TDK *tdk) {
	if (tdk == NULL) {
		return;
	}
	BN_free(tdk->n);
	BN_free(tdk->halfn);
	BN_free(tdk->p);
	BN_free(tdk->q);
	OPENSSL_free(tdk);
}

void TDF_PS_PK_print_fp(FILE *fp, const TDF_PS_PK *pk) {
	if (pk == NULL) {
		return;
	}
	BN_printdec_fp(fp, "pk_n", pk->n);
}

void TDF_PS_TDK_print_fp(FILE *fp, const TDF_PS_TDK *tdk) {
	if (tdk == NULL) {
		return;
	}
	BN_printdec_fp(fp, "tdk_n", tdk->n);
	BN_printdec_fp(fp, "tdk_p", tdk->p);
	BN_printdec_fp(fp, "tdk_q", tdk->q);
}

int TDF_PS_keygen(TDF_PS_PK **pk, TDF_PS_TDK **tdk, const int bits, BN_CTX *bn_ctx) {
	int ret, ok;
	TDF_PS_PK *rpk = NULL;
	TDF_PS_TDK *rtdk = NULL;
	BIGNUM *rem = NULL, *mod = NULL;
	CHECK_NONNULL(rem = BN_new());
	CHECK_NONNULL(mod = BN_new());
	CHECK_NONNULL(rpk = (TDF_PS_PK *) OPENSSL_malloc(sizeof(TDF_PS_PK)));
	CHECK_NONNULL(rtdk = (TDF_PS_TDK *) OPENSSL_malloc(sizeof(TDF_PS_TDK)));
	CHECK_NONNULL(rtdk->p = BN_new());
	CHECK_IS_ONE(BN_set_word(rem, 3));
	CHECK_IS_ONE(BN_set_word(mod, 8));
	CHECK_IS_ONE(BN_generate_prime_ex(rtdk->p, bits / 2, 0, mod, rem, NULL));
	CHECK_NONNULL(rtdk->q = BN_new());
	CHECK_IS_ONE(BN_set_word(rem, 7));
	CHECK_IS_ONE(BN_generate_prime_ex(rtdk->q, bits / 2, 0, mod, rem, NULL));
	CHECK_NONNULL(rtdk->n = BN_new());
	CHECK_IS_ONE(BN_mul(rtdk->n, rtdk->p, rtdk->q, bn_ctx));
	CHECK_NONNULL(rtdk->halfn = BN_new());
	CHECK_IS_ONE(BN_rshift1(rtdk->halfn, rtdk->n));
	CHECK_NONNULL(rpk->n = BN_dup(rtdk->n));
	CHECK_NONNULL(rpk->halfn = BN_dup(rtdk->halfn));
	*pk = rpk;
	*tdk = rtdk;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	TDF_PS_PK_free(rpk);
	TDF_PS_TDK_free(rtdk);
cleanup:
	BN_free(rem);
	BN_free(mod);
	return ret;

}

int TDF_PS_hash_onto_range(const TDF_PS_PK *pk, const unsigned char *msg, const int msg_length, BIGNUM *r, BN_CTX *bn_ctx) {
	int ret, ok;
	int ver;
	BIGNUM *h_bn = NULL;
	CHECK_NONNULL(h_bn = SHA256_mod(msg, msg_length, pk->halfn, bn_ctx));
	ver = 0;
	while (1) {
		CHECK_IS_ZERO(BN_jacobi_priv(h_bn, pk->n, &ver, bn_ctx));
		if (ver == 1) {
			ver = BN_cmp(h_bn, pk->halfn);
			if (ver < 0) {
				break;
			}
		}
		CHECK_IS_ONE(BN_mod_add(h_bn, h_bn, BN_value_one(), pk->n, bn_ctx));
	}
	ret = 1;
	CHECK_NONNULL(BN_copy(r, h_bn));
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(h_bn);
	return ret;

}

int TDF_PS_apply(BIGNUM *y, const TDF_PS_PK *pk, const BIGNUM *x, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *tmp = NULL;
	CHECK_NONNULL(tmp = BN_new());
	CHECK_IS_ONE(BN_mod_sqr(tmp, x, pk->n, bn_ctx));
	if (BN_cmp(tmp, pk->halfn) < 0) {
		CHECK_NONNULL(BN_copy(y, tmp));
	} else {
		CHECK_IS_ONE(BN_sub(y, pk->n, tmp));
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(tmp);
	return ret;
}

int TDF_PS_inv(BIGNUM *x, const TDF_PS_TDK *tdk, const BIGNUM *y, const int bit, BN_CTX *bn_ctx) {
	int ret, ok;
	TDF_PS_PK pk;
	pk.n = tdk->n;
	pk.halfn = tdk->halfn;
	BIGNUM *xmodp = NULL, *xmodq = NULL;
	BIGNUM *pminusxmodp = NULL;
	BIGNUM *yprime = NULL;
	xmodp = BN_mod_sqrt(NULL, y, tdk->p, bn_ctx);
	xmodq = BN_mod_sqrt(NULL, y, tdk->q, bn_ctx);
	if ((xmodp == NULL) || (xmodq == NULL)) {
		CHECK_NONNULL(yprime = BN_new());
		CHECK_IS_ONE(BN_sub(yprime, tdk->n, y));
		CHECK_NONNULL(xmodp = BN_mod_sqrt(NULL, yprime, tdk->p, bn_ctx));
		CHECK_NONNULL(xmodq = BN_mod_sqrt(NULL, yprime, tdk->q, bn_ctx));
	}
	CHECK_IS_ONE(BN_crt(x, xmodp, tdk->p, xmodq, tdk->q, bn_ctx));
	CHECK_GE_ZERO(TDF_PS_decide(&pk, x, bn_ctx));
	if (ok != bit) {
		CHECK_NONNULL(pminusxmodp = BN_new());
		CHECK_IS_ONE(BN_sub(pminusxmodp, tdk->p, xmodp));
		CHECK_IS_ONE(BN_crt(x, pminusxmodp, tdk->p, xmodq, tdk->q, bn_ctx));
	}
	if (BN_cmp(x, tdk->halfn) >= 0) {
		CHECK_IS_ONE(BN_sub(xmodp, tdk->n, x));
		CHECK_NONNULL(BN_copy(x, xmodp));
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(xmodp);
	BN_free(xmodq);
	BN_free(pminusxmodp);
	BN_free(yprime);
	return ret;
}

// returns:
//     -1 on error
//     0 if jacobi symbol is 1
//     1 if jac
int TDF_PS_decide(const TDF_PS_PK *pk, const BIGNUM *x, BN_CTX *bn_ctx) {
	int ret, ok;
	int jac;
	CHECK_IS_ZERO(BN_jacobi_priv(x, pk->n, &jac, bn_ctx));
	if (jac == 1) {
		ret = 0;
	} else if (jac == -1) {
		ret = 1;
	} else {
		goto err;
	}
	goto cleanup;
err:
	ret = -1;
cleanup:
	return ret;
}

int TDF_PS_test(int keylen, int print) {
	int ret, ok;
	int ver;
	TDF_PS_PK *pk = NULL;
	TDF_PS_TDK *tdk = NULL;
	BIGNUM *x = NULL, *y = NULL, *xprime = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(TDF_PS_keygen(&pk, &tdk, keylen, bn_ctx));
	CHECK_NONNULL(x = BN_new());
	CHECK_NONNULL(y = BN_new());
	CHECK_NONNULL(xprime = BN_new());
	for (int i = 0; i < 10; i++) {
		CHECK_IS_ONE(BN_rand_range(x, pk->halfn));
		int b = TDF_PS_decide(pk, x, bn_ctx);
		CHECK_GE_ZERO(b);
		CHECK_IS_ONE(TDF_PS_apply(y, pk, x, bn_ctx));
		CHECK_IS_ONE(TDF_PS_inv(xprime, tdk, y, b, bn_ctx));
		ver = BN_cmp(x, xprime);
		if (print) {
			TDF_PS_PK_print_fp(stdout, pk);
			TDF_PS_TDK_print_fp(stdout, tdk);
			BN_printdec_fp(stdout, "x", x);
			fprintf(stdout, "Decide(x) = %d\n", b);
			BN_printdec_fp(stdout, "y", y);
			BN_printdec_fp(stdout, "xprime", xprime);
		}
		CHECK_IS_ZERO(ver);
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(x);
	BN_free(y);
	BN_free(xprime);
	TDF_PS_PK_free(pk);
	TDF_PS_TDK_free(tdk);
	BN_CTX_free(bn_ctx);
	return ret;
}
