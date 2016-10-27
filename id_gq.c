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

/** \file id_gq.c
 * GQ identification scheme.
 */

#define UNUSED __attribute__ ((unused))

#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "common.h"
#include "bn_extra.h"
#include "id_gq.h"

void ID_GQ_PK_free(ID_GQ_PK *pk) {
	if (pk == NULL) {
		return;
	}
	BN_free(pk->n);
	BN_free(pk->e);
	BN_free(pk->X);
	OPENSSL_free(pk);
}

void ID_GQ_SK_free(ID_GQ_SK *sk) {
	if (sk == NULL) {
		return;
	}
	BN_free(sk->x);
	BN_free(sk->n);
	OPENSSL_free(sk);
}

void ID_GQ_TDK_free(ID_GQ_TDK *tdk) {
	if (tdk == NULL) {
		return;
	}
	BN_free(tdk->d);
	BN_free(tdk->n);
	RSA_free(tdk->rsa);
	OPENSSL_free(tdk);
}

void ID_GQ_CMT_free(ID_GQ_CMT *cmt) {
	if (cmt == NULL) {
		return;
	}
	BN_free(cmt->Y);
	OPENSSL_free(cmt);
}

void ID_GQ_STATE_free(ID_GQ_STATE *state) {
	if (state == NULL) {
		return;
	}
	BN_free(state->y);
	OPENSSL_free(state);
}

void ID_GQ_CH_free(ID_GQ_CH *ch) {
	if (ch == NULL) {
		return;
	}
	BN_free(ch->c);
	OPENSSL_free(ch);
}

void ID_GQ_RESP_free(ID_GQ_RESP *resp) {
	if (resp == NULL) {
		return;
	}
	BN_free(resp->z);
	OPENSSL_free(resp);
}

void ID_GQ_PK_print_fp(FILE *fp, const ID_GQ_PK *pk) {
	if (pk == NULL) {
		return;
	}
	BN_printdec_fp(fp, "pk_n", pk->n);
	BN_printdec_fp(fp, "pk_e", pk->e);
	BN_printdec_fp(fp, "pk_X", pk->X);
}

void ID_GQ_SK_print_fp(FILE *fp, const ID_GQ_SK *sk) {
	if (sk == NULL) {
		return;
	}
	BN_printdec_fp(fp, "sk_n", sk->n);
	BN_printdec_fp(fp, "sk_x", sk->x);
}

void ID_GQ_TDK_print_fp(FILE *fp, const ID_GQ_TDK *tdk) {
	if (tdk == NULL) {
		return;
	}
	BN_printdec_fp(fp, "tdk_n", tdk->n);
	BN_printdec_fp(fp, "tdk_d", tdk->d);
}

void ID_GQ_CMT_print_fp(FILE *fp, const ID_GQ_CMT *cmt) {
	if (cmt == NULL) {
		return;
	}
	BN_printdec_fp(fp, "cmt_Y", cmt->Y);
}

void ID_GQ_STATE_print_fp(FILE *fp, const ID_GQ_STATE *state) {
	if (state == NULL) {
		return;
	}
	BN_printdec_fp(fp, "state_y", state->y);
}

void ID_GQ_CH_print_fp(FILE *fp, const ID_GQ_CH *ch) {
	if (ch == NULL) {
		return;
	}
	BN_printdec_fp(fp, "ch_c", ch->c);
}

void ID_GQ_RESP_print_fp(FILE *fp, const ID_GQ_RESP *resp) {
	if (resp == NULL) {
		return;
	}
	BN_printdec_fp(fp, "resp_z", resp->z);
}

void ID_GQ_print_fp(FILE *fp, const ID_GQ_PK *pk, const ID_GQ_SK *sk, const ID_GQ_TDK *tdk, const ID_GQ_CMT *cmt, const ID_GQ_STATE *state, const ID_GQ_CH *ch, const ID_GQ_RESP *resp) {
	ID_GQ_PK_print_fp(fp, pk);
	ID_GQ_SK_print_fp(fp, sk);
	ID_GQ_TDK_print_fp(fp, tdk);
	ID_GQ_CMT_print_fp(fp, cmt);
	ID_GQ_STATE_print_fp(fp, state);
	ID_GQ_CH_print_fp(fp, ch);
	ID_GQ_RESP_print_fp(fp, resp);
}

// allocates *pk, *sk, and *tdk which must be later freed
// returns 1 on success and 0 on error
int ID_GQ_keygen(ID_GQ_PK **pk, ID_GQ_SK **sk, ID_GQ_TDK **tdk, const int bits, const int chlen, BN_CTX *bn_ctx) {
	int ret, ok;
	ID_GQ_PK *rpk = NULL;
	ID_GQ_SK *rsk = NULL;
	ID_GQ_TDK *rtdk = NULL;
	CHECK_NONNULL(rpk = (ID_GQ_PK *) OPENSSL_malloc(sizeof(ID_GQ_PK)));
	CHECK_NONNULL(rsk = (ID_GQ_SK *) OPENSSL_malloc(sizeof(ID_GQ_SK)));
	CHECK_NONNULL(rtdk = (ID_GQ_TDK *) OPENSSL_malloc(sizeof(ID_GQ_TDK)));
	CHECK_NONNULL(rtdk->rsa = RSA_new());
	CHECK_NONNULL(rpk->e = BN_new());
	if (chlen == 160) {
		CHECK_GT_ZERO(BN_dec2bn(&(rpk->e), "1461501637330902918203684832716283019655932542983")); // nextprime(2^160)
	} else if (chlen == 256) {
		CHECK_GT_ZERO(BN_dec2bn(&(rpk->e), "115792089237316195423570985008687907853269984665640564039457584007913129640233")); // nextprime(2^256)
	} else {
		fprintf(stderr, "IDGQ implementation currently only supports challenge lengths of 160 and 256;\n");
		fprintf(stderr, "update ID_GQ_keygen to set e to be nextprime(2^chlen)\n");
		fflush(stderr);
		goto err;
	}
	CHECK_IS_ONE(RSA_generate_key_ex(rtdk->rsa, bits, rpk->e, NULL));
	CHECK_NONNULL(rpk->n = BN_dup(rtdk->rsa->n));
	CHECK_NONNULL(rsk->n = BN_dup(rtdk->rsa->n));
	CHECK_NONNULL(rsk->x = BN_new());
	// x <-$ [0, ..., n-1]
	CHECK_IS_ONE(BN_rand_range(rsk->x, rsk->n));
	CHECK_NONNULL(rpk->X = BN_new());
	// X <- x^e mod n
	CHECK_IS_ONE(BN_mod_exp(rpk->X, rsk->x, rpk->e, rpk->n, bn_ctx));
	if (tdk != NULL) {
		CHECK_NONNULL(rtdk->n = BN_dup(rtdk->rsa->n));
		CHECK_NONNULL(rtdk->d = BN_dup(rtdk->rsa->d));
		*tdk = rtdk;
	}
	*pk = rpk;
	*sk = rsk;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_PK_free(rpk);
	ID_GQ_SK_free(rsk);
	ID_GQ_TDK_free(rtdk);
cleanup:
	return ret;
}

// allocates *cmt and *state which must be later freed
// returns 1 on success and 0 on error
int ID_GQ_cmt(const ID_GQ_PK *pk, ID_GQ_CMT **cmt, ID_GQ_STATE **state, BN_CTX *bn_ctx) {
	int ret, ok;
	ID_GQ_CMT *rcmt = NULL;
	ID_GQ_STATE *rstate = NULL;
	CHECK_NONNULL(rcmt = (ID_GQ_CMT *) OPENSSL_malloc(sizeof(ID_GQ_CMT)));
	CHECK_NONNULL(rstate = (ID_GQ_STATE *) OPENSSL_malloc(sizeof(ID_GQ_STATE)));
	CHECK_NONNULL(rstate->y = BN_new());
	// y <-$ [0, ..., n-1]
	CHECK_IS_ONE(BN_rand_range(rstate->y, pk->n));
	CHECK_NONNULL(rcmt->Y = BN_new());
	// Y <- y^e mod n
	CHECK_IS_ONE(BN_mod_exp(rcmt->Y, rstate->y, pk->e, pk->n, bn_ctx));
	*cmt = rcmt;
	*state = rstate;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_CMT_free(rcmt);
	ID_GQ_STATE_free(rstate);
cleanup:
	return ret;
}

// allocates *state which must be later freed
// returns 1 on success and 0 on error
int ID_GQ_cmt_inv(const ID_GQ_TDK *tdk, const ID_GQ_CMT *cmt, ID_GQ_STATE **state, BN_CTX *bn_ctx) {
	int ret, ok;
	ID_GQ_STATE *rstate = NULL;
	CHECK_NONNULL(rstate = (ID_GQ_STATE *) OPENSSL_malloc(sizeof(ID_GQ_STATE)));
	CHECK_NONNULL(rstate->y = BN_new());
	// y <- Y^d mod n
	if (strcmp(tdk->rsa->meth->name, "Eric Young's PKCS#1 RSA") == 0) {
		CHECK_IS_ONE(tdk->rsa->meth->rsa_mod_exp(rstate->y, cmt->Y, tdk->rsa, bn_ctx));
	} else {
		CHECK_IS_ONE(BN_mod_exp(rstate->y, cmt->Y, tdk->d, tdk->n, bn_ctx));
	}
	*state = rstate;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_STATE_free(rstate);
cleanup:
	return ret;
}

// allocates *ch which must be later freed
// returns 1 on success and 0 on error
int ID_GQ_ch_rand(ID_GQ_CH **ch, int chlen) {
	int ret, ok;
	ID_GQ_CH *rch = NULL;
	CHECK_NONNULL(rch = (ID_GQ_CH *) OPENSSL_malloc(sizeof(ID_GQ_CH)));
	CHECK_NONNULL(rch->c = BN_new());
	CHECK_IS_ONE(BN_rand(rch->c, chlen, -1, 0));
	*ch = rch;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_CH_free(rch);
cleanup:
	return ret;
}

// allocates *ch which must be later freed
// returns 1 on success and 0 on error
int ID_GQ_ch_hash(ID_GQ_CH **ch, const int chlen, const unsigned char *msg, const int length) {
	int ret;
	if (chlen > SHA256_DIGEST_LENGTH * 8) {
		return 0;
	}
	ID_GQ_CH *rch = NULL;
	CHECK_NONNULL(rch = (ID_GQ_CH *) OPENSSL_malloc(sizeof(ID_GQ_CH)));
	unsigned char h[SHA256_DIGEST_LENGTH];
	SHA256(msg, length, h);
	CHECK_NONNULL(rch->c = BN_bin2bn(h, chlen / 8, NULL));
	*ch = rch;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_CH_free(rch);
cleanup:
	return ret;
}

// allocates *resp which must be later freed
// returns 1 on success and 0 on error
int ID_GQ_resp(const ID_GQ_SK *sk, const ID_GQ_STATE *state, const ID_GQ_CH *ch, ID_GQ_RESP **resp, BN_CTX *bn_ctx) {
	int ret, ok;
	ID_GQ_RESP *rresp = NULL;
	CHECK_NONNULL(rresp = (ID_GQ_RESP *) OPENSSL_malloc(sizeof(ID_GQ_RESP)));
	CHECK_NONNULL(rresp->z = BN_new());
	// z <- yx^c mod n
	CHECK_IS_ONE(BN_mod_exp(rresp->z, sk->x, ch->c, sk->n, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(rresp->z, state->y, rresp->z, sk->n, bn_ctx));
	*resp = rresp;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_RESP_free(rresp);
cleanup:
	return ret;
}

// allocates *cmt which must be later freed
// returns 1 on success and 0 on error
int ID_GQ_resp_inv(const ID_GQ_PK *pk, ID_GQ_CMT **cmt, const ID_GQ_CH *ch, const ID_GQ_RESP *resp, BN_CTX *bn_ctx) {
	int ret, ok;
	ID_GQ_CMT *rcmt = NULL;
	BIGNUM *tmp1 = NULL, *tmp2 = NULL;
	CHECK_NONNULL(rcmt = (ID_GQ_CMT *) OPENSSL_malloc(sizeof(ID_GQ_CMT)));
	CHECK_NONNULL(rcmt->Y = BN_new());
	CHECK_NONNULL(tmp1 = BN_new());
	CHECK_NONNULL(tmp2 = BN_new());
	// Y <- z^e * (X^c)^(-1) mod N
	CHECK_IS_ONE(BN_mod_exp(tmp1, resp->z, pk->e, pk->n, bn_ctx));
	CHECK_IS_ONE(BN_mod_exp(tmp2, pk->X, ch->c, pk->n, bn_ctx));
	CHECK_NONNULL(BN_mod_inverse(tmp2, tmp2, pk->n, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(rcmt->Y, tmp1, tmp2, pk->n, bn_ctx));
	*cmt = rcmt;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_CMT_free(rcmt);
cleanup:
	BN_free(tmp1);
	BN_free(tmp2);
	return ret;
}

// allocates *resp which must be later freed
// returns 1 if verification succeeds, 0 if verification fails, and -1 on error
int ID_GQ_ver(const ID_GQ_PK *pk, const ID_GQ_CMT *cmt, const ID_GQ_CH *ch, const ID_GQ_RESP *resp, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *lhs = NULL;
	BIGNUM *rhs = NULL;
	CHECK_NONNULL(lhs = BN_new());
	CHECK_NONNULL(rhs = BN_new());
	// lhs <- z^e mod n
	CHECK_IS_ONE(BN_mod_exp(lhs, resp->z, pk->e, pk->n, bn_ctx));
	// rhs <- YX^c mod n
	CHECK_IS_ONE(BN_mod_exp(rhs, pk->X, ch->c, pk->n, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(rhs, cmt->Y, rhs, pk->n, bn_ctx));
	if (BN_cmp(lhs, rhs) == 0) {
		ret = 1;
	} else {
		ret = 0;
	}
	goto cleanup;
err:
	ret = -1;
cleanup:
	BN_free(lhs);
	BN_free(rhs);
	return ret;
}

// allocates *sk which must be later freed
// return 1 on success and 0 on error
int ID_GQ_extract(const ID_GQ_PK *pk, UNUSED const ID_GQ_CMT *cmt, const ID_GQ_CH *ch1, const ID_GQ_RESP *resp1, const ID_GQ_CH *ch2, const ID_GQ_RESP *resp2, ID_GQ_SK **sk, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *z = NULL, *c = NULL;
	BIGNUM *dprime = NULL, *a = NULL, *b = NULL;
	BIGNUM *tmp = NULL, *tmp2 = NULL;
	ID_GQ_SK *rsk = NULL;
	CHECK_NONNULL(rsk = (ID_GQ_SK *) OPENSSL_malloc(sizeof(ID_GQ_SK)));
	CHECK_NONNULL(rsk->n = BN_dup(pk->n));
	CHECK_NONNULL(rsk->x = BN_new());
	// z <- z_1 / z_2 = yx^c_1 / yx^c_2 = x^(c_1-c_2)
	CHECK_NONNULL(z = BN_new());
	CHECK_NONNULL(BN_mod_inverse(z, resp2->z, pk->n, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(z, resp1->z, z, pk->n, bn_ctx));
	// d', a, b <- extended-gcd(e, c_1-c_2) => ae + b(c_1-c_2) = d' = 1 (see Bellare-Palacio full version page 11)
	CHECK_NONNULL(dprime = BN_new());
	CHECK_NONNULL(a = BN_new());
	CHECK_NONNULL(b = BN_new());
	CHECK_NONNULL(c = BN_new());
	CHECK_IS_ONE(BN_sub(c, ch1->c, ch2->c));
	if (BN_is_negative(c)) {
		BN_set_negative(c, 0);
		CHECK_NONNULL(tmp = BN_mod_inverse(NULL, z, pk->n, bn_ctx));
		BN_free(z);
		z = tmp;
		tmp = NULL;
	}
	CHECK_IS_ONE(BN_extended_gcd(dprime, a, b, pk->e, c, bn_ctx));
	CHECK_IS_ONE(BN_is_one(dprime));
	// x <- X^a z^b mod n = x^{ae} x^{b(c_1-c_2)} mod n = x^{ae + b(c_1-c_2)} mod n = x mod n
	CHECK_NONNULL(tmp = BN_new());
	// BN_mod_exp doesn't deal with negative exponents properly so we need to do that ourselves
	if (BN_is_negative(b)) {
		BN_set_negative(b, 0);
		CHECK_IS_ONE(BN_mod_exp(tmp, z, b, pk->n, bn_ctx));
		CHECK_NONNULL(tmp2 = BN_mod_inverse(NULL, tmp, pk->n, bn_ctx));
		BN_free(tmp);
		tmp = tmp2;
		tmp2 = NULL;
		BN_set_negative(b, 1);
	} else {
		CHECK_IS_ONE(BN_mod_exp(tmp, z, b, pk->n, bn_ctx));
	}
	if (BN_is_negative(a)) {
		BN_set_negative(a, 0);
		CHECK_IS_ONE(BN_mod_exp(rsk->x, pk->X, a, pk->n, bn_ctx));
		CHECK_NONNULL(tmp2 = BN_mod_inverse(NULL, rsk->x, pk->n, bn_ctx));
		BN_free(rsk->x);
		rsk->x = tmp2;
		tmp2 = NULL;
		BN_set_negative(a, 1);
	} else {
		CHECK_IS_ONE(BN_mod_exp(rsk->x, pk->X, a, pk->n, bn_ctx));
	}
	CHECK_IS_ONE(BN_mod_mul(rsk->x, rsk->x, tmp, pk->n, bn_ctx));
	ret = 1;
	*sk = rsk;
	goto cleanup;
err:
	ret = 0;
	ID_GQ_SK_free(rsk);
cleanup:
	BN_free(z);
	BN_free(c);
	BN_free(dprime);
	BN_free(a);
	BN_free(b);
	BN_free(tmp);
	BN_free(tmp2);
	return ret;
}

// returns 1 on success and 0 on error
int ID_GQ_test_rand(const int keylen, const int chlen, const int print) {
	int ret, ok;
	ID_GQ_PK *pk = NULL;
	ID_GQ_SK *sk = NULL;
	ID_GQ_CMT *cmt = NULL;
	ID_GQ_STATE *state = NULL;
	ID_GQ_CH *ch = NULL;
	ID_GQ_RESP *resp = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(ID_GQ_keygen(&pk, &sk, NULL, keylen, chlen, bn_ctx));
	CHECK_IS_ONE(ID_GQ_cmt(pk, &cmt, &state, bn_ctx));
	CHECK_IS_ONE(ID_GQ_ch_rand(&ch, chlen));
	CHECK_IS_ONE(ID_GQ_resp(sk, state, ch, &resp, bn_ctx));
	int ver = ID_GQ_ver(pk, cmt, ch, resp, bn_ctx);
	if (print) {
		if (ver == 1) {
			printf("verifies\n");
		} else {
			printf("!!! DOES NOT VERIFY !!!\n");
		}
		ID_GQ_print_fp(stdout, pk, sk, NULL, cmt, state, ch, resp);
	}
	ret = (ver == 1);
	goto cleanup;
err:
	ret = 0;
	fprintf(stderr, "An error occurred.\n");
cleanup:
	ID_GQ_PK_free(pk);
	ID_GQ_SK_free(sk);
	ID_GQ_CMT_free(cmt);
	ID_GQ_STATE_free(state);
	ID_GQ_CH_free(ch);
	ID_GQ_RESP_free(resp);
	BN_CTX_free(bn_ctx);
	return ret;
}

// returns 1 on success and 0 on error
int ID_GQ_test_cmt_cmt_inv(const int keylen, const int chlen, const int print) {
	int ret, ok;
	ID_GQ_PK *pk = NULL;
	ID_GQ_SK *sk = NULL;
	ID_GQ_TDK *tdk = NULL;
	ID_GQ_CMT *cmt = NULL;
	ID_GQ_STATE *state = NULL, *state_prime = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(ID_GQ_keygen(&pk, &sk, &tdk, keylen, chlen, bn_ctx));
	CHECK_IS_ONE(ID_GQ_cmt(pk, &cmt, &state, bn_ctx));
	CHECK_IS_ONE(ID_GQ_cmt_inv(tdk, cmt, &state_prime, bn_ctx));
	int ver = (BN_cmp(state->y, state_prime->y) == 0);
	if (print) {
		if (ver == 1) {
			printf("cmt/cmt_inv works\n");
		} else {
			printf("!!! CMT/CMT_INV DOES NOT WORK !!!\n");
		}
		ID_GQ_PK_print_fp(stdout, pk);
		ID_GQ_SK_print_fp(stdout, sk);
		ID_GQ_TDK_print_fp(stdout, tdk);
		ID_GQ_CMT_print_fp(stdout, cmt);
		ID_GQ_STATE_print_fp(stdout, state);
		ID_GQ_STATE_print_fp(stdout, state_prime);
	}
	ret = (ver == 1);
	goto cleanup;
err:
	ret = 0;
	fprintf(stderr, "An error occurred.\n");
cleanup:
	ID_GQ_PK_free(pk);
	ID_GQ_TDK_free(tdk);
	ID_GQ_SK_free(sk);
	ID_GQ_CMT_free(cmt);
	ID_GQ_STATE_free(state);
	ID_GQ_STATE_free(state_prime);
	BN_CTX_free(bn_ctx);
	return ret;
}

// returns 1 on success and 0 on error
int ID_GQ_test_hash(const int keylen, const int chlen, const unsigned char *msg, const int length, const int print) {
	int ret, ok;
	ID_GQ_PK *pk = NULL;
	ID_GQ_SK *sk = NULL;
	ID_GQ_CMT *cmt = NULL;
	ID_GQ_STATE *state = NULL;
	ID_GQ_CH *ch = NULL;
	ID_GQ_RESP *resp = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(ID_GQ_keygen(&pk, &sk, NULL, keylen, chlen, bn_ctx));
	CHECK_IS_ONE(ID_GQ_cmt(pk, &cmt, &state, bn_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch, chlen, msg, length));
	CHECK_IS_ONE(ID_GQ_resp(sk, state, ch, &resp, bn_ctx));
	int ver = ID_GQ_ver(pk, cmt, ch, resp, bn_ctx);
	if (print) {
		if (ver == 1) {
			printf("verifies\n");
		} else {
			printf("!!! DOES NOT VERIFY !!!\n");
		}
		ID_GQ_print_fp(stdout, pk, sk, NULL, cmt, state, ch, resp);
	}
	ret = (ver == 1);
	goto cleanup;
err:
	ret = 0;
	fprintf(stderr, "An error occurred.\n");
cleanup:
	ID_GQ_PK_free(pk);
	ID_GQ_SK_free(sk);
	ID_GQ_CMT_free(cmt);
	ID_GQ_STATE_free(state);
	ID_GQ_CH_free(ch);
	ID_GQ_RESP_free(resp);
	BN_CTX_free(bn_ctx);
	return ret;
}

// returns 1 on success and 0 on error
int ID_GQ_test_hash_inv(const int keylen, const int chlen, const unsigned char *msg, const int length, const int print) {
	int ret, ok;
	ID_GQ_PK *pk = NULL;
	ID_GQ_SK *sk = NULL;
	ID_GQ_TDK *tdk = NULL;
	ID_GQ_CMT *cmt = NULL;
	ID_GQ_STATE *state = NULL;
	ID_GQ_CH *ch = NULL;
	ID_GQ_RESP *resp = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(ID_GQ_keygen(&pk, &sk, &tdk, keylen, chlen, bn_ctx));
	CHECK_NONNULL(cmt = (ID_GQ_CMT *) OPENSSL_malloc(sizeof(ID_GQ_CMT)));
	CHECK_NONNULL(cmt->Y = BN_new());
	CHECK_IS_ONE(BN_rand_range(cmt->Y, pk->n));
	CHECK_IS_ONE(ID_GQ_cmt_inv(tdk, cmt, &state, bn_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch, chlen, msg, length));
	CHECK_IS_ONE(ID_GQ_resp(sk, state, ch, &resp, bn_ctx));
	int ver = ID_GQ_ver(pk, cmt, ch, resp, bn_ctx);
	if (print) {
		if (ver == 1) {
			printf("verifies\n");
		} else {
			printf("!!! DOES NOT VERIFY !!!\n");
		}
		ID_GQ_print_fp(stdout, pk, sk, tdk, cmt, state, ch, resp);
	}
	ret = (ver == 1);
	goto cleanup;
err:
	ret = 0;
	fprintf(stderr, "An error occurred.\n");
cleanup:
	ID_GQ_PK_free(pk);
	ID_GQ_SK_free(sk);
	ID_GQ_TDK_free(tdk);
	ID_GQ_CMT_free(cmt);
	ID_GQ_STATE_free(state);
	ID_GQ_CH_free(ch);
	ID_GQ_RESP_free(resp);
	BN_CTX_free(bn_ctx);
	return ret;
}

// returns 1 on success and 0 on error
int ID_GQ_test_resp_inv(const int keylen, const int chlen, const unsigned char *msg, const int length, const int print) {
	int ret, ok;
	ID_GQ_PK *pk = NULL;
	ID_GQ_SK *sk = NULL;
	ID_GQ_TDK *tdk = NULL;
	ID_GQ_CMT *cmt = NULL, *cmtprime = NULL;
	ID_GQ_STATE *state = NULL;
	ID_GQ_CH *ch = NULL;
	ID_GQ_RESP *resp = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(ID_GQ_keygen(&pk, &sk, NULL, keylen, chlen, bn_ctx));
	CHECK_IS_ONE(ID_GQ_cmt(pk, &cmt, &state, bn_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch, chlen, msg, length));
	CHECK_IS_ONE(ID_GQ_resp(sk, state, ch, &resp, bn_ctx));
	CHECK_IS_ONE(ID_GQ_resp_inv(pk, &cmtprime, ch, resp, bn_ctx));
	int ver = BN_cmp(cmt->Y, cmtprime->Y);
	if (print) {
		if (ver == 0) {
			printf("recovers correct commitment\n");
		} else {
			printf("!!! DOES NOT RECOVER CORRECT COMMITMENT !!!\n");
		}
		ID_GQ_print_fp(stdout, pk, sk, tdk, cmt, state, ch, resp);
		ID_GQ_CMT_print_fp(stdout, cmtprime);
	}
	ret = (ver == 0);
	goto cleanup;
err:
	ret = 0;
	fprintf(stderr, "An error occurred.\n");
cleanup:
	ID_GQ_PK_free(pk);
	ID_GQ_SK_free(sk);
	ID_GQ_TDK_free(tdk);
	ID_GQ_CMT_free(cmt);
	ID_GQ_CMT_free(cmtprime);
	ID_GQ_STATE_free(state);
	ID_GQ_CH_free(ch);
	ID_GQ_RESP_free(resp);
	BN_CTX_free(bn_ctx);
	return ret;
}

// returns 1 on success and 0 on error
int ID_GQ_test_extract(const int keylen, const int chlen, const int print) {
	int ret, ok;
	ID_GQ_PK *pk = NULL;
	ID_GQ_SK *sk = NULL;
	ID_GQ_CMT *cmt = NULL;
	ID_GQ_STATE *state = NULL;
	ID_GQ_CH *ch1 = NULL, *ch2 = NULL;
	ID_GQ_RESP *resp1 = NULL, *resp2 = NULL;
	ID_GQ_SK *skprime = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(ID_GQ_keygen(&pk, &sk, NULL, keylen, chlen, bn_ctx));
	CHECK_IS_ONE(ID_GQ_cmt(pk, &cmt, &state, bn_ctx));
	CHECK_IS_ONE(ID_GQ_ch_rand(&ch1, chlen));
	CHECK_IS_ONE(ID_GQ_resp(sk, state, ch1, &resp1, bn_ctx));
	CHECK_IS_ONE(ID_GQ_ch_rand(&ch2, chlen));
	CHECK_IS_ONE(ID_GQ_resp(sk, state, ch2, &resp2, bn_ctx));
	CHECK_IS_ONE(ID_GQ_extract(pk, cmt, ch1, resp1, ch2, resp2, &skprime, bn_ctx));
	int ver = BN_cmp(sk->x, skprime->x);
	if (print) {
		if (ver == 0) {
			printf("extracts\n");
		} else {
			printf("!!! DOES NOT EXTRACT !!!\n");
		}
		ID_GQ_print_fp(stdout, pk, sk, NULL, cmt, state, ch1, resp1);
		ID_GQ_CH_print_fp(stdout, ch2);
		ID_GQ_RESP_print_fp(stdout, resp2);
		ID_GQ_SK_print_fp(stdout, skprime);
	}
	ret = (ver == 0);
	goto cleanup;
err:
	ret = 0;
	fprintf(stderr, "An error occurred.\n");
cleanup:
	ID_GQ_PK_free(pk);
	ID_GQ_SK_free(sk);
	ID_GQ_CMT_free(cmt);
	ID_GQ_STATE_free(state);
	ID_GQ_CH_free(ch1);
	ID_GQ_CH_free(ch2);
	ID_GQ_RESP_free(resp1);
	ID_GQ_RESP_free(resp2);
	ID_GQ_SK_free(skprime);
	BN_CTX_free(bn_ctx);
	return ret;
}
