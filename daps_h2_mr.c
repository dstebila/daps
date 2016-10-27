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

/** \file daps_h2_mr.c
 * H2[MR] DAPS scheme.
 */

#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "common.h"
#include "daps_h2_mr.h"
#include "bn_extra.h"

static void fprint_hex(FILE *fp, const unsigned char *s, const int len) {
	for (int i = 0; i < len; i++) {
		fprintf(fp, "%02X", (unsigned int) s[i]);
	}
}

void DAPS_H2_MR_VK_free(DAPS_H2_MR_VK *vk) {
	if (vk == NULL) {
		return;
	}
	BN_free(vk->N);
	OPENSSL_free(vk);
}

void DAPS_H2_MR_SK_free(DAPS_H2_MR_SK *sk) {
	if (sk == NULL) {
		return;
	}
	BN_free(sk->N);
	BN_free(sk->p);
	BN_free(sk->q);
	BN_free(sk->up);
	BN_free(sk->uq);
	BN_free(sk->vp);
	BN_free(sk->vq);
	OPENSSL_free(sk);
}

void DAPS_H2_MR_SIG_free(DAPS_H2_MR_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	BN_free(sig->z);
	OPENSSL_free(sig->s);
	OPENSSL_free(sig);
}

void DAPS_H2_MR_VK_print_fp(FILE *fp, const DAPS_H2_MR_VK *vk) {
	if (vk == NULL) {
		return;
	}
	BN_printdec_fp(fp, "N", vk->N);
}

void DAPS_H2_MR_SK_print_fp(FILE *fp, const DAPS_H2_MR_SK *sk) {
	if (sk == NULL) {
		return;
	}
	BN_printdec_fp(fp, "N", sk->N);
	BN_printdec_fp(fp, "p", sk->p);
	BN_printdec_fp(fp, "q", sk->q);
	BN_printdec_fp(fp, "up", sk->up);
	BN_printdec_fp(fp, "uq", sk->uq);
	BN_printdec_fp(fp, "vp", sk->vp);
	BN_printdec_fp(fp, "vq", sk->vq);
}

void DAPS_H2_MR_SIG_print_fp(FILE *fp, const DAPS_H2_MR_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	BN_printdec_fp(fp, "z", sig->z);
	fprintf(fp, "s := 0x");
	fprint_hex(fp, sig->s, sig->s_length);
	fprintf(fp, "\n");
}

static int Fprecompute(BIGNUM *up, BIGNUM *uq, BIGNUM *vp, BIGNUM *vq, const BIGNUM *p, const BIGNUM *q, const int l, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *t1 = NULL, *t2 = NULL, *l_bn = NULL, *one = NULL, *four = NULL;
	CHECK_NONNULL(t1 = BN_new());
	CHECK_NONNULL(t2 = BN_new());
	CHECK_NONNULL(l_bn = BN_new());
	CHECK_NONNULL(one = BN_new());
	CHECK_NONNULL(four = BN_new());
	CHECK_IS_ONE(BN_set_word(l_bn, l));
	CHECK_IS_ONE(BN_set_word(one, 1));
	CHECK_IS_ONE(BN_set_word(four, 4));
	// vp = ((p+1)/4)^l mod (p-1)
	CHECK_IS_ONE(BN_add(t1, p, one));
	CHECK_IS_ONE(BN_rshift(t1, t1, 2));
	CHECK_IS_ONE(BN_sub(t2, p, one));
	CHECK_IS_ONE(BN_mod_exp(vp, t1, l_bn, t2, bn_ctx));
	// vq = ((q+1)/4)^l mod (q-1)
	CHECK_IS_ONE(BN_add(t1, q, one));
	CHECK_IS_ONE(BN_rshift(t1, t1, 2));
	CHECK_IS_ONE(BN_sub(t2, q, one));
	CHECK_IS_ONE(BN_mod_exp(vq, t1, l_bn, t2, bn_ctx));
	// up = (4^{-1})^{vp} mod p
	CHECK_NONNULL(BN_mod_inverse(t1, four, p, bn_ctx));
	CHECK_IS_ONE(BN_mod_exp(up, t1, vp, p, bn_ctx));
	// uq = (4^{-1})^{vq} mod q
	CHECK_NONNULL(BN_mod_inverse(t1, four, q, bn_ctx));
	CHECK_IS_ONE(BN_mod_exp(uq, t1, vq, q, bn_ctx));
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(t1);
	BN_free(t2);
	BN_free(l_bn);
	BN_free(one);
	BN_free(four);
	return ret;
}

// F_0(x) = x^2 mod N
// note r can be same as x
static int F0(BIGNUM *r, const BIGNUM *x, const BIGNUM *N, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *rprime = NULL;
	if (x == r) {
		CHECK_NONNULL(rprime = BN_new());
		CHECK_IS_ONE(BN_mod_sqr(rprime, x, N, bn_ctx));
		CHECK_NONNULL(BN_copy(r, rprime));
	} else {
		CHECK_IS_ONE(BN_mod_sqr(r, x, N, bn_ctx));
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	if (x == r) {
		BN_free(rprime);
	}
	return ret;
}

// F_1(x) = 4x^2 mod N
// note r can be same as x
static int F1(BIGNUM *r, const BIGNUM *x, const BIGNUM *N, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *t1 = NULL, *t2 = NULL;
	CHECK_NONNULL(t1 = BN_new());
	CHECK_NONNULL(t2 = BN_new());
	CHECK_IS_ONE(BN_set_word(t1, 4));
	CHECK_IS_ONE(BN_mod_sqr(t2, x, N, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(r, t1, t2, N, bn_ctx));
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(t1);
	BN_free(t2);
	return ret;
}

// F_c(x) = x^(2^l)*4^c  mod N
static int F(BIGNUM *r, const BIGNUM *c, const BIGNUM *x, const int l, const BIGNUM *N, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *t1 = NULL, *t2 = NULL, *t3 = NULL;
	CHECK_NONNULL(t1 = BN_new());
	CHECK_NONNULL(t2 = BN_new());
	CHECK_NONNULL(t3 = BN_new());
	CHECK_IS_ONE(BN_set_word(t3, 1));
	CHECK_IS_ONE(BN_lshift(t3, t3, l));
	CHECK_IS_ONE(BN_mod_exp(t1, x, t3, N, bn_ctx));
	CHECK_IS_ONE(BN_set_word(t3, 4));
	CHECK_IS_ONE(BN_mod_exp(t2, t3, c, N, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(r, t1, t2, N, bn_ctx))
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	return ret;
}

// Finv_c(y) = y^(2^(-l))*u^c  mod N  where u = (1/4)^(2^(-l))
static int Finv(BIGNUM *r, const BIGNUM *c, const BIGNUM *y, const BIGNUM *p, const BIGNUM *q, const BIGNUM *up, const BIGNUM *uq, const BIGNUM *vp, const BIGNUM *vq, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *yp = NULL, *yq = NULL, *t1 = NULL, *t2 = NULL, *xp = NULL, *xq = NULL;
	CHECK_NONNULL(yp = BN_new());
	CHECK_NONNULL(yq = BN_new());
	CHECK_NONNULL(t1 = BN_new());
	CHECK_NONNULL(t2 = BN_new());
	CHECK_NONNULL(xp = BN_new());
	CHECK_NONNULL(xq = BN_new());
	CHECK_IS_ONE(BN_mod(yp, y, p, bn_ctx));
	CHECK_IS_ONE(BN_mod(yq, y, q, bn_ctx));
	// xp = yp^vp * up^c mod p
	CHECK_IS_ONE(BN_mod_exp(t1, yp, vp, p, bn_ctx));
	CHECK_IS_ONE(BN_mod_exp(t2, up, c, p, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(xp, t1, t2, p, bn_ctx));
	// xq = yq^vq * uq^c mod q
	CHECK_IS_ONE(BN_mod_exp(t1, yq, vq, q, bn_ctx));
	CHECK_IS_ONE(BN_mod_exp(t2, uq, c, q, bn_ctx));
	CHECK_IS_ONE(BN_mod_mul(xq, t1, t2, q, bn_ctx));
	// x = CRT(xp, xq, p, q)
	CHECK_IS_ONE(BN_crt(r, xp, p, xq, q, bn_ctx));
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(yp);
	BN_free(yq);
	BN_free(t1);
	BN_free(t2);
	BN_free(xp);
	BN_free(xq);
	return ret;
}

static int Fextract(BIGNUM *p, BIGNUM *q, const BIGNUM *x0, const BIGNUM *x1, const BIGNUM *N, int recursing, BN_CTX *bn_ctx) {
	int ret, ok;
	BIGNUM *t1 = NULL, *t2 = NULL, *one = NULL;
	CHECK_NONNULL(t1 = BN_new());
	CHECK_NONNULL(t2 = BN_new());
	CHECK_NONNULL(one = BN_new());
	CHECK_IS_ONE(BN_set_word(one, 1));
	// p = gcd(x0 - 2 * x1, N)
	CHECK_IS_ONE(BN_mod_lshift1(t1, x1, N, bn_ctx));
	CHECK_IS_ONE(BN_mod_sub(t2, x0, t1, N, bn_ctx));
	CHECK_IS_ONE(BN_gcd(p, t2, N, bn_ctx));
	CHECK_IS_ONE(BN_div(q, NULL, N, p, bn_ctx));
	if (((BN_cmp(p, one) == 0) || (BN_cmp(q, one) == 0)) && !recursing) {
		CHECK_IS_ONE(Fextract(p, q, x1, x0, N, 1, bn_ctx));
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	BN_free(t1);
	BN_free(t2);
	return ret;
}

// allocates *vk and *sk which must be later freed
// returns 1 on success and 0 on error
int DAPS_H2_MR_keygen(DAPS_H2_MR_VK **vk, DAPS_H2_MR_SK **sk, const int bits, const int chbits, BN_CTX *bn_ctx) {
	int ret, ok;
	DAPS_H2_MR_VK *rvk = NULL;
	DAPS_H2_MR_SK *rsk = NULL;
	BIGNUM *a = NULL, *b = NULL;
	// allocate memory
	CHECK_NONNULL(rvk = (DAPS_H2_MR_VK *) OPENSSL_malloc(sizeof(DAPS_H2_MR_VK)));
	CHECK_NONNULL(rsk = (DAPS_H2_MR_SK *) OPENSSL_malloc(sizeof(DAPS_H2_MR_SK)));
	CHECK_NONNULL(rsk->N = BN_new());
	CHECK_NONNULL(rsk->p = BN_new());
	CHECK_NONNULL(rsk->q = BN_new());
	CHECK_NONNULL(rsk->up = BN_new());
	CHECK_NONNULL(rsk->uq = BN_new());
	CHECK_NONNULL(rsk->vp = BN_new());
	CHECK_NONNULL(rsk->vq = BN_new());
	CHECK_NONNULL(a = BN_new());
	CHECK_NONNULL(b = BN_new());
	// generate Williams modulus
	CHECK_IS_ONE(BN_set_word(a, 3));
	CHECK_IS_ONE(BN_set_word(b, 8));
	CHECK_IS_ONE(BN_generate_prime_ex(rsk->p, bits / 2, 0, b, a, NULL));
	CHECK_IS_ONE(BN_set_word(a, 7));
	CHECK_IS_ONE(BN_set_word(b, 8));
	CHECK_IS_ONE(BN_generate_prime_ex(rsk->q, bits / 2, 0, b, a, NULL));
	CHECK_IS_ONE(BN_mul(rsk->N, rsk->p, rsk->q, bn_ctx));
	CHECK_NONNULL(rvk->N = BN_dup(rsk->N));
	CHECK_IS_ONE(Fprecompute(rsk->up, rsk->uq, rsk->vp, rsk->vq, rsk->p, rsk->q, chbits, bn_ctx));
	rvk->chbits = chbits;
	rsk->chbits = chbits;
	*vk = rvk;
	*sk = rsk;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	DAPS_H2_MR_VK_free(rvk);
	DAPS_H2_MR_SK_free(rsk);
cleanup:
	BN_free(a);
	BN_free(b);
	return ret;
}

int DAPS_H2_MR_sign(const DAPS_H2_MR_SK *sk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, DAPS_H2_MR_SIG **sig, BN_CTX *bn_ctx) {
	int ret, ok;
	DAPS_H2_MR_SIG *rsig = NULL;
	unsigned char c[SHA256_DIGEST_LENGTH];
	BIGNUM *Yprime = NULL, *Yprimemodp = NULL, *Yprimemodq = NULL, *t1 = NULL, *c_bn = NULL;
	SHA256_CTX sha256_ctx;
	CHECK_NONNULL(Yprimemodp = BN_new());
	CHECK_NONNULL(Yprimemodq = BN_new());
	CHECK_NONNULL(t1 = BN_new());
	CHECK_NONNULL(c_bn = BN_new());
	CHECK_NONNULL(rsig = (DAPS_H2_MR_SIG *) OPENSSL_malloc(sizeof(DAPS_H2_MR_SIG)));
	CHECK_NONNULL(rsig->z = BN_new());
	CHECK_NONNULL(rsig->s = OPENSSL_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH));
	rsig->s_length = SHA256_DIGEST_LENGTH;
	// s <- {0,1}^256
	CHECK_IS_ONE(RAND_bytes(rsig->s, SHA256_DIGEST_LENGTH));
	// Y' <- H(msg_subj) in Z_N^*
	CHECK_NONNULL(Yprime = SHA256_mod(msg_subj, msg_subj_length, sk->N, bn_ctx));
	// find which of Y', -Y', 2Y', -2Y' is a quadratic residue modulo N
	int jac_p, jac_q;
	CHECK_IS_ONE(BN_mod(Yprimemodp, Yprime, sk->p, bn_ctx));
	CHECK_IS_ONE(BN_mod(Yprimemodq, Yprime, sk->q, bn_ctx));
	CHECK_IS_ZERO(BN_jacobi_priv(Yprimemodp, sk->p, &jac_p, bn_ctx));
	CHECK_IS_ZERO(BN_jacobi_priv(Yprimemodq, sk->q, &jac_q, bn_ctx));
	if ((jac_p == 1) && (jac_q == 1)) {
		// Yprime is Y'
	} else if ((jac_p == -1) && (jac_q == -1)) {
		CHECK_IS_ONE(BN_mod_sub(t1, sk->N, Yprime, sk->N, bn_ctx));
		CHECK_NONNULL(BN_copy(Yprime, t1));
		// now Yprime is -Y'
	} else if ((jac_p == -1) && (jac_q == 1)) {
		CHECK_IS_ONE(BN_mod_lshift1(t1, Yprime, sk->N, bn_ctx));
		CHECK_NONNULL(BN_copy(Yprime, t1));
		// now Yprime is 2Y'
	} else if ((jac_p == 1) && (jac_q == -1)) {
		CHECK_IS_ONE(BN_mod_lshift1(t1, Yprime, sk->N, bn_ctx));
		CHECK_IS_ONE(BN_mod_sub(Yprime, sk->N, t1, sk->N, bn_ctx));
		// now Yprime is -2Y'
	} else {
		// we should never reach this point; at least one of the above should be a QR
		goto err;
	}

	// c = H(a || p || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, rsig->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_NONNULL(BN_bin2bn(c, SHA256_DIGEST_LENGTH, c_bn));
	// z = Y^{2^{-cl}} u^c mod N
	CHECK_IS_ONE(Finv(rsig->z, c_bn, Yprime, sk->p, sk->q, sk->up, sk->uq, sk->vp, sk->vq, bn_ctx));
	ret = 1;
	*sig = rsig;
	goto cleanup;
err:
	ret = 0;
	DAPS_H2_MR_SIG_free(rsig);
cleanup:
	BN_free(t1);
	BN_free(c_bn);
	BN_free(Yprime);
	return ret;
}

int DAPS_H2_MR_verify(const DAPS_H2_MR_VK *vk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const DAPS_H2_MR_SIG *sig, BN_CTX *bn_ctx) {
	int ret, ok;
	unsigned char c[SHA256_DIGEST_LENGTH];
	BIGNUM *c_bn = NULL, *Y = NULL, *Yprime = NULL, *t1 = NULL;
	SHA256_CTX sha256_ctx;
	CHECK_NONNULL(c_bn = BN_new());
	CHECK_NONNULL(Y = BN_new());
	CHECK_NONNULL(Yprime = BN_new());
	CHECK_NONNULL(t1 = BN_new());
	// c = H(subj || body || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, sig->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_NONNULL(BN_bin2bn(c, SHA256_DIGEST_LENGTH, c_bn));
	// Y = z^{2^cl} 4^c mod N
	CHECK_IS_ONE(F(Y, c_bn, sig->z, vk->chbits, vk->N, bn_ctx));
	// Y' <- H(msg_subj) in Z_N^*
	CHECK_NONNULL(Yprime = SHA256_mod(msg_subj, msg_subj_length, vk->N, bn_ctx));
	// check if Y in { Y', -Y', 2Y', -2Y' }
	if (BN_cmp(Y, Yprime) == 0) {
		ret = 1;
		goto cleanup;
	}
	CHECK_IS_ONE(BN_mod_sub(t1, vk->N, Yprime, vk->N, bn_ctx));
	CHECK_NONNULL(BN_copy(Yprime, t1)); // now Yprime is -Y'
	if (BN_cmp(Y, Yprime) == 0) {
		ret = 1;
		goto cleanup;
	}
	CHECK_IS_ONE(BN_mod_lshift1(t1, Yprime, vk->N, bn_ctx));
	CHECK_NONNULL(BN_copy(Yprime, t1)); // now Yprime is -2Y'
	if (BN_cmp(Y, Yprime) == 0) {
		ret = 1;
		goto cleanup;
	}
	CHECK_IS_ONE(BN_mod_sub(t1, vk->N, Yprime, vk->N, bn_ctx));
	CHECK_NONNULL(BN_copy(Yprime, t1)); // now Yprime is 2Y'
	if (BN_cmp(Y, Yprime) == 0) {
		ret = 1;
		goto cleanup;
	}
	ret = 0;
	goto cleanup;
err:
	ret = -1;
cleanup:
	BN_free(c_bn);
	BN_free(Y);
	BN_free(Yprime);
	BN_free(t1);
	return ret;
}

int DAPS_H2_MR_extract(const DAPS_H2_MR_VK *vk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body1, const int msg_body1_length, const DAPS_H2_MR_SIG *sig1, const unsigned char *msg_body2, const int msg_body2_length, const DAPS_H2_MR_SIG *sig2, DAPS_H2_MR_SK **sk, BN_CTX *bn_ctx) {
	int ret, ok;
	SHA256_CTX sha256_ctx;
	unsigned char c1[SHA256_DIGEST_LENGTH], c2[SHA256_DIGEST_LENGTH];
	BIGNUM *c1_bn = NULL, *c2_bn = NULL;
	BIGNUM *Y1 = NULL, *Y2 = NULL;
	BIGNUM *z1 = NULL, *z2 = NULL, *z1prime = NULL, *z2prime = NULL;
	BIGNUM *p = NULL, *q = NULL;
	DAPS_H2_MR_SK *rsk = NULL;

	// c1 = H(subj || body1 || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body1, msg_body1_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, sig1->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c1, &sha256_ctx));
	// c2 = H(subj || body2 || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body2, msg_body2_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, sig2->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c2, &sha256_ctx));

	// Y = z^{2^cl} 4^c mod N
	CHECK_NONNULL(c1_bn = BN_new());
	CHECK_NONNULL(BN_bin2bn(c1, SHA256_DIGEST_LENGTH, c1_bn));
	CHECK_NONNULL(Y1 = BN_new());
	CHECK_IS_ONE(F(Y1, c1_bn, sig1->z, vk->chbits, vk->N, bn_ctx));
	CHECK_NONNULL(c2_bn = BN_new());
	CHECK_NONNULL(BN_bin2bn(c2, SHA256_DIGEST_LENGTH, c2_bn));
	CHECK_NONNULL(Y2 = BN_new());
	CHECK_IS_ONE(F(Y2, c2_bn, sig2->z, vk->chbits, vk->N, bn_ctx));
	// Y1 should equal Y2
	CHECK_IS_ZERO(BN_cmp(Y1, Y2));

	CHECK_NONNULL(z1 = BN_dup(sig1->z));
	CHECK_NONNULL(z2 = BN_dup(sig2->z));
	CHECK_NONNULL(z1prime = BN_new());
	CHECK_NONNULL(z2prime = BN_new());
	int b1, b2;
	for (int i = SHA256_DIGEST_LENGTH * 8 - 1; i >= 0; i--) {
		b1 = BN_is_bit_set(c1_bn, i);
		if (b1 == 0) {
			CHECK_IS_ONE(F0(z1prime, z1, vk->N, bn_ctx));
		} else {
			CHECK_IS_ONE(F1(z1prime, z1, vk->N, bn_ctx));
		}
		b2 = BN_is_bit_set(c2_bn, i);
		if (b2 == 0) {
			CHECK_IS_ONE(F0(z2prime, z2, vk->N, bn_ctx));
		} else {
			CHECK_IS_ONE(F1(z2prime, z2, vk->N, bn_ctx));
		}
		if ((BN_cmp(z1prime, z2prime) == 0) && (b1 != b2)) {
			CHECK_NONNULL(p = BN_new());
			CHECK_NONNULL(q = BN_new());
			CHECK_IS_ONE(Fextract(p, q, z1, z2, vk->N, 0, bn_ctx));

			CHECK_NONNULL(rsk = (DAPS_H2_MR_SK *) OPENSSL_malloc(sizeof(DAPS_H2_MR_SK)));
			CHECK_NONNULL(rsk->N = BN_dup(vk->N));
			CHECK_NONNULL(rsk->p = BN_dup(p));
			CHECK_NONNULL(rsk->q = BN_dup(q));
			CHECK_NONNULL(rsk->up = BN_new());
			CHECK_NONNULL(rsk->uq = BN_new());
			CHECK_NONNULL(rsk->vp = BN_new());
			CHECK_NONNULL(rsk->vq = BN_new());
			CHECK_IS_ONE(Fprecompute(rsk->up, rsk->uq, rsk->vp, rsk->vq, rsk->p, rsk->q, vk->chbits, bn_ctx));
			rsk->chbits = vk->chbits;
			*sk = rsk;
			ret = 1;
			goto cleanup;
		}
		CHECK_NONNULL(BN_copy(z1, z1prime));
		CHECK_NONNULL(BN_copy(z2, z2prime));
	}
	// if we reach here, we didn't succeed; continue into err

err:
	ret = 0;
	OPENSSL_free(rsk);
cleanup:
	BN_free(c1_bn);
	BN_free(c2_bn);
	BN_free(Y1);
	BN_free(Y2);
	BN_free(z1);
	BN_free(z2);
	BN_free(z1prime);
	BN_free(z2prime);
	BN_free(p);
	BN_free(q);
	return ret;
}

int DAPS_H2_MR_test(const int keylen, const int hashlen, const int print) {
	int ret, ok;
	int ver;
	DAPS_H2_MR_VK *vk = NULL;
	DAPS_H2_MR_SK *sk = NULL, *skprime = NULL;
	DAPS_H2_MR_SIG *sig = NULL, *sig2 = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(DAPS_H2_MR_keygen(&vk, &sk, keylen, hashlen, bn_ctx));
	char msg_subj[100];
	sprintf(msg_subj, "www.google.com subject #%ld", random());
	char msg_body[100];
	sprintf(msg_body, "My public key certificate is %ld.", random());
	CHECK_IS_ONE(DAPS_H2_MR_sign(sk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), &sig, bn_ctx));
	ver = DAPS_H2_MR_verify(vk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx);
	if (print) {
		if (ver == 1) {
			printf("verifies\n");
		} else {
			printf("!!! DOES NOT VERIFY !!!\n");
		}
		DAPS_H2_MR_VK_print_fp(stdout, vk);
		DAPS_H2_MR_SK_print_fp(stdout, sk);
		DAPS_H2_MR_SIG_print_fp(stdout, sig);
	}
	if (ver != 1) {
		goto err;
	}
	char *msg_body2 = "My public key certificate is 43.";
	CHECK_IS_ONE(DAPS_H2_MR_sign(sk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body2, strlen(msg_body2), &sig2, bn_ctx));
	CHECK_IS_ONE(DAPS_H2_MR_extract(vk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, (unsigned char *) msg_body2, strlen(msg_body2), sig2, &skprime, bn_ctx));
	ver = ((BN_cmp(sk->p, skprime->p) == 0) && (BN_cmp(sk->q, skprime->q) == 0)) || ((BN_cmp(sk->p, skprime->q) == 0) && (BN_cmp(sk->q, skprime->p) == 0));
	if (print) {
		if (ver == 1) {
			printf("extracts\n");
		} else {
			printf("!!! DOES NOT EXTRACT !!!\n");
		}
		DAPS_H2_MR_SIG_print_fp(stdout, sig2);
		DAPS_H2_MR_SK_print_fp(stdout, skprime);
	}
	if (ver != 1) {
		goto err;
	}
	ret = 1;
	goto cleanup;
err:
	fprintf(stderr, "An error occurred.\n");
	ret = 0;
cleanup:
	fflush(stdout);
	DAPS_H2_MR_VK_free(vk);
	DAPS_H2_MR_SK_free(sk);
	DAPS_H2_MR_SIG_free(sig);
	BN_CTX_free(bn_ctx);
	return ret;
}
