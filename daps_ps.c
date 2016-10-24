/********************************************************************************************
 * DAPS: double-authentication preventing signatures
 *
 * Based on the paper:
 *     Mihir Bellare, Bertram Poettering, and Douglas Stebila.
 *     Deterring Certificate Subversion: Efficient Double-Authentication-Preventing Signatures.
 *     IACR Cryptology ePrint Archive, Report 2016/XXXX. October, 2016.
 *     https://eprint.iacr.org/2016/XXXX
 *
 * Software originally developed by Douglas Stebila.
 *
 * Released into the public domain; see LICENSE.txt for details.
 ********************************************************************************************/

/** \file daps_ps.c
 * PS DAPS scheme.
 */

#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "common.h"
#include "daps_ps.h"
#include "bn_extra.h"

void DAPS_PS_VK_free(DAPS_PS_VK *vk) {
	if (vk == NULL) {
		return;
	}
	TDF_PS_PK_free(vk->tdfpk);
	OPENSSL_free(vk);
}

void DAPS_PS_SK_free(DAPS_PS_SK *sk) {
	if (sk == NULL) {
		return;
	}
	TDF_PS_TDK_free(sk->tdftdk);
	OPENSSL_free(sk);
}

void DAPS_PS_SIG_free(DAPS_PS_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	BN_free(sig->s);
	if ((sig->a != NULL) && (sig->a_length > 0)) {
		for (int i = 0; i < sig->a_length; i++) {
			BN_free(sig->a[i]);
		}
	}
	OPENSSL_free(sig);
}

void DAPS_PS_VK_print_fp(FILE *fp, const DAPS_PS_VK *vk) {
	if (vk == NULL) {
		return;
	}
	TDF_PS_PK_print_fp(fp, vk->tdfpk);
}

void DAPS_PS_SK_print_fp(FILE *fp, const DAPS_PS_SK *sk) {
	if (sk == NULL) {
		return;
	}
	TDF_PS_TDK_print_fp(fp, sk->tdftdk);
}

void DAPS_PS_SIG_print_fp(FILE *fp, const DAPS_PS_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	BN_printdec_fp(fp, "sig_s", sig->s);
	for (int i = 0; i < sig->a_length; i++) {
		fprintf(fp, "sig_a_%d", i);
		BN_printdec_fp(fp, "", sig->a[i]);
	}
}

// allocates *vk and *sk which must be later freed
// returns 1 on success and 0 on error
int DAPS_PS_keygen(DAPS_PS_VK **vk, DAPS_PS_SK **sk, const int bits, BN_CTX *bn_ctx) {
	int ret, ok;
	DAPS_PS_VK *rvk = NULL;
	DAPS_PS_SK *rsk = NULL;
	CHECK_NONNULL(rvk = (DAPS_PS_VK *) OPENSSL_malloc(sizeof(DAPS_PS_VK)));
	CHECK_NONNULL(rsk = (DAPS_PS_SK *) OPENSSL_malloc(sizeof(DAPS_PS_SK)));
	CHECK_IS_ONE(TDF_PS_keygen(&(rvk->tdfpk), &(rsk->tdftdk), bits, bn_ctx));
	*vk = rvk;
	*sk = rsk;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	DAPS_PS_VK_free(rvk);
	DAPS_PS_SK_free(rsk);
cleanup:
	return ret;
}

int DAPS_PS_sign(const DAPS_PS_VK *vk, const DAPS_PS_SK *sk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const int hash_length, DAPS_PS_SIG **sig, BN_CTX *bn_ctx) {
	int ret, ok;
	DAPS_PS_SIG *rsig = NULL;
	SHA256_CTX sha256_ctx;
	BIGNUM *h = NULL;
	unsigned char *d = NULL;
	unsigned char *s_bin = NULL;
	unsigned char *b_i_bin = NULL;
	BIGNUM *b_i = NULL;
	if (hash_length > SHA256_DIGEST_LENGTH * 8) {
		goto err;
	}
	CHECK_NONNULL(h = BN_new());
	CHECK_NONNULL(rsig = (DAPS_PS_SIG *) OPENSSL_malloc(sizeof(DAPS_PS_SIG)));
	// h <- H_pub(subj)
	CHECK_IS_ONE(TDF_PS_hash_onto_range(vk->tdfpk, msg_subj, msg_subj_length, h, bn_ctx));
	CHECK_NONNULL(rsig->s = BN_new());
	// s <- Reverse(td, h, 0)
	CHECK_IS_ONE(TDF_PS_inv(rsig->s, sk->tdftdk, h, 0, bn_ctx));
	CHECK_NONNULL(s_bin = OPENSSL_malloc(BN_num_bytes(rsig->s)));
	CHECK_GT_ZERO(BN_bn2bin(rsig->s, s_bin));
	// d <- H(subj, s, body)
	CHECK_NONNULL(d = OPENSSL_malloc(SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, s_bin, BN_num_bytes(rsig->s)));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Final(d, &sha256_ctx));
	// for 1 <= i <= lambda:
	//     b_i <- H(subj, s, i)
	//     a_i <- Reverse(td, b_i, d_i)
	rsig->a_length = hash_length;
	CHECK_NONNULL(rsig->a = (BIGNUM **) OPENSSL_malloc(sizeof(BIGNUM *) * rsig->a_length));
	CHECK_NONNULL(b_i_bin = OPENSSL_malloc(SHA256_DIGEST_LENGTH));
	CHECK_NONNULL(b_i = BN_new());
	for (int i = 0; i < rsig->a_length / 8; i++) {
		for (int j = 0; j < 8; j++) {
			CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
			CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
			CHECK_IS_ONE(SHA256_Update(&sha256_ctx, s_bin, BN_num_bytes(rsig->s)));
			int ij = i * 8 + j;
			CHECK_IS_ONE(SHA256_Update(&sha256_ctx, (unsigned char *) &ij, sizeof(int)));
			CHECK_IS_ONE(SHA256_Final(b_i_bin, &sha256_ctx));
			CHECK_IS_ONE(TDF_PS_hash_onto_range(vk->tdfpk, b_i_bin, SHA256_DIGEST_LENGTH, b_i, bn_ctx));
			unsigned char dij = d[i] >> j;
			dij &= 1;
			CHECK_NONNULL(rsig->a[ij] = BN_new());
			CHECK_IS_ONE(TDF_PS_inv(rsig->a[ij], sk->tdftdk, b_i, dij, bn_ctx));
		}
	}
	ret = 1;
	*sig = rsig;
	goto cleanup;
err:
	ret = 0;
	DAPS_PS_SIG_free(rsig);
cleanup:
	OPENSSL_free(d);
	OPENSSL_free(s_bin);
	OPENSSL_free(b_i_bin);
	BN_free(h);
	BN_free(b_i);
	return ret;
}

int DAPS_PS_verify(const DAPS_PS_VK *vk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const DAPS_PS_SIG *sig, BN_CTX *bn_ctx) {
	int ret, ok;
	SHA256_CTX sha256_ctx;
	BIGNUM *h_rhs = NULL, *h_lhs = NULL;
	BIGNUM *aprime_rhs = NULL, *aprime_lhs = NULL;
	unsigned char *d = NULL;
	unsigned char *s_bin = NULL;
	unsigned char *aprime_rhs_bin = NULL;

	// If Decide(pk, s) != 0, abort
	ok = TDF_PS_decide(vk->tdfpk, sig->s, bn_ctx);
	if (ok == -1) {
		goto err;
	}
	if (ok == 1) {
		ret = 0;
		goto cleanup;
	}
	// If Apply(pub, s) != H_pub(subj), abort
	CHECK_NONNULL(h_rhs = BN_new());
	CHECK_IS_ONE(TDF_PS_hash_onto_range(vk->tdfpk, msg_subj, msg_subj_length, h_rhs, bn_ctx));
	CHECK_NONNULL(h_lhs = BN_new());
	CHECK_IS_ONE(TDF_PS_apply(h_lhs, vk->tdfpk, sig->s, bn_ctx));
	CHECK_IS_ZERO(BN_cmp(h_rhs, h_lhs));
	// d <- H(subj, s, body)
	CHECK_NONNULL(s_bin = OPENSSL_malloc(BN_num_bytes(sig->s)));
	CHECK_GT_ZERO(BN_bn2bin(sig->s, s_bin));
	CHECK_NONNULL(d = OPENSSL_malloc(SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, s_bin, BN_num_bytes(sig->s)));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Final(d, &sha256_ctx));
	// for 1 <= i <= lambda:
	//     If Apply(pub, a_i) != H_pub(subj, s, i), abort
	//     If Decide(pub, a_i) != d_i, abort
	CHECK_NONNULL(aprime_rhs_bin = OPENSSL_malloc(SHA256_DIGEST_LENGTH));
	CHECK_NONNULL(aprime_rhs = BN_new());
	CHECK_NONNULL(aprime_lhs = BN_new());
	for (int i = 0; i < sig->a_length / 8; i++) {
		for (int j = 0; j < 8; j++) {
			CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
			CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
			CHECK_IS_ONE(SHA256_Update(&sha256_ctx, s_bin, BN_num_bytes(sig->s)));
			int ij = i * 8 + j;
			CHECK_IS_ONE(SHA256_Update(&sha256_ctx, (unsigned char *) &ij, sizeof(int)));
			CHECK_IS_ONE(SHA256_Final(aprime_rhs_bin, &sha256_ctx));
			CHECK_IS_ONE(TDF_PS_hash_onto_range(vk->tdfpk, aprime_rhs_bin, SHA256_DIGEST_LENGTH, aprime_rhs, bn_ctx));
			CHECK_IS_ONE(TDF_PS_apply(aprime_lhs, vk->tdfpk, sig->a[ij], bn_ctx));
			ok = BN_cmp(aprime_lhs, aprime_rhs);
			if (ok != 0) {
				ret = 0;
				goto cleanup;
			}
			unsigned char dij = d[i] >> j;
			dij &= 1;
			ok = TDF_PS_decide(vk->tdfpk, sig->a[ij], bn_ctx);
			if (ok == -1) {
				goto err;
			}
			if (ok != dij) {
				ret = 0;
				goto cleanup;
			}
		}
	}
	ret = 1;
	goto cleanup;
err:
	ret = -1;
cleanup:
	BN_free(h_rhs);
	BN_free(h_lhs);
	BN_free(aprime_rhs);
	BN_free(aprime_lhs);
	OPENSSL_free(aprime_rhs_bin);
	OPENSSL_free(s_bin);
	return ret;
}

int DAPS_PS_test(int keylen, int hashlen, int print) {
	int ret, ok;
	int ver;
	DAPS_PS_VK *vk = NULL;
	DAPS_PS_SK *sk = NULL;
	DAPS_PS_SIG *sig = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());
	CHECK_IS_ONE(DAPS_PS_keygen(&vk, &sk, keylen, bn_ctx));
	char *msg_subj = "www.google.com";
	char *msg_body = "My public key certificate is 42.";
	CHECK_IS_ONE(DAPS_PS_sign(vk, sk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), hashlen, &sig, bn_ctx));
	ver = DAPS_PS_verify(vk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx);
	if (print) {
		if (ver == 1) {
			printf("verifies\n");
		} else {
			printf("!!! DOES NOT VERIFY !!!\n");
		}
		DAPS_PS_VK_print_fp(stdout, vk);
		DAPS_PS_SK_print_fp(stdout, sk);
		DAPS_PS_SIG_print_fp(stdout, sig);
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
	DAPS_PS_VK_free(vk);
	DAPS_PS_SK_free(sk);
	DAPS_PS_SIG_free(sig);
	BN_CTX_free(bn_ctx);
	return ret;
}
