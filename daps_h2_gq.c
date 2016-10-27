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

/** \file daps_h2_gq.c
 * H2[GQ] DAPS scheme.
 */

#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "common.h"
#include "daps_h2_gq.h"
#include "bn_extra.h"

static void fprint_hex(FILE *fp, const unsigned char *s, const int len) {
	for (int i = 0; i < len; i++) {
		fprintf(fp, "%02X", (unsigned int) s[i]);
	}
}

void DAPS_H2_GQ_VK_free(DAPS_H2_GQ_VK *vk) {
	if (vk == NULL) {
		return;
	}
	ID_GQ_PK_free(vk->ipk);
	OPENSSL_free(vk->TDK);
	OPENSSL_free(vk);
}

void DAPS_H2_GQ_SK_free(DAPS_H2_GQ_SK *sk) {
	if (sk == NULL) {
		return;
	}
	ID_GQ_SK_free(sk->isk);
	ID_GQ_TDK_free(sk->itdk);
	OPENSSL_free(sk);
}

void DAPS_H2_GQ_SIG_free(DAPS_H2_GQ_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	ID_GQ_RESP_free(sig->resp);
	OPENSSL_free(sig->s);
	OPENSSL_free(sig);
}

void DAPS_H2_GQ_VK_print_fp(FILE *fp, const DAPS_H2_GQ_VK *vk) {
	if (vk == NULL) {
		return;
	}
	ID_GQ_PK_print_fp(fp, vk->ipk);
	// fprintf(fp, "vk TDK: ");
	// fprint_hex(fp, vk->TDK, vk->TDK_length);
	// fprintf(fp, "\n");
}

void DAPS_H2_GQ_SK_print_fp(FILE *fp, const DAPS_H2_GQ_SK *sk) {
	if (sk == NULL) {
		return;
	}
	ID_GQ_SK_print_fp(fp, sk->isk);
	ID_GQ_TDK_print_fp(fp, sk->itdk);
}

void DAPS_H2_GQ_SIG_print_fp(FILE *fp, const DAPS_H2_GQ_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	ID_GQ_RESP_print_fp(fp, sig->resp);
	fprintf(fp, "s := 0x");
	fprint_hex(fp, sig->s, sig->s_length);
	fprintf(fp, "\n");
}

// allocates *vk and *sk which must be later freed
// returns 1 on success and 0 on error
int DAPS_H2_GQ_keygen(DAPS_H2_GQ_VK **vk, DAPS_H2_GQ_SK **sk, const int bits, const int chlen, BN_CTX *bn_ctx) {
	int ok, ret;
	DAPS_H2_GQ_VK *rvk = NULL;
	DAPS_H2_GQ_SK *rsk = NULL;
	unsigned char *x = NULL;
	unsigned char *h = NULL;
	CHECK_NONNULL(rvk = (DAPS_H2_GQ_VK *) OPENSSL_malloc(sizeof(DAPS_H2_GQ_VK)));
	CHECK_NONNULL(rsk = (DAPS_H2_GQ_SK *) OPENSSL_malloc(sizeof(DAPS_H2_GQ_SK)));
	CHECK_IS_ONE(ID_GQ_keygen(&(rvk->ipk), &(rsk->isk), &(rsk->itdk), bits, chlen, bn_ctx));
	// put d into TDK
	rvk->TDK_length = BN_num_bytes(rsk->itdk->d);
	CHECK_NONNULL(rvk->TDK = (unsigned char *) OPENSSL_malloc(BN_num_bytes(rsk->itdk->d)));
	CHECK_GT_ZERO(BN_bn2bin(rsk->itdk->d, rvk->TDK));
	// convert sk to binary
	CHECK_NONNULL(x = (unsigned char *) OPENSSL_malloc(BN_num_bytes(rsk->isk->x)));
	CHECK_GT_ZERO(BN_bn2bin(rsk->isk->x, x));
	// hash sk
	CHECK_NONNULL(h = SHA256_arbitrary(x, BN_num_bytes(rsk->isk->x), rvk->TDK_length));
	// XOR hash into TDK
	for (int i = 0; i < rvk->TDK_length; i++) {
		rvk->TDK[i] = rvk->TDK[i] ^ h[i];
	}
	*vk = rvk;
	*sk = rsk;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	DAPS_H2_GQ_VK_free(rvk);
	DAPS_H2_GQ_SK_free(rsk);
cleanup:
	OPENSSL_free(x);
	OPENSSL_free(h);
	return ret;
}

int DAPS_H2_GQ_sign(const DAPS_H2_GQ_VK *vk, const DAPS_H2_GQ_SK *sk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, DAPS_H2_GQ_SIG **sig, BN_CTX *bn_ctx) {
	int ok, ret;
	DAPS_H2_GQ_SIG *rsig = NULL;
	unsigned char c[SHA256_DIGEST_LENGTH];
	unsigned char *tmp = NULL;
	SHA256_CTX sha256_ctx;
	ID_GQ_CMT cmt;
	ID_GQ_STATE *state = NULL;
	ID_GQ_CH *ch = NULL;
	CHECK_NONNULL(rsig = (DAPS_H2_GQ_SIG *) OPENSSL_malloc(sizeof(DAPS_H2_GQ_SIG)));
	CHECK_NONNULL(rsig->s = OPENSSL_malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH));
	rsig->s_length = SHA256_DIGEST_LENGTH;
	// s <- {0,1}^256
	CHECK_IS_ONE(RAND_bytes(rsig->s, SHA256_DIGEST_LENGTH));
	// Y <- H(msg_subj) mod n
	CHECK_NONNULL(cmt.Y = SHA256_mod(msg_subj, msg_subj_length, vk->ipk->n, bn_ctx));
	// y <- ID.CmtInv(Y)
	CHECK_IS_ONE(ID_GQ_cmt_inv(sk->itdk, &cmt, &state, bn_ctx));
	CHECK_NONNULL(tmp = OPENSSL_malloc(sizeof(unsigned char) * BN_num_bytes(cmt.Y)));
	CHECK_GT_ZERO(BN_bn2bin(cmt.Y, tmp));
	// c = H(a || p || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, rsig->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch, hashlen, c, SHA256_DIGEST_LENGTH));
	// z = ID.Resp(c, y)
	CHECK_IS_ONE(ID_GQ_resp(sk->isk, state, ch, &(rsig->resp), bn_ctx));
	ret = 1;
	*sig = rsig;
	goto cleanup;
err:
	ret = 0;
	DAPS_H2_GQ_SIG_free(rsig);
cleanup:
	OPENSSL_free(tmp);
	BN_free(cmt.Y);
	ID_GQ_STATE_free(state);
	ID_GQ_CH_free(ch);
	return ret;
}

int DAPS_H2_GQ_verify(const DAPS_H2_GQ_VK *vk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const DAPS_H2_GQ_SIG *sig, BN_CTX *bn_ctx) {
	int ok, ret;
	unsigned char *tmp = NULL;
	unsigned char c[SHA256_DIGEST_LENGTH];
	ID_GQ_CMT cmt;
	ID_GQ_CH *ch = NULL;
	SHA256_CTX sha256_ctx;
	// Y <- H(msg_subj) mod n
	CHECK_NONNULL(cmt.Y = SHA256_mod(msg_subj, msg_subj_length, vk->ipk->n, bn_ctx));
	CHECK_NONNULL(tmp = OPENSSL_malloc(sizeof(unsigned char) * BN_num_bytes(cmt.Y)));
	CHECK_GT_ZERO(BN_bn2bin(cmt.Y, tmp));
	// c = H(subj || body || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, sig->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch, hashlen, c, SHA256_DIGEST_LENGTH));
	// ID.Verify(pk, cmt, ch, resp)
	ok = ID_GQ_ver(vk->ipk, &cmt, ch, sig->resp, bn_ctx);
	if ((ok == 0) || (ok == 1)) {
		ret = ok;
		goto cleanup;
	}
err:
	ret = -1;
cleanup:
	OPENSSL_free(tmp);
	BN_free(cmt.Y);
	ID_GQ_CH_free(ch);
	return ret;
}

int DAPS_H2_GQ_extract(const DAPS_H2_GQ_VK *vk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body1, const int msg_body1_length, const DAPS_H2_GQ_SIG *sig1, const unsigned char *msg_body2, const int msg_body2_length, const DAPS_H2_GQ_SIG *sig2, DAPS_H2_GQ_SK **sk, BN_CTX *bn_ctx) {
	int ret, ok;
	unsigned char *tmp = NULL;
	unsigned char c[SHA256_DIGEST_LENGTH];
	unsigned char *x = NULL;
	unsigned char *d = NULL;
	unsigned char *h = NULL;
	ID_GQ_CMT cmt;
	ID_GQ_CH *ch1 = NULL, *ch2 = NULL;
	SHA256_CTX sha256_ctx;
	DAPS_H2_GQ_SK *rsk = NULL;
	CHECK_NONNULL(rsk = (DAPS_H2_GQ_SK *) OPENSSL_malloc(sizeof(DAPS_H2_GQ_SK)));
	// Y <- H(msg_subj) mod n
	CHECK_NONNULL(cmt.Y = SHA256_mod(msg_subj, msg_subj_length, vk->ipk->n, bn_ctx));
	CHECK_NONNULL(tmp = OPENSSL_malloc(sizeof(unsigned char) * BN_num_bytes(cmt.Y)));
	CHECK_GT_ZERO(BN_bn2bin(cmt.Y, tmp));
	// c1 = H(subj || body1 || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body1, msg_body1_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, sig1->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch1, hashlen, c, SHA256_DIGEST_LENGTH));
	// c2 = H(subj || body2 || s)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body2, msg_body2_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, sig2->s, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch2, hashlen, c, SHA256_DIGEST_LENGTH));
	// extract ID secret key
	CHECK_IS_ONE(ID_GQ_extract(vk->ipk, &cmt, ch1, sig1->resp, ch2, sig2->resp, &(rsk->isk), bn_ctx));
	// unmask TDK
	// convert sk to binary
	CHECK_NONNULL(x = (unsigned char *) OPENSSL_malloc(BN_num_bytes(rsk->isk->x)));
	CHECK_GT_ZERO(BN_bn2bin(rsk->isk->x, x));
	// hash sk
	CHECK_NONNULL(h = SHA256_arbitrary(x, BN_num_bytes(rsk->isk->x), vk->TDK_length));
	CHECK_NONNULL(d = (unsigned char *) OPENSSL_malloc(vk->TDK_length));
	// XOR hash off of TDK
	for (int i = 0; i < vk->TDK_length; i++) {
		d[i] = vk->TDK[i] ^ h[i];
	}
	// convert back to integer
	CHECK_NONNULL(rsk->itdk = (ID_GQ_TDK *) OPENSSL_malloc(sizeof(ID_GQ_TDK)));
	CHECK_NONNULL(rsk->itdk->d = BN_bin2bn(d, vk->TDK_length, NULL));
	CHECK_NONNULL(rsk->itdk->n = BN_dup(vk->ipk->n));
	*sk = rsk;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	OPENSSL_free(rsk);
cleanup:
	OPENSSL_free(tmp);
	OPENSSL_free(x);
	OPENSSL_free(d);
	OPENSSL_free(h);
	BN_free(cmt.Y);
	ID_GQ_CH_free(ch1);
	ID_GQ_CH_free(ch2);
	return ret;
}

int DAPS_H2_GQ_test(int keylen, int hashlen, int print) {
	int ret, ok;
	int ver;
	DAPS_H2_GQ_VK *vk = NULL;
	DAPS_H2_GQ_SK *sk = NULL, *skprime = NULL;
	DAPS_H2_GQ_SIG *sig = NULL, *sig2 = NULL;
	BN_CTX *bn_ctx = NULL;
	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(DAPS_H2_GQ_keygen(&vk, &sk, keylen, hashlen, bn_ctx));
	char *msg_subj = "www.google.com";
	char *msg_body = "My public key certificate is 42.";
	CHECK_IS_ONE(DAPS_H2_GQ_sign(vk, sk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), &sig, bn_ctx));
	ver = DAPS_H2_GQ_verify(vk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx);
	if (print) {
		if (ver == 1) {
			printf("verifies\n");
		} else {
			printf("!!! DOES NOT VERIFY !!!\n");
		}
		DAPS_H2_GQ_VK_print_fp(stdout, vk);
		DAPS_H2_GQ_SK_print_fp(stdout, sk);
		DAPS_H2_GQ_SIG_print_fp(stdout, sig);
	}
	if (ver != 1) {
		goto err;
	}
	char *msg_body2 = "My public key certificate is 43.";
	CHECK_IS_ONE(DAPS_H2_GQ_sign(vk, sk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body2, strlen(msg_body2), &sig2, bn_ctx));
	CHECK_IS_ONE(DAPS_H2_GQ_extract(vk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, (unsigned char *) msg_body2, strlen(msg_body2), sig2, &skprime, bn_ctx));
	ver = (BN_cmp(sk->isk->n, skprime->isk->n) == 0);
	ver &= (BN_cmp(sk->isk->x, skprime->isk->x) == 0);
	ver &= (BN_cmp(sk->itdk->n, skprime->itdk->n) == 0);
	ver &= (BN_cmp(sk->itdk->d, skprime->itdk->d) == 0);
	if (print) {
		if (ver == 1) {
			printf("extracts\n");
		} else {
			printf("!!! DOES NOT EXTRACT !!!\n");
		}
		DAPS_H2_GQ_SIG_print_fp(stdout, sig2);
		DAPS_H2_GQ_SK_print_fp(stdout, skprime);
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
	DAPS_H2_GQ_VK_free(vk);
	DAPS_H2_GQ_SK_free(sk);
	DAPS_H2_GQ_SIG_free(sig);
	BN_CTX_free(bn_ctx);
	return ret;
}
