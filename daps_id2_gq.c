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

/** \file daps_id2_gq.c
 * ID2[GQ] DAPS scheme.
 */

#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "common.h"
#include "daps_id2_gq.h"
#include "bn_extra.h"

#define NUM_ROUNDS 20

void DAPS_ID2_GQ_VK_free(DAPS_ID2_GQ_VK *vk) {
	if (vk == NULL) {
		return;
	}
	ID_GQ_PK_free(vk->ipk);
	OPENSSL_free(vk->TDK);
	OPENSSL_free(vk);
}

void DAPS_ID2_GQ_SK_free(DAPS_ID2_GQ_SK *sk) {
	if (sk == NULL) {
		return;
	}
	ID_GQ_SK_free(sk->isk);
	ID_GQ_TDK_free(sk->itdk);
	OPENSSL_free(sk);
}

void DAPS_ID2_GQ_SIG_free(DAPS_ID2_GQ_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	ID_GQ_CH_free(sig->ch1);
	ID_GQ_RESP_free(sig->resp2);
	OPENSSL_free(sig);
}

void DAPS_ID2_GQ_VK_print_fp(FILE *fp, const DAPS_ID2_GQ_VK *vk) {
	if (vk == NULL) {
		return;
	}
	ID_GQ_PK_print_fp(fp, vk->ipk);
}

void DAPS_ID2_GQ_SK_print_fp(FILE *fp, const DAPS_ID2_GQ_SK *sk) {
	if (sk == NULL) {
		return;
	}
	ID_GQ_SK_print_fp(fp, sk->isk);
	ID_GQ_TDK_print_fp(fp, sk->itdk);
}

void DAPS_ID2_GQ_SIG_print_fp(FILE *fp, const DAPS_ID2_GQ_SIG *sig) {
	if (sig == NULL) {
		return;
	}
	ID_GQ_CH_print_fp(fp, sig->ch1);
	ID_GQ_RESP_print_fp(fp, sig->resp2);
}

// x_len must be a multiple of 32 bytes = 256 bits
// out must have length x_len
static int perm_F(const unsigned char i, const unsigned char *x, const size_t x_len, unsigned char *out) {
	int ret, ok;
	EVP_MD_CTX *mdctx = NULL;
	for (unsigned char j = 0; j < x_len / 32; j++) {
		// compute H(i || j || x)
		CHECK_NONNULL(mdctx = EVP_MD_CTX_create());
		CHECK_IS_ONE(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
		CHECK_IS_ONE(EVP_DigestUpdate(mdctx, &i, 1));
		CHECK_IS_ONE(EVP_DigestUpdate(mdctx, &j, 1));
		CHECK_IS_ONE(EVP_DigestUpdate(mdctx, x, x_len));
		unsigned int digest_len;
		CHECK_IS_ONE(EVP_DigestFinal_ex(mdctx, out + (j * 32), &digest_len));
		if (digest_len != 32) {
			goto err;
		}
		EVP_MD_CTX_destroy(mdctx);
		mdctx = NULL;
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	if (mdctx != NULL) {
		EVP_MD_CTX_destroy(mdctx);
		mdctx = NULL;
	}
	return ret;
}

// x_len must be a multiple of 32 bytes = 256 bits
// out must have length x_len
static int perm_E_forward(const unsigned char *x, const size_t x_len, unsigned char *out) {
	int ret, ok;
	unsigned char *x_im1 = NULL, *x_i = NULL, *x_ip1 = NULL;
	CHECK_NONNULL(x_im1 = OPENSSL_malloc(x_len / 2));
	CHECK_NONNULL(x_i = OPENSSL_malloc(x_len / 2));
	CHECK_NONNULL(x_ip1 = OPENSSL_malloc(x_len / 2));
	memcpy(x_im1, x, x_len / 2);
	memcpy(x_i, x + x_len / 2, x_len / 2);
	for (int i = 1; i <= NUM_ROUNDS; i++) {
		CHECK_IS_ONE(perm_F(i, x_i, x_len / 2, x_ip1));
		for (size_t j = 0; j < x_len / 2; j++) {
			x_ip1[j] ^= x_im1[j];
		}
		memcpy(x_im1, x_i, x_len / 2);
		if (i < NUM_ROUNDS) {
			memcpy(x_i, x_ip1, x_len / 2);
		}
	}
	memcpy(out, x_i, x_len / 2);
	memcpy(out + x_len / 2, x_ip1, x_len / 2);
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	OPENSSL_free(x_im1);
	OPENSSL_free(x_i);
	OPENSSL_free(x_ip1);
	return ret;
}

// x_len must be a multiple of 32 bytes = 256 bits
// out must have length x_len
static int perm_E_reverse(const unsigned char *x, const size_t x_len, unsigned char *out) {
	int ret, ok;
	unsigned char *x_im1 = NULL, *x_i = NULL, *x_ip1 = NULL;
	CHECK_NONNULL(x_im1 = OPENSSL_malloc(x_len / 2));
	CHECK_NONNULL(x_i = OPENSSL_malloc(x_len / 2));
	CHECK_NONNULL(x_ip1 = OPENSSL_malloc(x_len / 2));
	memcpy(x_i, x, x_len / 2);
	memcpy(x_ip1, x + x_len / 2, x_len / 2);
	for (int i = NUM_ROUNDS; i >= 1; i--) {
		CHECK_IS_ONE(perm_F(i, x_i, x_len / 2, x_im1));
		for (size_t j = 0; j < x_len / 2; j++) {
			x_im1[j] ^= x_ip1[j];
		}
		memcpy(x_ip1, x_i, x_len / 2);
		if (i > 1) {
			memcpy(x_i, x_im1, x_len / 2);
		}
	}
	memcpy(out, x_im1, x_len / 2);
	memcpy(out + x_len / 2, x_i, x_len / 2);
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	OPENSSL_free(x_im1);
	OPENSSL_free(x_i);
	OPENSSL_free(x_ip1);
	return ret;
}

static int perm_Z(BIGNUM *out, const BIGNUM *in, const BIGNUM *modulus, const int forward, BN_CTX *ctx) {
	int ret, ok;
	unsigned char *in_b = NULL, *out_b = NULL;
	BIGNUM *tmp = NULL;
	int m_len = BN_num_bytes(modulus);
	if (m_len % 32 != 0) {
		goto err;
	}
	if (BN_num_bytes(in) > m_len) {
		goto err;
	}
	CHECK_NONNULL(in_b = OPENSSL_malloc(m_len));
	CHECK_NONNULL(out_b = OPENSSL_malloc(m_len));
	bzero(in_b, m_len);
	bzero(out_b, m_len);
	int in_len = BN_num_bytes(in);
	ok = BN_bn2bin(in, in_b + (m_len - in_len));
	if (ok > m_len) {
		goto err;
	}
	if (forward) {
		CHECK_IS_ONE(perm_E_forward(in_b, m_len, out_b));
	} else {
		CHECK_IS_ONE(perm_E_reverse(in_b, m_len, out_b));
	}
	CHECK_NONNULL(BN_bin2bn(out_b, m_len, out));
	CHECK_NONNULL(tmp = BN_new());
	CHECK_IS_ONE(BN_gcd(tmp, out, modulus, ctx));
	if ((BN_cmp(out, modulus) >= 1) || (!BN_is_one(tmp))) {
		OPENSSL_free(in_b);
		OPENSSL_free(out_b);
		BN_free(tmp);
		return perm_Z(out, out, modulus, forward, ctx);
	}
	ret = 1;
	goto cleanup;
err:
	ret = 0;
cleanup:
	OPENSSL_free(in_b);
	OPENSSL_free(out_b);
	BN_free(tmp);
	return ret;
}

static int DAPS_ID2_GQ_perm(const DAPS_ID2_GQ_VK *vk, const BIGNUM *x, BIGNUM **y, BN_CTX *bn_ctx) {
	int ret, ok;
	CHECK_NONNULL(*y = BN_new());
	CHECK_IS_ONE(perm_Z(*y, x, vk->ipk->n, 1, bn_ctx));
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	BN_free(*y);
cleanup:
	return ret;
}

static int DAPS_ID2_GQ_perm_inv(const DAPS_ID2_GQ_VK *vk, const BIGNUM *y, BIGNUM **x, BN_CTX *bn_ctx) {
	int ret, ok;
	CHECK_NONNULL(*x = BN_new());
	CHECK_IS_ONE(perm_Z(*x, y, vk->ipk->n, 0, bn_ctx));
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	BN_free(*x);
cleanup:
	return ret;
}

// allocates *vk and *sk which must be later freed
// returns 1 on success and 0 on error
int DAPS_ID2_GQ_keygen(DAPS_ID2_GQ_VK **vk, DAPS_ID2_GQ_SK **sk, const int bits, const int chlen, BN_CTX *bn_ctx) {
	int ret, ok;
	DAPS_ID2_GQ_VK *rvk = NULL;
	DAPS_ID2_GQ_SK *rsk = NULL;
	unsigned char *x = NULL;
	unsigned char *h = NULL;
	CHECK_NONNULL(rvk = (DAPS_ID2_GQ_VK *) OPENSSL_malloc(sizeof(DAPS_ID2_GQ_VK)));
	CHECK_NONNULL(rsk = (DAPS_ID2_GQ_SK *) OPENSSL_malloc(sizeof(DAPS_ID2_GQ_SK)));
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
	DAPS_ID2_GQ_VK_free(rvk);
	DAPS_ID2_GQ_SK_free(rsk);
cleanup:
	OPENSSL_free(x);
	OPENSSL_free(h);
	return ret;
}

int DAPS_ID2_GQ_sign(const DAPS_ID2_GQ_VK *vk, const DAPS_ID2_GQ_SK *sk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, DAPS_ID2_GQ_SIG **sig, BN_CTX *bn_ctx) {
	int ret, ok;
	DAPS_ID2_GQ_SIG *rsig = NULL;
	unsigned char c[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256_ctx;
	ID_GQ_CMT cmt1, cmt2;
	ID_GQ_STATE *state1 = NULL, *state2 = NULL;
	ID_GQ_CH *ch2 = NULL;
	ID_GQ_RESP *resp1 = NULL;

	CHECK_NONNULL(rsig = (DAPS_ID2_GQ_SIG *) OPENSSL_malloc(sizeof(DAPS_ID2_GQ_SIG)));

	// Y1 <- H(msg_subj) mod n
	CHECK_NONNULL(cmt1.Y = SHA256_mod(msg_subj, msg_subj_length, vk->ipk->n, bn_ctx));
	// c1 <-$ {0,1}
	CHECK_IS_ONE(ID_GQ_ch_rand(&(rsig->ch1), 1));
	// y1 <- ID.CmtInv(Y1)
	CHECK_IS_ONE(ID_GQ_cmt_inv(sk->itdk, &cmt1, &state1, bn_ctx));
	// z1 <- ID.Rsp(c1, y1)
	CHECK_IS_ONE(ID_GQ_resp(sk->isk, state1, rsig->ch1, &resp1, bn_ctx));

	// Y2 <- Pi(z1)
	CHECK_IS_ONE(DAPS_ID2_GQ_perm(vk, resp1->z, &(cmt2.Y), bn_ctx));
	// c2 <- H(msg_subj || msg_body)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch2, hashlen, c, SHA256_DIGEST_LENGTH));
	// y2 <- ID.CmtInv(Y2)
	CHECK_IS_ONE(ID_GQ_cmt_inv(sk->itdk, &cmt2, &state2, bn_ctx));
	// z2 <- ID.Rsp(c2, y2)
	CHECK_IS_ONE(ID_GQ_resp(sk->isk, state2, ch2, &(rsig->resp2), bn_ctx));
	// sig <- (c1, z2)
	*sig = rsig;
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	DAPS_ID2_GQ_SIG_free(rsig);
cleanup:
	ID_GQ_STATE_free(state1);
	ID_GQ_RESP_free(resp1);
	BN_free(cmt2.Y);
	ID_GQ_CH_free(ch2);
	ID_GQ_STATE_free(state2);
	return ret;
}

int DAPS_ID2_GQ_verify(const DAPS_ID2_GQ_VK *vk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const DAPS_ID2_GQ_SIG *sig, BN_CTX *bn_ctx) {
	int ret, ok = 0;
	unsigned char c[SHA256_DIGEST_LENGTH];
	ID_GQ_CMT *cmt1 = NULL, *cmt2 = NULL;
	ID_GQ_CH *ch2 = NULL;
	ID_GQ_RESP resp1;
	resp1.z = NULL;
	SHA256_CTX sha256_ctx;
	BIGNUM *Y1prime = NULL;

	// c2 <- H(msg_subj || msg_body)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body, msg_body_length));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch2, hashlen, c, SHA256_DIGEST_LENGTH));
	// Y2 <- ID.RspInv(c2, z2)
	CHECK_IS_ONE(ID_GQ_resp_inv(vk->ipk, &cmt2, ch2, sig->resp2, bn_ctx));
	// z1 <- PiInv(Y2)
	CHECK_IS_ONE(DAPS_ID2_GQ_perm_inv(vk, cmt2->Y, &(resp1.z), bn_ctx));
	// Y1 <- ID.RspInv(c1, z1)
	CHECK_IS_ONE(ID_GQ_resp_inv(vk->ipk, &cmt1, sig->ch1, &resp1, bn_ctx));
	// Y1 =? H(msg_subj)
	CHECK_NONNULL(Y1prime = SHA256_mod(msg_subj, msg_subj_length, vk->ipk->n, bn_ctx));
	if (BN_cmp(cmt1->Y, Y1prime) == 0) {
		ret = 1;
	} else {
		ret = 0;
	}
	goto cleanup;

err:
	ret = -1;
cleanup:
	ID_GQ_CMT_free(cmt1);
	ID_GQ_CMT_free(cmt2);
	ID_GQ_CH_free(ch2);
	BN_free(resp1.z);
	BN_free(Y1prime);
	return ret;
}

int DAPS_ID2_GQ_extract(const DAPS_ID2_GQ_VK *vk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body1, const int msg_body1_length, const DAPS_ID2_GQ_SIG *sig1, const unsigned char *msg_body2, const int msg_body2_length, const DAPS_ID2_GQ_SIG *sig2, DAPS_ID2_GQ_SK **sk, BN_CTX *bn_ctx) {
	int ret, ok;
	int b;
	unsigned char c[SHA256_DIGEST_LENGTH];
	unsigned char *x = NULL;
	unsigned char *d = NULL;
	unsigned char *h = NULL;
	ID_GQ_CMT *cmt11 = NULL, *cmt12 = NULL;
	ID_GQ_CMT *cmt21 = NULL, *cmt22 = NULL;
	ID_GQ_CH *ch21 = NULL, *ch22 = NULL;
	ID_GQ_RESP resp11, resp12;
	resp11.z = NULL;
	resp12.z = NULL;
	SHA256_CTX sha256_ctx;
	DAPS_ID2_GQ_SK *rsk = NULL;

	CHECK_NONNULL(rsk = (DAPS_ID2_GQ_SK *) OPENSSL_malloc(sizeof(DAPS_ID2_GQ_SK)));

	// (c_1i, z_2i) <- sig_i
	ID_GQ_CH *ch11 = sig1->ch1;
	ID_GQ_RESP *resp21 = sig1->resp2;
	ID_GQ_CH *ch12 = sig2->ch1;
	ID_GQ_RESP *resp22 = sig2->resp2;
	// c_2i <- H(a_i, p_i)
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body1, msg_body1_length));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch21, hashlen, c, SHA256_DIGEST_LENGTH));
	CHECK_IS_ONE(SHA256_Init(&sha256_ctx));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_subj, msg_subj_length));
	CHECK_IS_ONE(SHA256_Update(&sha256_ctx, msg_body2, msg_body2_length));
	CHECK_IS_ONE(SHA256_Final(c, &sha256_ctx));
	CHECK_IS_ONE(ID_GQ_ch_hash(&ch22, hashlen, c, SHA256_DIGEST_LENGTH));
	// Y_2i <- ID.RspInv(ivk, c_2i, z_2i)
	CHECK_IS_ONE(ID_GQ_resp_inv(vk->ipk, &cmt21, ch21, resp21, bn_ctx));
	CHECK_IS_ONE(ID_GQ_resp_inv(vk->ipk, &cmt22, ch22, resp22, bn_ctx));
	// z_1i <- PermInv(Y_2i)
	CHECK_IS_ONE(DAPS_ID2_GQ_perm_inv(vk, cmt21->Y, &(resp11.z), bn_ctx));
	CHECK_IS_ONE(DAPS_ID2_GQ_perm_inv(vk, cmt22->Y, &(resp12.z), bn_ctx));
	// Y_1i <- ID.RspInv(iv, c_1i, z_1i)
	CHECK_IS_ONE(ID_GQ_resp_inv(vk->ipk, &cmt11, ch11, &resp11, bn_ctx));
	CHECK_IS_ONE(ID_GQ_resp_inv(vk->ipk, &cmt12, ch12, &resp12, bn_ctx));
	// if Y_21 = Y_22
	b = BN_cmp(cmt21->Y, cmt22->Y);
	if (b == 0) {
		// if c_21 = c_22: return bot
		CHECK_NONZERO(BN_cmp(ch21->c, ch22->c));
		// isk <- ID.Ex(ivk, Y_21 || c_21 || z_21, Y_22 || c_22 || z_22)
		CHECK_IS_ONE(ID_GQ_extract(vk->ipk, cmt21, ch21, resp21, ch22, resp22, &(rsk->isk), bn_ctx));
	} else {
		// isk <- ID.Ex(ivk, Y_11 || c_11 || z_11, Y_12 || c_12 || z_12)
		CHECK_IS_ONE(ID_GQ_extract(vk->ipk, cmt11, ch11, &resp11, ch12, &resp12, &(rsk->isk), bn_ctx));
	}
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
	ID_GQ_CMT_free(cmt11);
	ID_GQ_CMT_free(cmt12);
	ID_GQ_CMT_free(cmt21);
	ID_GQ_CMT_free(cmt22);
	ID_GQ_CH_free(ch21);
	ID_GQ_CH_free(ch22);
	BN_free(resp11.z);
	BN_free(resp12.z);
	return ret;
}

int DAPS_ID2_GQ_test(int keylen, int hashlen, int print) {
	int ret, ok;
	int ver;
	DAPS_ID2_GQ_VK *vk = NULL;
	DAPS_ID2_GQ_SK *sk = NULL, *skprime = NULL;
	DAPS_ID2_GQ_SIG *sig = NULL, *sig2 = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());

	CHECK_IS_ONE(DAPS_ID2_GQ_keygen(&vk, &sk, keylen, hashlen, bn_ctx));
	char *msg_subj = "www.google.com";
	char *msg_body = "My public key certificate is 42.";
	CHECK_IS_ONE(DAPS_ID2_GQ_sign(vk, sk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), &sig, bn_ctx));
	ver = DAPS_ID2_GQ_verify(vk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx);
	if (print) {
		if (ver == 1) {
			printf("verifies\n");
		} else {
			printf("!!! DOES NOT VERIFY !!!\n");
		}
		DAPS_ID2_GQ_VK_print_fp(stdout, vk);
		DAPS_ID2_GQ_SK_print_fp(stdout, sk);
		DAPS_ID2_GQ_SIG_print_fp(stdout, sig);
	}
	if (ver != 1) {
		goto err;
	}
	char *msg_body2 = "My public key certificate is 43.";
	CHECK_IS_ONE(DAPS_ID2_GQ_sign(vk, sk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body2, strlen(msg_body2), &sig2, bn_ctx));
	CHECK_IS_ONE(DAPS_ID2_GQ_extract(vk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, (unsigned char *) msg_body2, strlen(msg_body2), sig2, &skprime, bn_ctx));
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
		DAPS_ID2_GQ_SIG_print_fp(stdout, sig2);
		DAPS_ID2_GQ_SK_print_fp(stdout, skprime);
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
	DAPS_ID2_GQ_VK_free(vk);
	DAPS_ID2_GQ_SK_free(sk);
	DAPS_ID2_GQ_SIG_free(sig);
	BN_CTX_free(bn_ctx);
	return ret;
}

int DAPS_ID2_GQ_test_perm(int keylen, int hashlen, int print) {
	int ret, ok;
	DAPS_ID2_GQ_VK *vk = NULL;
	DAPS_ID2_GQ_SK *sk = NULL;
	BIGNUM *x = NULL, *y = NULL, *z = NULL;
	BN_CTX *bn_ctx = NULL;

	CHECK_NONNULL(bn_ctx = BN_CTX_new());
	CHECK_NONNULL(x = BN_new());
	CHECK_IS_ONE(DAPS_ID2_GQ_keygen(&vk, &sk, keylen, hashlen, bn_ctx));
	if (print) {
		printf("---\n");
		printf("n = ");
		BN_print_fp(stdout, vk->ipk->n);
		printf("\n");
	}
	CHECK_IS_ONE(BN_rand_range(x, vk->ipk->n));
	CHECK_IS_ONE(DAPS_ID2_GQ_perm(vk, x, &y, bn_ctx));
	CHECK_IS_ONE(DAPS_ID2_GQ_perm_inv(vk, y, &z, bn_ctx));
	if (print) {
		printf("x = ");
		BN_print_fp(stdout, x);
		printf("\n");
		printf("y = ");
		BN_print_fp(stdout, y);
		printf("\n");
		printf("z = ");
		BN_print_fp(stdout, z);
		printf("\n");
	}
	CHECK_IS_ZERO(BN_cmp(x, z));
	ret = 1;
	goto cleanup;
err:
	ret = 0;
	fprintf(stderr, "An error occurred.\n");
cleanup:
	DAPS_ID2_GQ_VK_free(vk);
	DAPS_ID2_GQ_SK_free(sk);
	BN_free(x);
	BN_free(y);
	BN_free(z);
	BN_CTX_free(bn_ctx);
	return ret;
}
