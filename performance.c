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

/** \file performance.c
 * Performance testing program.
 */

#define UNUSED __attribute__ ((unused))

#include <string.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "bn_extra.h"
#include "id_gq.h"
#include "daps_h2_gq.h"
#include "daps_id2_gq.h"
#include "daps_h2_mr.h"
#include "daps_ps.h"

#include "ds_benchmark.h"

#define SHORT_TIME 30
#define LONG_TIME 30

// this leaks lots of memory
void RSA_performance(const int keylen, UNUSED BN_CTX *bn_ctx) {
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	char *msg = "I am the very model of a modern Major-General.";
	unsigned char *ctxt = NULL;
	unsigned char *ptxt = NULL;

	rsa = RSA_new();
	if (rsa == NULL) {
		return;
	}
	e = BN_new();
	if (e == NULL) {
		return;
	}
	BN_set_word(e, 65537);

	TIME_OPERATION_SECONDS(RSA_generate_key_ex(rsa, keylen, e, NULL), "RSA_keygen", LONG_TIME);
	ctxt = OPENSSL_malloc(RSA_size(rsa));
	if (ctxt == NULL) {
		return;
	}
	TIME_OPERATION_SECONDS(RSA_public_encrypt(strlen(msg), (unsigned char *) msg, ctxt, rsa, RSA_PKCS1_PADDING), "RSA_pub", SHORT_TIME);
	ptxt = OPENSSL_malloc(RSA_size(rsa));
	if (ptxt == NULL) {
		return;
	}
	TIME_OPERATION_SECONDS(RSA_private_decrypt(RSA_size(rsa), ctxt, ptxt, rsa, RSA_PKCS1_PADDING), "RSA_priv", LONG_TIME);

	RSA_free(rsa);
	BN_free(e);
	OPENSSL_free(ctxt);
	OPENSSL_free(ptxt);
}

// this leaks lots of memory
void ID_GQ_performance(const int keylen, const int chlen, BN_CTX *bn_ctx) {
	ID_GQ_PK *pk = NULL;
	ID_GQ_SK *sk = NULL;
	ID_GQ_TDK *tdk = NULL;
	ID_GQ_CMT *cmt = NULL;
	ID_GQ_STATE *state = NULL;
	ID_GQ_CH *ch = NULL;
	ID_GQ_RESP *resp = NULL;

	TIME_OPERATION_SECONDS(ID_GQ_keygen(&pk, &sk, &tdk, keylen, chlen, bn_ctx), "ID_GQ_keygen", LONG_TIME);
	TIME_OPERATION_SECONDS(ID_GQ_cmt(pk, &cmt, &state, bn_ctx), "ID_GQ_cmt", SHORT_TIME);
	TIME_OPERATION_SECONDS(ID_GQ_cmt_inv(tdk, cmt, &state, bn_ctx), "ID_GQ_cmt_inv", SHORT_TIME);
	TIME_OPERATION_SECONDS(ID_GQ_ch_rand(&ch, chlen), "ID_GQ_ch_rand", SHORT_TIME);
	char *msg = "I am www.google.com and my public key certificate is 42.";
	TIME_OPERATION_SECONDS(ID_GQ_ch_hash(&ch, chlen, (unsigned char *) msg, strlen(msg)), "ID_GQ_ch_hash", SHORT_TIME);
	TIME_OPERATION_SECONDS(ID_GQ_resp(sk, state, ch, &resp, bn_ctx), "ID_GQ_resp", SHORT_TIME);
	TIME_OPERATION_SECONDS(ID_GQ_ver(pk, cmt, ch, resp, bn_ctx), "ID_GQ_ver", SHORT_TIME);

	ID_GQ_PK_free(pk);
	ID_GQ_SK_free(sk);
	ID_GQ_TDK_free(tdk);
	ID_GQ_CMT_free(cmt);
	ID_GQ_STATE_free(state);
	ID_GQ_CH_free(ch);
	ID_GQ_RESP_free(resp);
}

// this leaks lots of memory
void DAPS_H2_GQ_performance(const int keylen, const int hashlen, BN_CTX *bn_ctx) {
	DAPS_H2_GQ_VK *vk = NULL;
	DAPS_H2_GQ_SK *sk = NULL;
	DAPS_H2_GQ_SIG *sig = NULL;

	TIME_OPERATION_SECONDS(DAPS_H2_GQ_keygen(&vk, &sk, keylen, hashlen, bn_ctx), "DAPS_H2_GQ_keygen", LONG_TIME);
	char *msg_subj = "www.google.com";
	char *msg_body = "My public key certificate is 42.";
	TIME_OPERATION_SECONDS(DAPS_H2_GQ_sign(vk, sk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), &sig, bn_ctx), "DAPS_H2_GQ_sign", LONG_TIME);
	TIME_OPERATION_SECONDS(DAPS_H2_GQ_verify(vk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx), "DAPS_H2_GQ_verify", SHORT_TIME);

	DAPS_H2_GQ_VK_free(vk);
	DAPS_H2_GQ_SK_free(sk);
	DAPS_H2_GQ_SIG_free(sig);
}

// this leaks lots of memory
void DAPS_ID2_GQ_performance(const int keylen, const int hashlen, BN_CTX *bn_ctx) {
	DAPS_ID2_GQ_VK *vk = NULL;
	DAPS_ID2_GQ_SK *sk = NULL;
	DAPS_ID2_GQ_SIG *sig = NULL;

	TIME_OPERATION_SECONDS(DAPS_ID2_GQ_keygen(&vk, &sk, keylen, hashlen, bn_ctx), "DAPS_ID2_GQ_keygen", LONG_TIME);
	char *msg_subj = "www.google.com";
	char *msg_body = "My public key certificate is 42.";
	TIME_OPERATION_SECONDS(DAPS_ID2_GQ_sign(vk, sk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), &sig, bn_ctx), "DAPS_ID2_GQ_sign", LONG_TIME);
	TIME_OPERATION_SECONDS(DAPS_ID2_GQ_verify(vk, hashlen, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx), "DAPS_ID2_GQ_verify", SHORT_TIME);

	DAPS_ID2_GQ_VK_free(vk);
	DAPS_ID2_GQ_SK_free(sk);
	DAPS_ID2_GQ_SIG_free(sig);
}

// this leaks lots of memory
void DAPS_H2_MR_performance(const int keylen, const int hashlen, BN_CTX *bn_ctx) {
	DAPS_H2_MR_VK *vk = NULL;
	DAPS_H2_MR_SK *sk = NULL;
	DAPS_H2_MR_SIG *sig = NULL;

	TIME_OPERATION_SECONDS(DAPS_H2_MR_keygen(&vk, &sk, keylen, hashlen, bn_ctx), "DAPS_H2_MR_keygen", LONG_TIME);
	char *msg_subj = "www.google.com";
	char *msg_body = "My public key certificate is 42.";
	TIME_OPERATION_SECONDS(DAPS_H2_MR_sign(sk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), &sig, bn_ctx), "DAPS_H2_MR_sign", LONG_TIME);
	TIME_OPERATION_SECONDS(DAPS_H2_MR_verify(vk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx), "DAPS_H2_MR_verify", SHORT_TIME);

	DAPS_H2_MR_VK_free(vk);
	DAPS_H2_MR_SK_free(sk);
	DAPS_H2_MR_SIG_free(sig);
}

// this leaks lots of memory
void TDF_PS_performance(const int keylen, BN_CTX *bn_ctx) {
	TDF_PS_PK *pk = NULL;
	TDF_PS_TDK *tdk = NULL;

	BIGNUM *r = BN_new();
	BIGNUM *y = BN_new();

	TIME_OPERATION_SECONDS(TDF_PS_keygen(&pk, &tdk, keylen, bn_ctx), "TDF_PS_keygen", LONG_TIME);
	char *msg = "I am www.google.com and my public key certificate is 42.";
	TIME_OPERATION_SECONDS(TDF_PS_hash_onto_range(pk, (unsigned char *) msg, strlen(msg), r, bn_ctx), "TDF_PS_hash_onto_range", SHORT_TIME);
	TIME_OPERATION_SECONDS(TDF_PS_apply(y, pk, r, bn_ctx), "TDF_PS_apply", SHORT_TIME);
	TIME_OPERATION_SECONDS(TDF_PS_inv(r, tdk, y, 0, bn_ctx), "TDF_PS_inv b=0", SHORT_TIME);
	TIME_OPERATION_SECONDS(TDF_PS_inv(r, tdk, y, 1, bn_ctx), "TDF_PS_inv b=1", SHORT_TIME);
	TIME_OPERATION_SECONDS(TDF_PS_decide(pk, r, bn_ctx), "TDF_PS_decide", SHORT_TIME);

	TDF_PS_PK_free(pk);
	TDF_PS_TDK_free(tdk);
}

// this leaks lots of memory
void DAPS_PS_performance(const int keylen, const int hashlen, BN_CTX *bn_ctx) {
	DAPS_PS_VK *vk = NULL;
	DAPS_PS_SK *sk = NULL;
	DAPS_PS_SIG *sig = NULL;

	TIME_OPERATION_SECONDS(DAPS_PS_keygen(&vk, &sk, keylen, bn_ctx), "DAPS_PS_keygen", LONG_TIME);
	char *msg_subj = "www.google.com";
	char *msg_body = "My public key certificate is 42.";
	TIME_OPERATION_SECONDS(DAPS_PS_sign(vk, sk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), hashlen, &sig, bn_ctx), "DAPS_PS_sign", LONG_TIME);
	TIME_OPERATION_SECONDS(DAPS_PS_verify(vk, (unsigned char *) msg_subj, strlen(msg_subj), (unsigned char *) msg_body, strlen(msg_body), sig, bn_ctx), "DAPS_PS_verify", LONG_TIME);

	DAPS_PS_VK_free(vk);
	DAPS_PS_SK_free(sk);
	DAPS_PS_SIG_free(sig);
}

void BN_performance(const int modlen, const int hashlen, BN_CTX *bn_ctx) {
	DAPS_H2_MR_SK *sk = NULL;
	DAPS_H2_MR_VK *vk = NULL;
	BIGNUM *x = NULL, *y = NULL, *z = NULL;
	x = BN_new();
	y = BN_new();
	z = BN_new();
	DAPS_H2_MR_keygen(&vk, &sk, modlen, hashlen, bn_ctx);

	BN_rand_range(x, sk->p);
	int jac;
	TIME_OPERATION_SECONDS(BN_jacobi_priv(x, sk->p, &jac, bn_ctx), "BN_jacobi_priv modlen/2", LONG_TIME);

	BN_rand_range(x, sk->p);
	BN_rand_range(y, sk->p);
	TIME_OPERATION_SECONDS(BN_mod_exp(z, x, y, sk->p, bn_ctx), "BN_mod_exp modlen/2 ^ modlen/2", LONG_TIME);

	BN_rand_range(x, sk->p);
	BN_rand(y, hashlen, -1, -1);
	TIME_OPERATION_SECONDS(BN_mod_exp(z, x, y, sk->p, bn_ctx), "BN_mod_exp modlen/2 ^ hashlen", LONG_TIME);

	BN_rand_range(x, sk->p);
	BN_rand_range(y, sk->p);
	TIME_OPERATION_SECONDS(BN_crt(z, x, y, sk->p, sk->q, bn_ctx), "BN_crt modlen/2", LONG_TIME);

	BN_rand_range(x, vk->N);
	BN_rand_range(y, vk->N);
	TIME_OPERATION_SECONDS(BN_mod_exp(z, x, y, vk->N, bn_ctx), "BN_mod_exp modlen ^ modlen", LONG_TIME);

	BN_rand_range(x, vk->N);
	BN_rand(y, hashlen, -1, -1);
	TIME_OPERATION_SECONDS(BN_mod_exp(z, x, y, vk->N, bn_ctx), "BN_mod_exp modlen ^ hashlen", LONG_TIME);

	DAPS_H2_MR_SK_free(sk);
	DAPS_H2_MR_VK_free(vk);
	BN_free(x);
	BN_free(y);
	BN_free(z);
}

int main() {

	BN_CTX *bn_ctx = BN_CTX_new();
	if (bn_ctx == NULL) {
		fprintf(stderr, "BN_CTX_new failed\n");
		return EXIT_FAILURE;
	}

	printf("\n");
	printf("For most accurate results:\n");
	printf(" - disable hyperthreading a.k.a. hardware multithreading\n");
	printf("   (Linux instructions: http://bench.cr.yp.to/supercop.html)\n");
	printf("   (Mac OS X instructions: Instruments -> Preferences -> CPUs -> uncheck \"Hardware Multi-Threading\"  http://forums.macrumors.com/showthread.php?t=1484684)\n");
	printf(" - disable TurboBoost\n");
	printf("   (Linux instructions: http://bench.cr.yp.to/supercop.html)\n");
	printf("   (Max OS X: use http://www.rugarciap.com/turbo-boost-switcher-for-os-x/)\n");
	printf(" - run when the computer is idle (e.g., shut down all other applications, disable network access if possible, ...\n");
	printf("\n");

	int mod_sizes[1] = { 2048 };
	int h_sizes[1] = { 256 };

	for (int i = 0; i < 1; i++) {

		printf("\n=== MODULUS = %d, HASH = %d ===\n", mod_sizes[i], h_sizes[i]);

		PRINT_TIMER_HEADER
		BN_performance(mod_sizes[i], h_sizes[i], bn_ctx);
		RSA_performance(mod_sizes[i], bn_ctx);
		ID_GQ_performance(mod_sizes[i], h_sizes[i], bn_ctx);
		DAPS_H2_GQ_performance(mod_sizes[i], h_sizes[i], bn_ctx);
		DAPS_ID2_GQ_performance(mod_sizes[i], h_sizes[i], bn_ctx);
		DAPS_H2_MR_performance(mod_sizes[i], h_sizes[i], bn_ctx);
		TDF_PS_performance(mod_sizes[i], bn_ctx);
		DAPS_PS_performance(mod_sizes[i], h_sizes[i], bn_ctx);
		PRINT_TIMER_FOOTER

	}

	// cleanup
	BN_CTX_free(bn_ctx);
	return EXIT_SUCCESS;
}
