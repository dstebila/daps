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

/** \file daps_h2_mr.h
 * Interface for H2[MR] DAPS scheme.
 */

#ifndef _DAPS_H2_MR_H
#define _DAPS_H2_MR_H

#include <openssl/bn.h>

typedef struct DAPS_H2_MR_vk_st DAPS_H2_MR_VK;
struct DAPS_H2_MR_vk_st {
	BIGNUM *N;
	int chbits;
};

typedef struct DAPS_H2_MR_sk_st DAPS_H2_MR_SK;
struct DAPS_H2_MR_sk_st {
	BIGNUM *N;
	int chbits;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *up;
	BIGNUM *uq;
	BIGNUM *vp;
	BIGNUM *vq;
};

typedef struct DAPS_H2_MR_sig_st DAPS_H2_MR_SIG;
struct DAPS_H2_MR_sig_st {
	BIGNUM *z;
	unsigned char *s;
	int s_length;
};

void DAPS_H2_MR_VK_free(DAPS_H2_MR_VK *vk);
void DAPS_H2_MR_SK_free(DAPS_H2_MR_SK *sk);
void DAPS_H2_MR_SIG_free(DAPS_H2_MR_SIG *sig);

void DAPS_H2_MR_VK_print_fp(FILE *fp, const DAPS_H2_MR_VK *vk);
void DAPS_H2_MR_SK_print_fp(FILE *fp, const DAPS_H2_MR_SK *sk);
void DAPS_H2_MR_SIG_print_fp(FILE *fp, const DAPS_H2_MR_SIG *sig);

int DAPS_H2_MR_keygen(DAPS_H2_MR_VK **vk, DAPS_H2_MR_SK **sk, const int bits, const int chbits, BN_CTX *bn_ctx);
int DAPS_H2_MR_sign(const DAPS_H2_MR_SK *sk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, DAPS_H2_MR_SIG **sig, BN_CTX *bn_ctx);
int DAPS_H2_MR_verify(const DAPS_H2_MR_VK *vk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const DAPS_H2_MR_SIG *sig, BN_CTX *bn_ctx);
int DAPS_H2_MR_extract(const DAPS_H2_MR_VK *vk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body1, const int msg_body1_length, const DAPS_H2_MR_SIG *sig1, const unsigned char *msg_body2, const int msg_body2_length, const DAPS_H2_MR_SIG *sig2, DAPS_H2_MR_SK **sk, BN_CTX *bn_ctx);

int DAPS_H2_MR_test(const int keylen, const int hashlen, const int print);
int DAPS_H2_MR_test_count_trivial(const int keylen, const int hashlen, const int print);

#endif
