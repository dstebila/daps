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

/** \file daps_ps.h
 * Interface for PS DAPS scheme.
 */

#ifndef _DAPS_PS_H
#define _DAPS_PS_H

#include <openssl/bn.h>

#include "tdf_ps.h"

typedef struct DAPS_PS_vk_st DAPS_PS_VK;
struct DAPS_PS_vk_st {
	TDF_PS_PK *tdfpk;
};

typedef struct DAPS_PS_sk_st DAPS_PS_SK;
struct DAPS_PS_sk_st {
	TDF_PS_TDK *tdftdk;
};

typedef struct DAPS_PS_sig_st DAPS_PS_SIG;
struct DAPS_PS_sig_st {
	BIGNUM *s;
	BIGNUM **a;
	int a_length;
};

void DAPS_PS_VK_free(DAPS_PS_VK *vk);
void DAPS_PS_SK_free(DAPS_PS_SK *sk);
void DAPS_PS_SIG_free(DAPS_PS_SIG *sig);

void DAPS_PS_VK_print_fp(FILE *fp, const DAPS_PS_VK *vk);
void DAPS_PS_SK_print_fp(FILE *fp, const DAPS_PS_SK *sk);
void DAPS_PS_SIG_print_fp(FILE *fp, const DAPS_PS_SIG *sig);

int DAPS_PS_keygen(DAPS_PS_VK **vk, DAPS_PS_SK **sk, const int bits, BN_CTX *bn_ctx);
int DAPS_PS_sign(const DAPS_PS_VK *vk, const DAPS_PS_SK *sk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const int hashlen, DAPS_PS_SIG **sig, BN_CTX *bn_ctx);
int DAPS_PS_verify(const DAPS_PS_VK *vk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const DAPS_PS_SIG *sig, BN_CTX *bn_ctx);
int DAPS_PS_extract(const DAPS_PS_VK *vk, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body1, const int msg_body1_length, const DAPS_PS_SIG *sig1, const unsigned char *msg_body2, const int msg_body2_length, const DAPS_PS_SIG *sig2, DAPS_PS_SK **sk, BN_CTX *bn_ctx);

int DAPS_PS_test(int keylen, int hashlen, int print);

#endif
