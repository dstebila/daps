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

/** \file daps_id2_gq.h
 * Interface for ID2[GQ] DAPS scheme.
 */

#ifndef _DAPS_ID2_GQ_H
#define _DAPS_ID2_GQ_H

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "id_gq.h"

typedef struct DAPS_ID2_GQ_vk_st DAPS_ID2_GQ_VK;
struct DAPS_ID2_GQ_vk_st {
	ID_GQ_PK *ipk;
	unsigned char *TDK;
	int TDK_length;
};

typedef struct DAPS_ID2_GQ_sk_st DAPS_ID2_GQ_SK;
struct DAPS_ID2_GQ_sk_st {
	ID_GQ_SK *isk;
	ID_GQ_TDK *itdk;
};

typedef struct DAPS_ID2_GQ_sig_st DAPS_ID2_GQ_SIG;
struct DAPS_ID2_GQ_sig_st {
	ID_GQ_CH *ch1;
	ID_GQ_RESP *resp2;
};

void DAPS_ID2_GQ_VK_free(DAPS_ID2_GQ_VK *vk);
void DAPS_ID2_GQ_SK_free(DAPS_ID2_GQ_SK *sk);
void DAPS_ID2_GQ_SIG_free(DAPS_ID2_GQ_SIG *sig);

void DAPS_ID2_GQ_VK_print_fp(FILE *fp, const DAPS_ID2_GQ_VK *vk);
void DAPS_ID2_GQ_SK_print_fp(FILE *fp, const DAPS_ID2_GQ_SK *sk);
void DAPS_ID2_GQ_SIG_print_fp(FILE *fp, const DAPS_ID2_GQ_SIG *sig);

int DAPS_ID2_GQ_keygen(DAPS_ID2_GQ_VK **vk, DAPS_ID2_GQ_SK **sk, const int bits, const int chlen, BN_CTX *bn_ctx);
int DAPS_ID2_GQ_sign(const DAPS_ID2_GQ_VK *vk, const DAPS_ID2_GQ_SK *sk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, DAPS_ID2_GQ_SIG **sig, BN_CTX *bn_ctx);
int DAPS_ID2_GQ_verify(const DAPS_ID2_GQ_VK *vk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body, const int msg_body_length, const DAPS_ID2_GQ_SIG *sig, BN_CTX *bn_ctx);
int DAPS_ID2_GQ_extract(const DAPS_ID2_GQ_VK *vk, const int hashlen, const unsigned char *msg_subj, const int msg_subj_length, const unsigned char *msg_body1, const int msg_body1_length, const DAPS_ID2_GQ_SIG *sig1, const unsigned char *msg_body2, const int msg_body2_length, const DAPS_ID2_GQ_SIG *sig2, DAPS_ID2_GQ_SK **sk, BN_CTX *bn_ctx);

int DAPS_ID2_GQ_test(int keylen, int hashlen, int print);
int DAPS_ID2_GQ_test_perm(int keylen, int hashlen, int print);

#endif
