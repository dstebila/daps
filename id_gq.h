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

/** \file id_gq.h
 * Interface for GQ identification scheme.
 */

#ifndef _ID_GQ_H
#define _ID_GQ_H

#include <openssl/bn.h>
#include <openssl/rsa.h>

typedef struct ID_GQ_pk_st ID_GQ_PK;
struct ID_GQ_pk_st {
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *X;
};

typedef struct ID_GQ_sk_st ID_GQ_SK;
struct ID_GQ_sk_st {
	BIGNUM *x;
	BIGNUM *n;
};

typedef struct ID_GQ_tdk_st ID_GQ_TDK;
struct ID_GQ_tdk_st {
	BIGNUM *d;
	BIGNUM *n;
	RSA *rsa;
};

typedef struct ID_GQ_cmt_st ID_GQ_CMT;
struct ID_GQ_cmt_st {
	BIGNUM *Y;
};

typedef struct ID_GQ_state_st ID_GQ_STATE;
struct ID_GQ_state_st {
	BIGNUM *y;
};

typedef struct ID_GQ_ch_st ID_GQ_CH;
struct ID_GQ_ch_st {
	BIGNUM *c;
};

typedef struct ID_GQ_resp_st ID_GQ_RESP;
struct ID_GQ_resp_st {
	BIGNUM *z;
};

void ID_GQ_PK_free(ID_GQ_PK *pk);
void ID_GQ_SK_free(ID_GQ_SK *sk);
void ID_GQ_TDK_free(ID_GQ_TDK *tdk);
void ID_GQ_CMT_free(ID_GQ_CMT *cmt);
void ID_GQ_STATE_free(ID_GQ_STATE *state);
void ID_GQ_CH_free(ID_GQ_CH *ch);
void ID_GQ_RESP_free(ID_GQ_RESP *resp);

void ID_GQ_PK_print_fp(FILE *fp, const ID_GQ_PK *pk);
void ID_GQ_SK_print_fp(FILE *fp, const ID_GQ_SK *sk);
void ID_GQ_TDK_print_fp(FILE *fp, const ID_GQ_TDK *tdk);
void ID_GQ_CMT_print_fp(FILE *fp, const ID_GQ_CMT *cmt);
void ID_GQ_STATE_print_fp(FILE *fp, const ID_GQ_STATE *state);
void ID_GQ_CH_print_fp(FILE *fp, const ID_GQ_CH *ch);
void ID_GQ_RESP_print_fp(FILE *fp, const ID_GQ_RESP *resp);
void ID_GQ_print_fp(FILE *fp, const ID_GQ_PK *pk, const ID_GQ_SK *sk, const ID_GQ_TDK *tdk, const ID_GQ_CMT *cmt, const ID_GQ_STATE *state, const ID_GQ_CH *ch, const ID_GQ_RESP *resp);

int ID_GQ_keygen(ID_GQ_PK **pk, ID_GQ_SK **sk, ID_GQ_TDK **tdk, const int bits, const int chlen, BN_CTX *bn_ctx);
int ID_GQ_cmt(const ID_GQ_PK *pk, ID_GQ_CMT **cmt, ID_GQ_STATE **state, BN_CTX *bn_ctx);
int ID_GQ_cmt_inv(const ID_GQ_TDK *tdk, const ID_GQ_CMT *cmt, ID_GQ_STATE **state, BN_CTX *bn_ctx);
int ID_GQ_ch_rand(ID_GQ_CH **ch, const int chlen);
int ID_GQ_ch_hash(ID_GQ_CH **ch, const int chlen, const unsigned char *msg, const int length);
int ID_GQ_resp(const ID_GQ_SK *sk, const ID_GQ_STATE *state, const ID_GQ_CH *ch, ID_GQ_RESP **resp, BN_CTX *bn_ctx);
int ID_GQ_resp_inv(const ID_GQ_PK *pk, ID_GQ_CMT **cmt, const ID_GQ_CH *ch, const ID_GQ_RESP *resp, BN_CTX *bn_ctx);
int ID_GQ_ver(const ID_GQ_PK *pk, const ID_GQ_CMT *cmt, const ID_GQ_CH *ch, const ID_GQ_RESP *resp, BN_CTX *bn_ctx);
int ID_GQ_extract(const ID_GQ_PK *pk, const ID_GQ_CMT *cmt, const ID_GQ_CH *ch1, const ID_GQ_RESP *resp1, const ID_GQ_CH *ch2, const ID_GQ_RESP *resp2, ID_GQ_SK **sk, BN_CTX *bn_ctx);

int ID_GQ_test_rand(const int keylen, const int chlen, const int print);
int ID_GQ_test_cmt_cmt_inv(const int keylen, const int chlen, const int print);
int ID_GQ_test_hash(const int keylen, const int chlen, const unsigned char *msg, const int length, const int print);
int ID_GQ_test_hash_inv(const int keylen, const int chlen, const unsigned char *msg, const int length, const int print);
int ID_GQ_test_resp_inv(const int keylen, const int chlen, const unsigned char *msg, const int length, const int print);
int ID_GQ_test_extract(const int keylen, const int chlen, const int print);

#endif
