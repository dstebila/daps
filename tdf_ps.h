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

/** \file tdf_ps.h
 * Interface for PS trapdoor function.
 */

#ifndef _TDF_PS_H
#define _TDF_PS_H

#include <openssl/bn.h>

typedef struct TDF_PS_pk_st TDF_PS_PK;
struct TDF_PS_pk_st {
	BIGNUM *n;
	BIGNUM *halfn;
};

typedef struct TDF_PS_tdk_st TDF_PS_TDK;
struct TDF_PS_tdk_st {
	BIGNUM *n;
	BIGNUM *halfn;
	BIGNUM *p;
	BIGNUM *q;
};

void TDF_PS_PK_free(TDF_PS_PK *pk);
void TDF_PS_TDK_free(TDF_PS_TDK *tdk);

void TDF_PS_PK_print_fp(FILE *fp, const TDF_PS_PK *pk);
void TDF_PS_TDK_print_fp(FILE *fp, const TDF_PS_TDK *tdk);

int TDF_PS_keygen(TDF_PS_PK **pk, TDF_PS_TDK **tdk, const int bits, BN_CTX *bn_ctx);
int TDF_PS_hash_onto_range(const TDF_PS_PK *pk, const unsigned char *msg, const int msg_length, BIGNUM *r, BN_CTX *bn_ctx);
int TDF_PS_apply(BIGNUM *y, const TDF_PS_PK *pk, const BIGNUM *x, BN_CTX *bn_ctx);
int TDF_PS_inv(BIGNUM *x, const TDF_PS_TDK *tdk, const BIGNUM *y, const int bit, BN_CTX *bn_ctx);
int TDF_PS_decide(const TDF_PS_PK *pk, const BIGNUM *x, BN_CTX *bn_ctx);

int TDF_PS_test(int keylen, int print);

#endif
