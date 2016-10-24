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
 *
 * BN_jacobi_priv function by Adam L. Young.
 ********************************************************************************************/

/** \file bn_extra.h
 * Interface for extra BIGNUM functions.
 */

#ifndef _BNEXTRA_H
#define _BNEXTRA_H

#include <openssl/bn.h>
#include <openssl/sha.h>

#define BN_printdec_fp(fp, s, x) \
	{	char *bn_printdec_fp_tmp; \
		bn_printdec_fp_tmp = BN_bn2dec((x)); \
		fprintf((fp), "%s = %s\n", (s), bn_printdec_fp_tmp); \
		fflush((fp)); \
		free(bn_printdec_fp_tmp); \
	}
#define BN_printhex_fp(fp, s, x) \
	{	fprintf((fp), "%s = ", (s)); \
		BN_print_fp((fp), (x)); \
		fprintf((fp), "\n"); \
		fflush((fp)); \
	}

unsigned char *SHA256_arbitrary(const unsigned char *d, const int d_length, const int o_length);
BIGNUM *SHA256_mod(const unsigned char *d, const int d_length, BIGNUM *m, BN_CTX *bn_ctx);

int BN_extended_gcd(BIGNUM *r, BIGNUM *s, BIGNUM *t, const BIGNUM *a, const BIGNUM *b, BN_CTX *bn_ctx);
int BN_crt(BIGNUM *x, const BIGNUM *a1, const BIGNUM *n1, const BIGNUM *a2, const BIGNUM *n2, BN_CTX *bn_ctx);
int BN_jacobi_priv(const BIGNUM *A, const BIGNUM *N, int *jacobi, BN_CTX *ctx);

#endif
