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

/** \file common.h
 * Common preprocessor macros.
 */

#ifndef _COMMONH
#define _COMMONH

#define DEBUG_LINE fprintf(stderr, "@@@ %s:%d @@@\n", __FILE__, __LINE__); fflush(stderr);

#define CHECK_IS_ONE(x) \
	ok = (x); \
	if (ok != 1) { DEBUG_LINE; goto err; }
#define CHECK_IS_ZERO(x) \
	ok = (x); \
	if (ok != 0) { DEBUG_LINE; goto err; }
#define CHECK_GT_ZERO(x) \
	ok = (x); \
	if (ok <= 0) { DEBUG_LINE; goto err; }
#define CHECK_GE_ZERO(x) \
	ok = (x); \
	if (ok < 0) { DEBUG_LINE; goto err; }
#define CHECK_NONZERO(x) \
	ok = (x); \
	if (ok == 0) { DEBUG_LINE; goto err; }
#define CHECK_NONNULL(x) \
	if ((x) == NULL) { DEBUG_LINE; goto err; }

#endif
