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

/** \file main.c
 * Test harness program.
 */

#include <string.h>

#include "id_gq.h"
#include "daps_h2_gq.h"
#include "daps_id2_gq.h"
#include "daps_h2_mr.h"
#include "tdf_ps.h"
#include "daps_ps.h"

#define ITERATIONS 100
#define DO_TEST(s, f) \
	printf("\nTesting %s.\n", (s)); \
	for (int j = 0; j < ITERATIONS; j++) { \
		ok = (f); \
		if (ok != 1) { \
			printf("%s failed\n", (s)); \
			return EXIT_FAILURE; \
		} \
	}

int main() {

	int ok;

	char *s = "This is a test";

	int mod_sizes[1] = { 2048 };
	int h_sizes[1] = { 256 };

	for (int i = 0; i < 1; i++) {

		printf("\n=== MODULUS = %d, HASH = %d ===\n", mod_sizes[i], h_sizes[i]);

		DO_TEST("ID_GQ with a challenge generated at random", ID_GQ_test_rand(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("ID_GQ commitment inversion", ID_GQ_test_cmt_cmt_inv(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("ID_GQ extraction with challenges generated at random", ID_GQ_test_extract(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("ID_GQ with a challenge generated from a hash", ID_GQ_test_hash(mod_sizes[i], h_sizes[i], (unsigned char *) s, strlen(s), 0));
		DO_TEST("ID_GQ with a randomly generated commitment, the state then inverted, and then a challenge generated from a hash", ID_GQ_test_hash_inv(mod_sizes[i], h_sizes[i], (unsigned char *) s, strlen(s), 0));
		DO_TEST("ID_GQ response inversion", ID_GQ_test_resp_inv(mod_sizes[i], h_sizes[i], (unsigned char *) s, strlen(s), 0));
		DO_TEST("ID_GQ extraction", ID_GQ_test_extract(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("DAPS_H2_GQ", DAPS_H2_GQ_test(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("DAPS_ID2_GQ permutation/inversion", DAPS_ID2_GQ_test_perm(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("DAPS_ID2_GQ", DAPS_ID2_GQ_test(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("DAPS_H2_MR", DAPS_H2_MR_test(mod_sizes[i], h_sizes[i], 0));
		DO_TEST("TDF_PS", TDF_PS_test(mod_sizes[i], 0));
		DO_TEST("DAPS_PS", DAPS_PS_test(mod_sizes[i], h_sizes[i], 0));

	}

	return EXIT_SUCCESS;
}
