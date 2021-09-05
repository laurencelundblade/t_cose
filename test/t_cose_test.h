/*
 *  t_cose_test.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_test_h
#define t_cose_test_h

#include <stdint.h>

/**
 * \file t_cose_test.h
 *
 * \brief Entry points for the basic t_cose_tests.
 *
 * These tests can be performed without any crypto library such as OpenSSL
 * integrated with t_cose.
 */


/**
 * \brief Minimal message creation test using a short-circuit signature.
 *
 * \return non-zero on failure.
 *
 * This test makes a simple COSE_Sign1 and verify it.  It uses
 * short-circuit signatures so no keys or even integration with public
 * key crypto is necessary.
 */
int_fast32_t short_circuit_self_test(void);


/**
 * \brief Minimal message creation test using a short-circuit with the
 *        restartable API.
 *
 * \return non-zero on failure.
 *
 * This test makes a simple COSE_Sign1 and verify it.  It uses
 * short-circuit signatures so no keys or even integration with public
 * key crypto is necessary.
 */
int_fast32_t short_circuit_self_test_restartable(void);


/**
 * \brief COSE detached content test using a short-circuit signature.
 *
 * \return non-zero on failure.
 *
 * This test makes a detached content COSE_Sign1 and verify it.  It uses
 * short-circuit signatures so no keys or even integration with public
 * key crypto is necessary.
 */
int_fast32_t short_circuit_self_detached_content_test(void);


/**
 * \brief COSE detached content test using a short-circuit signature with the
 *        restartable API.
 *
 * \return non-zero on failure.
 *
 * This test makes a detached content COSE_Sign1 and verify it.  It uses
 * short-circuit signatures so no keys or even integration with public
 * key crypto is necessary.
 */
int_fast32_t short_circuit_self_detached_content_test_restartable(void);


/**
 * \brief Test where payload bytes are corrupted and sig fails.
 *
 * \return non-zero on failure.
 *
 * This test makes a simple COSE_Sign1 modifies the payload and sees that
 * verification fails.  It uses short-circuit signatures so no keys or
 * even integration with public key crypto is necessary.
 */
int_fast32_t short_circuit_verify_fail_test(void);


/**
 * \brief Test where payload bytes are corrupted and sig fails with restartable
 *        API
 *
 * \return non-zero on failure.
 *
 * This test makes a simple COSE_Sign1 modifies the payload and sees that
 * verification fails.  It uses short-circuit signatures so no keys or
 * even integration with public key crypto is necessary.
 */
int_fast32_t short_circuit_verify_fail_test_restartable(void);


/**
 * \brief Tests error condidtions for creating COSE_Sign1.
 *
 * \return non-zero on failure.
 *
 * It uses short-circuit signatures so no keys or even integration
 * with public key crypto is necessary.
 */
int_fast32_t short_circuit_signing_error_conditions_test(void);


/**
 * \brief Tests error condidtions for creating COSE_Sign1 with restartable API.
 *
 * \return non-zero on failure.
 *
 * It uses short-circuit signatures so no keys or even integration
 * with public key crypto is necessary.
 */
int_fast32_t short_circuit_signing_error_conditions_test_restartable(void);


/* Make a CWT and see that it compares to the sample in the CWT RFC
 */
int_fast32_t short_circuit_make_cwt_test(void);


/* Make a CWT and see that it compares to the sample in the CWT RFC using
 * restartable API
 */
int_fast32_t short_circuit_make_cwt_test_restartable(void);


/*
 * Test the decode only mode, the mode where the
 * headers are returned, but the signature is not
 * verified.
 */
int_fast32_t short_circuit_decode_only_test(void);


/*
 * Test the decode only mode, the mode where the
 * headers are returned, but the signature is no
 * verified. Using the restartable signing API.
 */
int_fast32_t short_circuit_decode_only_test_restartable(void);


/*
- protected header parameters not well formed CBOR
- unprotected header parameters not well formed CBOR
- unknown algorithm ID
- No algorithm ID parameter

 */
int_fast32_t bad_parameters_test(void);

/*
 * - protected header parameters not well formed CBOR
 * - unprotected header parameters not well formed CBOR
 * - unknown algorithm ID
 * - No algorithm ID parameter
 *
 * All with restartable signing API
 */
int_fast32_t bad_parameters_test_restartable(void);


/* Test that makes a CWT (CBOR Web Token)
 */
int_fast32_t cose_example_test(void);


/* Test that makes a CWT (CBOR Web Token) using restartable API.
 */
int_fast32_t cose_example_test_restartable(void);


/*
 Various tests involving the crit parameter.
 */
int_fast32_t crit_parameters_test(void);


/*
 * Various tests involving the crit parameter using restartable signing API.
 */
int_fast32_t crit_parameters_test_restartable(void);


/*
 Check that all types of headers are correctly returned.
 */
int_fast32_t all_header_parameters_test(void);


/*
 * Check that all types of headers are correctly returned using the restartable
 * signing API.
 */
int_fast32_t all_header_parameters_test_restartable(void);


/*
 * Check that setting the content type works
 */
int_fast32_t content_type_test(void);


/*
 * Check that setting the content type works with the restartable signing API
 */
int_fast32_t content_type_test_restartable(void);


/*
 * Check that setting the content type works
 */
int_fast32_t sign1_structure_decode_test(void);


#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
/*
 * This forces / simulates failures in the hash algorithm implementation
 * to test t_cose's handling of those condidtions. This test is off
 * by default because it needs a hacked version of a hash algorithm.
 * It is very hard to get hash algorithms to fail, so this hacked
 * version is necessary. This test will not run correctly with
 * OpenSSL or Mbed TLS hashes because they aren't (and shouldn't be) hacked.
 * It works only with the b_con hash bundled and not intended for
 * commercial use (though it is a perfectly fine implementation).
 */
int_fast32_t short_circuit_hash_fail_test(void);


/*
 * This forces / simulates failures in the hash algorithm implementation
 * to test t_cose's handling of those condidtions, using the restartable sign
 * API. For details see short_circuit_hash_fail_test.
 */
int_fast32_t short_circuit_hash_fail_test_restartable(void);

#endif /* T_COSE_ENABLE_HASH_FAIL_TEST*/



/*
 * Test tagging of COSE message
 */
int_fast32_t tags_test(void);

/*
 * Test tagging of COSE message with the restartable sign API
 */
int_fast32_t tags_test_restartable(void);


int_fast32_t get_size_test(void);

int_fast32_t get_size_test_restartable(void);


/*
 * Test the decoding of COSE messages that use indefinite length
 * maps and arrays instead of definite length.
 */
int_fast32_t indef_array_and_map_test(void);

/*
 * Test the decoding of COSE messages that use indefinite length
 * maps and arrays instead of definite length using the restartable sign API.
 */
int_fast32_t indef_array_and_map_test_restartable(void);


#endif /* t_cose_test_h */
