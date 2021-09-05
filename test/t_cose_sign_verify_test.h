/*
 *  t_cose_sign_verify_test.h
 *
 * Copyright 2019, 2022, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_sign_verify_test_h
#define t_cose_sign_verify_test_h

#include <stdint.h>


/**
 * \file t_cose_sign_verify_test.h
 *
 * \brief Tests that need public key crypto to be implemented
 */


/**
 * \brief Self test using single step crypto API.
 *
 * \return Positive on failure.
 * \return Negative on skip.
 * \return 0 on Success.
 */
int_fast32_t sign_verify_basic_test(void);


/**
 * \brief Self test using restartable crypto API.
 *
 * \return Positive on failure.
 * \return Negative on skip.
 * \return 0 on Success.
 */
int_fast32_t sign_verify_basic_test_restartable(void);


/*
 * Sign some data, perturb the data and see that sig validation fails using
 * single step crypto API.
 */
int_fast32_t sign_verify_sig_fail_test(void);


/*
 * Sign some data, perturb the data and see that sig validation fails using
 * restartable crypto API.
 */
int_fast32_t sign_verify_sig_fail_test_restartable(void);


/*
 * Make a CWT and compare it to the one in the CWT RFC
 */
int_fast32_t sign_verify_make_cwt_test(void);


/*
 * Make a CWT using restartable crypto API and compare it to the one in the CWT
 * RFC.
 */
int_fast32_t sign_verify_make_cwt_test_restartable(void);


/*
 * Test the ability to calculate size of a COSE_Sign1 using single step crypto
 * API.
 */
int_fast32_t sign_verify_get_size_test(void);

/*
 * Test the ability to calculate size of a COSE_Sign1 using restartable crypto
 * API.
 */
int_fast32_t sign_verify_get_size_test_restartable(void);

/*
 * Test against known good messages.
 */
int_fast32_t known_good_test(void);

#endif /* t_cose_sign_verify_test_h */
