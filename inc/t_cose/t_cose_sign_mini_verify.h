/*
 * t_cose_sign_mini_verify.h
 *
 * Copyright 2022-2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 8/17/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_sign_mini_verify_h
#define t_cose_sign_mini_verify_h

#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * The algorithm is set at compile time for mini sign and can't be
 * changed.  Only one algorithm is
 * supported at a time. Define one of these to configure the algorithm. If
 * none are configured, ES256 is selected.

#define T_COSE_MINI_VERIFY_SELECT_ES256
#define T_COSE_MINI_VERIFY_SELECT_ES384
#define T_COSE_MINI_VERIFY_SELECT_ES512
*/

#if !defined(T_COSE_MINI_VERIFY_SELECT_ES256) && \
    !defined(T_COSE_MINI_VERIFY_SELECT_ES384) && \
    !defined(T_COSE_MINI_VERIFY_SELECT_ES512)
#define T_COSE_MINI_VERIFY_SELECT_ES256
#endif


/**
 * @brief Minature verification of COSE_Sign1
 *
 * @param[in] cose_sign1   The COSE_Sign1 to verify.
 * @param[in] verification_key  The verification key.
 * @param[out] payload   Pointer and length of verified payload.
 *
 * @return The error result.
 *
 * This is an implementation of \c COSE_Sign1 verification
 * with very small, near  minimun code size. It has
 * almost no external dependency, except a crypto library,
 * not even a CBOR library.
 *
 * Only one algorithm is supported at a time. If the
 * input \c COSE_Sign1 doesn't use that algorithm
 * an error is returned.
 *
 * There is no header decoding to retrieve a key ID, so
 * identification of the key must be by some other means.
 *
 * It simply checks that the algorithm header parameter
 * matches what it compiled to support, decodes
 * the payload and the signature, verifies the
 * signature and returns the verified payload.
 *
 * This has very crude error reporting in order to keep
 * the code size small. Success is always success and failure
 * always failure, but the failure reported might be misleading
 * as to the actual reason for the failure.
 */
enum t_cose_err_t
t_cose_sign1_mini_verify(struct q_useful_buf_c   cose_sign1,
                         struct t_cose_key       verification_key,
                         struct q_useful_buf_c  *payload);



#endif /* t_cose_sign_mini_verify_h */
