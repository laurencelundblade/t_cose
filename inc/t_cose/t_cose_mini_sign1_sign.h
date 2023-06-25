/*
 *  t_cose_mini_sign1_sign.h
 *
 * Copyright 2022-2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_MINI_SIGN_H__
#define __T_COSE_MINI_SIGN_H__


#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif



/* The output buffer must be this much larger than the payload size. */
#define T_COSE_MINI_SIGN_SIZE_OVERHEAD_ES256 \
    1 + /* Open the array */ \
    6 + /* The header parameters */ \
    3 + /* The CBOR head of the payload */ \
        /* The payload -- add this in yourself */ \
    2 + /* CBOR head of signature */ \
    64  /* T_COSE_EC_P256_SIG_SIZE */

#define T_COSE_MINI_SIGN_SIZE_OVERHEAD_ES384 \
    1 + /* Open the array */ \
    6 + /* The header parameters */ \
    3 + /* The CBOR head of the payload */ \
        /* The payload -- add this in yourself */ \
    2 + /* CBOR head of signature */ \
    96 /* T_COSE_EC_P384_SIG_SIZE */

#define T_COSE_MINI_SIGN_SIZE_OVERHEAD_ES512 \
    1 + /* Open the array */ \
    6 + /* The header parameters */ \
    3 + /* The CBOR head of the payload */ \
        /* The payload -- add this in yourself */ \
    2 + /* CBOR head of signature */ \
    128 /* T_COSE_EC_P512_SIG_SIZE */


/**
 * @brief Create a COSE_Sign1 with fixed algorithm and no header parameters.
 *
 * @param[in] payload         The payload to sign.
 * @param[in] signing_key     The key to sign with.
 * @param[in] output_buffer   The buffer where the COSE_Sign1 is written.
 * @param[out] output         Pointer and length of the completed COSE_Sign1.
 *
 * @return  T_COSE_ERR_TOO_LONG The payload length is > UINT16_MAX
 *          T_COSE_ERR_TOO_SMALL  The output_buffer is too small for the
 *                                payload.
 *          Other errors related to invocation of the crypto algorithms.
 *
 * This is a small object code version of t_cose_sign1_sign(). The
 * small object code is achieved by fixing the algorithm at compile
 * time (the default is COSE ES256) and by not allowing or outputting
 * any header parameter except the algorithm ID. There is also
 * a maximum size of the payload at UINT16_MAX.
 *
 * Even if you don't need small object code, this is
 * a super easy to use COSE Sign1 API if ES256 is good enough
 * and you don't need any other header parameters.
 *
 * See \ref T_COSE_MINI_SIGN_SIZE_OVERHEAD_ES256 for a compile time
 * constant that gives the size over and above the payload size
 * for the output buffer. If \ref output_buffer is too small
 * an error will be returned.
 *
 * The object code size is about 500 bytes plus the crypto library.
 * This works with either OpenSSL and PSA Crypto (MbedTLS). It
 * is less total object code with PSA Crypto. This contrasts
 * with about 1500 bytes plus QCBOR plus the crypto library
 * for t_cose_sign1_sign().
 *
 * ES384 and ES512 are also supported, but you have to modify
 * the source to switch to one of them. The source could be
 * further modified to support RSA.
 *
 * See comments in the source code for changing the algorithm that
 * is supported, adding support for headers or reducing the object
 * code even futher.
 */
enum t_cose_err_t
t_cose_mini_sign1_sign(struct q_useful_buf_c  payload,
                       struct t_cose_key      signing_key,
                       struct q_useful_buf    output_buffer,
                       struct q_useful_buf_c *output);


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_MINI_SIGN_H__ */
