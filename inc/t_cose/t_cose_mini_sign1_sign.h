/*
 * t_cose_mini_sign1_sign.h
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
    5 + /* The header parameters */ \
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
    132 /* T_COSE_EC_P512_SIG_SIZE */


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
 * This signs a payload to make a COSE_Sign1 in the simplest possible
 * way. The object code for this is very small. This is achieved by
 * fixing the algorithm at compile time, not allowing any header
 * parameters but the signing algorithm and limiting the payload size
 * to \c UINT16_MAX. The default algorithm is COSE ES256 (EC with the
 * secp256r1 curve).
 *
 * See t_cose_sign1_sign() for full-featured signing.
 *
 * The inputs are a payload to sign and a signing key. The signing key
 * is a handle or pointer to a key usable with the crypto library this
 * is linked against (probably OpenSSL or Mbed TLS). The key
 * set up is the same as in the t_cose examples.
 *
 * An output buffer must be given sized large enough to hold the
 * COSE_Sign1 message produced. The size of this is \ref
 * T_COSE_MINI_SIGN_SIZE_OVERHEAD_ES256 larger than the payload. If
 * \c output_buffer is too small, an error will be returned.
 *
 * This does NOT need to link with a CBOR encoder. It does need to
 * link with a cryptographic library. OpenSSL and Mbed TLS are
 * supported. It uses the t_cose_crypto.h layer to interface with the
 * cryptographic library. It should be easy adapt this to other
 * cryptographic libraries.
 *
 * ES384 and ES512 are also supported, but you have to modify the
 * source to switch to one of them. The source could be further
 * modified to support RSA.
 *
 * See comments in the source code to change the algorithm and
 * discussion about other modifications.
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
