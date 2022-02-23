/*
 * t_cose_encrypt_enc.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_ENCRYPT_ENC_H__
#define __T_COSE_ENCRYPT_ENC_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "t_cose_parameters.h"
#include "t_cose_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QCBOR_SPIFFY_DECODE
#error This version of t_cose requires a version of QCBOR that supports spiffy decode
#endif


/**
 * \file t_cose_encrypt_enc.h
 *
 * \brief Encrypt plaintext and encode it in a CBOR-based structure referred to as
 * COSE_Encrypt0 or COSE_Encrypt.
 *
 * The functions defined encrypt plaintext with a symmetric cryptographic algorithm.
 * The result is then stored in \c COSE_Encrypt0 or in a \c COSE_Encrypt
 * message, as defined in [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152). \c COSE_Encrypt0 and \c COSE_Encrypt
 * messages are CBOR encoded binary payloads that contain header parameters,
 * a payload - the ciphertext. The payload may be detached in which case it is
 * not included in the CBOR encoded message and needs to be conveyed separately.
 *
 * \c COSE_Encrypt and \c COSE_Encrypt0 messages require a symmetric key for encryption
 * (referred to as Content Encryption Key or CEK). Hence, it is necessary to think
 * about  key distribution and COSE (RFC 8152) defines various "Content Key
 * Distribution Methods", as RFC 8152 calls it, and two of them are
 * implemented in this library:
 *
 * 1) Direct: The CEK is pre-negotiated between the involved communication parties.
 * Hence, no CEK is transported in the COSE message. For this approach the COSE_Encrypt0
 * message is used.
 *
 * 2) Key agreement: This approach requires utilizes an algorithm for establishing
 * a shared secret, which then serves as a CEK. Therefore, a recipient structure
 * must be included in the COSE message and the COSE_Encrypt message carries such
 * a recipient structure(while \c COSE_Encrypt0 does not). The key agreement
 * algorithm used in this implementation is based on Hybrid Public Key Encryption
 * (HPKE) and is described in https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/.
 *
 * This implementation is intended to be small and portable to
 * different OS's and platforms. Its dependencies are:
 * - [QCBOR](https://github.com/laurencelundblade/QCBOR)
 * - <stdint.h>, <string.h>, <stddef.h>
 * - Encryption functions like AES-GCM.
 * - HPKE when COSE_Encrypt is utilized. The HPKE library can be found
 *   at https://github.com/hannestschofenig/mbedtls/tree/hpke
 * - Hash functions like SHA-256 (for use with HPKE)
 *
 * Additionally, it is necessary to either sign or MAC the resulting
 * COSE_Encrypt0 or COSE_Encrypt message to provide authentication and
 * integrity protection. This functionality is supported by other APIs in
 * the t_cose library.
 *
 * There is a cryptographic adaptation layer defined in
 * t_cose_crypto.h.  An implementation can be made of the functions in
 * it for different cryptographic libraries. This means that different
 * integrations with different cryptographic libraries may, for example,
 * support only encryption with a particular set of algorithms.
 * At this moment, only the integration with Mbed TLS (and more
 * specifically the PSA Crypto API) is supported.
 *
 * See t_cose_common.h for preprocessor defines to reduce object code
 * and stack use by disabling features.
 *
 * Direct key distribution requires the following steps to be taken:
 *
 * 1. Use t_cose_encrypt_enc0_init() to initialize the
 *    \c t_cose_encrypt_enc_ctx context.
 * 2. Set the CEK with t_cose_encrypt_set_encryption_key().
 * 3. Call t_cose_encrypt_enc_detached() or t_cose_encrypt_enc().
 *    The former API call does not include the ciphertext in the
 *    COSE_Encrypt0 message while the latter API call does.
 * 4. Call t_cose_encrypt_enc_finish() to create the final output.
 *    When subsequently calling QCBOREncode_Finish() the output
 *    can be serialized into a byte string for distribution in an
 *    Internet protocol.
 *
 * HPKE-based key distribution requires more steps, namely:
 *
 * 1. A recipient context has to be created with
 *    t_cose_encrypt_hpke_recipient_init().
 * 2. A CEK has to be generated, for example via the
 *    psa_generate_random() API call, and then set via
 *    t_cose_encrypt_hpke_set_encryption_key().
 * 3. An ephemeral ECDHE key pair has to be generated,
 *    for example via psa_generate_key(), and then assigned
 *    to the recipient context using
 *    t_cose_encrypt_hpke_set_ephemeral_key().
 * 4. The public key of the recipient has to be imported
 *    and assigned to the recipient context via
 *    t_cose_encrypt_hpke_set_recipient_key().
 * 5. Now, the recipient structure can be created with
 *    t_cose_encrypt_hpke_create_recipient(). Using
 *    QCBOREncode_Finish() the recipient structure is
 *    seralized as a byte string.
 * 6. Now an encrypt context is needed, which must be
 *    initialized with t_cose_encrypt_enc_init().
 * 7. The t_cose_encrypt_set_encryption_key() is used to
 *    configure the CEK with the encryption context, which
 *    will subsequently be used to encrypt the plaintext.
 * 8. The t_cose_encrypt_enc_detached() or the 
 *    t_cose_encrypt_enc() functions will be used to
 *    encrypted the plaintext.
 * 9  The t_cose_encrypt_add_recipient() finalizes the
 *    COSE_Encrypt message the recipient structure has to be
 *    attached.
 * 10.t_cose_encrypt_enc_finish() completes the process and
 *    QCBOREncode_Finish() exports the COSE structure as a
 *    binary string for use in Internet protocols.
 *
 * In a nutshell, the steps are:
 *
 * (a) create a recipient structure, which contains the HPKE
 *     parameters,
 * (b) create a encrypt structure and encrypt the plaintext,
 * (c) attach the recipient to the encrypt structure, and
 * (d) wrap the entire encrypt structure (which includes the
 *     recipient structure).
 */


/**
 * An \c option_flag for t_cose_encrypt_enc_init() to use COSE_Encrypt0.
 */
#define T_COSE_OPT_COSE_ENCRYPT0 0x00000001

/**
 * This is the context for creating \c COSE_Encrypt and \c COSE_Encrypt0 structures.
 * The caller should allocate it and pass it to the functions here. This
 * is around 76 bytes, so it fits easily on the stack.
 */
struct t_cose_encrypt_enc_ctx {
    /* Private data structure */
    struct q_useful_buf_c protected_parameters;
    int32_t               cose_algorithm_id;
    uint8_t*              key;
    size_t                key_len;
    uint32_t              option_flags;
    struct q_useful_buf_c kid;
    uint8_t               nonce[T_COSE_ENCRYPTION_MAX_KEY_LENGTH];
    uint8_t               recipients;
};

/**
 * This is the context for creating a recipient structure for use with
 * HPKE. The caller should allocate it and pass it to the functions here.
 * The size of this structure is around 56 bytes.
 */
struct t_cose_encrypt_recipient_hpke_ctx {
    /* Private data structure */
    int32_t               cose_algorithm_id;
    struct q_useful_buf_c kid;
    uint8_t*              cek;
    size_t                cek_len;
    uint32_t              option_flags;
    struct t_cose_key     ephemeral_key;
    struct t_cose_key     recipient_key;
};

/**
 * \brief  Initialize to start creating a \c COSE_Encrypt structure.
 *
 * \param[in,out] context        The t_cose_encrypt_enc_ctx context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX.
 * \param[in] cose_algorithm_id  The algorithm to use for encrypting
 *                               data, for example
 *                               \ref COSE_ALGORITHM_A128GCM.
 *
 * Initializes the \ref t_cose_encrypt_enc_ctx context. No
 * \c option_flags are needed and 0 can be passed. A \c cose_algorithm_id
 * must always be given.
 *
 * The algorithm ID space is from
 * [COSE (RFC8152)](https://tools.ietf.org/html/rfc8152) and the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 * \ref COSE_ALGORITHM_A128GCM and a few others are defined here for
 * convenience. The supported algorithms depend on the
 * cryptographic library that t_cose is integrated with.
 */
static void
t_cose_encrypt_enc_init( struct t_cose_encrypt_enc_ctx* context,
                         uint32_t                       option_flags,
                         int32_t                        cose_algorithm_id);

/**
 * \brief  Initialize to start creating a \c COSE_Encrypt0 structure.
 *
 * \param[in,out] context            The t_cose_encrypt_enc_ctx context.
 * \param[in] option_flags           One of \c T_COSE_OPT_XXXX.
 * \param[in] cose_algorithm_id      The algorithm to use for encrypting
 *                                   data, for example
 *                                   \ref COSE_ALGORITHM_A128GCM.
 * \param[in] kid                    The key identifier.
 *
 * Initializes the \ref t_cose_encrypt_enc_ctx context. No
 * \c option_flags are needed and 0 can be passed. A \c cose_algorithm_id
 * must always be given.
 *
 * The algorithm ID space is from
 * [COSE (RFC8152)](https://tools.ietf.org/html/rfc8152) and the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 * \ref COSE_ALGORITHM_A128GCM and a few others are defined here for
 * convenience. The supported algorithms depend on the
 * cryptographic library that t_cose is integrated with.
 */
static void
t_cose_encrypt_enc0_init( struct t_cose_encrypt_enc_ctx* context,
                          uint32_t                       option_flags,
                          int32_t                        cose_algorithm_id,
                          struct q_useful_buf_c          kid);

/**
 * \brief  Initialize a recipient structure for use with HPKE.
 *
 * \param[in, out] context       The t_cose_encrypt_recipient_hpke_ctx context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX.
 * \param[in] cose_algorithm_id  the HPKE algorithm, for example
 *                               \ref COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM.
 *
 */
static void
t_cose_encrypt_hpke_recipient_init( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                    uint32_t                                  option_flags,
                                    int32_t                                   cose_algorithm_id);

/**
 * \brief  Set the ephemeral public key for use with HPKE.
 *
 * \param[in, out] context  The t_cose_encrypt_recipient_hpke_ctx context.
 * \param[in] t_cose_key    The ephemeral public key.
 */
static void
t_cose_encrypt_hpke_set_ephemeral_key( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                       struct t_cose_key                         ephemeral_key);

/**
 * \brief  Set the recipient public key for use with HPKE.
 *
 * \param[in,out] context      The t_cose_encrypt_recipient_hpke_ctx context.
 * \param[in] t_cose_key       The ephemeral public key.
 * \param[in] kid              The key identifier.
 */
static void
t_cose_encrypt_hpke_set_recipient_key( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                       struct t_cose_key                         recipient_key,
                                       struct q_useful_buf_c                     kid);

/**
 * \brief  Set the content encryption key (CEK). For use with this implementation, the
 * CEK is the plaintext input to the HPKE algorithm. More details can be found at
 * https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/.
 *
 * \param[in, out] context   The t_cose_encrypt_recipient_hpke_ctx context.
 * \param[in] cek            The CEK.
 * \param[in] cek_len        The length of the CEK.
 */
static void
t_cose_encrypt_hpke_set_encryption_key( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                        uint8_t*                                  cek,
                                        size_t                                    cek_len);

/**
 * \brief Creates a COSE recipient structure by populating the fields following the
 *  COSE HPKE specification, see https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/.
 *
 * \param[in, out] context      The t_cose_encrypt_recipient_hpke_ctx context.
 * \param[in, out] EC           The COSE-coded recpient structure.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 */
enum t_cose_err_t
t_cose_encrypt_hpke_create_recipient( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                      QCBOREncodeContext*                       EC);

/**
 * \brief Adds recipient structure to COSE_Encrypt.
 *
 * \param[in, out] context        The t_cose_encrypt_enc_ctx context.
 * \param[in] encrypt_ctx         The COSE_Encrypt structure.
 * \param[in] recipient_ctx       The COSE-coded recpient structure.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 */
enum t_cose_err_t
t_cose_encrypt_add_recipient( struct t_cose_encrypt_enc_ctx* context,
                              QCBOREncodeContext*            encrypt_ctx,
                              UsefulBufC*                    recipient_ctx);

/**
 * \brief Sets the content encryption key (CEK)
 *
 * \param[in,out] context    The t_cose_encrypt_enc_ctx context.
 * \param[in] cek            The CEK.
 * \param[in] cek_len        The CEK length.
 *
 * Note: When applied to a COSE_Encrypt0 structure this call will lead
 * to an error since COSE_Encrypt0 does not contain recipient information.
 */
static void
t_cose_encrypt_set_encryption_key( struct t_cose_encrypt_enc_ctx* context,
                                   uint8_t*                       cek,
                                   size_t                         cek_len);

/**
 * \brief  Create a \c COSE_Encrypt or \c COSE_Encrypt0 structure,
*  encrypt the provided plaintext and integrate the ciphertext into
*  the resulting COSE structure.
 *
 * \param[in] context             The t_cose_encrypt_enc_ctx context.
 * \param[in,out] encrypt_ctx     COSE encryption structure.
 * \param[in] payload             Plaintext.
 * \param[out] encrypted_payload  Ciphertext.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 */
enum t_cose_err_t
t_cose_encrypt_enc( struct t_cose_encrypt_enc_ctx*            context,
                    QCBOREncodeContext*                       encrypt_ctx,
                    struct q_useful_buf_c                     payload,
                    struct q_useful_buf_c                     encrypted_payload
                  );


/**
 * \brief  Create a \c COSE_Encrypt or \c COSE_Encrypt0 structure
 *  and encrypt the provided plaintext. The ciphertext is not included
 *  in the resulting COSE structure but has to be conveyed separately.
 *
 * \param[in] context                  The t_cose_encrypt_enc_ctx context.
 * \param[in,out] encrypt_ctx          COSE encryption structure.
 * \param[in] detached_payload         Plaintext.
 * \param[out] encrypted_payload       Ciphertext.
 * \param[out] encrypted_payload_size  Ciphertext length.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 */
enum t_cose_err_t
t_cose_encrypt_enc_detached( struct t_cose_encrypt_enc_ctx*            context,
                             QCBOREncodeContext*                       encrypt_ctx,
                             struct q_useful_buf_c                     detached_payload,
                             struct q_useful_buf_c                     encrypted_payload,
                             size_t*                                   encrypted_payload_size
                           );

/**
 * \brief  Finishes the computation of the \c COSE_Encrypt or
 * \c COSE_Encrypt0 structure.
 *
 * \param[in] context                   The t_cose_encrypt_enc_ctx context.
 * \param[in,out] encrypt_ctx           COSE encryption structure.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 */
enum t_cose_err_t
t_cose_encrypt_enc_finish( struct t_cose_encrypt_enc_ctx* context,
                           QCBOREncodeContext*            encrypt_ctx);

/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */
static inline void
t_cose_encrypt_enc_init( struct t_cose_encrypt_enc_ctx* context,
                         uint32_t                       option_flags,
                         int32_t                        cose_algorithm_id
                       )
{
    memset(context, 0, sizeof(*context));
    context->cose_algorithm_id = cose_algorithm_id;
    context->option_flags = option_flags;
    context->recipients = 0;
}

static void
t_cose_encrypt_enc0_init( struct t_cose_encrypt_enc_ctx* context,
                          uint32_t                       option_flags,
                          int32_t                        cose_algorithm_id,
                          struct q_useful_buf_c          kid
                        )
{

    memset(context, 0, sizeof(*context));
    context->cose_algorithm_id = cose_algorithm_id;
    context->option_flags = option_flags;
    context->recipients = 0;
    memcpy(&context->kid, &kid, sizeof(struct q_useful_buf_c));
}

static inline void
t_cose_encrypt_hpke_recipient_init( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                    uint32_t                                  option_flags,
                                    int32_t                                   cose_algorithm_id
                                  )
{
    memset(context, 0, sizeof(*context));
    context->cose_algorithm_id = cose_algorithm_id;
    context->option_flags = option_flags;
}

static inline void
t_cose_encrypt_hpke_set_ephemeral_key( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                       struct t_cose_key                         ephemeral_key
                                     )
{
    context->ephemeral_key = ephemeral_key;
}

static inline void
t_cose_encrypt_hpke_set_recipient_key( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                       struct t_cose_key                         recipient_key,
                                       struct q_useful_buf_c                     kid
                                     )
{
    context->recipient_key = recipient_key;
    context->kid = kid;
}

static inline void
t_cose_encrypt_hpke_set_encryption_key( struct t_cose_encrypt_recipient_hpke_ctx* context,
                                        uint8_t*                                  cek,
                                        size_t                                    cek_len
                                      )
{
    context->cek = cek;
    context->cek_len = cek_len;
}

static inline void
t_cose_encrypt_set_encryption_key( struct t_cose_encrypt_enc_ctx*            context,
                                   uint8_t*                                  cek,
                                   size_t                                    cek_len
                                 )
{
    context->key = cek;
    context->key_len = cek_len;
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_ENCRYPT_ENC_H__ */
