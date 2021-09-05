/*
 * t_cose_crypto.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_CRYPTO_H__
#define __T_COSE_CRYPTO_H__

#include <stdint.h>
#include <stdbool.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_standard_constants.h"

#ifdef __cplusplus
extern "C" {
#endif




/**
 * \file t_cose_crypto.h
 *
 * \brief This defines the adaptation layer for cryptographic
 * functions needed by t_cose.
 *
 * This is  small wrapper around the cryptographic functions to:
 * - Map COSE algorithm IDs to cryptographic library IDs
 * - Map cryptographic library errors to \ref t_cose_err_t errors
 * - Have inputs and outputs be \c struct \c q_useful_buf_c and
 *   \c struct \c q_useful_buf
 * - Handle key selection
 *
 * An implementation must be made of these functions
 * for the various cryptographic libraries that are used on
 * various platforms and OSs. The functions are:
 *   - t_cose_t_crypto_sig_size()
 *   - t_cose_crypto_pub_key_sign()
 *   - t_cose_crypto_pub_key_verify()
 *   - t_cose_crypto_hash_start()
 *   - t_cose_crypto_hash_update()
 *   - t_cose_crypto_hash_finish()
 *
 * This runs entirely off of COSE-style algorithm identifiers.  They
 * are simple integers and thus work nice as function parameters. An
 * initial set is defined by [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152). New ones can be registered
 * in the [IANA COSE Registry]
 * (https://www.iana.org/assignments/cose/cose.xhtml). Local use new
 * ones can also be defined (\c \#define) if what is needed is not in
 * the IANA registry.
 *
 * \anchor useful_buf_use
 * Binary data is returned to the caller using a \c struct \c
 * q_useful_buf to pass the buffer to receive the data and its length in
 * and a \c q_useful_buf_c to return the pointer and length of the
 * returned data. The point of this is coding hygiene. The buffer
 * passed in is not const as it is to be modified.  The \c
 * q_useful_buf_c returned is const. The lengths of buffers are
 * handled in a clear, consistent and enforced manner.
 *
 * The pointer in the \c q_useful_buf_c will always point to the
 * buffer passed in via the \c q_useful_buf so the lifetime of the
 * data is under control of the caller.
 *
 * This is not intended as any sort of general cryptographic API. It
 * is just the functions needed by t_cose in the form that is most
 * useful for t_cose.
 *
 * No other file in t_cose should need modification for new algorithms,
 * new key types and sizes or the integration of cryptographic libraries
 * except on some occasions, this file as follows:
 *
 * - Support for a new COSE_ALGORITHM_XXX signature algorithm
 *    - See t_cose_algorithm_is_ecdsa()
 *    - If not ECDSA add another function like t_cose_algorithm_is_ecdsa()
 * - Support for a new COSE_ALGORITHM_XXX signature algorithm is added
 *    - See \ref T_COSE_CRYPTO_MAX_HASH_SIZE for additional hashes
 * - Support larger key sizes (and thus signature sizes)
 *    - See \ref T_COSE_MAX_SIG_SIZE
 * - Support another hash implementation that is not a service
 *    - See struct \ref t_cose_crypto_hash
 *
 * To reduce stack usage and save a little code these can be defined.
 *    - T_COSE_DISABLE_ES384
 *    - T_COSE_DISABLE_ES512
 *
 * The actual code that implements these hashes in the crypto library may
 * or may not be saved with these defines depending on how the library
 * works, whether dead stripping of object code is on and such.
 */




#define T_COSE_EC_P256_SIG_SIZE 64  /* size for secp256r1 */
#define T_COSE_EC_P384_SIG_SIZE 96  /* size for secp384r1 */
#define T_COSE_EC_P512_SIG_SIZE 132 /* size for secp521r1 */


/**
 * There is a stack variable to hold the output of the signing
 * operation.  This sets the maximum signature size this code can
 * handle based on the COSE algorithms configured. The size of the
 * signature goes with the size of the key, not the algorithm, so a
 * key could be given for signing or verification that is larger than
 * this. However, it is not typical to do so. If the key or signature
 * is too large the failure will be graceful with an error.
 *
 * For ECDSA the signature format used is defined in RFC 8152 section
 * 8.1. It is the concatenation of r and s, each of which is the key
 * size in bits rounded up to the nearest byte.  That is twice the key
 * size in bytes.
 */
#ifndef T_COSE_DISABLE_ES512
    #define T_COSE_MAX_SIG_SIZE T_COSE_EC_P512_SIG_SIZE
#else
    #ifndef T_COSE_DISABLE_ES384
        #define T_COSE_MAX_SIG_SIZE T_COSE_EC_P384_SIG_SIZE
    #else
        #define T_COSE_MAX_SIG_SIZE T_COSE_EC_P256_SIG_SIZE
    #endif
#endif




/**
 * \brief Returns the size of a signature given the key and algorithm.
 *
 * \param[in] cose_algorithm_id  The algorithm ID
 * \param[in] signing_key        Key to compute size of
 * \param[out] sig_size          The returned size in bytes.
 *
 * \return An error code or \ref T_COSE_SUCCESS.
 *
 * This is used the caller wishes to compute the size of a token in
 * order to allocate memory for it.
 *
 * The size of a signature depends primarily on the key size but it is
 * usually necessary to know the algorithm too.
 *
 * This always returns the exact size of the signature.
 */
enum t_cose_err_t
t_cose_crypto_sig_size(int32_t            cose_algorithm_id,
                       struct t_cose_key  signing_key,
                       size_t            *sig_size);


/**
 * \brief Perform public key signing. Part of the t_cose crypto
 * adaptation layer.
 *
 * \param[in] cose_algorithm_id The algorithm to sign with. The IDs are
 *                              defined in [COSE (RFC 8152)]
 *                              (https://tools.ietf.org/html/rfc8152) or
 *                              in the [IANA COSE Registry]
 *                              (https://www.iana.org/assignments/cose/cose.xhtml).
 *                              A proprietary ID can also be defined
 *                              locally (\c \#define) if the needed
 *                              one hasn't been registered.
 * \param[in] signing_key       Indicates or contains key to sign with.
 * \param[in] hash_to_sign      The bytes to sign. Typically, a hash of
 *                              a payload.
 * \param[in] signature_buffer  Pointer and length of buffer into which
 *                              the resulting signature is put.
 * \param[in] signature         Pointer and length of the signature
 *                              returned.
 * \param[in] started           If this pointer is not NULL, restartable
 *                              operation is requested by the caller. if the
 *                              value pointed by the pointer is False, that this
 *                              is the first call of a signing operation. If it
 *                              is true, this is a subsequent call. If the
 *                              pointer is null, then one step signing is
 *                              expected.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully created the signature.
 * \retval T_COSE_ERR_SIG_BUFFER_SIZE
 *         The \c signature_buffer too small.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         The requested signing algorithm, \c cose_algorithm_id, is not
 *         supported.
 * \retval T_COSE_ERR_UNKNOWN_KEY
 *         The key identified by \c key_select was not found.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key was found, but it was the wrong type.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Some (unspecified) argument was not valid.
 * \retval T_COSE_ERR_INSUFFICIENT_MEMORY
 *         Insufficient heap memory.
 * \retval T_COSE_ERR_FAIL
 *         General unspecific failure.
 * \retval T_COSE_ERR_TAMPERING_DETECTED
 *         Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED.
 * \retval T_COSE_ERR_SIGN_RESTART_NOT_SUPPORTED
 *         Restartable signing is not implemented.
 *
 * This is called to do public key signing. The implementation will
 * vary from one platform / OS to another but should conform to the
 * description here.
 *
 * The contents of signing_key is usually the type that holds
 * a key for the cryptographic library.
 *
 * See the note in the Detailed Description (the \\file comment block)
 * for details on how \c q_useful_buf and \c q_useful_buf_c are used
 * to return the signature.
 *
 * To find out the size of the signature buffer needed, call this with
 * \c signature_buffer->ptr \c NULL and \c signature_buffer->len a
 * very large number like \c UINT32_MAX. The size will be returned in
 * \c signature->len.
 */
enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   void                  *crypto_context,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature,
                   const bool            *started);


/**
 * \brief Perform public key signature verification. Part of the
 * t_cose crypto adaptation layer.
 *
 * \param[in] cose_algorithm_id The algorithm to use for verification.
 *                              The IDs are defined in [COSE (RFC 8152)]
 *                              (https://tools.ietf.org/html/rfc8152)
 *                              or in the [IANA COSE Registry]
 *                       (https://www.iana.org/assignments/cose/cose.xhtml).
 *                              A proprietary ID can also be defined
 *                              locally (\c \#define) if the needed one
 *                              hasn't been registered.
 * \param[in] verification_key  The verification key to use.
 * \param[in] kid               The COSE kid (key ID) or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] hash_to_verify    The data or hash that is to be verified.
 * \param[in] signature         The COSE-format signature.
 *
 * This verifies that the \c signature passed in was over the \c
 * hash_to_verify passed in.
 *
 * The public key used to verify the signature is selected by the \c
 * kid if it is not \c NULL_Q_USEFUL_BUF_C or the \c key_select if it
 * is.
 *
 * The key selected must be, or include, a public key of the correct
 * type for \c cose_algorithm_id.
 *
 * \retval T_COSE_SUCCESS
 *         The signature is valid
 * \retval T_COSE_ERR_SIG_VERIFY
 *         Signature verification failed. For example, the
 *         cryptographic operations completed successfully but hash
 *         wasn't as expected.
 * \retval T_COSE_ERR_UNKNOWN_KEY
 *         The key identified by \c key_select or a \c kid was
 *         not found.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key was found, but it was the wrong type
 *         for the operation.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         The requested signing algorithm is not supported.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Some (unspecified) argument was not valid.
 * \retval T_COSE_ERR_INSUFFICIENT_MEMORY
 *         Out of heap memory.
 * \retval T_COSE_ERR_FAIL
 *         General unspecific failure.
 * \retval T_COSE_ERR_TAMPERING_DETECTED
 *         Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED.
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t               cose_algorithm_id,
                     struct t_cose_key     verification_key,
                     void                  *crypto_context,
                     struct q_useful_buf_c kid,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature);


/**
 * \brief Start cryptographic hash. Part of the t_cose crypto
 * adaptation layer.
 *
 * \param[in,out] hash_ctx      Pointer to the hash context that
 *                              will be initialized.
 * \param[in] cose_hash_alg_id  Algorithm ID that identifies the
 *                              hash to use. This is from the
 *                              [IANA COSE Registry]
 *                          (https://www.iana.org/assignments/cose/cose.xhtml)
 *
 * \retval T_COSE_ERR_UNSUPPORTED_HASH
 *         The requested algorithm is unknown or unsupported.
 *
 * \retval T_COSE_ERR_HASH_GENERAL_FAIL
 *         Some general failure of the hash function
 *
 * \retval T_COSE_SUCCESS
 *         Success.
 *
 * This initializes the hash context for the particular algorithm. It
 * must be called first. A \c hash_ctx can be reused if it is
 * reinitialized.
 *
 * \ref T_COSE_INVALID_ALGORITHM_ID may be passed to this function, in which
 * case \ref T_COSE_ERR_UNSUPPORTED_HASH must be returned.
 *
 * Other errors can be returned and will usually be propagated up, but hashes
 * generally don't fail so it is suggested not to bother (and to reduce
 * object code size for mapping errors).
 */
enum t_cose_err_t
t_cose_crypto_hash_start(void                      *crypto_context,
                         int32_t                    cose_hash_alg_id);


/**
 * \brief Feed data into a cryptographic hash. Part of the t_cose
 * crypto adaptation layer.
 *
 * \param[in,out] hash_ctx  Pointer to the hash context in which
 *                          accumulate the hash.
 * \param[in]  data_to_hash Pointer and length of data to feed into
 *                          hash. The pointer may by \c NULL in which
 *                          case no hashing is performed.
 *
 * There is no return value. If an error occurs it is remembered in \c
 * hash_ctx and returned when t_cose_crypto_hash_finish() is called.
 * Once in the error state, this function may be called, but it will
 * not do anything.
 *
 * This function can be called with \c data_to_hash.ptr NULL and it
 * will pretend to hash. This allows the same code that is used to
 * produce the real hash to be used to return a length of the would-be
 * hash for encoded data structure size calculations.
 */
void t_cose_crypto_hash_update(void                      *crypto_context,
                               struct q_useful_buf_c      data_to_hash);


/**
 * \brief Finish a cryptographic hash. Part of the t_cose crypto
 * adaptation layer.
 *
 * \param[in,out] hash_ctx           Pointer to the hash context.
 * \param[in] buffer_to_hold_result  Pointer and length into which
 *                                   the resulting hash is put.
 * \param[out] hash_result           Pointer and length of the
 *                                   resulting hash.
 *
 * \retval T_COSE_ERR_HASH_GENERAL_FAIL
 *         Some general failure of the hash function.
 * \retval T_COSE_ERR_HASH_BUFFER_SIZE
 *         The size of the buffer to hold the hash result was
 *         too small.
 * \retval T_COSE_SUCCESS
 *         Success.
 *
 * Call this to complete the hashing operation. If the everything
 * completed correctly, the resulting hash is returned. Note that any
 * errors that occurred during t_cose_crypto_hash_update() are
 * returned here.
 *
 * See \ref useful_buf_use for details on how \c q_useful_buf and
 * \c q_useful_buf_c are used to return the hash.
 *
 * Other errors can be returned and will usually be propagated up, but
 * hashes generally don't fail so it is suggested not to bother (and
 * to reduce object code size for mapping errors).
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(void                      *crypto_context,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result);



/**
 * \brief Indicate whether a COSE algorithm is ECDSA or not.
 *
 * \param[in] cose_algorithm_id    The algorithm ID to check.
 *
 * \returns This returns \c true if the algorithm is ECDSA and \c false if not.
 *
 * This is a convenience function to check whether a given
 * integer COSE algorithm ID uses the ECDSA signing algorithm
 * or not.
 *
 * (As other types of signing algorithms are added, RSA for example,
 * a similar function can be added for them.)
 */
static bool
t_cose_algorithm_is_ecdsa(int32_t cose_algorithm_id);




/*
 * Inline implementations. See documentation above.
 */

/**
 * \brief Look for an integer in a zero-terminated list of integers.
 *
 * \param[in] cose_algorithm_id    The algorithm ID to check.
 * \param[in] list                 zero-terminated list of algorithm IDs.
 *
 * \returns This returns \c true if an integer is in the list, \c false if not.
 *
 * Used to implement t_cose_algorithm_is_ecdsa() and in the future
 * _is_rsa() and such.
 *
 * Typically used once in the crypto adaptation layer, so defining it
 * inline rather than in a .c file is OK and saves creating a whole
 * new .c file just for this.
 */
static inline bool
t_cose_check_list(int32_t cose_algorithm_id, const int32_t *list)
{
    while(*list) {
        if(*list == cose_algorithm_id) {
            return true;
        }
        list++;
    }

    return false;
}

static inline bool
t_cose_algorithm_is_ecdsa(int32_t cose_algorithm_id)
{
    /* The simple list of COSE alg IDs that use ECDSA */
    static const int32_t ecdsa_list[] = {
        COSE_ALGORITHM_ES256,
#ifndef T_COSE_DISABLE_ES384
        COSE_ALGORITHM_ES384,
#endif
#ifndef T_COSE_DISABLE_ES512
        COSE_ALGORITHM_ES512,
#endif
        0}; /* 0 is a reserved COSE alg ID ans will never be used */

    return t_cose_check_list(cose_algorithm_id, ecdsa_list);
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_CRYPTO_H__ */
