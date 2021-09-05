/*
 * t_cose_mbedtls_crypto.c
 *
 * Copyright 2019, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

/**
 * \file t_cose_mbedtls_crypto.c
 *
 * \brief Crypto Adaptation for t_cose to use Mbed TLS's ECDSA and hashes.
 *
 * This connects up the abstract interface in t_cose_crypto.h to the
 * implementations of ECDSA signing and hashing in Mbed TLS library.
 *
 * This adapter layer doesn't bloat the implementation as everything
 * here had to be done anyway -- the mapping of algorithm IDs, the
 * data format rearranging, the error code translation.
 *
 * This code should just work out of the box if compiled and linked
 * against Mbed TLS. No preprocessor #defines are needed.
 *
 * You can disable SHA-384 and SHA-512 to save code and space by
 * defining T_COSE_DISABLE_ES384 or T_COSE_DISABLE_ES512. This saving
 * is most in stack space in the main t_cose implementation. (It seems
 * likely that changes to Mbed TLS itself would be needed to remove the
 * SHA-384 and SHA-512 implementations to save that code. Lack of
 * reference and dead stripping the executable won't do it).
 */

#include "t_cose_crypto.h"  /* The interface this implements */

#include "mbedtls/md.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha256.h"
#include "mbedtls/asn1.h"
#include "mbedtls/ecdsa.h"
#include <mbedtls/entropy.h>
#include <mbedtls/hmac_drbg.h>


/* Avoid compiler warning due to unused argument */
#define ARG_UNUSED(arg) (void)(arg)


/**
 * \brief Returns whether the COSE signing algorithm ID is an ECDSA algorithm.
 *
 * If the algorithm is not ECDSA, the out parameters are not set.
 *
 * \param[in]  cose_algorithm_id  The COSE algorithm ID.
 * \param[out] md_alg             The hash algorithm ID for this signing alg.
 *
 * \return 1 if the algorithm is ECDSA, 0 otherwise.
 */
static int is_ecdsa_algorithm(int32_t cose_algorithm_id, int *md_alg)
{
    switch (cose_algorithm_id) {
    case COSE_ALGORITHM_ES256:
        *md_alg = MBEDTLS_MD_SHA256;
        return 1;
    case COSE_ALGORITHM_ES384:
        *md_alg = MBEDTLS_MD_SHA384;
        return 1;
    case COSE_ALGORITHM_ES512:
        *md_alg = MBEDTLS_MD_SHA512;
        return 1;
    default:
        return 0;
    }
}


static enum t_cose_err_t mbedtls_err_to_t_cose_error_signing(int err)
{
    return
      err == 0                                ? T_COSE_SUCCESS :
      err == MBEDTLS_ERR_ECP_BAD_INPUT_DATA   ? T_COSE_ERR_INVALID_ARGUMENT :
      err == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL ? T_COSE_ERR_SIG_BUFFER_SIZE :
      err == MBEDTLS_ERR_ECP_VERIFY_FAILED    ? T_COSE_ERR_SIG_VERIFY :
      err == MBEDTLS_ERR_ECP_ALLOC_FAILED     ? T_COSE_ERR_INSUFFICIENT_MEMORY :
      err == MBEDTLS_ERR_MPI_BAD_INPUT_DATA   ? T_COSE_ERR_INVALID_ARGUMENT :
      err == MBEDTLS_ERR_MPI_ALLOC_FAILED     ? T_COSE_ERR_INSUFFICIENT_MEMORY :
      err == MBEDTLS_ERR_ASN1_ALLOC_FAILED    ? T_COSE_ERR_INSUFFICIENT_MEMORY :
                                                T_COSE_ERR_SIG_FAIL;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t               cose_algorithm_id,
                     struct t_cose_key     verification_key,
                     struct q_useful_buf_c kid,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature)
{
    int md_alg;
    int ret;
    enum t_cose_err_t return_value = T_COSE_ERR_SIG_VERIFY;
    mbedtls_ecp_keypair *ecp_keypair =
        (mbedtls_ecp_keypair *)verification_key.k.key_ptr;
    mbedtls_mpi r, s;
    size_t curve_bytes = (ecp_keypair->MBEDTLS_PRIVATE(grp).pbits + 7) / 8;

    /* This implementation does no look up keys by kid in the key
     * store
     */
    ARG_UNUSED(kid);

    /* This implementation supports ECDSA and only ECDSA. The
     * interface allows it to support other, but none are implemented.
     * This implementation works for different keys lengths and
     * curves. That is the curve and key length as associated with the
     * signing_key passed in, not the cose_algorithm_id. This check
     * looks for ECDSA signing as indicated by COSE and rejects what
     * is not.
     */
    if (!is_ecdsa_algorithm(cose_algorithm_id, &md_alg)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (signature.len != 2 * curve_bytes) {
        return_value = T_COSE_ERR_INVALID_ARGUMENT;
        goto cleanup;
    }

    ret = mbedtls_mpi_read_binary(&r,
                                  signature.ptr,
                                  curve_bytes);
    if (ret) {
        return_value = mbedtls_err_to_t_cose_error_signing(ret);
        goto cleanup;
    }
    ret = mbedtls_mpi_read_binary(&s,
                                 (unsigned char *)(signature.ptr) + curve_bytes,
                                 curve_bytes);
    if (ret) {
        return_value = mbedtls_err_to_t_cose_error_signing(ret);
        goto cleanup;
    }

    /* Check whether the public part is loaded. If not, load it. */
    if (mbedtls_ecp_is_zero(&ecp_keypair->MBEDTLS_PRIVATE(Q))) {
        return_value = T_COSE_ERR_WRONG_TYPE_OF_KEY;
        goto cleanup;
    }

    ret = mbedtls_ecdsa_verify(&ecp_keypair->MBEDTLS_PRIVATE(grp),
                               hash_to_verify.ptr,
                               hash_to_verify.len,
                               &ecp_keypair->MBEDTLS_PRIVATE(Q), &r, &s);
    if (ret) {
        return_value = mbedtls_err_to_t_cose_error_signing(ret);
        goto cleanup;
    }

    return_value = T_COSE_SUCCESS;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

Done:
    return return_value;
}

enum t_cose_err_t
t_cose_crypto_sign_internal(
                   int32_t                    cose_algorithm_id,
                   struct t_cose_key          signing_key,
                   struct q_useful_buf_c      hash_to_sign,
                   struct q_useful_buf        signature_buffer,
                   struct q_useful_buf_c     *signature,
                   mbedtls_ecdsa_context     *ecdsa_context,
                   mbedtls_ecdsa_restart_ctx *ecdsa_rst_ctx,
                   bool                      *started)
{
    enum t_cose_err_t return_value = T_COSE_ERR_FAIL;
    mbedtls_ecp_keypair *ecp_keypair =
        (mbedtls_ecp_keypair *)signing_key.k.key_ptr;
    Q_USEFUL_BUF_MAKE_STACK_UB(asn1_signature, MBEDTLS_ECDSA_MAX_LEN);
    size_t required_sign_buf_size;
    int md_alg;
    unsigned char *p = asn1_signature.ptr;
    unsigned char *end;
    int ret;
    size_t len;
    const mbedtls_md_info_t *md_info;
    mbedtls_entropy_context entropy_ctx;
    mbedtls_hmac_drbg_context drbg_ctx;

    mbedtls_mpi r, s;

    size_t curve_bytes = (ecp_keypair->MBEDTLS_PRIVATE(grp).pbits + 7) / 8;

    /* This implementation supports ECDSA and only ECDSA. The
     * interface allows it to support other, but none are implemented.
     * This implementation works for different keys lengths and
     * curves. That is the curve and key length as associated with the
     * signing_key passed in, not the cose_algorithm_id. This check
     * looks for ECDSA signing as indicated by COSE and rejects what
     * is not.
     */
    if (!is_ecdsa_algorithm(cose_algorithm_id, &md_alg)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if (t_cose_crypto_sig_size(cose_algorithm_id,
                                signing_key,
                                &required_sign_buf_size)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if (signature_buffer.len < required_sign_buf_size) {
        return_value = T_COSE_ERR_SIG_BUFFER_SIZE;
        goto Done;
    }

    /* Initialize a local PRNG context */
    mbedtls_entropy_init(&entropy_ctx);
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hmac_drbg_init(&drbg_ctx);
    ret = mbedtls_hmac_drbg_seed(&drbg_ctx,
                                md_info,
                                mbedtls_entropy_func,
                                &entropy_ctx,
                                NULL, 0);
    if (ret != 0) {
        return_value = mbedtls_err_to_t_cose_error_signing(ret);
        goto Done;
    }

    if (started) {
#ifdef MBEDTLS_ECP_RESTARTABLE
        if (*started) {
            goto Sign_restartable;
        }
        /* No need to set the started flag to true as it is done in the general
         * implementation.
         */
#else
    return T_COSE_ERR_SIGN_RESTART_NOT_SUPPORTED;
#endif
    }

    /* Do the signing */
    mbedtls_ecdsa_init(ecdsa_context);
#ifdef MBEDTLS_ECP_RESTARTABLE
    if (started) { /* non-null 'started' pointer means restartable behaviour */
        mbedtls_ecdsa_restart_init(ecdsa_rst_ctx);
    }
#endif
    ret = mbedtls_ecdsa_from_keypair(ecdsa_context, ecp_keypair);
    if (ret != 0) {
        return_value = mbedtls_err_to_t_cose_error_signing(ret);
        goto Done;
    }

#ifdef MBEDTLS_ECP_RESTARTABLE
    if (started) { /* non-null 'started' pointer means restartable behaviour */
Sign_restartable:
        ret = mbedtls_ecdsa_write_signature_restartable(ecdsa_context,
            md_alg,
            hash_to_sign.ptr,
            hash_to_sign.len,
            asn1_signature.ptr,
            asn1_signature.len,
            &asn1_signature.len,
            mbedtls_hmac_drbg_random,
            &drbg_ctx,
            ecdsa_rst_ctx);

        if (ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
            return_value = T_COSE_ERR_SIG_IN_PROGRESS;
            goto Done;
        }
    } else
#endif /* MBEDTLS_ECP_RESTARTABLE */
    {
        ret = mbedtls_ecdsa_write_signature(ecdsa_context,
            md_alg,
            hash_to_sign.ptr,
            hash_to_sign.len,
            asn1_signature.ptr,
            asn1_signature.len,
            &asn1_signature.len,
            mbedtls_hmac_drbg_random,
            &drbg_ctx);
    }

    if (ret != 0) {
        return_value = mbedtls_err_to_t_cose_error_signing(ret);
        goto Done;
    }

    /* Extract r and s from ASN1 format */
    end = p + asn1_signature.len;
    ret = mbedtls_asn1_get_tag(&p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if (p + len != end) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if ((ret = mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
        (ret = mbedtls_asn1_get_mpi(&p, end, &s)) != 0) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        goto Done;
    }

    mbedtls_mpi_write_binary(&r, signature_buffer.ptr, curve_bytes);
    mbedtls_mpi_write_binary(&s, (unsigned char *)signature_buffer.ptr +
                                 curve_bytes, curve_bytes);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

#ifdef MBEDTLS_ECP_RESTARTABLE
    if (started) { /* non-null 'started' pointer means restartable behaviour */
        (void)mbedtls_ecdsa_restart_free(ecdsa_rst_ctx);
    }
#endif
    (void)mbedtls_ecdsa_free(ecdsa_context);

    return_value = T_COSE_SUCCESS;

Done:
    mbedtls_hmac_drbg_free(&drbg_ctx);

    /* Success, fill in the return useful_buf's ptr */
    if (return_value == T_COSE_SUCCESS) {
        signature->ptr = signature_buffer.ptr;
        signature->len = curve_bytes * 2;
    }

    return return_value;
}

/* Wrap the internal signing function, so that no duplicate memory is allocated
 * on the stack if restart context is provided.
 */
#ifdef MBEDTLS_ECP_RESTARTABLE
static enum t_cose_err_t
t_cose_crypto_sign_with_context(int32_t                cose_algorithm_id,
                                struct t_cose_key      signing_key,
                                struct q_useful_buf_c  hash_to_sign,
                                struct q_useful_buf    signature_buffer,
                                struct q_useful_buf_c *signature,
                                struct t_cose_crypto_backend_ctx *crypto_ctx,
                                bool                  *started)
{
    return t_cose_crypto_sign_internal(cose_algorithm_id,
                                signing_key,
                                hash_to_sign,
                                signature_buffer,
                                signature,
                                &(crypto_ctx->ecdsa_ctx),
                                &(crypto_ctx->ecdsa_rst_ctx),
                                started);
}
#endif /* MBEDTLS_ECP_RESTARTABLE */

static enum t_cose_err_t
t_cose_crypto_sign_without_context(int32_t                cose_algorithm_id,
                                   struct t_cose_key      signing_key,
                                   struct q_useful_buf_c  hash_to_sign,
                                   struct q_useful_buf    signature_buffer,
                                   struct q_useful_buf_c *signature,
                                   struct t_cose_crypto_backend_ctx *crypto_ctx,
                                   bool                  *started)
{
    mbedtls_ecdsa_context ecdsa_context;
    return t_cose_crypto_sign_internal(cose_algorithm_id,
                                signing_key,
                                hash_to_sign,
                                signature_buffer,
                                signature,
                                &ecdsa_context,
                                NULL,
                                started);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature,
                   struct t_cose_crypto_backend_ctx *crypto_ctx,
                   bool                  *started)
{
#ifdef MBEDTLS_ECP_RESTARTABLE
    if (started) {
        return t_cose_crypto_sign_with_context(cose_algorithm_id,
                                               signing_key,
                                               hash_to_sign,
                                               signature_buffer,
                                               signature,
                                               crypto_ctx,
                                               started);
    } else
#endif /* MBEDTLS_ECP_RESTARTABLE */
    {
        return t_cose_crypto_sign_without_context(cose_algorithm_id,
                                                  signing_key,
                                                  hash_to_sign,
                                                  signature_buffer,
                                                  signature,
                                                  crypto_ctx,
                                                  started);
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_sig_size(int32_t           cose_algorithm_id,
                                         struct t_cose_key signing_key,
                                         size_t           *sig_size)
{
    if (!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    mbedtls_ecp_keypair *ecp_keypair = signing_key.k.key_ptr;
    size_t curve_bytes = (ecp_keypair->MBEDTLS_PRIVATE(grp).pbits + 7) / 8;
    *sig_size = curve_bytes * 2;
    return T_COSE_SUCCESS;
}


/**
 * \brief Map a Mbed TLS error into a t_cose error for hashes.
 *
 * \param[in] error   The Mbed TLS error.
 *
 * \return The \ref t_cose_err_t.
 */
static enum t_cose_err_t
mbedtls_status_to_t_cose_error_hash(int error)
{
    /* Intentionally limited to just this minimum set of errors to
     * save object code as hashes don't really fail much
     */
    return error == 0                                 ? T_COSE_SUCCESS :
           error == MBEDTLS_ERR_SHA256_BAD_INPUT_DATA ? T_COSE_ERR_INVALID_ARGUMENT :
                    /* MbedTLS doesn't have an error code for the following
                     * cases, so we use the t_cose error codes instead. As the
                     * MbedTLS error codes are negative, there shouldn't be a
                     * match.
                     */
           error == T_COSE_ERR_UNSUPPORTED_HASH       ? T_COSE_ERR_UNSUPPORTED_HASH :
           error == T_COSE_ERR_INVALID_ARGUMENT       ? T_COSE_ERR_INVALID_ARGUMENT :
                                                        T_COSE_ERR_HASH_GENERAL_FAIL;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id)
{
    int is384 = 0;

    /* Map the algorithm ID */
    switch (cose_hash_alg_id) {
    case COSE_ALGORITHM_SHA_256:
        mbedtls_sha256_init(&(hash_ctx->sha256_ctx));
        hash_ctx->status = mbedtls_sha256_starts(
            &(hash_ctx->sha256_ctx), 0);
        break;
    case COSE_ALGORITHM_SHA_384:
        is384 = 1;
        /* Fallthrough! */
    case COSE_ALGORITHM_SHA_512:
        mbedtls_sha512_init(&(hash_ctx->sha512_ctx));
        hash_ctx->status = mbedtls_sha512_starts(
            &(hash_ctx->sha512_ctx), is384);
        break;
    default:
        hash_ctx->status = T_COSE_ERR_UNSUPPORTED_HASH;
        goto Done;
    }

    hash_ctx->cose_hash_alg_id = cose_hash_alg_id;

Done:
    /* Map errors and return */
    return mbedtls_status_to_t_cose_error_hash(hash_ctx->status);
}


/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c      data_to_hash)
{
    if (hash_ctx->status) {
        /* In error state. Nothing to do. */
        return;
    }

    if (data_to_hash.ptr == NULL) {
        /* This allows for NULL buffers to be passed in all the way at
         * the top of signer or message creator when all that is
         * happening is the size of the result is being computed.
         */
        return;
    }

    /* Actually hash the data */
    if (hash_ctx->cose_hash_alg_id == COSE_ALGORITHM_SHA_256) {
        hash_ctx->status = mbedtls_sha256_update(&(hash_ctx->sha256_ctx),
            data_to_hash.ptr, data_to_hash.len);
    } else {
        hash_ctx->status = mbedtls_sha512_update(&(hash_ctx->sha512_ctx),
            data_to_hash.ptr, data_to_hash.len);
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result)
{
    if (hash_ctx->status) {
        /* Error state. Nothing to do */
        goto Done;
    }

    /* Actually finish up the hash */
    if (hash_ctx->cose_hash_alg_id == COSE_ALGORITHM_SHA_256) {
        if (buffer_to_hold_result.len < T_COSE_CRYPTO_SHA256_SIZE) {
            hash_ctx->status = T_COSE_ERR_INVALID_ARGUMENT;
            goto Done;
        }
        hash_result->len = T_COSE_CRYPTO_SHA256_SIZE;
        hash_ctx->status = mbedtls_sha256_finish(&(hash_ctx->sha256_ctx),
            buffer_to_hold_result.ptr);
    } else {
        if (hash_ctx->cose_hash_alg_id == COSE_ALGORITHM_SHA_384) {
            if (buffer_to_hold_result.len < T_COSE_CRYPTO_SHA384_SIZE) {
                hash_ctx->status = T_COSE_ERR_INVALID_ARGUMENT;
                goto Done;
            }
            hash_result->len = T_COSE_CRYPTO_SHA384_SIZE;
        } else {
            if (buffer_to_hold_result.len < T_COSE_CRYPTO_SHA512_SIZE) {
                hash_ctx->status = T_COSE_ERR_INVALID_ARGUMENT;
                goto Done;
            }
            hash_result->len = T_COSE_CRYPTO_SHA512_SIZE;
        }
        hash_ctx->status = mbedtls_sha512_finish(&(hash_ctx->sha512_ctx),
            buffer_to_hold_result.ptr);
    }

    hash_result->ptr = buffer_to_hold_result.ptr;

Done:
    if (hash_ctx->cose_hash_alg_id == COSE_ALGORITHM_SHA_256) {
        mbedtls_sha256_free(&(hash_ctx->sha256_ctx));
    } else {
        mbedtls_sha512_free(&(hash_ctx->sha512_ctx));
    }

    return mbedtls_status_to_t_cose_error_hash(hash_ctx->status);
}
