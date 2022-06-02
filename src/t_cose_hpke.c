/**
 * \file t_cose_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#include "t_cose/t_cose_hpke.h"    /* The interface this implements */
//#include <psa/crypto.h>     /* PSA Crypto Interface to mbed crypto or such */
#include "mbedtls/hpke.h"   /* HPKE Interface */
#include "qcbor/qcbor.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include <stdint.h>
#include <stdbool.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_standard_constants.h"

/**
 * \brief Given a COSE HPKE algorithm id this function returns the
 *        HPKE algorithm structure, the key length (in bits) and
 *        the COSE algorithm ID.
 *
 * \param[in] buffer             Pointer and length of buffer into which
 *                               the resulting random bytes are put.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully produced the HPKE algorithm structure.
 * \retval T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG
 *         The supported key exchange algorithm is not supported.
 */
enum t_cose_err_t
t_cose_crypto_convert_hpke_algorithms(
                int32_t                           hpke_cose_algorithm_id,
                struct t_cose_crypto_hpke_suite_t *hpke_suite,
                size_t                            *key_bitlen,
                int64_t                           *cose_algorithm_id)
{
    switch (hpke_cose_algorithm_id) {
    case COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
        *key_bitlen = 128;
        *cose_algorithm_id = COSE_ALGORITHM_A128GCM;
        hpke_suite->kem_id = HPKE_KEM_ID_P256;
        hpke_suite->kdf_id = HPKE_KDF_ID_HKDF_SHA256;
        hpke_suite->aead_id = HPKE_AEAD_ID_AES_GCM_128;
        break;
    case COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
        *key_bitlen = 256;
        *cose_algorithm_id = COSE_ALGORITHM_A256GCM;
        hpke_suite->kem_id = HPKE_KEM_ID_P521;
        hpke_suite->kdf_id = HPKE_KDF_ID_HKDF_SHA512;
        hpke_suite->aead_id = HPKE_AEAD_ID_AES_GCM_256;
        break;
    default:
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    return(T_COSE_SUCCESS);
}



/**
 * \brief HPKE Decrypt Wrapper
 *
 * \param[in] cose_algorithm_id   COSE algorithm id
 * \param[in] pkE                 pkE buffer
 * \param[in] pkR                 pkR key
 * \param[in] ciphertext          Ciphertext buffer
 * \param[in] plaintext           Plaintext buffer
 * \param[out] plaintext_len      Length of the returned plaintext
 *
 * \retval T_COSE_SUCCESS
 *         HPKE decrypt operation was successful.
 * \retval T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG
 *         An unsupported algorithm was supplied to the function call.
 * \retval T_COSE_ERR_HPKE_DECRYPT_FAIL
 *         Decrypt operation failed.
 */
enum t_cose_err_t
t_cose_crypto_hpke_decrypt(int32_t                            cose_algorithm_id,
                           struct q_useful_buf_c              pkE,
                           struct t_cose_key                  pkR,
                           struct q_useful_buf_c              ciphertext,
                           struct q_useful_buf                plaintext,
                           size_t                             *plaintext_len)
{
    hpke_suite_t           suite;
//    psa_algorithm_t        psa_algorithm;
//    psa_key_type_t         psa_keytype;
    size_t                 key_bitlen;
    int                    ret;

    /* Setting key distribution parameters. */
    switch(cose_algorithm_id) {
    case COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
        key_bitlen = 128;
        suite.kem_id = HPKE_KEM_ID_P256;
        suite.kdf_id = HPKE_KDF_ID_HKDF_SHA256;
        suite.aead_id = HPKE_AEAD_ID_AES_GCM_128;
//        psa_algorithm = PSA_ALG_GCM;
//        psa_keytype = PSA_KEY_TYPE_AES;
        break;

    case COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
        key_bitlen = 256;
        suite.kem_id = HPKE_KEM_ID_P521;
        suite.kdf_id = HPKE_KDF_ID_HKDF_SHA512;
        suite.aead_id = HPKE_AEAD_ID_AES_GCM_256;
//        psa_algorithm = PSA_ALG_GCM;
//        psa_keytype = PSA_KEY_TYPE_AES;
        break;

    default:
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    /* Execute HPKE */
    *plaintext_len = plaintext.len;

    ret = mbedtls_hpke_decrypt(
            HPKE_MODE_BASE,                  // HPKE mode
            suite,                           // ciphersuite
            NULL, 0, NULL,                   // PSK for authentication
            0, NULL,                         // pkS
            pkR.k.key_handle,                // skR handle
            pkE.len,                         // pkE_len
            (unsigned char *) pkE.ptr,       // pkE
            ciphertext.len,                  // Ciphertext length
            (unsigned char *)
                ciphertext.ptr,              // Ciphertext
            0, NULL,                         // Additional data
            0, NULL,                         // Info
            plaintext_len,                   // Plaintext length
            plaintext.ptr                    // Plaintext
        );

    if (ret != 0) {
        return(T_COSE_ERR_HPKE_DECRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}


/**
 * \brief HPKE Encrypt Wrapper
 *
 * \param[in] suite               HPKE ciphersuite
 * \param[in] pkR                 pkR buffer
 * \param[in] pkE                 pkE buffer
 * \param[in] plaintext           Plaintext buffer
 * \param[in] ciphertext          Ciphertext buffer
 * \param[out] ciphertext_len     Length of the produced ciphertext
 *
 * \retval T_COSE_SUCCESS
 *         HPKE encrypt operation was successful.
 * \retval T_COSE_ERR_HPKE_ENCRYPT_FAIL
 *         Encrypt operation failed.
 */

enum t_cose_err_t
t_cose_crypto_hpke_encrypt(struct t_cose_crypto_hpke_suite_t  suite,
                           struct q_useful_buf_c              pkR,
                           struct t_cose_key                  pkE,
                           struct q_useful_buf_c              plaintext,
                           struct q_useful_buf                ciphertext,
                           size_t                             *ciphertext_len)
{
    int             ret;
    hpke_suite_t    hpke_suite;

    hpke_suite.aead_id = suite.aead_id;
    hpke_suite.kdf_id = suite.kdf_id;
    hpke_suite.kem_id = suite.kem_id;

    ret = mbedtls_hpke_encrypt(
            HPKE_MODE_BASE,                     // HPKE mode
            hpke_suite,                         // ciphersuite
            NULL, 0, NULL,                      // PSK
            pkR.len,                            // pkR length
            (uint8_t *) pkR.ptr,                // pkR
            0,                                  // skI
            plaintext.len,                      // plaintext length
            (uint8_t *) plaintext.ptr,          // plaintext
            0, NULL,                            // Additional data
            0, NULL,                            // Info
            pkE.k.key_handle,                   // skE handle
            0, NULL,                            // pkE
            ciphertext_len, ciphertext.ptr);   // ciphertext

    if (ret != 0) {
        return(T_COSE_ERR_HPKE_ENCRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}


/*
 * See documentation in t_cose_hpke.h
 */
enum t_cose_err_t t_cose_create_hpke_recipient(
                           struct t_cose_encrypt_recipient_ctx  *context,
                           int32_t                               cose_algorithm_id,
                           struct t_cose_key                     recipient_key,
                           struct q_useful_buf_c                 plaintext,
                           QCBOREncodeContext                   *encrypt_ctx)
{
    size_t                 key_bitlen;
    size_t                 x_len;
    int64_t                algorithm_id;
    QCBORError             ret = QCBOR_SUCCESS;
    UsefulBufC             scratch;
    QCBOREncodeContext     ephemeral_key_struct;
    uint8_t                ephemeral_buf[100] = {0};
    struct q_useful_buf    e_buf = {ephemeral_buf, sizeof(ephemeral_buf)};
    uint8_t                encrypted_cek[PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH)];
    size_t                 encrypted_cek_len = PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH);
    UsefulBufC             cek_encrypted_cbor;
    size_t                 pkR_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkR[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    size_t                 pkE_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkE[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    enum t_cose_err_t      return_value;
    struct t_cose_crypto_hpke_suite_t hpke_suite;
    struct t_cose_key     ephemeral_key;


    if (context == NULL || encrypt_ctx == NULL) {
        return(T_COSE_ERR_INVALID_ARGUMENT);
    }

    return_value = t_cose_crypto_convert_hpke_algorithms(context->cose_algorithm_id,
                                                    &hpke_suite,
                                                    &key_bitlen,
                                                    &algorithm_id);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Create ephemeral key */
    return_value = t_cose_crypto_generate_key(&context->ephemeral_key, context->cose_algorithm_id);
    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Export pkR */
    return_value = t_cose_crypto_export_public_key(
                         context->recipient_key,
                         (struct q_useful_buf) {.ptr=pkR, .len=pkR_len},
                         &pkR_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Export pkE */
    return_value = t_cose_crypto_export_public_key(
                         context->ephemeral_key,
                         (struct q_useful_buf) {.ptr=pkE, .len=pkE_len},
                         &pkE_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* HPKE encryption */
    return_value = t_cose_crypto_hpke_encrypt(
                        hpke_suite,
                        (struct q_useful_buf_c) {.ptr = pkR, .len = pkR_len},
                        context->ephemeral_key,
                        (struct q_useful_buf_c) {.ptr = plaintext.ptr, .len = plaintext.len},
                        (struct q_useful_buf) {.ptr = encrypted_cek, .len = encrypted_cek_len},
                        &encrypted_cek_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Create recipient array */
    QCBOREncode_OpenArray(encrypt_ctx);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(encrypt_ctx);

    QCBOREncode_OpenMap(encrypt_ctx);

    QCBOREncode_AddInt64ToMapN(encrypt_ctx,
                               COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(encrypt_ctx);

    QCBOREncode_CloseBstrWrap2(encrypt_ctx,
                               false,
                               &scratch);

    /* Add unprotected Header */
    QCBOREncode_OpenMap(encrypt_ctx);

    /* Create ephemeral parameter map */
    QCBOREncode_Init(&ephemeral_key_struct, e_buf);

    QCBOREncode_OpenMap(&ephemeral_key_struct);

    /* -- add kty paramter */
    QCBOREncode_AddInt64ToMapN(&ephemeral_key_struct,
                               COSE_KEY_COMMON_KTY,
                               COSE_KEY_TYPE_EC2);

    /* -- add crv parameter */
    if (key_bitlen == 128) {
        QCBOREncode_AddInt64ToMapN(&ephemeral_key_struct,
                                   COSE_KEY_PARAM_CRV,
                                   COSE_ELLIPTIC_CURVE_P_256);
    } else if (key_bitlen == 256) {
        QCBOREncode_AddInt64ToMapN(&ephemeral_key_struct,
                                   COSE_KEY_PARAM_CRV,
                                   COSE_ELLIPTIC_CURVE_P_521);
    } else {
        return(T_COSE_ERR_UNSUPPORTED_KEY_LENGTH);
    }

    /* x_len is calculated as ( pkE_len - 1) / 2 */

    /* -- add x parameter */
    QCBOREncode_AddBytesToMapN(&ephemeral_key_struct,
                               COSE_KEY_PARAM_X_COORDINATE,
                               (struct q_useful_buf_c)
                               {
                                 pkE + 1,
                                 (pkE_len - 1) / 2
                               }
                              );

    /* -- add y parameter */
    QCBOREncode_AddBytesToMapN(&ephemeral_key_struct,
                               COSE_KEY_PARAM_Y_COORDINATE,
                               (struct q_useful_buf_c)
                               {
                                 &pkE[(pkE_len - 1) / 2 + 1],
                                 (pkE_len - 1) / 2
                               }
                              );

    /* Close ephemeral parameter map */
    QCBOREncode_CloseMap(&ephemeral_key_struct);

    /* Finish ephemeral parameter map */
    ret = QCBOREncode_Finish(&ephemeral_key_struct, &scratch);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    /* Add ephemeral parameter to unprotected map */
    QCBOREncode_AddBytesToMapN(encrypt_ctx,
                               COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY,
                               (struct q_useful_buf_c)
                               {
                                 scratch.ptr,
                                 scratch.len
                               }
                              );

    /* Add kid to unprotected map  */
    QCBOREncode_AddBytesToMapN(encrypt_ctx,
                               COSE_HEADER_PARAM_KID,
                               context->kid);

    /* Close unprotected map */
    QCBOREncode_CloseMap(encrypt_ctx);

    /* Convert to UsefulBufC structure */
    cek_encrypted_cbor.len = encrypted_cek_len;
    cek_encrypted_cbor.ptr = encrypted_cek;

    /* Add encrypted CEK */
    QCBOREncode_AddBytes(encrypt_ctx, cek_encrypted_cbor);

    /* Close recipient array */
    QCBOREncode_CloseArray(encrypt_ctx);

    return(T_COSE_SUCCESS);
}

