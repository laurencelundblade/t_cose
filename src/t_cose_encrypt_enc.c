/*
 * t_cose_encrypt_enc.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose_standard_constants.h"
#include "psa/crypto.h"
#include "qcbor/qcbor.h"
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include <mbedtls/aes.h>
#include <mbedtls/nist_kw.h>
#include <mbedtls/hkdf.h>
#include "t_cose_crypto.h"
#include "mbedtls/hpke.h"

enum t_cose_err_t
t_cose_encrypt_enc_detached(struct t_cose_encrypt_enc_ctx* context,
                            QCBOREncodeContext* encrypt_ctx,
                            struct q_useful_buf_c detached_payload,
                            struct q_useful_buf_c encrypted_payload,
                            size_t* encrypted_payload_size
                           )
{
    psa_status_t           status;
    QCBOREncodeContext     additional_data;
    UsefulBufC             scratch;
    QCBORError             ret;
    psa_key_attributes_t   attributes=PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t       cek_handle=0;

    /* Additional data buffer */
    UsefulBufC             add_data_buf;
    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};

    size_t                 ciphertext_length;
    size_t                 key_bitlen;

    /* Determine algorithm parameters */
    switch(context->cose_algorithm_id) {
    case COSE_ALGORITHM_A128GCM:
        psa_algorithm=PSA_ALG_GCM;
        psa_keytype=PSA_KEY_TYPE_AES;
        key_bitlen=128;
        break;
    case COSE_ALGORITHM_A256GCM:
        psa_algorithm=PSA_ALG_GCM;
        psa_keytype=PSA_KEY_TYPE_AES;
        key_bitlen=256;
        break;
    default:
        /* Unsupported algorithm */
        return(EXIT_FAILURE);
    }

    if (context->option_flags == T_COSE_OPT_COSE_ENCRYPT0) {
        /* Add the CBOR tag indicating COSE_Encrypt */
        QCBOREncode_AddTag(encrypt_ctx, CBOR_TAG_COSE_ENCRYPT0);
    } else {
        /* Add the CBOR tag indicating COSE_Encrypt */
        QCBOREncode_AddTag(encrypt_ctx, CBOR_TAG_COSE_ENCRYPT);
    }

    /* Open COSE_Encrypt array */
    QCBOREncode_OpenArray(encrypt_ctx);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(encrypt_ctx);

    QCBOREncode_OpenMap(encrypt_ctx);

    QCBOREncode_AddInt64ToMapN(encrypt_ctx,
                               COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(encrypt_ctx);

    QCBOREncode_CloseBstrWrap2(encrypt_ctx, false, &scratch);

    /* Add unprotected Header with IV parameter */
    QCBOREncode_OpenMap(encrypt_ctx);

    /* Generate random nonce */
    status=psa_generate_random(context->nonce,key_bitlen/8);

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    QCBOREncode_AddBytesToMapN(encrypt_ctx,
                               COSE_HEADER_PARAM_IV,
                               (struct q_useful_buf_c) {
                                    .len = key_bitlen / 8,
                                    .ptr = context->nonce}
                              );

    /* Add kid */
    if (context->option_flags == T_COSE_OPT_COSE_ENCRYPT0) {
        QCBOREncode_AddBytesToMapN(encrypt_ctx,
                                   COSE_HEADER_PARAM_KID,
                                   context->kid);
    }

    /* Close unprotected header map */
    QCBOREncode_CloseMap(encrypt_ctx);

    /* Indicate detached ciphertext with NULL */
    QCBOREncode_AddSimple(encrypt_ctx, CBOR_SIMPLEV_NULL);

    /* Encrypt detached payload */

    /* Create Additional Data Structure
    *
    *  Enc_structure = [
    *    context : "Encrypt",
    *    protected : empty_or_serialized_map,
    *    external_aad : bstr
    *  ]
    */

    /* Initialize additional data CBOR array */
    QCBOREncode_Init(&additional_data, add_data_struct);

    QCBOREncode_BstrWrap(&additional_data);

    /* Open array */
    QCBOREncode_OpenArray(&additional_data);

    /* 1. Add context string "Encrypt" or "Encrypt0" */
    if (context->option_flags == T_COSE_OPT_COSE_ENCRYPT0) {
        QCBOREncode_AddText(&additional_data,
                            ((struct q_useful_buf_c) {"Encrypt0", 8}));
    } else
    {
        QCBOREncode_AddText(&additional_data,
                            ((struct q_useful_buf_c) {"Encrypt", 7}));
    }

    /* 2. Add protected headers (as bstr) */
    QCBOREncode_BstrWrap(&additional_data);

    QCBOREncode_OpenMap(&additional_data);

    QCBOREncode_AddInt64ToMapN(&additional_data,
                               COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data, false, &add_data_buf);

    /* 3. Add any externally provided additional data,
     * which is empty in our case.
     */
    QCBOREncode_BstrWrap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data, false, &add_data_buf);

    /* Close array */
    QCBOREncode_CloseArray(&additional_data);

    QCBOREncode_CloseBstrWrap2(&additional_data, false, &add_data_buf);

    /* Finish and check the results */
    ret = QCBOREncode_Finish(&additional_data, &add_data_buf);

    if (ret != QCBOR_SUCCESS) {
        return(EXIT_FAILURE);
    }

    psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes,psa_algorithm);
    psa_set_key_type(&attributes,psa_keytype);
    psa_set_key_bits(&attributes,key_bitlen);

    status=psa_import_key(&attributes,
                          context->key,
                          context->key_len,
                          &cek_handle);

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    status=psa_aead_encrypt(
             cek_handle,                             // key
             psa_algorithm,                          // algorithm
             (const uint8_t *) context->nonce,       // nonce
             key_bitlen/8,                           // nonce length
             (const uint8_t *) add_data_buf.ptr,     // additional data
             add_data_buf.len,                       // additional data length
             (const uint8_t *) detached_payload.ptr, // plaintext
             detached_payload.len,                   // plaintext length
             (uint8_t *) encrypted_payload.ptr,      // ciphertext
             encrypted_payload.len,                  // ciphertext length
             encrypted_payload_size );               // length of output

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    return(T_COSE_SUCCESS);
}

enum t_cose_err_t
t_cose_encrypt_enc(struct t_cose_encrypt_enc_ctx* context,
                   QCBOREncodeContext* encrypt_ctx,
                   struct q_useful_buf_c payload,
                   struct q_useful_buf_c encrypted_payload
                  )
{
    psa_status_t           status;
    QCBOREncodeContext     additional_data;
    UsefulBufC             scratch;
    size_t                 ciphertext_length;
    psa_key_attributes_t   attributes=PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t       cek_handle=0;
    QCBORError             ret;
    psa_algorithm_t        psa_algorithm;
    psa_key_type_t         psa_keytype;
    size_t                 key_bitlen;

    /* Additional data buffer */
    UsefulBufC             add_data_buf;
    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};

    /* Determine algorithm parameters */
    switch(context->cose_algorithm_id) {
    case COSE_ALGORITHM_A128GCM:
        psa_algorithm=PSA_ALG_GCM;
        psa_keytype=PSA_KEY_TYPE_AES;
        key_bitlen=128;
        break;
    case COSE_ALGORITHM_A256GCM:
        psa_algorithm=PSA_ALG_GCM;
        psa_keytype=PSA_KEY_TYPE_AES;
        key_bitlen=256;
        break;
    default:
        /* Unsupported algorithm */
        return(EXIT_FAILURE);
    }

    /* Add the CBOR tag */
    if (context->option_flags==T_COSE_OPT_COSE_ENCRYPT0) {
        QCBOREncode_AddTag(encrypt_ctx,CBOR_TAG_ENCRYPT0);
    } else {
        QCBOREncode_AddTag(encrypt_ctx,CBOR_TAG_ENCRYPT);
    }

    /* Open COSE_Encrypt array */
    QCBOREncode_OpenArray(encrypt_ctx);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(encrypt_ctx);

    QCBOREncode_OpenMap(encrypt_ctx);

    QCBOREncode_AddInt64ToMapN(encrypt_ctx,
                               COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(encrypt_ctx);

    QCBOREncode_CloseBstrWrap2(encrypt_ctx, false, &scratch);

    /* Add unprotected Header with IV/nonce parameter */
    QCBOREncode_OpenMap(encrypt_ctx);

    /* Generate random nonce */
    status=psa_generate_random(context->nonce,key_bitlen/8);

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    QCBOREncode_AddBytesToMapN(encrypt_ctx,
                               COSE_HEADER_PARAM_IV,
                               (struct q_useful_buf_c) {
                                 .len = nonce.len,
                                 .ptr = nonce.ptr}
                              );

    /* Add kid */
    if (context->option_flags == T_COSE_OPT_COSE_ENCRYPT0) {
        QCBOREncode_AddBytesToMapN(encrypt_ctx,
                                   COSE_HEADER_PARAM_KID,
                                   context->kid);
    }

    /* Close unprotected header map */
    QCBOREncode_CloseMap(encrypt_ctx);

    /* Encrypt payload */

    /* Create Additional Data Structure
    *
    *  Enc_structure = [
    *    context : "Encrypt",
    *    protected : empty_or_serialized_map,
    *    external_aad : bstr
    *  ]
    */

    /* Initialize additional data CBOR array */
    QCBOREncode_Init(&additional_data, add_data_struct);

    QCBOREncode_BstrWrap(&additional_data);

    /* Open array */
    QCBOREncode_OpenArray(&additional_data);

    /* 1. Add context string "Encrypt" or "Encrypt0" */
    if (context->option_flags == T_COSE_OPT_COSE_ENCRYPT0) {
        QCBOREncode_AddText(&additional_data,
                            ((struct q_useful_buf_c) {"Encrypt0", 8}));
    } else {
        QCBOREncode_AddText(&additional_data,
                            ((struct q_useful_buf_c) {"Encrypt", 7}));
    }

    /* 2. Add protected headers (as bstr) */
    QCBOREncode_BstrWrap(&additional_data);

    QCBOREncode_OpenMap(&additional_data);

    QCBOREncode_AddInt64ToMapN(&additional_data,
                               COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data,
                               false,
                               &add_data_buf);

    /* 3. Add any externally provided additional data,
     * which is empty in our case.
     */
    QCBOREncode_BstrWrap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data,
                               false,
                               &add_data_buf);

    /* Close array */
    QCBOREncode_CloseArray(&additional_data);

    QCBOREncode_CloseBstrWrap2(&additional_data,
                               false,
                               &add_data_buf);

    /* Finish and check the results */
    ret = QCBOREncode_Finish(&additional_data, &add_data_buf);

    if (ret != QCBOR_SUCCESS) {
        return(EXIT_FAILURE);
    }

    psa_set_key_usage_flags(&attributes,PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes,psa_algorithm);
    psa_set_key_type(&attributes,psa_keytype);
    psa_set_key_bits(&attributes,key_bitlen);

    status = psa_import_key(&attributes,
                            context->key,
                            context->key_len,
                            &cek_handle);

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    status=psa_aead_encrypt(
             cek_handle,                          // key
             psa_algorithm,                       // algorithm
             (const uint8_t *) context->nonce,    // nonce
             key_bitlen / 8,                      // nonce length
             (const uint8_t *) add_data_buf.ptr,  // additional data
             add_data_buf.len,                    // additional data length
             (const uint8_t *) payload.ptr,       // plaintext
             payload.len,                         // plaintext length
             (uint8_t *) encrypted_payload.ptr,   // ciphertext
             encrypted_payload.len,               // ciphertext length
             &ciphertext_length);                 // length of output

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    QCBOREncode_AddBytes(encrypt_ctx,
                         (struct q_useful_buf_c)
                            {
                              .len = ciphertext_length,
                              .ptr = encrypted_payload.ptr
                            }
                        );

    return(T_COSE_SUCCESS);
}

enum t_cose_err_t
t_cose_encrypt_add_recipient(struct t_cose_encrypt_enc_ctx* context,
                             QCBOREncodeContext* encrypt_ctx,
                             UsefulBufC* recipient_ctx)
{
    if (context->option_flags != T_COSE_OPT_COSE_ENCRYPT0) {
        QCBOREncode_AddBuffer(encrypt_ctx,
                              CBOR_MAJOR_NONE_TYPE_RAW,
                              *recipient_ctx);
        context->recipients++;
        return(T_COSE_SUCCESS);
    } else {
        return(T_COSE_ERR_RECIPIENT_CANNOT_BE_ADDED);
    }
}


enum t_cose_err_t
t_cose_encrypt_hpke_create_recipient(struct t_cose_encrypt_recipient_hpke_ctx* context,
                                     QCBOREncodeContext* EC)
{
    size_t                 key_bitlen;
    size_t                 x_len;
    psa_algorithm_t        psa_algorithm;
    int64_t                algorithm_id;
    psa_status_t           status;
    QCBORError             ret=QCBOR_SUCCESS;
    UsefulBufC             scratch;
    QCBOREncodeContext     ephemeral_key;
    uint8_t                ephemeral_buf[100]={0};
    struct q_useful_buf    e_buf={ephemeral_buf,sizeof(ephemeral_buf)};
    hpke_suite_t           suite;
    uint8_t                encrypted_cek[PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH)];
    size_t                 encrypted_cek_len = PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH);
    UsefulBufC             cek_encrypted_cbor;
    size_t                 pkR_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkR[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    size_t                 pkE_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkE[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};

    if (context == NULL || EC == NULL) {
        return(T_COSE_ERR_INVALID_ARGUMENT);
    }

    /* Sanity check on the input */
    switch (context->cose_algorithm_id) {
        case COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
            psa_algorithm=PSA_ALG_GCM;
            key_bitlen=128;
            algorithm_id=COSE_ALGORITHM_A128GCM;
            suite.kem_id=HPKE_KEM_ID_P256;
            suite.kdf_id=HPKE_KDF_ID_HKDF_SHA256;
            suite.aead_id=HPKE_AEAD_ID_AES_GCM_128;
            break;
        case COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
            psa_algorithm=PSA_ALG_GCM;
            key_bitlen=256;
            algorithm_id=COSE_ALGORITHM_A256GCM;
            suite.kem_id=HPKE_KEM_ID_P521;
            suite.kdf_id=HPKE_KDF_ID_HKDF_SHA512;
            suite.aead_id=HPKE_AEAD_ID_AES_GCM_256;
            break;

        default:
            return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    status=psa_export_public_key(context->recipient_key.k.key_handle,
                                 pkR,
                                 pkR_len,
                                 &pkR_len
                                );

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    /* Export pkE */
    status = psa_export_public_key(context->ephemeral_key.k.key_handle,
                                   pkE,
                                   pkE_len,
                                   &pkE_len
                                  );

    if (status!=PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    /* HPKE encryption */
    ret = mbedtls_hpke_encrypt(
            HPKE_MODE_BASE,                     // HPKE mode
            suite,                              // ciphersuite
            NULL, 0, NULL,                      // PSK
            pkR_len, pkR,                       // pkR
            0,                                  // skI
            context->cek_len, context->cek,     // plaintext
            0, NULL,                            // Additional data
            0, NULL,                            // Info
            context->ephemeral_key.k.key_handle,// skE hadle
            NULL, NULL,                         // pkE
            &encrypted_cek_len, encrypted_cek); // ciphertext

    if (ret!=0) {
        return(EXIT_FAILURE);
    }

    /* Create recipient array */
    QCBOREncode_OpenArray(EC);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(EC);

    QCBOREncode_OpenMap(EC);

    QCBOREncode_AddInt64ToMapN(EC,
                               COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(EC);

    QCBOREncode_CloseBstrWrap2(EC,
                               false,
                               &scratch);

    /* Add unprotected Header */
    QCBOREncode_OpenMap(EC);

    /* Create ephemeral parameter map */
    QCBOREncode_Init(&ephemeral_key, e_buf);

    QCBOREncode_OpenMap(&ephemeral_key);

    /* -- add kty paramter */
    QCBOREncode_AddInt64ToMapN(&ephemeral_key,
                               COSE_KEY_COMMON_KTY,
                               COSE_KEY_TYPE_EC2);

    /* -- add crv parameter */
    if (key_bitlen == 128) {
        QCBOREncode_AddInt64ToMapN(&ephemeral_key,
                                   COSE_KEY_PARAM_CRV,
                                   COSE_ELLIPTIC_CURVE_P_256);
    } else if (key_bitlen == 256) {
        QCBOREncode_AddInt64ToMapN(&ephemeral_key,
                                   COSE_KEY_PARAM_CRV,
                                   COSE_ELLIPTIC_CURVE_P_521);
    } else {
        return(T_COSE_ERR_UNSUPPORTED_KEY_LENGTH);
    }

    /* x_len is calculated as ( pkE_len - 1) / 2 */

    /* -- add x parameter */
    QCBOREncode_AddBytesToMapN(&ephemeral_key,
                               COSE_KEY_PARAM_X_COORDINATE,
                               (struct q_useful_buf_c)
                               {
                                 pkE + 1,
                                 (pkE_len - 1) / 2
                               }
                              );

    /* -- add y parameter */
    QCBOREncode_AddBytesToMapN(&ephemeral_key,
                               COSE_KEY_PARAM_Y_COORDINATE,
                               (struct q_useful_buf_c)
                               {
                                 &pkE[(pkE_len - 1) / 2 + 1],
                                 (pkE_len - 1) / 2
                               }
                              );

    /* Close ephemeral parameter map */
    QCBOREncode_CloseMap(&ephemeral_key);

    /* Finish ephemeral parameter map */
    ret = QCBOREncode_Finish(&ephemeral_key, &scratch);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_FAIL);
    }

    /* Add ephemeral parameter to unprotected map */
    QCBOREncode_AddBytesToMapN(EC,
                               COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY,
                               (struct q_useful_buf_c)
                               {
                                 scratch.ptr,
                                 scratch.len
                               }
                              );

    /* Add kid to unprotected map  */
    QCBOREncode_AddBytesToMapN(EC,
                               COSE_HEADER_PARAM_KID,
                               context->kid);

    /* Close unprotected map */
    QCBOREncode_CloseMap(EC);

    /* Convert to UsefulBufC structure */
    cek_encrypted_cbor.len = encrypted_cek_len;
    cek_encrypted_cbor.ptr = encrypted_cek;

    /* Add encrypted CEK */
    QCBOREncode_AddBytes(EC, cek_encrypted_cbor);

    /* Close recipient array */
    QCBOREncode_CloseArray(EC);

    return(T_COSE_SUCCESS);
}


enum t_cose_err_t
t_cose_encrypt_enc_finish(struct t_cose_encrypt_enc_ctx* context,
                          QCBOREncodeContext* encrypt_ctx)
{
     /* Close COSE_Encrypt array */
    QCBOREncode_CloseArray(encrypt_ctx);

    // TBD: Maybe close some PSA calls or so.
    return(T_COSE_SUCCESS);
}
