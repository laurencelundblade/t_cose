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
#include "qcbor/qcbor.h"
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"

enum t_cose_err_t
t_cose_encrypt_enc_detached(struct t_cose_encrypt_enc_ctx* context,
                            QCBOREncodeContext* encrypt_ctx,
                            struct q_useful_buf_c detached_payload,
                            struct q_useful_buf   encrypted_payload,
                            size_t* encrypted_payload_size
                           )
{
    psa_status_t           status;
    QCBOREncodeContext     additional_data;
    UsefulBufC             scratch;
    QCBORError             ret;
    struct q_useful_buf    nonce;

    /* Additional data buffer */
    UsefulBufC             add_data_buf;
    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};

    size_t                 ciphertext_length;
    size_t                 key_bitlen;
    enum t_cose_err_t      cose_result;

    /* Determine algorithm parameters */
    switch(context->cose_algorithm_id) {
    case COSE_ALGORITHM_A128GCM:
        key_bitlen = 128;
        break;
    case COSE_ALGORITHM_A256GCM:
        key_bitlen = 256;
        break;
    default:
        /* Unsupported algorithm */
        return(T_COSE_ERR_UNSUPPORTED_CIPHER_ALG);
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
    nonce.len = key_bitlen / 8;
    nonce.ptr = context->nonce;

    cose_result = t_cose_crypto_get_random(nonce);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
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
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    cose_result = t_cose_crypto_encrypt(
                       context->cose_algorithm_id,
                       (struct q_useful_buf_c)
                       {
                          .ptr = context->key,
                          .len = context->key_len
                       },
                       (struct q_useful_buf_c)
                       {
                          .ptr = context->nonce,
                          .len = key_bitlen / 8
                       },
                       add_data_buf,
                       detached_payload,
                       encrypted_payload,
                       encrypted_payload_size);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }
    return(T_COSE_SUCCESS);
}

enum t_cose_err_t
t_cose_encrypt_enc(struct t_cose_encrypt_enc_ctx* context,
                   QCBOREncodeContext* encrypt_ctx,
                   struct q_useful_buf_c payload,
                   struct q_useful_buf encrypted_payload
                  )
{
    psa_status_t           status;
    QCBOREncodeContext     additional_data;
    UsefulBufC             scratch;
    size_t                 ciphertext_length;
    size_t                 cek_verification_len;
    QCBORError             ret;
    size_t                 key_bitlen;
    enum t_cose_err_t      cose_result;
    struct q_useful_buf    nonce;

    /* Additional data buffer */
    UsefulBufC             add_data_buf;
    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};

    /* Determine algorithm parameters */
    switch(context->cose_algorithm_id) {
    case COSE_ALGORITHM_A128GCM:
        key_bitlen = 128;
        break;
    case COSE_ALGORITHM_A256GCM:
        key_bitlen = 256;
        break;
    default:
        return(T_COSE_ERR_UNSUPPORTED_CIPHER_ALG);
    }

    /* Add the CBOR tag */
    if (context->option_flags == T_COSE_OPT_COSE_ENCRYPT0) {
        QCBOREncode_AddTag(encrypt_ctx, CBOR_TAG_COSE_ENCRYPT0);
    } else {
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

    /* Add unprotected Header with IV/nonce parameter */
    QCBOREncode_OpenMap(encrypt_ctx);

    /* Generate nonce */
    nonce.len = key_bitlen / 8;
    nonce.ptr = context->nonce;

    cose_result = t_cose_crypto_get_random(nonce);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
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
    *    context : "Encrypt" or "Encrypt0",
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
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    cose_result = t_cose_crypto_encrypt(
                       context->cose_algorithm_id,
                       (struct q_useful_buf_c)
                       {
                          .ptr = context->key,
                          .len = context->key_len
                       },
                       (struct q_useful_buf_c)
                       {
                          .ptr = context->nonce,
                          .len = key_bitlen / 8
                       },
                       add_data_buf,
                       payload,
                       encrypted_payload,
                       &ciphertext_length);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
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
    int64_t                algorithm_id;
    QCBORError             ret = QCBOR_SUCCESS;
    UsefulBufC             scratch;
    QCBOREncodeContext     ephemeral_key;
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

    if (context == NULL || EC == NULL) {
        return(T_COSE_ERR_INVALID_ARGUMENT);
    }

    return_value = t_cose_crypto_convert_hpke_algorithms(context->cose_algorithm_id,
                                                         &hpke_suite,
                                                         &key_bitlen,
                                                         &algorithm_id);

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
                        (struct q_useful_buf_c) {.ptr = context->cek, .len = context->cek_len},
                        (struct q_useful_buf) {.ptr = encrypted_cek, .len = encrypted_cek_len},
                        &encrypted_cek_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
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
        return(T_COSE_ERR_CBOR_FORMATTING);
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

    return(T_COSE_SUCCESS);
}
