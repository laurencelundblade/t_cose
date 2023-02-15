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
#include "t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor.h"
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_recipient_enc_hpke.h"
#include "t_cose/t_cose_recipient_enc_aes_kw.h"


enum t_cose_err_t
t_cose_encrypt_enc_detached(struct t_cose_encrypt_enc *context,
                            struct q_useful_buf_c      payload,
                            struct q_useful_buf_c      aad,
                            struct q_useful_buf        buffer_for_detached,
                            struct q_useful_buf        buffer_for_message,
                            struct q_useful_buf_c     *encrypted_detached,
                            struct q_useful_buf_c     *encrypted_cose_message)
{
    QCBOREncodeContext     additional_data;
    UsefulBufC             scratch;
    QCBORError             ret;
    QCBOREncodeContext     encrypt_ctx;
    struct q_useful_buf_c  nonce_result;
    struct q_useful_buf_c  cek_bytes={NULL,0};

    /* Additional data buffer */
    UsefulBufC             add_data_buf;
    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};

    size_t                 key_bitlen;
    enum t_cose_err_t      cose_result;
    Q_USEFUL_BUF_MAKE_STACK_UB(cek_buffer, 16);
    Q_USEFUL_BUF_MAKE_STACK_UB(nonce, T_COSE_ENCRYPTION_MAX_KEY_LENGTH);

    struct q_useful_buf encrypt_buffer;
    struct q_useful_buf_c encrypt_output;

    /* Determine algorithm parameters */
    switch(context->payload_cose_algorithm_id) {
    case T_COSE_ALGORITHM_A128GCM:
        key_bitlen = 128;
        break;
    case T_COSE_ALGORITHM_A256GCM:
        key_bitlen = 256;
        break;
    default:
        /* Unsupported algorithm */
        return(T_COSE_ERR_UNSUPPORTED_CIPHER_ALG);
    }

    /* Initialize CBOR encoder context with output buffer */
    QCBOREncode_Init(&encrypt_ctx, buffer_for_message);

    /* Should we use COSE_Encrypt or COSE_Encrypt0? */
    if ((context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) > 0) {
        /* Add the CBOR tag indicating COSE_Encrypt0 */
        QCBOREncode_AddTag(&encrypt_ctx, CBOR_TAG_COSE_ENCRYPT0);
    } else {
        /* Add the CBOR tag indicating COSE_Encrypt */
        QCBOREncode_AddTag(&encrypt_ctx, CBOR_TAG_COSE_ENCRYPT);
    }

    /* Open array */
    QCBOREncode_OpenArray(&encrypt_ctx);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(&encrypt_ctx);

    QCBOREncode_OpenMap(&encrypt_ctx);

    QCBOREncode_AddInt64ToMapN(&encrypt_ctx,
                               T_COSE_HEADER_PARAM_ALG,
                               context->payload_cose_algorithm_id);

    QCBOREncode_CloseMap(&encrypt_ctx);

    QCBOREncode_CloseBstrWrap2(&encrypt_ctx, false, &scratch);

    /* Add unprotected Header */
    QCBOREncode_OpenMap(&encrypt_ctx);

    /* Generate random nonce */
    cose_result = t_cose_crypto_get_random(nonce, key_bitlen / 8,
                                           &nonce_result );

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    /* Add nonce */
    QCBOREncode_AddBytesToMapN(&encrypt_ctx,
                               T_COSE_HEADER_PARAM_IV,
                               nonce_result
                              );

    /* TODO: kid is going to get handled when this switches to t_cose_encode_parameters() */


    /* Close unprotected header map */
    QCBOREncode_CloseMap(&encrypt_ctx);


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
    if ( (context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) > 0) {
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
                               T_COSE_HEADER_PARAM_ALG,
                               context->payload_cose_algorithm_id);

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

    struct t_cose_key cek_handle;

    if ( (context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) == 0) {
        /* For everything but direct encryption, we create a
         * random CEK and encrypt payload with CEK.
         */
        cose_result = t_cose_crypto_get_random(cek_buffer, 16, &cek_bytes);
        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        }

        cose_result = t_cose_crypto_make_symmetric_key_handle(context->payload_cose_algorithm_id,
                                                              cek_bytes,
                                                             &cek_handle);

    } else {
        /* Direct encryption with recipient key. This requires us
         * to export the shared secret for later use in the payload
         * encryption.
         */

        cose_result = t_cose_crypto_export_symmetric_key(context->cek,
                                                         cek_buffer,
                                                        &cek_bytes);

        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        }

        cek_handle = context->cek;
    }

    // TODO: for non-recipient HPKE, there will have to be algorithm mapping and other stuff here



    if(q_useful_buf_is_null(buffer_for_detached)) {
        QCBOREncode_OpenBytes(&encrypt_ctx, &encrypt_buffer);
    } else {
        encrypt_buffer = buffer_for_detached;
    }

    cose_result = t_cose_crypto_aead_encrypt(
                        context->payload_cose_algorithm_id, /* in: AEAD algorithm */
                        cek_handle, /* in: content encryption key handle */
                        nonce_result, /* in: nonce / IV */
                        add_data_buf, /* in: additional data to authenticate */
                        payload, /* in: payload to encrypt */
                        encrypt_buffer, /* in: buffer to write to */
                       &encrypt_output /* out: ciphertext */);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    if(q_useful_buf_is_null(buffer_for_detached)) {
        QCBOREncode_CloseBytes(&encrypt_ctx, encrypt_output.len);
    } else {
        QCBOREncode_AddNULL(&encrypt_ctx);
        *encrypted_detached = encrypt_output;
    }


    /* COSE_Encrypt0 does contain a recipient structure. Furthermore, there
     * is no function pointer associated with context->recipient_ctx.recipient_func.
     *
     * COSE_Encrypt, however, requires a recipient structure. Here we add it.
     */
    if ( (context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) == 0) {
        struct t_cose_recipient_enc *recipient;
        for(recipient = context->recipients_list; recipient != NULL; recipient = recipient->next_in_list) {
            /* Array holding the recipients */
            QCBOREncode_OpenArray(&encrypt_ctx);

            /* This does the public-key crypto and outputs the COSE_Recipient */
            cose_result = recipient->creat_cb(recipient,
                                              cek_bytes,
                                              &encrypt_ctx);
            if(cose_result) {
                // TODO: hard and soft errors
                break;
            }

            QCBOREncode_CloseArray(&encrypt_ctx);
        }
/*
        cose_result = context->recipient_ctx.recipient_func(
                                    &context->recipient_ctx,
                                    context->cose_algorithm_id,
                                    context->recipient_ctx.recipient_key,
                                    random_result,
                                    &encrypt_ctx);

        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        } */
    }

     /* Close COSE_Encrypt/COSE_Encrypt0 array */
    QCBOREncode_CloseArray(&encrypt_ctx);

    /* Export COSE_Encrypt structure */
    ret = QCBOREncode_Finish(&encrypt_ctx, encrypted_cose_message);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_FAIL); // TODO: map error
    }

    return(T_COSE_SUCCESS);
}



void
t_cose_encrypt_add_recipient(struct t_cose_encrypt_enc   *me,
                             struct t_cose_recipient_enc *recipient)
{
    if(me->recipients_list == NULL) {
        me->recipients_list = recipient;
    } else {
        /* find end of list and add it */
    }
}
