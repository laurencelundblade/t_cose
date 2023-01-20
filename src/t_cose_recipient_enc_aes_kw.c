/**
 * \file t_cose_recipient_enc_aes_kw.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#include "t_cose/t_cose_recipient_enc_aes_kw.h" /* Interface implemented */
#include "qcbor/qcbor.h"
#include "t_cose_crypto.h"
#include <stdint.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"


#ifndef T_COSE_DISABLE_AES_KW

static enum t_cose_err_t
recipient_create_keywrap_cb(struct t_cose_recipient_enc  *me_x,
                            struct q_useful_buf_c   plaintext,
                            QCBOREncodeContext     *cbor_encoder)
{
    UsefulBufC             scratch;
    enum t_cose_err_t      return_value;
    enum t_cose_err_t      cose_result;
    size_t                 recipient_key_len;
    struct t_cose_recipient_enc_keywrap *context;


    Q_USEFUL_BUF_MAKE_STACK_UB(recipient_key_buf, T_COSE_ENCRYPTION_MAX_KEY_LENGTH);
    // TODO: make sure this has room for key wrap authentication tag
    Q_USEFUL_BUF_MAKE_STACK_UB(encrypted_cek, T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH));
    struct q_useful_buf_c  recipient_key_result={NULL,0};
    struct q_useful_buf_c  encrypted_cek_result={NULL,0};

    context=(struct t_cose_recipient_enc_keywrap *) me_x;


    cose_result = t_cose_crypto_export_key(
                                    context->wrapping_key,
                                    recipient_key_buf,
                                    &recipient_key_len);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    recipient_key_result.ptr = recipient_key_buf.ptr;
    recipient_key_result.len = recipient_key_len;

    /* AES key wrap encryption */
    return_value = t_cose_crypto_aes_kw(
                        0,
                        recipient_key_result,
                        plaintext,
                        encrypted_cek,
                        &encrypted_cek_result);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Create recipient array */
    QCBOREncode_OpenArray(cbor_encoder);

    /* Add empty protected map encoded as bstr */
    QCBOREncode_BstrWrap(cbor_encoder);
    QCBOREncode_CloseBstrWrap2(cbor_encoder, false, &scratch);

    /* Add unprotected header alg and kid parameters */
    QCBOREncode_OpenMap(cbor_encoder);

    // TODO: pretty sure algorithm ID has to be a protected parameter
    QCBOREncode_AddInt64ToMapN(cbor_encoder,
                               T_COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_AddBytesToMapN(cbor_encoder,
                               T_COSE_HEADER_PARAM_KID,
                               context->kid);

    /* Close protected header map */
    QCBOREncode_CloseMap(cbor_encoder);

    /* Add encrypted CEK */
    QCBOREncode_AddBytes(cbor_encoder, encrypted_cek_result);

    /* Close recipient array */
    QCBOREncode_CloseArray(cbor_encoder);

    return(T_COSE_SUCCESS);
}


enum t_cose_err_t
t_cose_recipient_enc_keywrap_init(struct t_cose_recipient_enc_keywrap *me,
                                  int32_t                              cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->e.creat_cb = recipient_create_keywrap_cb;
    me->cose_algorithm_id = cose_algorithm_id;

    return T_COSE_SUCCESS;
}


void
t_cose_recipient_enc_keywrap_set_key(struct t_cose_recipient_enc_keywrap *me,
                                     struct t_cose_key wrapping_key,
                                     struct q_useful_buf_c kid)
{
    me->wrapping_key = wrapping_key;
    me->kid          = kid;
}

#else /* T_COSE_DISABLE_AES_KW */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_enc_aes_placeholder(void) {}

#endif /* T_COSE_DISABLE_AES_KW */
