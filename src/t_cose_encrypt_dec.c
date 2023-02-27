/*
 * t_cose_encrypt_dec.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include <stdlib.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_recipient_dec.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"


/* These errors do not stop the calling of further verifiers for
 * a given COSE_Recipient.
 */
static bool
is_soft_verify_error(enum t_cose_err_t error)
{
    switch(error) {
        case T_COSE_ERR_UNSUPPORTED_SIGNING_ALG:
        case T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG:
        case T_COSE_ERR_UNSUPPORTED_ENCRYPTION_ALG:
        case T_COSE_ERR_UNSUPPORTED_CIPHER_ALG:
        case T_COSE_ERR_KID_UNMATCHED:
        case T_COSE_ERR_UNSUPPORTED_HASH:
        case T_COSE_ERR_DECLINE:
            return true;
        default:
            return false;
    }
}


static enum t_cose_err_t
decrypt_one_recipient(struct t_cose_encrypt_dec_ctx      *me,
                      const struct t_cose_header_location header_location,
                      QCBORDecodeContext                 *cbor_decoder,
                      struct q_useful_buf                 cek_buffer,
                      struct t_cose_parameter           **decoded_rec_parameter_list,
                      struct q_useful_buf_c              *cek)
{
    struct t_cose_recipient_dec *recipient_decoder;
    enum t_cose_err_t            return_value;

#ifdef QCBOR_FOR_T_COSE_2
    SaveDecodeCursor saved_cursor;

    QCBORDecode_SaveCursor(qcbor_decoder, &saved_cursor);
#endif

    /* Loop over the configured recipients */
    for(recipient_decoder = me->recipient_list;
        recipient_decoder != NULL;
        recipient_decoder = (struct t_cose_recipient_dec *)recipient_decoder->base_obj.next) {
        return_value = recipient_decoder->decode_cb(recipient_decoder,
                                            header_location,
                                            cbor_decoder,
                                            cek_buffer,
                                            me->p_storage,
                                            decoded_rec_parameter_list,
                                            cek);

        /* This is pretty much the same as for decrypting recipients */
        if(return_value == T_COSE_SUCCESS) {
            /* Only need to find one success and this is it so done.*/
            return T_COSE_SUCCESS;
        }

        if(return_value == T_COSE_ERR_NO_MORE) {
            /* Tried all the recipient decoders. None succeeded and none gave a hard failure */
            return T_COSE_ERR_NO_MORE;
        }

        if(!is_soft_verify_error(return_value)) {
            return return_value;
            /* Something very wrong. */
        }

        /* Go on to the next recipient */
#ifdef QCBOR_FOR_T_COSE_2
        QCBORDecode_RestoreCursor(qcbor_decoder, &saved_cursor);
#else
        return T_COSE_ERR_CANT_PROCESS_MULTIPLE;
#endif
    }

    /* Got to end of list and no recipient attempted to verify */
    return T_COSE_ERR_DECLINE;
}


enum t_cose_err_t
t_cose_encrypt_dec_detached(struct t_cose_encrypt_dec_ctx* me,
                            const struct q_useful_buf_c    message,
                            const struct q_useful_buf_c    aad,
                            const struct q_useful_buf_c    detached_ciphertext,
                            struct q_useful_buf            plaintext_buffer,
                            struct q_useful_buf_c         *plain_text,
                            struct t_cose_parameter      **returned_parameters)
{
    enum t_cose_err_t      return_value;
    UsefulBufC             nonce_cbor;
    int32_t                algorithm_id;
    QCBORDecodeContext     cbor_decoder;
    QCBORItem              Item;
    struct q_useful_buf_c  cipher_text;
    Q_USEFUL_BUF_MAKE_STACK_UB(  enc_struct_buffer, T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE);
    struct q_useful_buf_c  cek;
    struct t_cose_key      cek_key;
    struct t_cose_parameter *decoded_recipient_params;
    MakeUsefulBufOnStack(cek_buf, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    uint32_t                 message_type;
    struct t_cose_header_location   header_location;
    struct q_useful_buf_c           protected_parameters;
    struct t_cose_parameter        *decoded_body_parameter_list;
    struct q_useful_buf_c        enc_structure;
    QCBORError                   cbor_error;


    /* Initialize decoder */
    QCBORDecode_Init(&cbor_decoder, message, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&cbor_decoder, &Item);

   /* Make sure the first item is a tag */
    message_type = me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK;

    /* Check whether tag is CBOR_TAG_COSE_ENCRYPT or CBOR_TAG_COSE_ENCRYPT0 */
    // TODO: allow tag determination of message_type
    if (QCBORDecode_IsTagged(&cbor_decoder, &Item, CBOR_TAG_COSE_ENCRYPT) == false &&
        QCBORDecode_IsTagged(&cbor_decoder, &Item, CBOR_TAG_COSE_ENCRYPT0) == false) {
        return(T_COSE_ERR_INCORRECTLY_TAGGED);
    }

    /* ---- The header parameters ---- */
    /* The location of body header parameters is 0, 0 */
    header_location.nesting = 0;
    header_location.index   = 0;

    return_value = t_cose_headers_decode(&cbor_decoder,
                          header_location, /* in: location of headers in message */
                          NULL, /* TODO: fill this in */
                          NULL, /* TODO: fill this in */
                          me->p_storage, /* in: Pool of nodes for linked list */
                          &decoded_body_parameter_list, /* out: linked list */
                          &protected_parameters); /* out: pointer and length of encoded protected parameters */

    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    nonce_cbor = t_cose_find_parameter_iv(decoded_body_parameter_list);
    algorithm_id = t_cose_find_parameter_alg_id(decoded_body_parameter_list, true);

    if(returned_parameters != NULL) {
        *returned_parameters = decoded_body_parameter_list;
    }

    /* --- The Ciphertext ---- */
    if(!q_useful_buf_c_is_null(detached_ciphertext)) {
        QCBORDecode_GetNull(&cbor_decoder);
        cipher_text = detached_ciphertext;
    } else {
        QCBORDecode_GetByteString(&cbor_decoder, &cipher_text);
    }

    if (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0) {

        /* --- No Recipients ---- */
        // TODO: need a mechanism to detect whether cek was set. This may be a change to the defintion of t_cose_key
        if(me->recipient_list != NULL) {
            return T_COSE_ERR_FAIL; // TODO: need better error here
        }
        // TODO: create example / test of using custom headers to check the kid here.
        cek_key = me->cek;

    } else if (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT) {

        /* ---- The recipients ---- */
        struct t_cose_header_location loc = {.nesting = 1,
                                             .index = 0};

        QCBORDecode_EnterArray(&cbor_decoder, NULL);

        /* Loop over recipients */
        while(1) {
            return_value = decrypt_one_recipient(me,
                                                 loc,
                                                 &cbor_decoder,
                                                 cek_buf,
                                                &decoded_recipient_params,
                                                 &cek);
            /* This will have consumed the CBOR of one recipient */

            if(return_value == T_COSE_SUCCESS) {
                break; /* One success is good enough. This is done. */
            }
            
            if(return_value != T_COSE_ERR_DECLINE) {
                /* Either we got to the end of the list and on recipient decoder
                 * attempted, or some decoder attemted and there was an error.
                 * TODO: a lot of testing to be sure this is suffiient.*/
                goto Done;;
            }

            /* Going on to try another recipient since this one
             * wasn't a success and wasn't a hard error -- all
             * recipient decoders declined to try it.
             */
            loc.index++;
        }

        /* Successfully decoded one recipient */
        QCBORDecode_ExitArray(&cbor_decoder);

        if(decoded_body_parameter_list == NULL) {
            decoded_body_parameter_list = decoded_recipient_params;
        } else {
            t_cose_parameter_list_append(decoded_body_parameter_list,
                                         decoded_recipient_params);
        }

        return_value = t_cose_crypto_make_symmetric_key_handle(algorithm_id,
                                                               cek,
                                                              &cek_key);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }

    } else {
        /* Message type is not right. */
        // TODO: better error here.
        return T_COSE_ERR_FAIL;
    }

    QCBORDecode_ExitArray(&cbor_decoder);

    cbor_error = QCBORDecode_Finish(&cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        // TODO: there is probably more to be done here...
        return_value = T_COSE_ERR_CBOR_DECODE;
        goto Done;
    }

    /* A lot of stuff is done now: 1) All the CBOR decoding is done, 2) we
     * have the CEK, 3) all the headers are decoded and in a linked list
     */


    /* --- Make the Enc_structure ---- */
    if(!q_useful_buf_is_null(me->extern_enc_struct_buffer)) {
        /* Caller gave us a (bigger) buffer for Enc_structure */
        enc_struct_buffer = me->extern_enc_struct_buffer;
    }
    return_value = create_enc_structure(message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0 ? "Encrypt0" : "Encrypt",
                         protected_parameters,
                         aad,
                         enc_struct_buffer,
                         &enc_structure);
    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* ---- The body decryption ---- */
    return_value = t_cose_crypto_aead_decrypt((int32_t) algorithm_id,
                                             cek_key,
                                             nonce_cbor,
                                             enc_structure,
                                             cipher_text,
                                             plaintext_buffer,
                                             plain_text);

Done:
    return return_value;
}



enum t_cose_err_t
t_cose_encrypt_dec(struct t_cose_encrypt_dec_ctx *me,
                   struct q_useful_buf_c          message,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf            plaintext_buffer,
                   struct q_useful_buf_c         *plaintext,
                   struct t_cose_parameter      **returned_parameters)
{
    return t_cose_encrypt_dec_detached(me,
                                       message,
                                       aad,
                                       NULL_Q_USEFUL_BUF_C,
                                       plaintext_buffer,
                                       plaintext,
                                       returned_parameters);
}
