/*
 * t_cose_encrypt_enc.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include <stdlib.h>
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_recipient_enc.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_recipient_enc_hpke.h" /* Interface implemented */

// For debugging purposes only
#include <stdio.h>

/* Local helper: minimal parameter encoding for HPKE integrated path
 * to avoid calling internal-only t_cose_params_encode().
 */
static enum t_cose_err_t
encode_param_entries_simple(QCBOREncodeContext            *cbor_encoder,
                            const struct t_cose_parameter *parameters,
                            bool                           is_protected_bucket)
{
    const struct t_cose_parameter *p_param;

    for(p_param = parameters; p_param != NULL; p_param = p_param->next) {
        if(is_protected_bucket && !p_param->in_protected) {
            continue;
        }
        if(!is_protected_bucket && p_param->in_protected) {
            continue;
        }

        switch(p_param->value_type) {
            case T_COSE_PARAMETER_TYPE_INT64:
                QCBOREncode_AddInt64ToMapN(cbor_encoder, p_param->label, p_param->value.int64);
                break;
            case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                QCBOREncode_AddTextToMapN(cbor_encoder, p_param->label, p_param->value.string);
                break;
            case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                QCBOREncode_AddBytesToMapN(cbor_encoder, p_param->label, p_param->value.string);
                break;
            case T_COSE_PARAMETER_TYPE_SPECIAL:
                if(p_param->value.special_encode.encode_cb) {
                    enum t_cose_err_t rv =
                        p_param->value.special_encode.encode_cb(p_param, cbor_encoder);
                    if(rv != T_COSE_SUCCESS) {
                        return rv;
                    }
                }
                break;
            default:
                return T_COSE_ERR_INVALID_PARAMETER_TYPE;
        }
    }
    return T_COSE_SUCCESS;
}


enum t_cose_err_t
t_cose_encrypt_enc_hpke_integrated(struct t_cose_encrypt_enc *me,
                                   struct q_useful_buf_c      payload,
                                   struct q_useful_buf_c      ext_sup_data,
                                   struct q_useful_buf        buffer_for_message,
                                   struct q_useful_buf_c     *encrypted_cose_message)
{
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    QCBOREncodeContext           cbor_encoder;
    unsigned                     message_type;

    struct t_cose_parameter      params_alg_only[1];
    struct q_useful_buf_c        body_prot_headers;
    struct q_useful_buf_c        enc_structure;
    Q_USEFUL_BUF_MAKE_STACK_UB(  enc_struct_buffer, T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE);
    const char                  *enc_struct_string;

    /* HPKE outputs */
    Q_USEFUL_BUF_MAKE_STACK_UB(  ct_tmp_buf, 0); /* not used directly */
    (void)ct_tmp_buf;

    /* For ek (encapsulated key) */
    Q_USEFUL_BUF_MAKE_STACK_UB(  ek_buf, 256); /* genug für typische enc sizes */
    struct q_useful_buf_c        ek = NULL_Q_USEFUL_BUF_C;

    /* ciphertext output */
    struct q_useful_buf          encrypt_buffer;
    uint8_t                     *ciphertext_mem = NULL;
    size_t                       ciphertext_len = 0;

    fprintf(stderr, "t_cose_encrypt_enc_hpke_integrated\n");

    /* ---- Figure out message type (must be Encrypt0 for Integrated Mode) ---- */
    message_type = T_COSE_OPT_MESSAGE_TYPE_MASK & me->option_flags;
    switch(message_type) {
        case T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED:
            message_type = T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0;
            break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0:
            break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT:
            /* Integrated Mode is ONLY for Encrypt0 and NO recipients */
            return T_COSE_ERR_BAD_OPT;
        default:
            return T_COSE_ERR_BAD_OPT;
    }

    /* Integrated Mode for Encrypt0 with HPKE requires exactly one recipient
     * providing the ephemeral key and recipient public key configuration.
     * This recipient is not serialized as a COSE_Recipient but used internally.
     */
    if(me->recipients_list == NULL) {
        return T_COSE_ERR_BAD_OPT;
    }

    /* ---- Protected header: alg only (must be protected if present) ---- */
    params_alg_only[0] = t_cose_param_make_alg_id(me->payload_cose_algorithm_id);
    params_alg_only[0].next = me->added_body_parameters;

    /* ---- Start CBOR encoding: COSE_Encrypt0 = [ protected, unprotected, ciphertext ] ---- */
    QCBOREncode_Init(&cbor_encoder, buffer_for_message);
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(&cbor_encoder, message_type);
    }
    QCBOREncode_OpenArray(&cbor_encoder);

    /* ---- Encode protected headers (bstr), unprotected will follow later ---- */
    QCBOREncode_BstrWrap(&cbor_encoder);
    QCBOREncode_OpenMap(&cbor_encoder);
    return_value = encode_param_entries_simple(&cbor_encoder,
                                               &params_alg_only[0],
                                               true);
    QCBOREncode_CloseMap(&cbor_encoder);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    QCBOREncode_CloseBstrWrap2(&cbor_encoder, false, &body_prot_headers);

    /* ---- Build Enc_structure for AAD with context "Encrypt0" ---- */
    if(!q_useful_buf_is_null(me->extern_enc_struct_buffer)) {
        enc_struct_buffer = me->extern_enc_struct_buffer;
    }
    enc_struct_string = "Encrypt0";

    return_value =
        create_enc_structure(enc_struct_string,
                             body_prot_headers,
                             ext_sup_data,
                             enc_struct_buffer,
                             &enc_structure);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* ---- Prepare info (default empty) ---- */
    struct q_useful_buf_c info = me->hpke_info;
    if(q_useful_buf_c_is_null(info)) {
        info = (struct q_useful_buf_c){ "", 0 };
    }
    struct q_useful_buf_c aad = (struct q_useful_buf_c){ "", 0 }; /* Draft-19 integrated: empty AAD */

    /* ---- Prepare ciphertext buffer for HPKE output ---- */
    /* Ciphertext is plaintext + tag; add margin for tag and potential padding */
    size_t ct_capacity = payload.len + 32; /* AEAD tags are small; 32 bytes is ample */
    ciphertext_mem = (uint8_t *)malloc(ct_capacity);
    if(ciphertext_mem == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    encrypt_buffer = (struct q_useful_buf){ ciphertext_mem, ct_capacity };
    ciphertext_len = ct_capacity;

    /* ---- Get the first HPKE recipient from the recipients_list ---- */
    struct t_cose_recipient_enc_hpke *hpke_recipient = NULL;
    if(me->recipients_list != NULL) {
        /* Cast the base recipient_enc to HPKE recipient
         * (assumes the recipients_list contains t_cose_recipient_enc_hpke items)
         */
        hpke_recipient = (struct t_cose_recipient_enc_hpke *)me->recipients_list;
    } else {
        /* No recipients configured */
        return T_COSE_ERR_BAD_OPT;
    }

    /*
     * Call HPKE wrapper:
     * - suite: derived from me->payload_cose_algorithm_id
     * - recipient_pub_key: hpke_recipient->recipient_pub_key (pkR)
     * - hpke_suite: hpke_recipient->hpke_suite
     * - aad: enc_structure
     * - info: info
     * - plaintext: payload
     * - ciphertext: encrypt_buffer
     */

    /* Use helper to generate ephemeral key, HPKE-seal the payload and
     * return the encapsulated key (ek) into ek_buf. */
    return_value = t_cose_recipient_enc_hpke_encrypt_for_encrypt0(
                        hpke_recipient,
                        aad,           /* aad (empty by default) */
                        info,          /* info (empty or provided) */
                        payload,
                        encrypt_buffer,
                        ek_buf,
                        &ek,
                        &ciphertext_len);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /*
     * ---- Unprotected header MUST contain 'ek' (enc) as bstr ----
     */
    if(q_useful_buf_c_is_null(ek) || ek.len == 0) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    QCBOREncode_OpenMap(&cbor_encoder);
    /* Any caller-supplied unprotected headers */
    return_value = encode_param_entries_simple(&cbor_encoder,
                                                &params_alg_only[0],
                                                false);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    QCBOREncode_AddBytesToMapN(&cbor_encoder,
                                T_COSE_HEADER_ALG_PARAM_HPKE_ENCAPSULATED_KEY,
                                ek);
    QCBOREncode_CloseMap(&cbor_encoder);

    /* ---- Ciphertext (3rd array item) ---- */
    QCBOREncode_AddBytes(&cbor_encoder,
                         (struct q_useful_buf_c){ ciphertext_mem, ciphertext_len });

    /* ---- Finish COSE array ---- */
    QCBOREncode_CloseArray(&cbor_encoder);
    cbor_err = QCBOREncode_Finish(&cbor_encoder, encrypted_cose_message);
    if(cbor_err != QCBOR_SUCCESS) {
        return qcbor_encode_error_to_t_cose_error(&cbor_encoder);
    }

    return_value = T_COSE_SUCCESS;

Done:
    if(ciphertext_mem != NULL) {
        free(ciphertext_mem);
    }
    return return_value;
}


/*
 * Pubilc Function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_encrypt_enc_detached(struct t_cose_encrypt_enc *me,
                            struct q_useful_buf_c      payload,
                            struct q_useful_buf_c      ext_sup_data,
                            struct q_useful_buf        buffer_for_detached,
                            struct q_useful_buf        buffer_for_message,
                            struct q_useful_buf_c     *encrypted_detached,
                            struct q_useful_buf_c     *encrypted_cose_message)
{
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    QCBOREncodeContext           cbor_encoder;
    unsigned                     message_type;
    struct q_useful_buf_c        nonce;
    struct t_cose_parameter      params[2]; /* 1 for Alg ID plus 1 for IV */
    struct q_useful_buf_c        body_prot_headers;
    struct q_useful_buf_c        enc_structure;
    struct t_cose_alg_and_bits   ce_alg;
    Q_USEFUL_BUF_MAKE_STACK_UB(  cek_buffer, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    struct q_useful_buf_c        cek_bytes;
    struct t_cose_key            cek_handle;
    Q_USEFUL_BUF_MAKE_STACK_UB(  nonce_buffer, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    Q_USEFUL_BUF_MAKE_STACK_UB(  enc_struct_buffer, T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE);
    const char                  *enc_struct_string;
    struct q_useful_buf          encrypt_buffer;
    struct q_useful_buf_c        encrypt_output;
    bool                         is_cose_encrypt0;
    bool                         is_non_aead_cipher;
    struct t_cose_recipient_enc *recipient;


    /* ---- Figure out the COSE message type ---- */
    message_type = T_COSE_OPT_MESSAGE_TYPE_MASK & me->option_flags;
    is_cose_encrypt0 = true;
    switch(message_type) {
        case T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED:
            message_type = T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0;
            break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0:
            break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT:
            is_cose_encrypt0 = false;
            break;
        default:
            return T_COSE_ERR_BAD_OPT;
    }

    /* ---- Algorithm ID, IV and parameter list ---- */
    /* Determine algorithm parameters */
    is_non_aead_cipher = t_cose_alg_is_non_aead(me->payload_cose_algorithm_id);
    if(is_non_aead_cipher && !q_useful_buf_c_is_null_or_empty(ext_sup_data)) {
        /* Section 6 of RFC9459 says,
        * COSE libraries that support either AES-CTR or AES-CBC and
        * accept Additional Authenticated Data (AAD) as input MUST return an error
        */
        return T_COSE_ERR_AAD_WITH_NON_AEAD;
    }

    ce_alg.cose_alg_id = me->payload_cose_algorithm_id;
    ce_alg.bits_in_key = bits_in_crypto_alg(ce_alg.cose_alg_id);
    ce_alg.bits_iv = bits_iv_alg(ce_alg.cose_alg_id);
    if(ce_alg.bits_in_key == UINT32_MAX) {
        return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }
    params[0] = is_non_aead_cipher ? t_cose_param_make_unprot_alg_id(ce_alg.cose_alg_id):
                                     t_cose_param_make_alg_id(ce_alg.cose_alg_id);


    /* Generate random nonce (aka iv) */
    return_value = t_cose_crypto_get_random(nonce_buffer,
                                            ce_alg.bits_iv / 8,
                                            &nonce);
    params[1] = t_cose_param_make_iv(nonce);

    params[0].next = &params[1];
    params[1].next = me->added_body_parameters;
    /* At this point all the header parameters to be encoded are in a
     * linked list the head of which is params[0]. */


    /* ---- Get started with the CBOR encoding ---- */
    QCBOREncode_Init(&cbor_encoder, buffer_for_message);
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(&cbor_encoder, message_type);
    }
    QCBOREncode_OpenArray(&cbor_encoder);


    /* ---- The body header parameters ---- */
    return_value = t_cose_headers_encode(&cbor_encoder, /* in: cbor encoder */
                                         &params[0],    /* in: param linked list */
                                         &body_prot_headers); /* out: bytes for CBOR-encoded protected params */
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* ---- Figure out the CEK ---- */
    if(is_cose_encrypt0) {
        /* For COSE_Encrypt0, the caller must have set the cek explicitly. */
        cek_handle = me->cek;
    } else {
        /* For COSE_Encrypt, a random key is generated (which will be
         * conveyed to the recipient by some key distribution method in
         * a COSE_Recipient). */
        return_value = t_cose_crypto_get_random(cek_buffer,
                                                ce_alg.bits_in_key / 8,
                                                &cek_bytes);
        if (return_value != T_COSE_SUCCESS) {
            goto Done;
        }
        return_value = t_cose_crypto_make_symmetric_key_handle(
                                    ce_alg.cose_alg_id, /* in: alg id */
                                    cek_bytes,          /* in: key bytes */
                                   &cek_handle);        /* out: key handle */
    }
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    /* At this point cek_handle has the encryption key for the AEAD */


    /* ---- Encrypt the payload, detached or not */
    if(q_useful_buf_is_null(buffer_for_detached)) {
        /* Set up so encryption writes directly to the output buffer to save lots
         * of memory since no intermediate buffer is needed!
         */
        QCBOREncode_OpenBytes(&cbor_encoder, &encrypt_buffer);
    } else {
        /* For detached, write to the buffer supplied by the caller. */
        encrypt_buffer = buffer_for_detached;
    }

    if(is_non_aead_cipher) {
        return_value =
            t_cose_crypto_non_aead_encrypt(ce_alg.cose_alg_id, /* in: non AEAD alg ID */
                                           cek_handle,     /* in: content encryption key handle */
                                           nonce,          /* in: nonce / IV */
                                           payload,        /* in: payload to encrypt */
                                           encrypt_buffer, /* in: buffer to write to */
                                          &encrypt_output  /* out: ciphertext */);
    } else {
        /* ---- Make the Enc_structure ---- */
        /* Per RFC 9052 section 5.3 this is the structure that is authenticated
         * along with the payload by the AEAD.
         *
         *  Enc_structure = [
         *    context : "Encrypt",
         *    protected : empty_or_serialized_map,
         *    external_aad : bstr
         *  ]
         */
        if(!q_useful_buf_is_null(me->extern_enc_struct_buffer)) {
            /* Caller gave us a (bigger) buffer for Enc_structure */
            enc_struct_buffer = me->extern_enc_struct_buffer;
        }
        enc_struct_string = is_cose_encrypt0 ? "Encrypt0" : "Encrypt";
        return_value =
            create_enc_structure(enc_struct_string, /* in: message context string */
                                 body_prot_headers, /* in: CBOR encoded prot hdrs */
                                 ext_sup_data,      /* in: external AAD */
                                 enc_struct_buffer, /* in: output buffer */
                                &enc_structure);    /* out: encoded Enc_structure */
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }

        return_value =
            t_cose_crypto_aead_encrypt(ce_alg.cose_alg_id, /* in: AEAD alg ID */
                                       cek_handle,     /* in: content encryption key handle */
                                       nonce,          /* in: nonce / IV */
                                       enc_structure,  /* in: AAD to authenticate */
                                       payload,        /* in: payload to encrypt */
                                       encrypt_buffer, /* in: buffer to write to */
                                      &encrypt_output  /* out: ciphertext */);
    }

    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(q_useful_buf_is_null(buffer_for_detached)) {
        QCBOREncode_CloseBytes(&cbor_encoder, encrypt_output.len);
    } else {
        QCBOREncode_AddNULL(&cbor_encoder);
        *encrypted_detached = encrypt_output;
    }

    /* ---- COSE_Recipients for COSE_Encrypt message ---- */
    if ( !is_cose_encrypt0 ) {
        for(recipient = me->recipients_list;
            recipient != NULL;
            recipient = recipient->next_in_list) {

            /* Array holding the COSE_Recipients */
            QCBOREncode_OpenArray(&cbor_encoder);

            /* Do the public key crypto and output a COSE_Recipient */
            /* cek_bytes is not uninitialized here despite what some
             * compilers think. It is a waste of code to put in an
             * unneccessary initialization for them. */
            return_value = recipient->creat_cb(recipient,
                                               cek_bytes,
                                               ce_alg,
                                              &cbor_encoder);
            if(return_value) {
                goto Done;
            }

            QCBOREncode_CloseArray(&cbor_encoder);
        }
        t_cose_crypto_free_symmetric_key(cek_handle);
    }

     /* ---- Close out the CBOR encoding ---- */
    QCBOREncode_CloseArray(&cbor_encoder);
    cbor_err = QCBOREncode_Finish(&cbor_encoder, encrypted_cose_message);
    if (cbor_err != QCBOR_SUCCESS) {
        return qcbor_encode_error_to_t_cose_error(&cbor_encoder);
    }

Done:
    return return_value;
}
