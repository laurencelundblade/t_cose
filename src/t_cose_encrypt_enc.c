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

static enum t_cose_err_t
hpke_sender_mode_from_psk(struct q_useful_buf_c psk,
                          struct q_useful_buf_c psk_id,
                          bool                 *use_psk)
{
    const bool have_psk_id = !q_useful_buf_c_is_null(psk_id);
    const bool have_psk = !q_useful_buf_c_is_null(psk) && psk.len != 0;

    if(have_psk_id && !have_psk) {
        return T_COSE_ERR_INVALID_ARGUMENT;
    }
    if(have_psk && !have_psk_id) {
        return T_COSE_ERR_INVALID_ARGUMENT;
    }

    *use_psk = have_psk_id;
    return T_COSE_SUCCESS;
}

static struct t_cose_parameter
t_cose_param_make_hpke_psk_id_protected(struct q_useful_buf_c psk_id)
{
    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = true;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = T_COSE_HEADER_PARAM_HPKE_PSK_ID;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    parameter.value.string     = psk_id;
    parameter.next             = NULL;

    return parameter;
}

static struct t_cose_parameter *
build_hpke_encrypt0_header_params(struct t_cose_parameter       *local_params,
                                  int32_t                        payload_alg_id,
                                  struct q_useful_buf_c          psk_id,
                                  struct q_useful_buf_c          kid,
                                  struct q_useful_buf_c          ek,
                                  struct t_cose_parameter       *added_params)
{
    struct t_cose_parameter *params_list = NULL;
    size_t                   param_index = 0;

    local_params[param_index] = t_cose_param_make_alg_id(payload_alg_id);
    t_cose_params_append(&params_list, &local_params[param_index]);
    param_index++;

    if(!q_useful_buf_c_is_null(psk_id)) {
        local_params[param_index] = t_cose_param_make_hpke_psk_id_protected(psk_id);
        t_cose_params_append(&params_list, &local_params[param_index]);
        param_index++;
    }

    if(!q_useful_buf_c_is_null(kid)) {
        local_params[param_index] = t_cose_param_make_kid(kid);
        t_cose_params_append(&params_list, &local_params[param_index]);
        param_index++;
    }

    if(!q_useful_buf_c_is_null(ek)) {
        local_params[param_index] = t_cose_param_make_encapsulated_key(ek);
        t_cose_params_append(&params_list, &local_params[param_index]);
    }

    t_cose_params_append(&params_list, added_params);

    return params_list;
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
    QCBOREncodeContext           header_encoder;
    unsigned                     message_type;

    struct t_cose_parameter      header_params[4];
    struct t_cose_parameter     *header_params_list;
    struct q_useful_buf_c        body_prot_headers;
    struct q_useful_buf_c        encoded_headers;
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
    bool                         use_psk = false;
    struct q_useful_buf_c        info;
    struct q_useful_buf_c        aad;
    size_t                       ct_capacity;
    struct t_cose_recipient_enc_hpke *hpke_recipient = NULL;

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

    /* ---- Get the first HPKE recipient from the recipients_list ---- */
    if(me->recipients_list != NULL) {
        /* Cast the base recipient_enc to HPKE recipient
         * (assumes the recipients_list contains t_cose_recipient_enc_hpke items)
         */
        hpke_recipient = (struct t_cose_recipient_enc_hpke *)me->recipients_list;
    } else {
        /* No recipients configured */
        return T_COSE_ERR_BAD_OPT;
    }

    return_value = hpke_sender_mode_from_psk(hpke_recipient->psk,
                                             hpke_recipient->psk_id,
                                             &use_psk);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    header_params_list = build_hpke_encrypt0_header_params(header_params,
                                                           me->payload_cose_algorithm_id,
                                                           use_psk ? hpke_recipient->psk_id : NULL_Q_USEFUL_BUF_C,
                                                           hpke_recipient->kid,
                                                           NULL_Q_USEFUL_BUF_C,
                                                           me->added_body_parameters);

    /* Pre-encode the headers to obtain the exact protected header bstr for HPKE AAD. */
    QCBOREncode_Init(&header_encoder, buffer_for_message);
    return_value = t_cose_headers_encode(&header_encoder,
                                         header_params_list,
                                         &body_prot_headers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    cbor_err = QCBOREncode_Finish(&header_encoder, &encoded_headers);
    if(cbor_err != QCBOR_SUCCESS) {
        return_value = qcbor_encode_error_to_t_cose_error(&header_encoder);
        goto Done;
    }

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
    info = me->hpke_info;
    if(q_useful_buf_c_is_null(info)) {
        info = (struct q_useful_buf_c){ "", 0 };
    }
    /* Draft-19 requires HPKE AAD to be the Enc_structure (with external_aad) */
    aad = enc_structure;

    /* ---- Prepare ciphertext buffer for HPKE output ---- */
    /* Ciphertext is plaintext + tag; add margin for tag and potential padding */
    ct_capacity = payload.len + 32; /* AEAD tags are small; 32 bytes is ample */
    ciphertext_mem = (uint8_t *)malloc(ct_capacity);
    if(ciphertext_mem == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    encrypt_buffer = (struct q_useful_buf){ ciphertext_mem, ct_capacity };
    ciphertext_len = ct_capacity;

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
                        aad,           /* aad */
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

    header_params_list = build_hpke_encrypt0_header_params(header_params,
                                                           me->payload_cose_algorithm_id,
                                                           use_psk ? hpke_recipient->psk_id : NULL_Q_USEFUL_BUF_C,
                                                           hpke_recipient->kid,
                                                           ek,
                                                           me->added_body_parameters);

    /* ---- Start CBOR encoding: COSE_Encrypt0 = [ protected, unprotected, ciphertext ] ---- */
    QCBOREncode_Init(&cbor_encoder, buffer_for_message);
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(&cbor_encoder, message_type);
    }
    QCBOREncode_OpenArray(&cbor_encoder);

    return_value = t_cose_headers_encode(&cbor_encoder,
                                         header_params_list,
                                         &body_prot_headers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

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
