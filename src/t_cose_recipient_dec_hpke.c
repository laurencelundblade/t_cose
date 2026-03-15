/*
 * \file t_cose_recipient_dec_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2024, Hannes Tschofenig. All rights reserved.

 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef T_COSE_DISABLE_HPKE

#include <stdint.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_recipient_dec_hpke.h"  /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "hpke.h"
#include "t_cose_util.h"


// TODO: maybe rearrange this to align with what happens in crypto adaptor layer
struct hpke_sender_info {
    uint64_t               kem_id;
    uint64_t               kdf_id;
    uint64_t               aead_id;
    struct q_useful_buf_c  enc;
};

static enum t_cose_err_t
hpke_recipient_mode_from_message_psk(struct q_useful_buf_c message_psk_id,
                                     struct q_useful_buf_c configured_psk,
                                     struct q_useful_buf_c configured_psk_id,
                                     unsigned int         *mode,
                                     const uint8_t       **pskid_ptr,
                                     size_t               *pskid_len,
                                     unsigned char       **psk_ptr,
                                     size_t               *psk_len)
{
    if(q_useful_buf_c_is_null(message_psk_id)) {
        *mode = HPKE_MODE_BASE;
        *pskid_ptr = NULL;
        *pskid_len = 0;
        *psk_ptr = NULL;
        *psk_len = 0;
        return T_COSE_SUCCESS;
    }

    if(q_useful_buf_c_is_null(configured_psk) || configured_psk.len == 0) {
        return T_COSE_ERR_DECLINE;
    }

    if(!q_useful_buf_c_is_null(configured_psk_id) &&
       q_useful_buf_compare(configured_psk_id, message_psk_id)) {
        return T_COSE_ERR_DECLINE;
    }

    *mode = HPKE_MODE_PSK;
    *pskid_ptr = (const uint8_t *)message_psk_id.ptr;
    *pskid_len = message_psk_id.len;
    *psk_ptr = (unsigned char *)configured_psk.ptr;
    *psk_len = configured_psk.len;

    return T_COSE_SUCCESS;
}

/* This is an implementation of t_cose_recipient_dec_cb */
enum t_cose_err_t
t_cose_recipient_dec_hpke_cb_private(struct t_cose_recipient_dec *me_x,
                                     const struct t_cose_header_location loc,
                                     const struct t_cose_alg_and_bits      ce_alg,
                                     QCBORDecodeContext *cbor_decoder,
                                     struct q_useful_buf cek_buffer,
                                     struct t_cose_parameter_storage *p_storage,
                                     struct t_cose_parameter **params,
                                     struct q_useful_buf_c *cek)
{
    struct t_cose_recipient_dec_hpke *me;
    QCBORError             cbor_error;
    int64_t                alg = 0;
    UsefulBufC   cek_encrypted;
    struct q_useful_buf_c  protected_params;
    enum t_cose_err_t      cose_result;
    struct hpke_sender_info  sender_info;
    int                    psa_ret;
    hpke_suite_t           suite;
    size_t                 cek_len_in_out;
    unsigned int           mode;
    const uint8_t         *pskid_ptr;
    size_t                 pskid_len;
    unsigned char         *psk_ptr;
    size_t                 psk_len;
    UsefulBufC   kid;
    UsefulBufC   enc;
    const struct t_cose_parameter *psk_id_param;
    struct q_useful_buf_c  psk_id;
    // TODO: allow this to be supplied externally
     Q_USEFUL_BUF_MAKE_STACK_UB( recipient_struct_buf, T_COSE_RECIPIENT_STRUCT_DEFAULT_SIZE);

    struct q_useful_buf_c recipient_struct;
    struct q_useful_buf_c aad;

    me = (struct t_cose_recipient_dec_hpke *)me_x;

    (void)ce_alg; /* TODO: Still up for debate whether COSE-HPKE does COSE_KDF_Context or not. */

    /* One recipient */
    QCBORDecode_EnterArray(cbor_decoder, NULL);
    cbor_error = QCBORDecode_GetError(cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        goto Done;
    }

    cose_result = t_cose_headers_decode(cbor_decoder, /* in: decoder to read from */
                                loc,          /* in: location in COSE message*/
                                NULL,// hpke_encapsulated_key_decode_cb, /* in: callback for specials */
                                NULL, // &sender_info, /* in: context for callback */
                                p_storage,    /* in: parameter storage */
                                params,       /* out: list of decoded params */
                               &protected_params /* out: encoded prot params */
                                );
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }


    /* get CEK */
    QCBORDecode_GetByteString(cbor_decoder, &cek_encrypted);
//    uErr = QCBORDecode_GetAndResetError(cbor_decoder);
   
    /* Close out decoding and error check */
    QCBORDecode_ExitArray(cbor_decoder);
    cbor_error = QCBORDecode_GetError(cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        cose_result = qcbor_decode_error_to_t_cose_error(cbor_error,
                                                  T_COSE_ERR_RECIPIENT_FORMAT);
        goto Done;
    }

    /* Fetch algorithm id */
    alg = t_cose_param_find_alg_id_prot(*params);
    switch(alg) {
    case T_COSE_HPKE_Base_P256_SHA256_AES128GCM:
    case T_COSE_HPKE_KE_P256_SHA256_AES128GCM:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_P256;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128;
        break;
    case T_COSE_HPKE_Base_P256_SHA256_AES256GCM:
    case T_COSE_HPKE_KE_P256_SHA256_AES256GCM:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_P256;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        break;
    case T_COSE_HPKE_Base_P384_SHA384_AES256GCM:
    case T_COSE_HPKE_KE_P384_SHA384_AES256GCM:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_P384;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA384;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        break;
    case T_COSE_HPKE_Base_P521_SHA512_AES256GCM:
    case T_COSE_HPKE_KE_P521_SHA512_AES256GCM:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_P521;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        break;
    case T_COSE_HPKE_Base_X25519_SHA256_AES128GCM:
    case T_COSE_HPKE_KE_X25519_SHA256_AES128GCM:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_25519;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128;
        break;
    case T_COSE_HPKE_Base_X25519_SHA256_CHACHA20POLY1305:
    case T_COSE_HPKE_KE_X25519_SHA256_CHACHA20POLY1305:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_25519;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305;
        break;
    case T_COSE_HPKE_Base_X448_SHA512_AES256GCM:
    case T_COSE_HPKE_KE_X448_SHA512_AES256GCM:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_448;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        break;
    case T_COSE_HPKE_Base_X448_SHA512_CHACHA20POLY1305:
    case T_COSE_HPKE_KE_X448_SHA512_CHACHA20POLY1305:
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_448;
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305;
        break;
    default:
        /* Unsupported HPKE algorithm */
        cose_result = T_COSE_ERR_UNSUPPORTED_CONTENT_KEY_DISTRIBUTION_ALG;
        goto Done;
    }

    if(t_cose_params_empty(protected_params)) {
        cose_result = T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING;
        goto Done;
    }

    /* Fetch encapsulated key */
    enc = t_cose_param_find_enc(*params);
    if(q_useful_buf_c_is_null(enc)) {
        cose_result = T_COSE_ERR_FAIL;
        goto Done;
    }
//    sender_info.enc = enc_param->value.string;
    sender_info.enc = enc;

    /* Fetch kid, if present */
    kid = t_cose_param_find_kid(*params);
    if(!q_useful_buf_c_is_null(me->kid)) {
        if(q_useful_buf_c_is_null(kid)) {
            cose_result = T_COSE_ERR_NO_KID;
            goto Done;
        }
        if(q_useful_buf_compare(kid, me->kid)) {
            cose_result = T_COSE_ERR_KID_UNMATCHED;
            goto Done;
        }
    }

    psk_id = NULL_Q_USEFUL_BUF_C;
    psk_id_param = t_cose_param_find(*params, T_COSE_HEADER_PARAM_HPKE_PSK_ID);
    if(psk_id_param != NULL) {
        if(psk_id_param->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
            cose_result = T_COSE_ERR_PARAMETER_CBOR;
            goto Done;
        }
        if(!psk_id_param->in_protected) {
            cose_result = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
            goto Done;
        }
        psk_id = psk_id_param->value.string;
    }
    cose_result = hpke_recipient_mode_from_message_psk(psk_id, me->psk, me->psk_id,
                                                       &mode, &pskid_ptr, &pskid_len,
                                                       &psk_ptr, &psk_len);
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- Make the Recipient_structure ---- */
    cose_result =
        create_recipient_structure("HPKE Recipient",/* in: context string */
                              ce_alg.cose_alg_id,  /* in: next layer algorithm */
                              protected_params, /* in: CBOR encoded protected headers */
                              me->info, /* in: recipient_extra_info */
                              recipient_struct_buf,  /* in: output buffer */
                              &recipient_struct);  /* out: encoded Recipient_structure */

    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    // TODO: check that the sender_info decode happened correctly
    // before proceeding
    suite.aead_id = (uint16_t)sender_info.aead_id;
    suite.kdf_id = (uint16_t)sender_info.kdf_id;
    suite.kem_id = (uint16_t)sender_info.kem_id;

    cek_len_in_out = cek_buffer.len;

    aad = me->aad;
    if(q_useful_buf_c_is_null(aad)) {
        aad = (struct q_useful_buf_c){ "", 0 };
    }

    psa_ret = mbedtls_hpke_decrypt(
             mode,                            // HPKE mode
             suite,                           // ciphersuite
             pskid_len, pskid_ptr,            // psk id
             psk_len, psk_ptr,                // PSK for authentication
             0, NULL,                         // pkS
             (psa_key_handle_t)me->skr.key.handle, // skR handle
             sender_info.enc.len,                         // pkE_len
             sender_info.enc.ptr,                         // pkE
             cek_encrypted.len,                  // Ciphertext length
             cek_encrypted.ptr,                  // Ciphertext
        // TODO: fix the const-ness all the way down so the cast can be removed
             aad.len, (uint8_t *)(uintptr_t)aad.ptr, // AAD (optional, defaults to empty)
             recipient_struct.len,               // Info length
             (uint8_t *) recipient_struct.ptr,   // Info
             &cek_len_in_out,                   // Plaintext length
             cek_buffer.ptr                   // Plaintext
         );

     if (psa_ret != 0) {
         cose_result = T_COSE_ERR_HPKE_DECRYPT_FAIL;
         goto Done;
     }

    cek->ptr = cek_buffer.ptr;
    cek->len = cek_len_in_out;

Done:
    return(cose_result);
}

#else /* T_COSE_DISABLE_HPKE */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_dec_hpke_placeholder(void) {}

#endif /* T_COSE_DISABLE_HPKE */
