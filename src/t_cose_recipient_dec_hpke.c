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
    QCBORError             result;
    QCBORError             cbor_error;
    int64_t                alg = 0;
    UsefulBufC   cek_encrypted;
    struct q_useful_buf_c  protected_params;
    enum t_cose_err_t      cose_result;
    struct hpke_sender_info  sender_info;
    int                    psa_ret;
    bool prot;
    const struct t_cose_parameter *enc_param;
//    const struct t_cose_parameter *kid_param;
    UsefulBufC   kid;
    UsefulBufC   enc;
 //   QCBORError         uErr;

    MakeUsefulBufOnStack(enc_struct_buf, 50); // TODO: allow this to be
                                              // supplied externally
    struct q_useful_buf_c enc_struct;

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
    if (alg == T_COSE_HPKE_Base_P256_SHA256_AES128GCM) {
        sender_info.kem_id = T_COSE_HPKE_KEM_ID_P256;          /* kem id */
        //cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256; /* curve */
        sender_info.kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA256;   /* kdf id */
        sender_info.aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128; /* aead id */        
    } else {
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



    /* --- Make the Enc_structure ---- */
    cose_result = create_enc_structure("Enc_Recipient", /* in: context string */
                         protected_params,
                         NULL_Q_USEFUL_BUF_C, /* in: Externally supplied AAD */
                         enc_struct_buf,
                         &enc_struct);
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    // TODO: There is a big rearrangement necessary when the crypto adaptation
    // layer calls for HPKE are sorted out. Lots of work to complete that...
    hpke_suite_t     suite;
    size_t           cek_len_in_out;

    // TODO: check that the sender_info decode happened correctly
    // before proceeding
    suite.aead_id = (uint16_t)sender_info.aead_id;
    suite.kdf_id = (uint16_t)sender_info.kdf_id;
    suite.kem_id = (uint16_t)sender_info.kem_id;

    cek_len_in_out = cek_buffer.len;

    psa_ret = mbedtls_hpke_decrypt(
             HPKE_MODE_BASE,                  // HPKE mode
             suite,                           // ciphersuite
             NULL, 0, NULL,                   // PSK for authentication
             0, NULL,                         // pkS
             (psa_key_handle_t)me->skr.key.handle, // skR handle
             sender_info.enc.len,                         // pkE_len
             sender_info.enc.ptr,                         // pkE
             cek_encrypted.len,                  // Ciphertext length
             cek_encrypted.ptr,                  // Ciphertext
        // TODO: fix the const-ness all the way down so the cast can be removed
             0, NULL, // enc_struct.len, (uint8_t *)(uintptr_t)enc_struct.ptr,   // AAD
             0, NULL,                         // Info
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
