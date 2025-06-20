/**
 * \file t_cose_recipient_enc_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2024, Hannes Tschofenig. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef T_COSE_DISABLE_HPKE

#include <stdint.h>
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_recipient_enc.h"
#include "t_cose/t_cose_recipient_enc_hpke.h" /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "hpke.h"
#include "t_cose_util.h"


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
                           struct t_cose_key                  recipient_pub_key,
                           struct t_cose_key                  pkE,
                           struct q_useful_buf_c              aad,
                           struct q_useful_buf_c              plaintext,
                           struct q_useful_buf                ciphertext,
                           size_t                             *ciphertext_len)
{
    int             ret;
    hpke_suite_t    hpke_suite;
    struct q_useful_buf_c              pkR;
    enum t_cose_err_t      result;
    int32_t                cose_curve;
    MakeUsefulBufOnStack(  x_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    MakeUsefulBufOnStack(  y_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    Q_USEFUL_BUF_MAKE_STACK_UB(x_y_coord_buf, 2*T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS)+1);

    struct q_useful_buf_c  x_coord;
    struct q_useful_buf_c  y_coord;
    bool                   y_sign;

    hpke_suite.aead_id = suite.aead_id;
    hpke_suite.kdf_id = suite.kdf_id;
    hpke_suite.kem_id = suite.kem_id;

    result = t_cose_crypto_export_ec2_key(recipient_pub_key,
                                         &cose_curve,
                                          x_coord_buf,
                                         &x_coord,
                                          y_coord_buf,
                                         &y_coord,
                                         &y_sign);
    if(result != T_COSE_SUCCESS) {
        return result;
    }

    memset(x_y_coord_buf.ptr, 0x04, x_coord.len + y_coord.len + 1);
    memcpy(x_y_coord_buf.ptr + 1, x_coord.ptr, x_coord.len);
    memcpy(x_y_coord_buf.ptr + 1 + x_coord.len, y_coord.ptr, y_coord.len);

    ret = mbedtls_hpke_encrypt(
            HPKE_MODE_BASE,                     // HPKE mode
            hpke_suite,                         // ciphersuite
            NULL, 0, NULL,                      // PSK
            x_coord.len + y_coord.len + 1,          // pkR length
            x_y_coord_buf.ptr,                      // pkR
            0,                                  // skI
            plaintext.len,                      // plaintext length
            plaintext.ptr,                      // plaintext
            //TODO: fix the const-ness all the way down so this cast can go away
            0, NULL, // aad.len, (uint8_t *)(uintptr_t)aad.ptr,         // Additional data
            0, NULL,                            // Info
            (psa_key_handle_t)
            pkE.key.handle,                   // skE handle
            0, NULL,                            // pkE
            ciphertext_len,                     // ciphertext length
            (uint8_t *) ciphertext.ptr);        // ciphertext

    if (ret != 0) {
        return(T_COSE_ERR_HPKE_ENCRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}

/*
 * See documentation in t_cose_recipient_enc_hpke.h
 */
enum t_cose_err_t
t_cose_recipient_create_hpke_cb_private(struct t_cose_recipient_enc  *me_x,
                                        struct q_useful_buf_c         cek,
                                        struct t_cose_alg_and_bits    ce_alg,
                                        QCBOREncodeContext           *cbor_encoder)
{
    struct q_useful_buf_c  protected_params;
    uint8_t                encrypted_cek[T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH)];
    size_t                 encrypted_cek_len = T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    struct q_useful_buf_c  cek_encrypted_cbor;
    enum t_cose_err_t      return_value;
    struct t_cose_key      ephemeral_key;
    MakeUsefulBufOnStack(  enc_struct_buf, 100); // TODO: allow this to be
                                                // supplied externally
    struct q_useful_buf_c  enc_struct;
    struct t_cose_recipient_enc_hpke *context;
    struct q_useful_buf_c   header;
//    Q_USEFUL_BUF_MAKE_STACK_UB(    enc_struct_buffer, T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE);

    struct t_cose_parameter params[3];
    struct t_cose_parameter *params2;
    struct t_cose_parameter *params_tail;

    int32_t                cose_curve;
    MakeUsefulBufOnStack(  x_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    MakeUsefulBufOnStack(  y_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    Q_USEFUL_BUF_MAKE_STACK_UB(x_y_coord_buf, 2*T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS)+1);
    struct q_useful_buf_c  x_coord;
    struct q_useful_buf_c  y_coord;
    bool                   y_sign;

    context = (struct t_cose_recipient_enc_hpke *)me_x;

    (void)ce_alg; /* TODO: Still up for debate whether COSE-HPKE does COSE_KDF_Context or not. */

    /* Create COSE_recipient array */
    QCBOREncode_OpenArray(cbor_encoder);

    /* Create ephemeral key */
    return_value = t_cose_crypto_generate_ec_key(context->cose_ec_curve_id, &ephemeral_key);

    if (return_value != T_COSE_SUCCESS) {
        goto done;
    }

    return_value = t_cose_crypto_export_ec2_key(ephemeral_key,
                                         &cose_curve,
                                          x_coord_buf,
                                         &x_coord,
                                          y_coord_buf,
                                         &y_coord,
                                         &y_sign);
    if(return_value != T_COSE_SUCCESS) {
        goto done_free_ec;
    }

    memset(x_y_coord_buf.ptr, 0x04, 1);
    memcpy(x_y_coord_buf.ptr + 1, x_coord.ptr, x_coord.len);
    memcpy(x_y_coord_buf.ptr + 1 + x_coord.len, y_coord.ptr, y_coord.len);
    x_y_coord_buf.len = 1 + x_coord.len + y_coord.len;

    /* ---- Make list of the header parameters and encode them ---- */
    
    /* Alg ID param */
    params[0]  = t_cose_param_make_alg_id(context->cose_algorithm_id);
    params_tail = &params[0];

    /* Enc param */
    params[1] = t_cose_param_make_encapsulated_key(
                                    (struct q_useful_buf_c)
                                    {.ptr = x_y_coord_buf.ptr, .len = x_y_coord_buf.len});

    params_tail->next = &params[1];
    params_tail       = params_tail->next;

    /* Optional kid param */
    if(!q_useful_buf_c_is_null(context->kid)) {
        params[2]         = t_cose_param_make_kid(context->kid);
        params_tail->next = &params[2];
        params_tail       = params_tail->next;
    }

    /* Custom params from caller */
    params2 = params;
    t_cose_params_append(&params2, context->added_params);

    /* List complete, do the actual encode */
    return_value = t_cose_headers_encode(cbor_encoder,
                                         params2,
                                         &header);

    if(return_value) {
        goto done_free_ec;
    }

    /* --- Make the Enc_structure ---- */
    return_value =
        create_enc_structure("Enc_Recipient",/* in: context string */
                              header, /* in: CBOR encoded headers */
                              NULL_Q_USEFUL_BUF_C, /* in: Externally supplied AAD */
                              enc_struct_buf,  /* in: output buffer */
                              &enc_struct);    /* out: encoded Enc_structure */

    if (return_value != T_COSE_SUCCESS) {
        goto done_free_ec;
    }

    /* --- HPKE encryption of the CEK ---- */
    return_value = t_cose_crypto_hpke_encrypt(
                        context->hpke_suite,
                        context->recipient_pub_key,
                        ephemeral_key,
                        enc_struct,
                        cek,
                        (struct q_useful_buf) {.ptr = encrypted_cek,
                                               .len = encrypted_cek_len},
                        &encrypted_cek_len);

    if (return_value != T_COSE_SUCCESS) {
        goto done_free_ec;
    }

    /* Convert to UsefulBufC structure */
//    cek_encrypted_cbor.len = encrypted_cek_len;
//    cek_encrypted_cbor.ptr = encrypted_cek;

    /* Add encrypted CEK */
    QCBOREncode_AddBytes(cbor_encoder, 
                        (struct q_useful_buf_c) {.ptr = encrypted_cek,
                                                 .len = encrypted_cek_len});

    /* Close recipient array */
    QCBOREncode_CloseArray(cbor_encoder);

    return_value = T_COSE_SUCCESS;

done_free_ec:
    t_cose_crypto_free_ec_key(ephemeral_key);

done:
    return(return_value);
}


#else

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_enc_hpke_placeholder(void) {}

#endif /* T_COSE_DISABLE_HPKE */
