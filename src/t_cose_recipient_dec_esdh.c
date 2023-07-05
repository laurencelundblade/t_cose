/*
 * t_cose_recipient_dec_esdh.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.

 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */


#include <stdint.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"  /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"


// TODO: this turns into a COSE_Key decoder
struct esdh_sender_info {
    uint64_t               kem_id;
    uint64_t               kdf_id;
    uint64_t               aead_id;
    struct q_useful_buf_c  enc;
};

static enum t_cose_err_t
esdh_sender_info_decode_cb(void                    *cb_context,
                            QCBORDecodeContext      *cbor_decoder,
                            struct t_cose_parameter *parameter)
{
    if(parameter->label != T_COSE_HEADER_ALG_PARAM_HPKE_SENDER_INFO) {
        return 0;
    }
    // TODO: this will have to cascade to an external supplied
    // special header decoder too
    struct esdh_sender_info  *sender_info = (struct esdh_sender_info  *)cb_context;

    QCBORDecode_EnterArray(cbor_decoder, NULL);
    QCBORDecode_GetUInt64(cbor_decoder, &(sender_info->kem_id));
    QCBORDecode_GetUInt64(cbor_decoder, &(sender_info->kdf_id));
    QCBORDecode_GetUInt64(cbor_decoder, &(sender_info->aead_id));
    QCBORDecode_GetByteString(cbor_decoder, &(sender_info->enc));
    QCBORDecode_ExitArray(cbor_decoder);
    if(QCBORDecode_GetError(cbor_decoder)) {
        sender_info->kem_id = UINT64_MAX; /* This indicates failure */
    }

    // TODO: more error handling
    return 0;
}


/* This is an implementation of t_cose_recipient_dec_cb */
enum t_cose_err_t
t_cose_recipient_dec_esdh_cb_private(struct t_cose_recipient_dec *me_x,
                                     const struct t_cose_header_location loc,
                                     const struct t_cose_alg_and_bits    ce_alg,
                                     QCBORDecodeContext *cbor_decoder,
                                     struct q_useful_buf cek_buffer,
                                     struct t_cose_parameter_storage *p_storage,
                                     struct t_cose_parameter **params,
                                     struct q_useful_buf_c *cek)
{
    struct t_cose_recipient_dec_esdh *me;
    QCBORError             result;
    int64_t                alg = 0;
    struct q_useful_buf_c  cek_encrypted;
    struct q_useful_buf_c  info_struct;
    struct q_useful_buf_c  kek;
    struct t_cose_key      kekx;
    struct q_useful_buf_c  derived_key;
    struct q_useful_buf_c  protected_params;
    enum t_cose_err_t      cose_result;
    struct esdh_sender_info  sender_info;
    int32_t                cose_key_wrap_alg;
    int32_t                kdf_hash_alg;
    const struct t_cose_parameter *salt_param;
    struct q_useful_buf_c  salt;
    struct t_cose_key      ephemeral_key;
    MakeUsefulBufOnStack(  kek_buffer ,T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH));

    MakeUsefulBufOnStack(  derived_secret_buf ,T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH)); // TODO: size this correctly
    MakeUsefulBufOnStack(info_buf, 50); // TODO: allow this to be
                                              // supplied externally

    me = (struct t_cose_recipient_dec_esdh *)me_x;

    // TODO: some of these will have to get used
    (void)ce_alg;

    /* One recipient */
    QCBORDecode_EnterArray(cbor_decoder, NULL);

    cose_result = t_cose_headers_decode(cbor_decoder, /* in: decoder to read from */
                                loc,          /* in: location in COSE message*/
                                esdh_sender_info_decode_cb, /* in: callback for specials */
                                &sender_info, /* in: context for callback */
                                p_storage,    /* in: parameter storage */
                                params,       /* out: list of decoded params */
                               &protected_params /* out: encoded prot params */
                                );
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Recipient array contains AES Key Wrap algorithm.
     * The KEK used to encrypt the CEK with AES-KW is then
     * found in an inner recipient array.
     */

    // TODO: put kid processing back in

    /* get CEK */
    QCBORDecode_GetByteString(cbor_decoder, &cek_encrypted);

    /* Close out decoding and error check */
    QCBORDecode_ExitArray(cbor_decoder);
    result = QCBORDecode_GetError(cbor_decoder);
    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }


    alg = t_cose_param_find_alg_id(*params, false);

    switch(alg) {
    case T_COSE_ALGORITHM_ECDH_ES_A128KW:
        kek_buffer.len = 128/8;
        cose_key_wrap_alg = T_COSE_ALGORITHM_A128KW;
        kdf_hash_alg = T_COSE_ALGORITHM_SHA_256;
        break;

    case T_COSE_ALGORITHM_ECDH_ES_A192KW:
        kek_buffer.len = 192/8;
        cose_key_wrap_alg = T_COSE_ALGORITHM_A192KW;
        kdf_hash_alg = T_COSE_ALGORITHM_SHA_256;
        break;

    case T_COSE_ALGORITHM_ECDH_ES_A256KW:
        kek_buffer.len = 256/8;
        cose_key_wrap_alg = T_COSE_ALGORITHM_A256KW;
        kdf_hash_alg = T_COSE_ALGORITHM_SHA_256;

        break;
    default:
        return T_COSE_ERR_UNSUPPORTED_CONTENT_KEY_DISTRIBUTION_ALG;
    }


    /* --- Run ECDH --- */
    /* Inputs: pub key, ephemeral key
     * Outputs: shared key */
    cose_result = t_cose_crypto_ecdh(me->skr, /* in: secret key */
                                     ephemeral_key, /* in: public key */
                                     derived_secret_buf, /* in: output buf */
                                     &derived_key /* out: derived key*/
                                     );
    if(cose_result != T_COSE_SUCCESS) {
         goto Done;
     }


    /* --- Make the info structure ---- */
    // TODO: make the info structure. Just set to 'x's for now
    info_struct = UsefulBuf_Set(info_buf, 'x');



    /* --- Run the HKDF --- */
    salt_param = t_cose_param_find(*params, -20); /* The salt parameter */ // TODO: constant for salt param label
    if(salt_param != NULL) {
        if(salt_param->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
            goto Done;
        }
        salt = salt_param->value.string;
    } else {
        salt = NULL_Q_USEFUL_BUF_C;
    }

    cose_result = t_cose_crypto_hkdf(kdf_hash_alg,
                                     salt, /* in: salt */
                                     derived_key, /* in: ikm */
                                     info_struct, /* in: info */
                                     kek_buffer); /* in/out: buffer and kek */
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }
    kek.ptr = kek_buffer.ptr;
    kek.len = kek_buffer.len;



    /* Perform key unrwap. */
    cose_result = t_cose_crypto_make_symmetric_key_handle(cose_key_wrap_alg,
                                                          kek,
                                                          &kekx);
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    cose_result = t_cose_crypto_kw_unwrap(
                        cose_key_wrap_alg, /* in: key wrap algorithm */
                        kekx, /* in: key encryption key */
                        cek_encrypted, /* in: encrypted CEK */
                        cek_buffer, /* in: buffer for CEK */
                        cek); /* out: the CEK*/

Done:
    return(cose_result);
}
