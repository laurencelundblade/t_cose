/*
 * t_cose_key.c
 *
 * Copyright 2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Created by Laurence Lundblade on 2/6/23.
 *
 * See BSD-3-Clause license in README.md
 */
#include "t_cose/t_cose_key.h"
#include "t_cose_crypto.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"


/*
 * Public function. See t_cose_key.h
 */
enum t_cose_err_t
t_cose_key_init_symmetric(int32_t                cose_algorithm_id,
                          struct q_useful_buf_c  symmetric_key,
                          struct t_cose_key     *key)
{
    return  t_cose_crypto_make_symmetric_key_handle(cose_algorithm_id,
                                                    symmetric_key,
                                                    key);
}


/*
 * Public function. See t_cose_key.h
 */
void
t_cose_key_free_symmetric(struct t_cose_key key)
{
    t_cose_crypto_free_symmetric_key(key);
}



enum t_cose_err_t
t_cose_key_decode(struct q_useful_buf_c cbor_encoded,
                  struct t_cose_key     *key)
{
    QCBORDecodeContext cbor_decoder;
    int64_t  kty;
    int64_t  curve;
    struct q_useful_buf_c x;
    struct q_useful_buf_c y_string;
    bool y_bool;
    QCBORItem y;
    enum t_cose_err_t result;


    QCBORDecode_Init(&cbor_decoder, cbor_encoded, 0);


    QCBORDecode_EnterMap(&cbor_decoder, NULL);

    QCBORDecode_GetInt64InMapN(&cbor_decoder, T_COSE_KEY_COMMON_KTY, &kty);
    QCBORDecode_GetInt64InMapN(&cbor_decoder, T_COSE_KEY_PARAM_CRV, &curve);
    QCBORDecode_GetByteStringInMapN(&cbor_decoder, T_COSE_KEY_PARAM_X_COORDINATE, &x);
    QCBORDecode_GetItemInMapN(&cbor_decoder, T_COSE_KEY_PARAM_Y_COORDINATE, QCBOR_TYPE_ANY, &y);

    QCBORDecode_ExitMap(&cbor_decoder);
    if(QCBORDecode_GetError(&cbor_decoder)) {
        return T_COSE_ERR_FAIL; // TODO: is this right?
    }

    // TODO: check kty

    /* If y is a bool, then point compression is used and y is a boolean
     * indicating the sign. If not then it is a byte string with the y.
     * Anything else is an error. See RFC 9053 7.1.1.
     */
    switch(y.uDataType) {
        case QCBOR_TYPE_BYTE_STRING:
            y_string = y.val.string;
            y_bool = true; /* Unused. Only here to avoid compiler warning */
            break;

        case QCBOR_TYPE_TRUE:
            y_bool = true;
            y_string = NULL_Q_USEFUL_BUF_C;
            break;

        case QCBOR_TYPE_FALSE:
            y_bool = true;
            y_string = NULL_Q_USEFUL_BUF_C;
            break;

        default:
            return 77; // TODO: error code
    }

    /* Turn it into a t_cose_key that is imported into the library */

    if(curve > INT32_MAX || curve < INT32_MIN) {
        // Make sure cast is safe
        return T_COSE_ERR_FAIL; // TODO: error
    }
    result = t_cose_crypto_import_ec2_pubkey((int32_t)curve,
                                 x,
                                 y_string,
                                 y_bool,
                                 key);

    return result;
}
