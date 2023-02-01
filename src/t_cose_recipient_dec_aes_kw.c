/**
 * \file t_cose_recipient_dec_aes_kw.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#include "t_cose/t_cose_recipient_dec_aes_kw.h" /* Interface implemented */
#include <stdint.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"



enum t_cose_err_t
t_cose_recipient_dec_kw_unwrap_cb_private(struct t_cose_recipient_dec *me_x,
                                          const struct t_cose_header_location loc,
                                          QCBORDecodeContext *cbor_decoder,
                                          struct q_useful_buf cek_buffer,
                                          struct t_cose_parameter_storage *p_storage,
                                          struct t_cose_parameter **params,
                                          struct q_useful_buf_c *cek)
{
    struct q_useful_buf_c  ciphertext;
    struct q_useful_buf_c  protected_params;
    enum t_cose_err_t      err;
    int32_t                cose_algorithm_id;
    QCBORError             cbor_error;

    struct t_cose_recipient_dec_keywrap *me = (struct t_cose_recipient_dec_keywrap *)me_x;


    QCBORDecode_EnterArray(cbor_decoder, NULL);

    // TODO: header decode call backs
    *params = NULL;
    err = t_cose_headers_decode(cbor_decoder,
                                loc,
                                NULL,
                                NULL,
                                p_storage,
                                params,
                               &protected_params);
    if(err != T_COSE_SUCCESS) {
        goto Done;
    }

    if(!q_useful_buf_c_is_empty(protected_params)) {
        return T_COSE_ERR_PUBLIC_KEY_EXPORT_FAILED;
    }

    QCBORDecode_GetByteString(cbor_decoder, &ciphertext);
    QCBORDecode_ExitArray(cbor_decoder);
    cbor_error = QCBORDecode_GetError(cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        return qcbor_decode_error_to_t_cose_error(cbor_error, T_COSE_ERR_RECIPIENT_FORMAT);
    }

    cose_algorithm_id = t_cose_find_parameter_alg_id(*params);

    err = t_cose_crypto_kw_unwrap(cose_algorithm_id,
                                  me->kek,
                                  ciphertext,
                                  cek_buffer,
                                  cek);

Done:
    return err;
}

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_dec_aes_kw_placeholder(void) {}

/* Nothing so far */

