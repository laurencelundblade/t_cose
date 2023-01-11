/*
 * t_cose_recipient_enc_aes_kw.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_ENC_AES_KW_H__
#define __T_COSE_RECIPIENT_ENC_AES_KW_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "t_cose_parameters.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_recipient_enc.h"

#ifdef __cplusplus
extern "C" {
#endif


struct t_cose_recipient_enc_keywrap {
    struct t_cose_recipient_enc e;

    int32_t cose_algorithm_id;
    struct t_cose_key wrapping_key;
    struct q_useful_buf_c kid;
};





enum t_cose_err_t
t_cose_recipient_enc_keywrap_init(struct t_cose_recipient_enc_keywrap *me,
                                  int32_t                              cose_algoroithm_id);


enum t_cose_err_t
t_cose_recipient_enc_keywrap_set_recipient_key(struct t_cose_recipient_enc_keywrap *me,
                                               struct t_cose_key wrapping_key,
                                               struct q_useful_buf_c kid);


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_AES_KW_H__ */
