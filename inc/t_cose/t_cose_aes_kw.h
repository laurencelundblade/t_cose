/*
 * t_cose_aes_kw.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_AES_KW_H__
#define __T_COSE_AES_KW_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "t_cose_parameters.h"
#include "t_cose_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TBD */
enum t_cose_err_t t_cose_create_aes_kw_recipient(
                           struct t_cose_encrypt_recipient_ctx *context,
                           int32_t                              cose_algorithm_id,
                           struct t_cose_key                    recipient_key,
                           struct q_useful_buf_c                plaintext,
                           QCBOREncodeContext                  *encrypt_ctx);

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_AES_KW_H__ */
