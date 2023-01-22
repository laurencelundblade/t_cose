/*
 * t_cose_recipient_enc_aes_kw.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
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
    /* Private data structure */

    /* t_cose_recipient_enc must be the first item for the polymorphism to
      * work.  This structure, t_cose_recipient_enc_keywrap, will sometimes be
      * uses as a t_cose_recipient_enc.
      */
    struct t_cose_recipient_enc e;

    int32_t               keywrap_cose_algorithm_id;
    struct t_cose_key     wrapping_key;
    struct q_useful_buf_c kid;
};


/**
 * @brief Initialize the creator COSE_Recipient for keywrap content key distribution.

 * @param[in]  keywrap_cose_algorithm_id  The key wrap algorithm ID.
 *
 * This must be called not only to set the key wrap algorithm ID, but also because
 * this sets up the callbacks in the t_cose_recipient_enc_keywrap. That is when
 * all the real work of keywrapping gets done.
 *
 * This typically only supports AES key wrap.
 *
 * If an unknown algortihm ID is passed, the error will occur when t_cose_encrypt_enc() is
 * called and the error code will be returned there.
 */
static void
t_cose_recipient_enc_keywrap_init(struct t_cose_recipient_enc_keywrap *me,
                                  int32_t                              keywrap_cose_algorithm_id);


/**
 * @brief Sets the wrapping key to use.
 *
 * The key must be usable with the key wrap algorithm passed to t_cose_recipient_enc_keywrap_init() The
 * kid is optional.
 */
static void
t_cose_recipient_enc_keywrap_set_key(struct t_cose_recipient_enc_keywrap *me,
                                     struct t_cose_key                    wrapping_key,
                                     struct q_useful_buf_c                kid);




/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */

/* Private function referenced by inline implementation. */
enum t_cose_err_t
t_cose_recipient_create_keywrap_cb_private(struct t_cose_recipient_enc  *me_x,
                                           struct q_useful_buf_c         plaintext,
                                           QCBOREncodeContext           *cbor_encoder);


static inline void
t_cose_recipient_enc_keywrap_init(struct t_cose_recipient_enc_keywrap *me,
                                  int32_t                              cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->e.creat_cb = t_cose_recipient_create_keywrap_cb_private;
    me->keywrap_cose_algorithm_id = cose_algorithm_id;
}



static inline void
t_cose_recipient_enc_keywrap_set_key(struct t_cose_recipient_enc_keywrap *me,
                                     struct t_cose_key wrapping_key,
                                     struct q_useful_buf_c kid)
{
    me->wrapping_key = wrapping_key;
    me->kid          = kid;
}
#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_AES_KW_H__ */
