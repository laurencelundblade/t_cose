/*
 * t_cose_recipient_dec_aes_kw.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_DEC_AES_KW_H__
#define __T_COSE_RECIPIENT_DEC_AES_KW_H__

#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose_recipient_dec.h"

#ifdef __cplusplus
extern "C" {
#endif


struct t_cose_recipient_dec_keywrap {
     /* Private data structure */

     /* t_cose_recipient_dec must be the first item for the polymorphism to
       * work.  This structure, t_cose_recipient_enc_keywrap, will sometimes be
       * uses as a t_cose_recipient_enc.
       */
    struct t_cose_recipient_dec e;

    struct t_cose_key kek;
};


static void
t_cose_recipient_dec_keywrap_init(struct t_cose_recipient_dec_keywrap *context);


static void
t_cose_recipient_dec_keywrap_set_key(struct t_cose_recipient_dec_keywrap *context,
                                     struct t_cose_key key);


/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */


enum t_cose_err_t
t_cose_recipient_dec_kw_unwrap_cb_private(struct t_cose_recipient_dec        *me_x,
                                          const struct t_cose_header_location loc,
                                          QCBORDecodeContext                 *cbor_decoder,
                                          struct q_useful_buf                 cek_buffer,
                                          struct t_cose_parameter_storage    *p_storage,
                                          struct t_cose_parameter           **params,
                                          struct q_useful_buf_c              *cek);

static inline void
t_cose_recipient_dec_keywrap_init(struct t_cose_recipient_dec_keywrap *me)
{
    memset(me, 0, sizeof(*me));

    me->e.decode_cb = t_cose_recipient_dec_kw_unwrap_cb_private;
}



static inline void
t_cose_recipient_dec_keywrap_set_key(struct t_cose_recipient_dec_keywrap *me,
                                     struct t_cose_key key)
{
    me->kek = key;
}



/* Nothing so far */

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_DEC_AES_KW_H__ */
