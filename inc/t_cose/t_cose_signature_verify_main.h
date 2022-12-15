/*
 * t_cose_signature_verify_main.h
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 7/22/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_signature_verify_main_h
#define t_cose_signature_verify_main_h

#include "t_cose/t_cose_signature_verify.h"
#include "t_cose_parameters.h"


/* Warning: this is still early development. Documentation may be incorrect. */


/**
 * Verification context. */
struct t_cose_signature_verify_main {
    /* Private data structure */

    /* t_cose_signature_verify must be the first item for the polymorphism to work.
     * This structure, t_cose_signature_verify_main, will sometimes be uses as
     * a t_cose_signature_verify.
     */
    struct t_cose_signature_verify  s;
    struct t_cose_key               verification_key;
    t_cose_parameter_decode_cb     *param_decode_cb;
    void                           *param_decode_cb_context;
};


void
t_cose_signature_verify_main_init(struct t_cose_signature_verify_main *me);


static void
t_cose_signature_verify_main_set_key(struct t_cose_signature_verify_main *me,
                                      struct t_cose_key verification_key);

static void
t_cose_signature_verify_main_set_param_decoder(struct t_cose_signature_verify_main *me,
                                               t_cose_parameter_decode_cb         *decode_cb,
                                               void                               *decode_cb_context);

static struct t_cose_signature_verify *
t_cose_signature_verify_from_main(struct t_cose_signature_verify_main *context);




/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

static inline void
t_cose_signature_verify_main_set_key(struct t_cose_signature_verify_main *me,
                                      struct t_cose_key verification_key)
{
    me->verification_key = verification_key;
}


static inline void
t_cose_signature_verify_main_set_param_decoder(struct t_cose_signature_verify_main *me,
                                                t_cose_parameter_decode_cb         *decode_cb,
                                                void                               *decode_cb_context)
{
    me->param_decode_cb         = decode_cb;
    me->param_decode_cb_context = decode_cb_context;
}


static inline struct t_cose_signature_verify *
t_cose_signature_verify_from_main(struct t_cose_signature_verify_main *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}

#endif /* t_cose_signature_verify_main_h */
