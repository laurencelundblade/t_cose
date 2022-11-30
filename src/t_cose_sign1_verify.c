/*
 * t_cose_sign1_verify.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/t_cose_standard_constants.h"

/**
 * \file t_cose_sign1_verify.c
 *
 * \brief \c COSE_Sign1 verification compatibility layer over the t_cose_sign_verify which
 *        is now the main implementation of \c COSE_Sign1 and \c COSE_Sign.
 */


void
t_cose_sign1_verify_init(struct t_cose_sign1_verify_ctx *me,
                         uint32_t                        option_flags)
{
    t_cose_sign_verify_init(&(me->me2),
                            option_flags | T_COSE_OPT_MESSAGE_TYPE_SIGN1);
    me->option_flags = option_flags;

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    t_cose_signature_verify_short_init(&(me->short_circuit_verifier));
    t_cose_sign_add_verifier(&(me->me2),
                       t_cose_signature_verify_from_short(&(me->short_circuit_verifier)));
#endif
    t_cose_signature_verify_ecdsa_init(&(me->general_verifier));
    t_cose_sign_add_verifier(&(me->me2),
                       t_cose_signature_verify_from_ecdsa(&(me->general_verifier)));

    t_cose_signature_verify_eddsa_init(&(me->eddsa_verifier), option_flags);
    t_cose_sign_add_verifier(&(me->me2),
                       t_cose_signature_verify_from_eddsa(&(me->eddsa_verifier)));
}


void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *me,
                                  struct t_cose_key           verification_key)
{
    /* Set the same key for both. We don't know which verifier will be used
     * until decoding the input. There is only one key in t_cose_sign1(). */
    t_cose_signature_verify_eddsa_set_key(&(me->eddsa_verifier), verification_key);
    t_cose_signature_verify_ecdsa_set_key(&(me->general_verifier), verification_key);
}




void
t_cose_sign1_verify_set_auxiliary_buffer(struct t_cose_sign1_verify_ctx *me,
                                         struct q_useful_buf             auxiliary_buffer)
{
    t_cose_signature_verify_eddsa_set_auxiliary_buffer(&(me->eddsa_verifier), auxiliary_buffer);
}


size_t
t_cose_sign1_verify_auxiliary_buffer_size(struct t_cose_sign1_verify_ctx *me)
{
    return t_cose_signature_verify_eddsa_auxiliary_buffer_size(&(me->eddsa_verifier));
}
