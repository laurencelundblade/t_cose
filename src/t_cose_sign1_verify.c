/*
 *  t_cose_sign1_verify.c
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
    t_cose_sign_verify_init(&(me->me2), option_flags | T_COSE_OPT_COSE_SIGN1);
    me->option_flags = option_flags;

    t_cose_signature_verify_short_init(&(me->verifier_sc));
    t_cose_sign_add_verifier(&(me->me2),
                             t_cose_signature_verify_from_short(&(me->verifier_sc)));
}


void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *me,
                                  struct t_cose_key               verification_key)
{
    t_cose_signature_verify_ecdsa_init(&(me->verifier));
    t_cose_signature_verify_ecdsa_set_key(&(me->verifier), verification_key);
    t_cose_sign_add_verifier(&(me->me2),
                             t_cose_signature_verify_from_ecdsa(&(me->verifier)));
}


void
t_cose_translate_params_private(const struct t_cose_header_param *decoded_params,
                                struct t_cose_parameters   *returned_parameters)
{
    // TODO: some of these return errors -- need to distinguish absent parameters from errors
    returned_parameters->kid = t_cose_find_parameter_kid(decoded_params);
    returned_parameters->iv = t_cose_find_parameter_iv(decoded_params);
    returned_parameters->cose_algorithm_id = t_cose_find_parameter_alg_id(decoded_params);
    returned_parameters->partial_iv = t_cose_find_parameter_partial_iv(decoded_params);
#ifndef T_COSE_DISABLE_CONTENT_TYPE
    returned_parameters->content_type_uint = t_cose_find_parameter_content_type_int(decoded_params);
    returned_parameters->content_type_tstr = t_cose_find_parameter_content_type_tstr(decoded_params);
#endif /* T_COSE_DISABLE_CONTENT_TYPE */
}

