/*
 * t_cose_sign1_verify.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_util.h"

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

    t_cose_signature_verify_main_init(&(me->main_verifier));
    t_cose_sign_add_verifier(&(me->me2),
                       t_cose_signature_verify_from_main(&(me->main_verifier)));

    t_cose_signature_verify_eddsa_init(&(me->eddsa_verifier), option_flags);
    t_cose_sign_add_verifier(&(me->me2),
                    t_cose_signature_verify_from_eddsa(&(me->eddsa_verifier)));
}


void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *me,
                                  struct t_cose_key           verification_key)
{
    /* Set the same key for both. We don't know which verifier will be used
     * until decoding the input. There is only one key in t_cose_sign1().
     * Also, t_cose_sign1 didn't do any kid matching, so it is NULL here.
     */
    t_cose_signature_verify_eddsa_set_key(&(me->eddsa_verifier),
                                          verification_key,
                                          // TODO: should this be NULL?
                                          NULL_Q_USEFUL_BUF_C);
    t_cose_signature_verify_main_set_key(&(me->main_verifier),
                                         verification_key,
                                         NULL_Q_USEFUL_BUF_C);
}



/**
 * \brief Copy tags for t_cose v1 compatibility.
 *
 * \param[in] me                 The verification context.
 * \param[in] cbor_decoder     The decoder context to pull from.
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 */
static enum t_cose_err_t
copy_tags(struct t_cose_sign1_verify_ctx *me, QCBORDecodeContext *cbor_decoder)
{
    QCBORError  cbor_error;
    QCBORItem   item;
    uint64_t    uTag;
    uint32_t    item_tag_index = 0;
    int         returned_tag_index;

    cbor_error = QCBORDecode_PeekNext(cbor_decoder, &item);
    if(cbor_error) {
        return qcbor_decode_error_to_t_cose_error(cbor_error, T_COSE_ERR_SIGN1_FORMAT);
    }

    /* Initialize auTags, the returned tags, to CBOR_TAG_INVALID64 */
#if CBOR_TAG_INVALID64 != 0xffffffffffffffff
#error Initializing return tags array
#endif
    returned_tag_index = 0;
    memset(me->auTags, 0xff, sizeof(me->auTags));

    for(item_tag_index = 0; ; item_tag_index++) {
        uTag = QCBORDecode_GetNthTag(cbor_decoder, &item, item_tag_index);
        if(uTag == CBOR_TAG_INVALID64) {
            break;
        }
        if(returned_tag_index > T_COSE_MAX_TAGS_TO_RETURN) {
            return T_COSE_ERR_TOO_MANY_TAGS;
        }
        if((uTag == CBOR_TAG_COSE_SIGN1 || uTag == CBOR_TAG_COSE_SIGN) && item_tag_index == 0) {
            continue;
        }

        me->auTags[returned_tag_index] = uTag;
        returned_tag_index++;
    }

    return T_COSE_SUCCESS;
}



enum t_cose_err_t
t_cose_sign1_verify(struct t_cose_sign1_verify_ctx *me,
                    struct q_useful_buf_c           cose_sign1,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameters       *parameters)
{
    enum t_cose_err_t        return_value;
    struct t_cose_parameter *decoded_params;
    QCBORDecodeContext       cbor_decoder;

    QCBORDecode_Init(&cbor_decoder, cose_sign1, 0);

    /* t_cose 2 has simplified tag processing. This does the copying
     * of tags that t_cose sig verification doesn't.
     */
    return_value = copy_tags(me, &cbor_decoder);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    return_value = t_cose_sign_verify(&(me->me2),
                                      cose_sign1,
                                      NULL_Q_USEFUL_BUF_C,
                                      payload,
                                      &decoded_params);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* t_cose 2 doesn't fill in the common parameters data structure
     * but we need it filled in for t_cose 1 compatibility.
     */
    if(parameters != NULL) {
        return_value = t_cose_params_common(decoded_params,
                                            parameters);
    }

Done:
    return return_value;
}
