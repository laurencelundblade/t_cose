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

/**
 * \file t_cose_sign1_verify.c
 *
 * \brief \c COSE_Sign1 verification compatibility layer over the t_cose_sign_verify which
 *        is now the main implementation of \c COSE_Sign1 and \c COSE_Sign.
 */


/**
 * \brief Check the tagging of the COSE about to be validated.
 *
 * \param[in] me                 The validation context.
 * \param[in] decode_context     The decoder context to pull from.
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * This must be called after decoding the opening array of four that
 * starts all COSE message that is the item that is the content of the
 * tags.
 *
 * This checks that the tag usage is as requested by the caller.
 *
 * This returns any tags that enclose the COSE message for processing
 * at the level above COSE.
 */
static inline enum t_cose_err_t
process_tags(struct t_cose_mac_validate_ctx *me,
             QCBORDecodeContext             *decode_context)
{
    /* Aproximate stack usage
     *                  64-bit      32-bit
     *   local vars     20          16
     *   TOTAL          20          16
     */
    uint64_t uTag;
    uint32_t item_tag_index = 0;
    int returned_tag_index;

    /* The 0th tag is the only one that might identify the type of the
     * CBOR we are trying to decode so it is handled special.
     */
    uTag = QCBORDecode_GetNthTagOfLast(decode_context, item_tag_index);
    item_tag_index++;
    if(me->option_flags & T_COSE_OPT_TAG_REQUIRED) {
        /* The protocol that is using COSE says the input CBOR must
         * be a COSE tag.
         */
        if(uTag != CBOR_TAG_COSE_MAC0) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    if(me->option_flags & T_COSE_OPT_TAG_PROHIBITED) {
        /* The protocol that is using COSE says the input CBOR must
         * not be a COSE tag.
         */
        if(uTag == CBOR_TAG_COSE_MAC0) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    /* If the protocol using COSE doesn't say one way or another about the
     * tag, then either is OK.
     */

    /* Initialize auTags, the returned tags, to CBOR_TAG_INVALID64 */
#if CBOR_TAG_INVALID64 != 0xffffffffffffffff
#error Initializing return tags array
#endif
    memset(me->auTags, 0xff, sizeof(me->auTags));

    returned_tag_index = 0;

    if(uTag != CBOR_TAG_COSE_MAC0) {
        /* Never return the tag that this code is about to process. Note
         * that you can MAC a COSE_MAC0 recursively. This only takes out
         * the one tag layer that is processed here.
         */
        me->auTags[returned_tag_index] = uTag;
        returned_tag_index++;
    }

    while(1) {
        uTag = QCBORDecode_GetNthTagOfLast(decode_context, item_tag_index);
        item_tag_index++;
        if(uTag == CBOR_TAG_INVALID64) {
            break;
        }
        if(returned_tag_index > T_COSE_MAX_TAGS_TO_RETURN) {
            return T_COSE_ERR_TOO_MANY_TAGS;
        }
        me->auTags[returned_tag_index] = uTag;
        returned_tag_index++;
    }

    return T_COSE_SUCCESS;
}




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

#ifndef T_COSE_DISABLE_EDDSA
    t_cose_signature_verify_eddsa_init(&(me->eddsa_verifier), option_flags);
    t_cose_sign_add_verifier(&(me->me2),
                    t_cose_signature_verify_from_eddsa(&(me->eddsa_verifier)));
#endif /* !T_COSE_DISABLE_EDDSA */
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



enum t_cose_err_t
t_cose_sign1_verify(struct t_cose_sign1_verify_ctx *me,
                    struct q_useful_buf_c           cose_sign1,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameters       *parameters)
{
    enum t_cose_err_t           return_value;
    struct t_cose_parameter *decoded_params;
    QCBORDecodeContext cbor_decoder;
    QCBORItem           item;
    QCBORError  cbor_error;

    QCBORDecode_Init(&cbor_decoder, cose_sign1, 0);

    cbor_error = QCBORDecode_PeekNext(&cbor_decoder, &item);


    return_value = t_cose_sign_verify(&(me->me2),
                                      cose_sign1,
                                      NULL_Q_USEFUL_BUF_C,
                                      payload,
                                      &decoded_params);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(parameters != NULL) {
        return_value = t_cose_params_common(decoded_params,
                                            parameters);
    }

    //memcpy(me->auTags, me->me2.auTags, sizeof(me->auTags));

Done:
    return return_value;
}
