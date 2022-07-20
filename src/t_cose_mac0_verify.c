/*
 * Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_mac0_verify.h"
#include "t_cose_parameters.h"
#include "t_cose_util.h"

#ifndef T_COSE_DISABLE_MAC0

/**
 * \brief Check the tagging of the COSE about to be verified.
 *
 * \param[in] me                 The verification context.
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
process_tags(struct t_cose_mac0_verify_ctx *me, QCBORDecodeContext *decode_context)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    20          16
     *   TOTAL                                         20          16
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
        if(uTag != CBOR_TAG_COSE_SIGN1) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    if(me->option_flags & T_COSE_OPT_TAG_PROHIBITED) {
        /* The protocol that is using COSE says the input CBOR must
         * not be a COSE tag.
         */
        if(uTag == CBOR_TAG_COSE_SIGN1) {
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

    if(uTag != CBOR_TAG_COSE_SIGN1) {
        /* Never return the tag that this code is about to process. Note
         * that you can sign a COSE_SIGN1 recursively. This only takes out
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

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/**
 *  \brief Verify a short-circuit tag
 *
 * \param[in] cose_alg_id  Algorithm ID. This is used only to make
 *                         the short-circuit signature the same size as the
 *                         real tag would be for the particular algorithm.
 * \param[in] header       The Header of COSE_Mac0.
 * \param[in] payload      The payload of COSE_Mac0
 * \param[in] tag          Pointer and length of tag to be verified
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * See short_circuit_tag() in t_cose_mac0_sign.c for description of
 * the short-circuit tag.
 */
static inline enum t_cose_err_t
short_circuit_verify(int32_t               cose_alg_id,
                     struct q_useful_buf_c header,
                     struct q_useful_buf_c payload,
                     struct q_useful_buf_c tag_to_verify)
{
    /* approximate stack use on 32-bit machine: local use: 16 bytes */
    enum t_cose_err_t         return_value;
    struct t_cose_crypto_hash hash_ctx;
    Q_USEFUL_BUF_MAKE_STACK_UB(tag_buffer, T_COSE_CRYPTO_HMAC_TAG_MAX_SIZE);
    struct q_useful_buf_c     tag;
    int32_t                   hash_alg_id;

    hash_alg_id = t_cose_hmac_to_hash_alg_id(cose_alg_id);
    if (hash_alg_id == INT32_MAX) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    return_value = t_cose_crypto_hash_start(&hash_ctx, hash_alg_id);
    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Hash the Header */
    t_cose_crypto_hash_update(&hash_ctx, q_useful_buf_head(header, header.len));

    /* Hash the payload */
    t_cose_crypto_hash_update(&hash_ctx, payload);

    return_value = t_cose_crypto_hash_finish(&hash_ctx, tag_buffer, &tag);
    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if (q_useful_buf_compare(tag_to_verify, tag)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
    } else {
        return_value = T_COSE_SUCCESS;
    }

Done:
    return return_value;
}
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */

/**
 * \file t_cose_mac0_verify.c
 *
 * \brief This verifies t_cose Mac authentication structure without a recipient
 *        structure.
 *        Only HMAC is supported so far.
 */

/*
 * Public function. See t_cose_mac0.h
 */
enum t_cose_err_t t_cose_mac0_verify(struct t_cose_mac0_verify_ctx *context,
                                     struct q_useful_buf_c     cose_mac0,
                                     struct q_useful_buf_c    *payload)
{
    QCBORDecodeContext            decode_context;
    struct q_useful_buf_c         protected_parameters;
    struct t_cose_parameters      parameters;
    struct t_cose_label_list      critical_parameter_labels;
    struct t_cose_label_list      unknown_parameter_labels;
    QCBORError                    qcbor_error;

    enum t_cose_err_t             return_value;
    struct q_useful_buf_c         tag = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c         tbm_first_part;
    /* Buffer for the ToBeMaced */
    Q_USEFUL_BUF_MAKE_STACK_UB(   tbm_first_part_buf,
                                  T_COSE_SIZE_OF_TBM);
    struct t_cose_crypto_hmac     hmac_ctx;

    *payload = NULL_Q_USEFUL_BUF_C;

    clear_label_list(&unknown_parameter_labels);
    clear_label_list(&critical_parameter_labels);
    clear_cose_parameters(&parameters);

    QCBORDecode_Init(&decode_context, cose_mac0, QCBOR_DECODE_MODE_NORMAL);

    /* --- The array of 4 and tags --- */
    QCBORDecode_EnterArray(&decode_context, NULL);
    return_value = qcbor_decode_error_to_t_cose_error(QCBORDecode_GetError(&decode_context));
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    return_value = process_tags(context, &decode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The protected parameters --- */
    QCBORDecode_EnterBstrWrapped(&decode_context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
    if(protected_parameters.len) {
        return_value = parse_cose_header_parameters(&decode_context,
                                                    &parameters,
                                                    &critical_parameter_labels,
                                                    &unknown_parameter_labels);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }
    }
    QCBORDecode_ExitBstrWrapped(&decode_context);

    /* ---  The unprotected parameters --- */
    return_value = parse_cose_header_parameters(&decode_context,
                                                &parameters,
                                                 NULL,
                                                &unknown_parameter_labels);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The payload --- */
    QCBORDecode_GetByteString(&decode_context, payload);

    /* --- The tag --- */
    QCBORDecode_GetByteString(&decode_context, &tag);

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&decode_context);

    /* This check make sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also that the payload
     * and signature were decoded correctly. */
    qcbor_error = QCBORDecode_Finish(&decode_context);
    return_value = qcbor_decode_error_to_t_cose_error(qcbor_error);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* === End of the decoding of the array of four === */
    if((context->option_flags & T_COSE_OPT_REQUIRE_KID) && q_useful_buf_c_is_null(parameters.kid)) {
        return_value = T_COSE_ERR_NO_KID;
        goto Done;
    }

    return_value = check_critical_labels(&critical_parameter_labels,
                                         &unknown_parameter_labels);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- Skip tag verification if requested --*/
    if(context->option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }

    /* -- Compute the ToBeMaced -- */
    return_value = create_tbm(tbm_first_part_buf,
                              protected_parameters,
                              &tbm_first_part,
                              T_COSE_TBM_BARE_PAYLOAD,
                              *payload);
    if(return_value) {
        goto Done;
    }

    if (context->option_flags & T_COSE_OPT_ALLOW_SHORT_CIRCUIT) {
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        /* Short-circuit tag. Hash is used to generated tag instead of HMAC */
        return_value = short_circuit_verify(
                                  parameters.cose_algorithm_id,
                                  tbm_first_part,
                                  *payload,
                                  tag);
#else
        return_value = T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED;
#endif
        goto Done;

    }
    /*
     * Start the HMAC verification.
     * Calculate the tag of the first part of ToBeMaced and the wrapped
     * payload, to save a bigger buffer containing the entire ToBeMaced.
     */
    return_value = t_cose_crypto_hmac_verify_setup(&hmac_ctx,
                                  parameters.cose_algorithm_id,
                                  context->verification_key);
    if(return_value) {
        goto Done;
    }

    /* Compute the tag of the first part. */
    return_value = t_cose_crypto_hmac_update(&hmac_ctx,
                                         q_useful_buf_head(tbm_first_part,
                                                           tbm_first_part.len));
    if(return_value) {
        goto Done;
    }

    return_value = t_cose_crypto_hmac_update(&hmac_ctx, *payload);
    if(return_value) {
        goto Done;
    }

    return_value = t_cose_crypto_hmac_verify_finish(&hmac_ctx, tag);

Done:

    return return_value;
}

#endif /* !T_COSE_DISABLE_MAC0 */
