/*
 *  t_cose_sign1_verify.c
 *
 * Copyright 2019-2020, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "qcbor/qcbor.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"
#include "t_cose_parameters.h"


/**
 * \file t_cose_sign1_verify.c
 *
 * \brief \c COSE_Sign1 verification implementation.
 */



#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/**
 * \brief Verify a short-circuit signature
 *
 * \param[in] hash_to_verify  Pointer and length of hash to verify.
 * \param[in] signature       Pointer and length of signature.
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * See t_cose_sign1_sign_init() for description of the short-circuit
 * signature.
 */
static inline enum t_cose_err_t
t_cose_crypto_short_circuit_verify(struct q_useful_buf_c hash_to_verify,
                                   struct q_useful_buf_c signature)
{
    struct q_useful_buf_c hash_from_sig;
    enum t_cose_err_t     return_value;

    hash_from_sig = q_useful_buf_head(signature, hash_to_verify.len);
    if(q_useful_buf_c_is_null(hash_from_sig)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    if(q_useful_buf_compare(hash_from_sig, hash_to_verify)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
    } else {
        return_value = T_COSE_SUCCESS;
    }

Done:
    return return_value;
}
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


static inline
enum t_cose_err_t check_tag(QCBORDecodeContext *me, uint32_t uOptions)
{
    QCBORItem array_item;
    QCBORDecode_PeekNext(me, &array_item);

    // TODO: finish the logic here
    return T_COSE_SUCCESS;
}


/*
 * Public function. See t_cose_sign1_verify.h
 */
enum t_cose_err_t
t_cose_sign1_verify(struct t_cose_sign1_verify_ctx *me,
                    struct q_useful_buf_c           cose_sign1,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameters       *returned_parameters)
{
    /* Stack use for 32-bit CPUs:
     *   268 for local except hash output
     *   32 to 64 local for hash output
     *   220 to 434 to make TBS hash
     * Total 420 to 768 depending on hash and EC alg.
     * Stack used internally by hash and crypto is extra.
     */
    QCBORDecodeContext            decode_context;
    struct q_useful_buf_c         protected_parameters;
    enum t_cose_err_t             return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(   buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c         tbs_hash;
    struct q_useful_buf_c         signature;
    struct t_cose_label_list      critical_parameter_labels;
    struct t_cose_label_list      unknown_parameter_labels;
    struct t_cose_parameters      parameters;
    QCBORError                    qcbor_error;
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    struct q_useful_buf_c         short_circuit_kid;
#endif

    clear_label_list(&unknown_parameter_labels);
    clear_label_list(&critical_parameter_labels);
    clear_cose_parameters(&parameters);


    /* === Decoding of the array of four starts here === */
    QCBORDecode_Init(&decode_context, cose_sign1, QCBOR_DECODE_MODE_NORMAL);

    /* --- Check the tag on the array --- */
#if 0
    // TODO: fix this.
    return_value = check_tag(&decode_context, me->option_flags);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
#endif
    
    QCBORDecode_EnterArray(&decode_context);

    /* --- The protected parameters --- */
    QCBORDecode_EnterBstrWrapped(&decode_context, QCBOR_TAGSPEC_MATCH_TAG_CONTENT_TYPE, &protected_parameters);
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
    QCBORDecode_GetBytes(&decode_context, payload); // TODO: have QCBORDecode_GetBytes set payload to NULL on error?

    QCBORDecode_GetBytes(&decode_context, &signature);

    QCBORDecode_ExitArray(&decode_context);

    /* --- Finish up the CBOR decode --- */
    /* This check make sure the array only had the expected four
     * items. Works for definite and indefinte length arrays. Also
     * make sure there were no extra bytes. */
    qcbor_error = QCBORDecode_Finish(&decode_context);
    if(QCBORDecode_IsNotWellFormed(qcbor_error)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }

    /* === End of the decoding of the array of four === */


    if((me->option_flags & T_COSE_OPT_REQUIRE_KID) && q_useful_buf_c_is_null(parameters.kid)) {
        return_value = T_COSE_ERR_NO_KID;
        goto Done;
    }

    return_value = check_critical_labels(&critical_parameter_labels,
                                         &unknown_parameter_labels);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* -- Skip signature verification if such is requested --*/
    if(me->option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }


    /* -- Compute the TBS bytes -- */
    return_value = create_tbs_hash(parameters.cose_algorithm_id,
                                   protected_parameters,
                                   *payload,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if(return_value) {
        goto Done;
    }


    /* -- Check for short-circuit signature and verify if it exists -- */
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    short_circuit_kid = get_short_circuit_kid();
    if(!q_useful_buf_compare(parameters.kid, short_circuit_kid)) {
        if(!(me->option_flags & T_COSE_OPT_ALLOW_SHORT_CIRCUIT)) {
            return_value = T_COSE_ERR_SHORT_CIRCUIT_SIG;
            goto Done;
        }

        return_value = t_cose_crypto_short_circuit_verify(tbs_hash, signature);
        goto Done;
    }
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


    /* -- Verify the signature (if it wasn't short-circuit) -- */
    return_value = t_cose_crypto_pub_key_verify(parameters.cose_algorithm_id,
                                                me->verification_key,
                                                parameters.kid,
                                                tbs_hash,
                                                signature);

Done:
    if(returned_parameters != NULL) {
        *returned_parameters = parameters;
    }

    return return_value;
}

