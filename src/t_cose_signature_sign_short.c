/*
 * t_cose_signature_sign_short.c
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_signature_sign_short.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"


static const uint8_t defined_short_circuit_kid[] = {
    0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70,
    0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
    0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6,
    0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6};

static struct q_useful_buf_c short_circuit_kid;

/*
 * Public function (well maybe...)
 */
struct q_useful_buf_c
t_cose_get_short_circuit_kid_l(void)
{
    short_circuit_kid.len = sizeof(defined_short_circuit_kid);
    short_circuit_kid.ptr = defined_short_circuit_kid;

    return short_circuit_kid;
}




/**
 * See \ref t_cose_signature_sign_h_callback of which this is an implementation.
 *
 * While this is a private function, it is called externally as a
 * callback via a function pointer that is set up in
 * t_cose_short_signer_init().
 */
static void
t_cose_short_headers(struct t_cose_signature_sign *me_x,
                     struct t_cose_parameter     **params)
{
    struct t_cose_signature_sign_short *me =
                                   (struct t_cose_signature_sign_short *)me_x;

    /* Output the configured kid or the never-changing kid for
     * short-circuit signatures. */
    struct q_useful_buf_c kid = me->kid;
    if(q_useful_buf_c_is_null(kid)) {
        kid = t_cose_get_short_circuit_kid_l();
    }

    /* Make the linked list of two parameters, the alg id and kid. */
    me->local_params[0] = t_cose_make_alg_id_parameter(me->cose_algorithm_id);
    me->local_params[1] = t_cose_make_kid_parameter(kid);
    me->local_params[0].next = &me->local_params[1];

    *params = me->local_params;
}


/**
 * See \ref t_cose_signature_sign_callback of which this is an implementation.
 *
 * While this is a private function, it is called externally as a
 * callback via a function pointer that is set up in
 * t_cose_short_signer_init().
 */
static enum t_cose_err_t
t_cose_short_sign(struct t_cose_signature_sign *me_x,
                  uint32_t                      options,
                  const struct q_useful_buf_c   protected_body_headers,
                  const struct q_useful_buf_c   aad,
                  const struct q_useful_buf_c   signed_payload,
                  QCBOREncodeContext           *qcbor_encoder)
{
    struct t_cose_signature_sign_short *me =
                                    (struct t_cose_signature_sign_short *)me_x;
    enum t_cose_err_t                  return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(        buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf                buffer_for_signature;
    struct q_useful_buf_c              tbs_hash;
    struct q_useful_buf_c              signature;
    struct q_useful_buf_c              signer_protected_headers;
    size_t                             tmp_sig_size;
    struct t_cose_parameter           *parameter_list;
    struct t_cose_key                  dummy_key;

    dummy_key = T_COSE_NULL_KEY;

    /* Get the sig size to find out if this is an alg that short-circuit
     * signer can pretend to be.
     */
    return_value = t_cose_crypto_sig_size(me->cose_algorithm_id, dummy_key, &tmp_sig_size);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- The headers if it is a COSE_Sign -- */
    signer_protected_headers = NULL_Q_USEFUL_BUF_C;
    if(T_COSE_OPT_IS_SIGN(options)) {
        /* COSE_Sign, so making a COSE_Signature  */
        /* Open the array enclosing the two header buckets and the sig. */
        QCBOREncode_OpenArray(qcbor_encoder);

        t_cose_short_headers(me_x, &parameter_list);
        t_cose_parameter_list_append(parameter_list, me->added_signer_params);

        t_cose_encode_headers(qcbor_encoder, parameter_list, &signer_protected_headers);
    }

    /* -- The signature -- */
    QCBOREncode_OpenBytes(qcbor_encoder, &buffer_for_signature);

    if (QCBOREncode_IsBufferNULL(qcbor_encoder)) {
        /* Size calculation mode */
        signature.ptr = NULL;
        t_cose_crypto_sig_size(me->cose_algorithm_id, dummy_key, &signature.len);

        return_value = T_COSE_SUCCESS;

    } else {
        /* Run the crypto to produce the signature */

        /* Create the hash of the to-be-signed bytes. Inputs to the
         * hash are the protected parameters, the payload that is
         * getting signed, the cose signature alg from which the hash
         * alg is determined. The cose_algorithm_id was checked in
         * t_cose_sign1_init() so it doesn't need to be checked here.
         */
        return_value = create_tbs_hash(me->cose_algorithm_id,
                                       protected_body_headers,
                                       signer_protected_headers,
                                       aad,
                                       signed_payload,
                                       buffer_for_tbs_hash,
                                       &tbs_hash);
        if(return_value) {
            goto Done;
        }

        /* The signature gets written directly into the output buffer.
         * The matching QCBOREncode_CloseBytes call further down still needs do a
         * memmove to make space for the CBOR header, but at least we avoid the need
         * to allocate an extra buffer.
         */
        // TODO: does this mess up the size calculation mode?
        // Check that it is OK in master branch too

        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          dummy_key,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);
    }
    QCBOREncode_CloseBytes(qcbor_encoder, signature.len);


    /* -- If a COSE_Sign, close of the COSE_Signature */
    if(T_COSE_OPT_IS_SIGN(options)) {
        /* Close the array enclosing the two header buckets and the sig. */
        QCBOREncode_CloseArray(qcbor_encoder);
    }
    // TODO: lots of error handling

Done:
    return return_value;
}


/*
 * Pubilc Function. See t_cose_signature_sign_short.h
 */
void
t_cose_signature_sign_short_init(struct t_cose_signature_sign_short *me,
                                 int32_t                             cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.callback        = t_cose_short_sign;
    me->s.h_callback      = t_cose_short_headers;
    me->cose_algorithm_id = cose_algorithm_id;
}
