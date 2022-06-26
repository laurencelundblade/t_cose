//
//  t_cose_test_signer.c
//  t_cose_test
//
//  Created by Laurence Lundblade on 6/14/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose_test_signer.h"
#include "t_cose/t_cose_signer.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose_parameters.h"



#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
static inline enum t_cose_err_t
short_circuit_sig_size(int32_t            cose_algorithm_id,
                       size_t            *sig_size)
{
    *sig_size = cose_algorithm_id == COSE_ALGORITHM_ES256 ? T_COSE_EC_P256_SIG_SIZE :
                cose_algorithm_id == COSE_ALGORITHM_ES384 ? T_COSE_EC_P384_SIG_SIZE :
                cose_algorithm_id == COSE_ALGORITHM_ES512 ? T_COSE_EC_P512_SIG_SIZE :
                0;

    return sig_size == 0 ? T_COSE_ERR_UNSUPPORTED_SIGNING_ALG : T_COSE_SUCCESS;
}




/**
 * \brief Create a short-circuit signature
 *
 * \param[in] cose_algorithm_id Algorithm ID. This is used only to make
 *                              the short-circuit signature the same size
 *                              as the real signature would be for the
 *                              particular algorithm.
 * \param[in] hash_to_sign      The bytes to sign. Typically, a hash of
 *                              a payload.
 * \param[in] signature_buffer  Pointer and length of buffer into which
 *                              the resulting signature is put.
 * \param[in] signature         Pointer and length of the signature
 *                              returned.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This creates the short-circuit signature that is a concatenation of
 * hashes up to the expected size of the signature. This is a test
 * mode only has it has no security value. This is retained in
 * commercial production code as a useful test or demo that can run
 * even if key material is not set up or accessible.
 */
static inline enum t_cose_err_t
short_circuit_sign(int32_t               cose_algorithm_id,
                   struct q_useful_buf_c hash_to_sign,
                   struct q_useful_buf   signature_buffer,
                   struct q_useful_buf_c *signature)
{
    /* approximate stack use on 32-bit machine: local use: 16 bytes
     */
    enum t_cose_err_t return_value;
    size_t            array_indx;
    size_t            amount_to_copy;
    size_t            sig_size;

    return_value = short_circuit_sig_size(cose_algorithm_id, &sig_size);

    /* Check the signature length against buffer size */
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(sig_size > signature_buffer.len) {
        /* Buffer too small for this signature type */
        return_value = T_COSE_ERR_SIG_BUFFER_SIZE;
        goto Done;
    }

    /* Loop concatening copies of the hash to fill out to signature size */
    for(array_indx = 0; array_indx < sig_size; array_indx += hash_to_sign.len) {
        amount_to_copy = sig_size - array_indx;
        if(amount_to_copy > hash_to_sign.len) {
            amount_to_copy = hash_to_sign.len;
        }
        memcpy((uint8_t *)signature_buffer.ptr + array_indx,
               hash_to_sign.ptr,
               amount_to_copy);
    }
    signature->ptr = signature_buffer.ptr;
    signature->len = sig_size;
    return_value   = T_COSE_SUCCESS;

Done:
    return return_value;
}
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */




/* While this is a private function, it is called externally
 as a callback via a function pointer. */
static enum t_cose_err_t
t_cose_test_sign(struct t_cose_ecdsa_signer  *me,
                  const struct q_useful_buf_c  protected_body_headers,
                  const struct q_useful_buf_c  aad,
                  const struct q_useful_buf_c  signed_payload,
                  QCBOREncodeContext          *qcbor_encoder)
{
    enum t_cose_err_t            return_value;
    struct q_useful_buf_c        protected_headers;
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_signature, T_COSE_MAX_SIG_SIZE);
    const struct q_useful_buf_c  tbs_hash;
    struct q_useful_buf_c        signature;


    if(!q_useful_buf_c_is_null(protected_headers)) {
        QCBOREncode_OpenArray(qcbor_encoder);

        /* Protected headers */
        add_parameters(header_parameters,
                       qcbor_encoder,
                       me->cose_algorithm_id,
                       &protected_headers)

        /* Unprotected header parameters */
        add_parameters(header_parameters,
                       qcbor_encoder,
                       T_COSE_ALGORITHM_NONE,
                       NULL);
    } else {
        protected_body_headers = protected_headers;
    }

    if (QCBOREncode_IsBufferNULL(cbor_encode_ctx)) {

        /* Size calculation mode */
        signature.ptr = NULL;
        short_circuit_sig_size(cose_alg_id, signing_key, &signature.len);

    } else {

        /* Create the hash of the to-be-signed bytes. Inputs to the
         * hash are the protected parameters, the payload that is
         * getting signed, the cose signature alg from which the hash
         * alg is determined. The cose_algorithm_id was checked in
         * t_cose_sign1_init() so it doesn't need to be checked here.
         */
        return_value = create_tbs_hash(cose_alg_id,
                                       protected_headers,
                                       aad,
                                       signed_payload,
                                       buffer_for_tbs_hash,
                                       &tbs_hash);
        if(return_value) {
            goto Done;
        }

        return_value = short_circuit_sign(cose_alg_id,
                                          signing_key,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);
    }

    QCBOREncode_AddBytes(qcbor_encoder, signature);

    if(!q_useful_buf_c_is_null(protected_headers)) {
        QCBOREncode_CloseArray(qcbor_encoder);
    }
    // TODO: lots of error handling

    return return_value;
}


void
t_cose_test_signer_init(struct t_cose_ecdsa_signer *me,
                         int32_t                     cose_algorithm_id)
{
    me->s.callback = (t_cose_signer_callback)t_cose_test_sign;
    me->cose_algorithm_id = cose_algorithm_id;
}
