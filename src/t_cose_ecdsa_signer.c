//
//  t_cose_ecdsa_signer.c
//  t_cose_test
//
//  Created by Laurence Lundblade on 5/23/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_ecdsa_signer.h"
#include "t_cose/t_cose_signer.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose_parameters.h"
#include "t_cose_util.h"



/* While this is a private function, it is called externally
 as a callback via a function pointer that is set up in  t_cose_ecdsa_signer_init().  */
static enum t_cose_err_t
t_cose_ecdsa_sign(struct t_cose_ecdsa_signer  *me,
                  bool                         sign_only,
                  const struct q_useful_buf_c  protected_body_headers,
                  const struct q_useful_buf_c  aad,
                  const struct q_useful_buf_c  signed_payload,
                  QCBOREncodeContext          *qcbor_encoder)
{
    enum t_cose_err_t                  return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(        buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    Q_USEFUL_BUF_MAKE_STACK_UB(        buffer_for_signature, T_COSE_MAX_SIG_SIZE);
    struct q_useful_buf_c              tbs_hash;
    struct q_useful_buf_c              signature;
    const struct t_cose_header_param  *params_vector[3];
    struct t_cose_header_param         local_params[3];
    struct q_useful_buf_c              signer_protected_headers;

    if(!sign_only) {
        QCBOREncode_OpenArray(qcbor_encoder);

        // TODO: kid handling may not be right

        local_params[0]  = T_COSE_MAKE_ALG_ID_PARAM(me->cose_algorithm_id);
        local_params[1]  = T_COSE_KID_PARAM(me->kid);
        local_params[2]  = T_COSE_END_PARAM;
        params_vector[0] = local_params;
        params_vector[1] = me->added_signer_params;
        params_vector[2] = NULL;

        t_cose_encode_headers(qcbor_encoder, params_vector, &signer_protected_headers);
    } else {
        signer_protected_headers = NULLUsefulBufC;
    }

    if (QCBOREncode_IsBufferNULL(qcbor_encoder)) {

        /* Size calculation mode */
        signature.ptr = NULL;
        t_cose_crypto_sig_size(me->cose_algorithm_id, me->signing_key, &signature.len);

        return_value = T_COSE_SUCCESS;

    } else {

        /* Create the hash of the to-be-signed bytes. Inputs to the
         * hash are the protected parameters, the payload that is
         * getting signed, the cose signature alg from which the hash
         * alg is determined. The cose_algorithm_id was checked in
         * t_cose_sign1_init() so it doesn't need to be checked here.
         */

        // TODO: the other signature protected headers
        return_value = create_tbs_hash(me->cose_algorithm_id,
                                       protected_body_headers,
                                       signer_protected_headers,
                                       signed_payload,
                                       aad,
                                       buffer_for_tbs_hash,
                                       &tbs_hash);
        if(return_value) {
            goto Done;
        }

        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          me->signing_key,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);
    }

    QCBOREncode_AddBytes(qcbor_encoder, signature);

    if(!sign_only) {
        QCBOREncode_CloseArray(qcbor_encoder);
    }
    // TODO: lots of error handling

Done:
    return return_value;
}


void
t_cose_ecdsa_signer_init(struct t_cose_ecdsa_signer *me,
                         int32_t                     cose_algorithm_id)
{
    me->s.callback = (t_cose_signer_callback)t_cose_ecdsa_sign;
    me->cose_algorithm_id = cose_algorithm_id;
}
