//
//  t_cose_ecdsa_signer.c
//  t_cose_test
//
//  Created by Laurence Lundblade on 5/23/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose_ecdsa_signer.h"
#include "t_cose/t_cose_signer.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_sign1_sign.h"




static enum t_cose_err_t
t_cose_ecdsa_sign(struct t_cose_ecdsa_signer  *me,
                  const struct q_useful_buf_c  tbs_hash,
                  QCBOREncodeContext          *qcbor_encoder)
{
    enum t_cose_err_t            return_value;
    /* Pointer and length of the completed signature */
    struct q_useful_buf_c        signature;
    /* Buffer for the actual signature */
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_signature, T_COSE_MAX_SIG_SIZE);
    /* Buffer for the tbs hash. */

    QCBOREncode_OpenArray(qcbor_encoder);
    /* Protected headers */
    encode_protected_parameters(me->cose_algorithm_id, qcbor_encoder);
    /* Add empty unprotected headers */
    QCBOREncode_OpenMap(qcbor_encoder);
    QCBOREncode_CloseMap(qcbor_encoder);

    return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                      me->signing_key,
                                      tbs_hash,
                                      buffer_for_signature,
                                      &signature);

    QCBOREncode_AddBytes(qcbor_encoder, signature);
    QCBOREncode_CloseArray(qcbor_encoder);
    // TODO: lots of error handling

    return return_value;
}

void
t_cose_ecdsa_signer_init(struct t_cose_ecdsa_signer *me,
                         int32_t                     cose_algorithm_id)
{
    me->s.callback = (t_cose_signer_callback)t_cose_ecdsa_sign;
    me->cose_algorithm_id = cose_algorithm_id;
}
