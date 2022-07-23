//
//  t_cose_sign_verify.h
//  t_cose
//
//  Created by Laurence Lundblade on 7/17/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_sign_verify_h
#define t_cose_sign_verify_h


#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_signature_verify.h"

/**
 * Context for signature verification.
 */
struct t_cose_sign_verify_ctx {
    /* Private data structure */
    struct t_cose_signature_verify *verifiers;
    uint32_t                        option_flags;
    uint64_t                        auTags[4]; // TODO: constants
    struct header_param_storage     params;
    struct t_cose_header_param      __params[10];
    t_cose_header_reader           *reader;
    void                           *reader_ctx;
};


/* Three modes to determine whether the input is COSE_Sign or COSE_Sign1.
 1) expliclity indicate COSE_SIGN1
 2) explicitly indicate COSE_SIGN
 3) require a CBOR tag number to tell which
 */
#define T_COSE_OPT_COSE_SIGN1 0x00000004
#define T_COSE_OPT_COSE_SIGN  0x00000008
#define T_COSE_OPT_COSE_SIGN_TYPE_BY_TAG  0x00000010


/**
 * \brief Initialize for \c COSE_Sign1 message verification.
 *
 * \param[in,out]  context       The context to initialize.
 * \param[in]      option_flags  Options controlling the verification.
 *
 * This must be called before using the verification context.
 */
static void
t_cose_sign_verify_init(struct t_cose_sign_verify_ctx *context,
                        uint32_t                       option_flags);


/* Some verifiers must be added or this won't work. */
void
t_cose_sign_add_verifier(struct t_cose_sign_verify_ctx  *context,
                         struct t_cose_signature_verify *verifier);


/* Use this to increase the number of header parameters that can be decoded
 * if the number expected is larger than XXX. If it is less than XXX,
 * the internal storage is used and there is no need to call this.
 */
static void
t_cose_sign_add_param_storage(struct t_cose_sign_verify_ctx *context,
                              struct header_param_storage    param_storage);


/* Set the call back for processing custom body header parameters */
static void
t_cose_sign_set_header_reader(struct t_cose_sign_verify_ctx *context,
                              t_cose_header_reader          *reader,
                              void                          *reader_ctx);


/* Main entry point for verifying a COSE_Sign or COSE_Sign1.
 */
static enum t_cose_err_t
t_cose_sign_verify(struct t_cose_sign_verify_ctx *context,
                   struct q_useful_buf_c          sign,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c          payload,
                   struct t_cose_header_param   **parameters);


/* Main entry point for verifying a COSE_Sign or COSE_Sign1
   with detached payload.
*/
static enum t_cose_err_t
t_cose_sign_verify_detached(struct t_cose_sign_verify_ctx *context,
                             struct q_useful_buf_c         sign,
                             struct q_useful_buf_c         aad,
                             struct q_useful_buf_c        *payload,
                             struct t_cose_header_param  **parameters);




/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

/**
 * \brief Semi-private function to verify a COSE_Sign1.
 *
 * \param[in,out] me   The t_cose signature verification context.
 * \param[in] sign         Pointer and length of CBOR encoded \c COSE_Sign1
 *                          or \c COSE_Sign message that is to be verified.
 * \param[in] aad           The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in,out] payload   Pointer and length of the payload.
 * \param[out] parameters   Place to return parsed parameters. May be \c NULL.
 * \param[in] is_detached         Indicates the payload is detached.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This does the work for t_cose_sign1_verify(),
 * t_cose_sign1_verify_aad() and t_cose_sign1_verify_detached(). It is
 * a semi-private function which means its interface isn't guaranteed
 * so it should not to call it directly.
 */
enum t_cose_err_t
t_cose_sign_verify_private(struct t_cose_sign_verify_ctx *me,
                             struct q_useful_buf_c        sign,
                             struct q_useful_buf_c        aad,
                             struct q_useful_buf_c       *payload,
                             struct t_cose_header_param **parameters,
                             bool                         is_detached);



static inline enum t_cose_err_t
t_cose_sign_verify(struct t_cose_sign_verify_ctx *me,
                   struct q_useful_buf_c          sign,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c          payload,
                   struct t_cose_header_param   **parameters)
{
    return t_cose_sign_verify_private(me,
                                      sign,
                                      aad,
                                      &payload,
                                      parameters,
                                      false);
}


static inline enum t_cose_err_t
t_cose_sign_verify_detached(struct t_cose_sign_verify_ctx *me,
                   struct q_useful_buf_c          sign,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c         *payload,
                   struct t_cose_header_param   **parameters)
{
    return t_cose_sign_verify_private(me,
                                      sign,
                                      aad,
                                     &payload,
                                      parameters,
                                      true);
}


static inline void
t_cose_sign_verify_init(struct t_cose_sign_verify_ctx *me,
                        uint32_t                       option_flags)
{
    memset(me, 0, sizeof(*me));
    me->option_flags = option_flags;
    me->params.storage = me->__params;
    me->params.storage_size = sizeof(me->__params);
    me->__params[0].parameter_type = T_COSE_PARAMETER_TYPE_NONE;
}


static inline void
t_cose_sign_add_param_storage(struct t_cose_sign_verify_ctx *me,
                              struct header_param_storage  param_storage)
{
    me->params = param_storage;
}


static void
t_cose_sign_set_header_reader(struct t_cose_sign_verify_ctx *me,
                              t_cose_header_reader          *reader,
                              void                          *reader_ctx)
{
    me->reader     = reader;
    me->reader_ctx = reader_ctx;
}

#endif /* t_cose_sign_verify_h */
