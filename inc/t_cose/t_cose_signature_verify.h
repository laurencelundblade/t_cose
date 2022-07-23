//
//  t_cose_signature_verify.h
//  t_cose
//
//  Created by Laurence Lundblade on 7/17/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_signature_verify_h
#define t_cose_signature_verify_h

#include "t_cose/t_cose_parameters.h"

/*
 * An instance of this may be used without any verification
 * key material to decode to get the key ID or such.
 *
 * An instance of this may also be set up with key material,
 * perhaps just one key.
 *
 * An instance of this may be wired up to a key database.
 */
struct t_cose_signature_verify;


/*
 This is called on each signature to verify it or to decode the parameters.

 This needs to return parameters.

 This needs to handle decoding without verifying.

Verify a COSE_Sign

 */
typedef enum t_cose_err_t
(t_cose_signature_verify_callback)(struct t_cose_signature_verify   *me,
                                   bool                              run_crypto,
                                   const struct header_location      loc,
                                   const struct q_useful_buf_c       protected_body_headers,
                                   const struct q_useful_buf_c       payload,
                                   const struct q_useful_buf_c       aad,
                                   const struct header_param_storage params,
                                   QCBORDecodeContext               *qcbor_decoder);




/* Verify a COSE_Sign1 */
typedef enum t_cose_err_t
(t_cose_signature_verify1_callback)(struct t_cose_signature_verify   *me,
                                    const struct q_useful_buf_c       protected_body_headers,
                                    const struct q_useful_buf_c       protected_signature_headers,
                                    const struct q_useful_buf_c       payload,
                                    const struct q_useful_buf_c       aad,
                                    const struct t_cose_header_param *body_parameters,
                                    const struct q_useful_buf_c       signature);



/* The definition (not declaration) of the context that every
 * signer implemtation has.
 */
struct t_cose_signature_verify {
    t_cose_signature_verify_callback  *callback; /* some will call this a vtable with one entry */
    t_cose_signature_verify1_callback *callback1; /* some will call this a vtable with one entry */
    struct t_cose_signature_verify    *next_in_list; /* Linked list of signers */
};


#endif /* t_cose_signature_verify_h */
