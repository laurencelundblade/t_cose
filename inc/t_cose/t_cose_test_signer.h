//
//  t_cose_test_signer.h
//  t_cose_test
//
//  Created by Laurence Lundblade on 6/14/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_test_signer_h
#define t_cose_test_signer_h

#include "t_cose_ecdsa_signer.h"
#include "t_cose/t_cose_signer.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"


struct t_cose_test_signer {
    /* Private data structure */

    /* t_cose_signer must be the first item for the polymorphism to work.
     * This structure, t_cose_ecdsa_signer, will sometimes be uses as a t_cose_signer.
     */
    struct t_cose_signer s;

    /* The rest of this is mostly specific to ECDSA signing */
    int32_t               cose_algorithm_id;
    uint32_t              option_flags;
    struct q_useful_buf_c kid;
    void                 *header_parameters;
};


void
t_cose_test_signer_init(struct t_cose_ecdsa_signer *context,
                         int32_t                     cose_algorithm_id);



/* The header parameter for the algorithm ID is generated automatically.
   and should not be added in this list.  The kid will be generated
   automatically if it not NULL when set_signing_key is called.
 */
static void
t_cose_test_signer_set_header_parameter(struct t_cose_ecdsa_signer *context,
                                    void * header_parameters); // TODO make this the right type


/* This is how you get the general interface / instance for a signer,
 * a t_cose_signer, from the specific and concrete instance of a
 * signer. Because the t_cose_signer is the first member in a
 * t_cose_ecdsa_signer, the implementation for this is in essence just a
 * cast and in the end no code is generated.
 */
static struct t_cose_signer *
t_cose_test_from_ecdsa_signer(struct t_cose_ecdsa_signer *me);



/* =========================================================================
 BEGINNING OF PRIVATE INLINE IMPLEMENTATION
 ========================================================================= */



static inline struct t_cose_signer *
t_cose_signer_from_test_signer(struct t_cose_test_signer *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}


static void
t_cose_test_signer_set_header_parameter(struct t_cose_test_signer *me,
                                    void * header_parameters)
{
    // TODO: fix the type
    me->header_parameters = header_parameters;
}

#endif /* t_cose_test_signer_h */
