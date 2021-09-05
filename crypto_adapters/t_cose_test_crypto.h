//
//  t_cose_test_crypto.h
//  t_cose
//
//  Created by Laurence Lundblade on 5/30/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_test_crypto_h
#define t_cose_test_crypto_h

/* This is code for use with Brad Conte's crypto.  See
 * https://github.com/B-Con/crypto-algorithms and see the description
 * of t_cose_crypto_hash
 */
#include "sha256.h"

struct t_cose_test_crypto_context {
    int32_t    iteration_counter;
    bool       started;

    SHA256_CTX b_con_hash_context;
};

static inline void
t_cose_test_crypto_context_init(struct t_cose_test_crypto_context *me,
                                int32_t                            restart_test_iterations)
{
    me->iteration_counter = restart_test_iterations;
    me->started = false;
}



#endif /* t_cose_test_crypto_h */
