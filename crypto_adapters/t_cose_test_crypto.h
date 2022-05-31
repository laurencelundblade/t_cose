//
//  t_cose_test_crypto.h
//  t_cose
//
//  Created by Laurence Lundblade on 5/30/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_test_crypto_h
#define t_cose_test_crypto_h


struct t_cose_test_crypto_context {
    bool       enable_restart;
    int32_t    iteration_counter;
};



static inline void
t_cose_test_crypto_restart_init(struct t_cose_test_crypto_context *me,
                                bool                               enable_restart,
                                int32_t                            restart_test_iterations)
{
    me->enable_restart = enable_restart;
    me->iteration_counter = restart_test_iterations;
}



#endif /* t_cose_test_crypto_h */
