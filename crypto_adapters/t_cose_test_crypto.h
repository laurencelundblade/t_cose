//
//  t_cose_test_crypto.h
//  t_cose
//
//  Created by Laurence Lundblade on 12/9/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_test_crypto_h
#define t_cose_test_crypto_h

/* This is used to test the crypto_context feature. If it's
 * value is SUCCESS, then operation is as normal. If it's
 * value is something else, then that value is returned. */
struct t_cose_test_crypto_context {
    enum t_cose_err_t test_error;
};


#endif /* t_cose_test_crypto_h */
