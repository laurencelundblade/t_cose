//
//  t_cose_sign_mini_verify.h
//  t_cose
//
//  Created by Laurence Lundblade on 8/17/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_sign_mini_verify_h
#define t_cose_sign_mini_verify_h

#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"

/*

 This has very crude error reporting in order to keep
 the code size small. Success is always success and failure
 always failure, but the failure reported might be misleading
 as to the actual reason for the failure.
 */

enum t_cose_err_t
t_cose_sign1_mini_verify(struct q_useful_buf_c   cose_sign1,
                         struct t_cose_key       verification_key,
                         struct q_useful_buf_c  *payload);



#endif /* t_cose_sign_mini_verify_h */
