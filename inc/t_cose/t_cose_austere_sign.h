//
//  t_cose_austere_sign.h
//  t_cose
//
//  Created by Laurence Lundblade on 5/2/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_austere_sign_h
#define t_cose_austere_sign_h


#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"

/* The algorithm ID, and such are defined as hard constants
 * in the implementation.
 * The payload length is also defined in the implementation
 * despite being passed in here in payload.len
 *
 * 
 */
enum t_cose_err_t
t_cose_austere_sign(struct q_useful_buf_c  payload,
                    struct t_cose_key      signing_key,
                    struct q_useful_buf    output_buffer,
                    struct q_useful_buf_c *output);


#endif /* t_cose_austere_sign_h */
