/**
 * \file t_cose_recipient_dec.h
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * Created by Laurence Lundblade on 1/23/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */


#ifndef t_cose_recipient_dec_h
#define t_cose_recipient_dec_h


#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_common.h"


/* This is an "abstract base class" for all decoders of COSE_Recipients
* of all types for all algorithms. This is the interface
* and data structure that t_cose_encrypt_dec knows about to be able
* to create each type of COSE_Recipient regardles of its type or algorithm.
*
* See longer discussion in t_cose_signature_sign.h about this
* approach.
*/


/* Forward declaration */
struct t_cose_recipient_dec;


/**
 * \brief Typedef of callback that creates a COSE_Recipient.
 *
 * \param[in] context                Context for create COSE_Recipient
 * \param[in] cek              Plaintext (typically the CEK)
 * \param[out] cbor_decoder           Resulting encryption structure
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval Error messages otherwise.
 */
typedef enum t_cose_err_t
t_cose_decode_recipient_cb(struct t_cose_recipient_dec *context,
                                          const struct t_cose_header_location loc,
                                          QCBORDecodeContext *cbor_decoder,
                                          struct q_useful_buf cek_buffer,
                                          struct t_cose_parameter_storage *p_storage,
                                          struct t_cose_parameter **params,
                                          struct q_useful_buf_c *cek);


/**
 * Data structure that must be the first part of every context of every concrete
 * implementation of t_cose_recipient_dec.
 */
struct t_cose_recipient_dec {
    struct t_cose_recipient_dec  *next_in_list;
    t_cose_decode_recipient_cb   *decode_cb;
};



#endif /* t_cose_recipient_dec_h */
