/**
 * \file t_cose_recipient_enc_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef t_cose_recipient_enc_h
#define t_cose_recipient_enc_h


#include "t_cose_parameters.h"
#include "t_cose_crypto.h"

struct t_cose_recipient_enc;


/**
 * \brief Creating a COSE recipient for use with AES Key Wrap.
 *
 * \param[in] context                COSE context for use with AES-KW
 * \param[in] cose_algorithm_id      Algorithm id
 * \param[in] recipient_key          Recipient key (symmetric key, KEK)
 * \param[in] plaintext              Plaintext (typically the CEK)
 * \param[out] encrypt_ctx           Resulting encryption structure
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval Error messages otherwise.
 */

/**
 * \brief Function pointer for use with different key agreement / key transport
 *        schemes used within the recipient structure of COSE_Encrypt.
 *
 * \param[in] ...TBD...
 *
 * \return The \ref t_cose_err_t.
 */

typedef enum t_cose_err_t
t_cose_create_recipient(struct t_cose_recipient_enc  *me,
                        struct t_cose_key             recipient_key,
                        struct q_useful_buf_c         cek,
                        QCBOREncodeContext           *cbor_encoder);


/**
 * This is the context for storing a recipient structure for use with
 * HPKE and AES-KW. The caller should allocate it.
 * The size of this structure is around 56 bytes.
 */
struct t_cose_recipient_enc {
    t_cose_create_recipient *creat_cb;
    struct t_cose_recipient_enc *next_in_list;
    
    
    /* Private data structure */
    int32_t                   cose_algorithm_id;
    struct q_useful_buf_c     kid;
    struct t_cose_key         cek;
    uint32_t                  option_flags;
    struct t_cose_key         ephemeral_key;
    struct t_cose_key         recipient_key;
    t_cose_create_recipient  *recipient_func;
};



#endif /* t_cose_recipient_enc_h */
