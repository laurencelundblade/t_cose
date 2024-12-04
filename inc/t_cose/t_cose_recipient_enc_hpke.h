/*
 * t_cose_recipient_enc_hpke.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2024, Hannes Tschofenig. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_ENC_HPKE_H__
#define __T_COSE_RECIPIENT_ENC_HPKE_H__

#include <stdint.h>
#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif


struct t_cose_recipient_enc_hpke {
    /* Private data structure */

    /* t_cose_recipient_enc must be the first item for the polymorphism to
      * work.  This structure, t_cose_recipient_enc_hpke, will sometimes be
      * used as a t_cose_recipient_enc.
      */
    struct t_cose_recipient_enc e;

    struct t_cose_key           recipient_pub_key;
    struct q_useful_buf_c       kid;
    int32_t                     cose_ec_curve_id;
    int32_t                     cose_algorithm_id;
    struct t_cose_parameter    *added_params;
    struct t_cose_crypto_hpke_suite_t  hpke_suite;
};



/**
 * @brief Initialize the creator COSE_Recipient for HPKE content key distribution.

 * @param[in]  kem_id   The key encapsulation mechanism ID.
 * @param[in]  kdf_id   The key derivation funtion ID.
 * @param[in]  aead_id  The AEAD ID.
 *
 * This must be called not only to set the kem, kdf, and the AEAD IDs, but also because
 * this sets up the recipient callbacks. That is when all the real work of content key
 * distribution gets done.
 *
 * If unknown algortihm IDs are passed, an error will occur when t_cose_encrypt_enc() is
 * called and the error code will be returned there.
 */
static void
t_cose_recipient_enc_hpke_init(struct t_cose_recipient_enc_hpke *context,
                               int32_t                           cose_algorithm_id);


/**
 * @brief Sets the recipient key, pkR
 *
 * The kid is optional and can be NULL
 */
static void
t_cose_recipient_enc_hpke_set_key(struct t_cose_recipient_enc_hpke *context,
                                  struct t_cose_key                 recipient,
                                  struct q_useful_buf_c             kid);



/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */

enum t_cose_err_t
t_cose_recipient_create_hpke_cb_private(struct t_cose_recipient_enc  *me_x,
                                        struct q_useful_buf_c         cek,
                                        struct t_cose_alg_and_bits    ce,
                                        QCBOREncodeContext           *cbor_encoder);


static inline void
t_cose_recipient_enc_hpke_init(struct t_cose_recipient_enc_hpke *me,
                               int32_t                           cose_algorithm_id)
{
    uint16_t                          kem_id;
    uint16_t                          kdf_id;
    uint16_t                          aead_id;
    int32_t                           cose_ec_curve_id;

    memset(me, 0, sizeof(*me));
    me->e.creat_cb = t_cose_recipient_create_hpke_cb_private;
  
    switch (cose_algorithm_id) {
      case T_COSE_HPKE_Base_P256_SHA256_AES128GCM:
        kem_id = T_COSE_HPKE_KEM_ID_P256;          /* kem id */
        cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256; /* curve */
        kdf_id = T_COSE_HPKE_KDF_ID_HKDF_SHA256;   /* kdf id */
        aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128; /* aead id */
        break;
      default:
        kem_id = 0;
        kdf_id = 0;
        aead_id = 0;
        cose_ec_curve_id = 0;
    }

    me->cose_algorithm_id = cose_algorithm_id;
    me->cose_ec_curve_id = cose_ec_curve_id;
    me->hpke_suite.kem_id = kem_id;
    me->hpke_suite.kdf_id = kdf_id;
    me->hpke_suite.aead_id = aead_id;
}


static inline void
t_cose_recipient_enc_hpke_set_key(struct t_cose_recipient_enc_hpke *me,
                                  struct t_cose_key                 pkR,
                                  struct q_useful_buf_c             kid)
{
    me->recipient_pub_key = pkR;
    me->kid = kid;
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_HPKE_H__ */
