/*
 * t_cose_private.c
 *
 * Copyright 2026, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_private.h" /* Interface implemented */

#include "t_cose_crypto.h"


enum t_cose_err_t
t_cose_private_tcrypto_hash_start(struct t_cose_private_tcrypto_hash *hash_ctx,
                                  const int32_t                       cose_hash_alg_id)
{
    if(sizeof(struct t_cose_crypto_hash) > sizeof(struct t_cose_private_tcrypto_hash)) {
        return T_COSE_ERR_FAIL;
    }

    return t_cose_crypto_hash_start((struct t_cose_crypto_hash *)hash_ctx, cose_hash_alg_id);
}


void
t_cose_private_tcrypto_hash_update(struct t_cose_private_tcrypto_hash *hash_ctx,
                                   const struct q_useful_buf_c      data_to_hash)
{
    t_cose_crypto_hash_update((struct t_cose_crypto_hash *)hash_ctx, data_to_hash);
}


enum t_cose_err_t
t_cose_private_tcrypto_hash_finish(struct t_cose_private_tcrypto_hash *hash_ctx,
                                   struct q_useful_buf        buffer_to_hold_result,
                                   struct q_useful_buf_c     *hash_result)
{
    return t_cose_crypto_hash_finish((struct t_cose_crypto_hash *)hash_ctx,
                                     buffer_to_hold_result,
                                     hash_result);
}


enum t_cose_err_t
t_cose_private_tcrypto_sign(int32_t                cose_algorithm_id,
                            struct t_cose_key      signing_key,
                            void                  *crypto_context,
                            struct q_useful_buf_c  hash_to_sign,
                            struct q_useful_buf    signature_buffer,
                            struct q_useful_buf_c *signature)
{
    return t_cose_crypto_sign(cose_algorithm_id,
                              signing_key,
                              crypto_context,
                              hash_to_sign,
                              signature_buffer,
                              signature);
}


enum t_cose_err_t
t_cose_private_tcrypto_make_symmetric_key_handle(int32_t               cose_algorithm_id,
                                                 struct q_useful_buf_c symmetric_key,
                                                 struct t_cose_key     *key)
{
    return t_cose_crypto_make_symmetric_key_handle(cose_algorithm_id,
                                                   symmetric_key,
                                                   key);
}

enum t_cose_err_t
t_cose_private_tcrypto_aead_encrypt(int32_t                cose_algorithm_id,
                                    struct t_cose_key      key,
                                    struct q_useful_buf_c  nonce,
                                    struct q_useful_buf_c  add_data,
                                    struct q_useful_buf_c  plaintext,
                                    struct q_useful_buf    ciphertext_buffer,
                                    struct q_useful_buf_c *ciphertext)
{
    return t_cose_crypto_aead_encrypt(cose_algorithm_id,
                                      key,
                                      nonce,
                                      add_data,
                                      plaintext,
                                      ciphertext_buffer,
                                      ciphertext);
}


enum t_cose_err_t
t_cose_private_tcrypto_aead_decrypt(int32_t                cose_algorithm_id,
                                    struct t_cose_key      key,
                                    struct q_useful_buf_c  nonce,
                                    struct q_useful_buf_c  add_data,
                                    struct q_useful_buf_c  ciphertext,
                                    struct q_useful_buf    plaintext_buffer,
                                    struct q_useful_buf_c *plaintext)
{
    return t_cose_crypto_aead_decrypt(cose_algorithm_id,
                                      key,
                                      nonce,
                                      add_data,
                                      ciphertext,
                                      plaintext_buffer,
                                      plaintext);
}


enum t_cose_err_t
t_cose_private_tcrypto_kw_wrap(int32_t                 cose_algorithm_id,
                               struct t_cose_key       kek,
                               struct q_useful_buf_c   plaintext,
                               struct q_useful_buf     ciphertext_buffer,
                               struct q_useful_buf_c  *ciphertext_result)
{
    return t_cose_crypto_kw_wrap(cose_algorithm_id,
                                 kek,
                                 plaintext,
                                 ciphertext_buffer,
                                 ciphertext_result);
}


enum t_cose_err_t
t_cose_private_tcrypto_kw_unwrap(int32_t                 cose_algorithm_id,
                                 struct t_cose_key       kek,
                                 struct q_useful_buf_c   ciphertext,
                                 struct q_useful_buf     plaintext_buffer,
                                 struct q_useful_buf_c  *plaintext_result)
{
    return t_cose_crypto_kw_unwrap(cose_algorithm_id,
                                   kek,
                                   ciphertext,
                                   plaintext_buffer,
                                   plaintext_result);
}


enum t_cose_err_t
t_cose_private_tcrypto_hkdf(const int32_t               cose_hash_algorithm_id,
                            const struct q_useful_buf_c salt,
                            const struct q_useful_buf_c ikm,
                            const struct q_useful_buf_c info,
                            const struct q_useful_buf   okm_buffer)
{
    return t_cose_crypto_hkdf(cose_hash_algorithm_id,
                              salt,
                              ikm,
                              info,
                              okm_buffer);
}


enum t_cose_err_t
t_cose_private_tcrypto_ecdh(struct t_cose_key      private_key,
                            struct t_cose_key      public_key,
                            struct q_useful_buf    shared_key_buf,
                            struct q_useful_buf_c *shared_key)
{
    return t_cose_crypto_ecdh(private_key,
                              public_key,
                              shared_key_buf,
                              shared_key);
}


enum t_cose_err_t
t_cose_private_tcrypto_export_ec2_key(struct t_cose_key      key_handle,
                                      int32_t               *curve,
                                      struct q_useful_buf    x_coord_buf,
                                      struct q_useful_buf_c *x_coord,
                                      struct q_useful_buf    y_coord_buf,
                                      struct q_useful_buf_c *y_coord,
                                      bool                  *y_bool)
{
    return t_cose_crypto_export_ec2_key(key_handle,
                                        curve,
                                        x_coord_buf,
                                        x_coord,
                                        y_coord_buf,
                                        y_coord,
                                        y_bool);
}


enum t_cose_err_t
t_cose_private_tcrypto_import_ec2_pubkey(int32_t               cose_ec_curve_id,
                                         struct q_useful_buf_c x_coord,
                                         struct q_useful_buf_c y_coord,
                                         bool                  y_bool,
                                         struct t_cose_key    *key_handle)
{
    return t_cose_crypto_import_ec2_pubkey(cose_ec_curve_id,
                                           x_coord,
                                           y_coord,
                                           y_bool,
                                           key_handle);
}
