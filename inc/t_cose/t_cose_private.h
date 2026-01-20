/*
 * t_cose_private.h
 *
 * Copyright 2026, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor.h"
#include "t_cose/t_cose_key.h"


/* These are functions exposed for the use of the t_cose test suite,
 * not part of public interface.
 *
 * They mostly correspond to the adaptation/abstraction layer t_cose uses
 * to access the crypto library it is configured for. Exposing
 * this allows the test suite to make use of the crypto functions
 * to construct test messages and to test the crypto
 * adaptation layer itself.
 *
 * They are not document here to discourage use.
 */



/* Do not want to make struct t_cose_crypto_hash public, so fake
 * it with an overly large stand in
 */
struct t_cose_private_test_crypto_hash {
    uint8_t large[512]; /* This is larger than struct t_cose_crypto_hash */
};

enum t_cose_err_t
t_cose_private_test_crypto_hash_start(struct t_cose_private_test_crypto_hash *hash_ctx,
                                      int32_t                    cose_hash_alg_id);


void
t_cose_private_test_crypto_hash_update(struct t_cose_private_test_crypto_hash *hash_ctx,
                                       struct q_useful_buf_c      data_to_hash);


enum t_cose_err_t
t_cose_private_test_crypto_hash_finish(struct t_cose_private_test_crypto_hash *hash_ctx,
                                       struct q_useful_buf        buffer_to_hold_result,
                                       struct q_useful_buf_c     *hash_result);


enum t_cose_err_t
t_cose_private_test_crypto_sign(int32_t                cose_algorithm_id,
                                struct t_cose_key      signing_key,
                                void                  *crypto_context,
                                struct q_useful_buf_c  hash_to_sign,
                                struct q_useful_buf    signature_buffer,
                                struct q_useful_buf_c *signature);


enum t_cose_err_t
t_cose_private_test_crypto_make_symmetric_key_handle(int32_t               cose_algorithm_id,
                                                     struct q_useful_buf_c symmetric_key,
                                                     struct t_cose_key     *key);


enum t_cose_err_t
t_cose_private_test_crypto_aead_encrypt(int32_t                cose_algorithm_id,
                                        struct t_cose_key      key,
                                        struct q_useful_buf_c  nonce,
                                        struct q_useful_buf_c  add_data,
                                        struct q_useful_buf_c  plaintext,
                                        struct q_useful_buf    ciphertext_buffer,
                                        struct q_useful_buf_c *ciphertext);


enum t_cose_err_t
t_cose_private_test_crypto_aead_decrypt(int32_t                cose_algorithm_id,
                                        struct t_cose_key      key,
                                        struct q_useful_buf_c  nonce,
                                        struct q_useful_buf_c  add_data,
                                        struct q_useful_buf_c  ciphertext,
                                        struct q_useful_buf    plaintext_buffer,
                                        struct q_useful_buf_c *plaintext);


enum t_cose_err_t
t_cose_private_test_crypto_kw_wrap(int32_t                 cose_algorithm_id,
                                   struct t_cose_key       kek,
                                   struct q_useful_buf_c   plaintext,
                                   struct q_useful_buf     ciphertext_buffer,
                                   struct q_useful_buf_c  *ciphertext_result);


enum t_cose_err_t
t_cose_private_test_crypto_kw_unwrap(int32_t                 cose_algorithm_id,
                                     struct t_cose_key       kek,
                                     struct q_useful_buf_c   ciphertext,
                                     struct q_useful_buf     plaintext_buffer,
                                     struct q_useful_buf_c  *plaintext_result);


enum t_cose_err_t
t_cose_private_test_crypto_hkdf(const int32_t               cose_hash_algorithm_id,
                                const struct q_useful_buf_c salt,
                                const struct q_useful_buf_c ikm,
                                const struct q_useful_buf_c info,
                                const struct q_useful_buf   okm_buffer);


enum t_cose_err_t
t_cose_private_test_crypto_ecdh(struct t_cose_key      private_key,
                                struct t_cose_key      public_key,
                                struct q_useful_buf    shared_key_buf,
                                struct q_useful_buf_c *shared_key);


enum t_cose_err_t
t_cose_private_test_crypto_export_ec2_key(struct t_cose_key      key_handle,
                                          int32_t               *curve,
                                          struct q_useful_buf    x_coord_buf,
                                          struct q_useful_buf_c *x_coord,
                                          struct q_useful_buf    y_coord_buf,
                                          struct q_useful_buf_c *y_coord,
                                          bool                  *y_bool);


enum t_cose_err_t
t_cose_private_test_crypto_import_ec2_pubkey(int32_t               cose_ec_curve_id,
                                             struct q_useful_buf_c x_coord,
                                             struct q_useful_buf_c y_coord,
                                             bool                  y_bool,
                                             struct t_cose_key    *key_handle);
