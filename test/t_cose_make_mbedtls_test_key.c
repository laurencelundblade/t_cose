/*
 *  t_cose_make_psa_test_key.c
 *
 * Copyright 2019-2020, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include <string.h>

#include "t_cose_make_test_pub_key.h" /* The interface implemented here */
#include "t_cose_standard_constants.h"
#include "t_cose/t_cose_crypto_public.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"

/*
 * Some hard coded keys for the test cases here.
 */
#define PRIVATE_KEY_prime256v1 \
0xd9, 0xb5, 0xe7, 0x1f, 0x77, 0x28, 0xbf, 0xe5, 0x63, 0xa9, 0xdc, 0x93, 0x75, \
0x62, 0x27, 0x7e, 0x32, 0x7d, 0x98, 0xd9, 0x94, 0x80, 0xf3, 0xdc, 0x92, 0x41, \
0xe5, 0x74, 0x2a, 0xc4, 0x58, 0x89

#define PRIVATE_KEY_secp384r1 \
 0x63, 0x88, 0x1c, 0xbf, \
 0x86, 0x65, 0xec, 0x39, 0x27, 0x33, 0x24, 0x2e, 0x5a, 0xae, 0x63, 0x3a, \
 0xf5, 0xb1, 0xb4, 0x54, 0xcf, 0x7a, 0x55, 0x7e, 0x44, 0xe5, 0x7c, 0xca, \
 0xfd, 0xb3, 0x59, 0xf9, 0x72, 0x66, 0xec, 0x48, 0x91, 0xdf, 0x27, 0x79, \
 0x99, 0xbd, 0x1a, 0xbc, 0x09, 0x36, 0x49, 0x9c

#define PRIVATE_KEY_secp521r1 \
0x00, 0x4b, 0x35, 0x4d, \
0xa4, 0xab, 0xf7, 0xa5, 0x4f, 0xac, 0xee, 0x06, 0x49, 0x4a, 0x97, 0x0e, \
0xa6, 0x5f, 0x85, 0xf0, 0x6a, 0x2e, 0xfb, 0xf8, 0xdd, 0x60, 0x9a, 0xf1, \
0x0b, 0x7a, 0x13, 0xf7, 0x90, 0xf8, 0x9f, 0x49, 0x02, 0xbf, 0x5d, 0x5d, \
0x71, 0xa0, 0x90, 0x93, 0x11, 0xfd, 0x0c, 0xda, 0x7b, 0x6a, 0x5f, 0x7b, \
0x82, 0x9d, 0x79, 0x61, 0xe1, 0x6b, 0x31, 0x0a, 0x30, 0x6f, 0x4d, 0xf3, \
0x8b, 0xe3

/* The keypair for the sign operation */
static  mbedtls_ecp_keypair ec;

/* There is a single instance of this context: we assume the tests are
 * executed sequentially.
 */
static struct t_cose_crypto_backend_ctx mbedtls_crypto_backend_ctx;


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
enum t_cose_err_t make_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                      struct t_cose_key *key_pair)
{
    const uint8_t       *private_key;
    size_t               private_key_len;
    mbedtls_ecp_group_id grp_id;
    int                  ret;

    const mbedtls_md_info_t *md_info;
    mbedtls_entropy_context entropy_ctx;
    mbedtls_hmac_drbg_context drbg_ctx;

    static const uint8_t private_key_256[] = {PRIVATE_KEY_prime256v1};
    static const uint8_t private_key_384[] = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[] = {PRIVATE_KEY_secp521r1};

#ifdef MBEDTLS_ECP_RESTARTABLE
    /* Set the number of max operations per iteration */
    mbedtls_ecp_set_max_ops(682); /* include/mbedtls/ecp.h:446 */
#endif

    /* There is not a 1:1 mapping from alg to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

    switch (cose_algorithm_id) {
    case COSE_ALGORITHM_ES256:
        private_key     = private_key_256;
        private_key_len = sizeof(private_key_256);
        grp_id = MBEDTLS_ECP_DP_SECP256R1;
        break;

    case COSE_ALGORITHM_ES384:
        private_key     = private_key_384;
        private_key_len = sizeof(private_key_384);
        grp_id = MBEDTLS_ECP_DP_SECP384R1;
        break;

    case COSE_ALGORITHM_ES512:
        private_key     = private_key_521;
        private_key_len = sizeof(private_key_521);
        grp_id = MBEDTLS_ECP_DP_SECP521R1;
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Setup ECC key */
    mbedtls_ecp_keypair_init(&ec);
    ret = mbedtls_ecp_group_load(&ec.MBEDTLS_PRIVATE(grp), grp_id);
    if (ret != 0) {
        return T_COSE_ERR_FAIL;
    }

    ret = mbedtls_mpi_read_binary(&ec.MBEDTLS_PRIVATE(d), private_key, private_key_len);
    if (ret != 0) {
        return T_COSE_ERR_FAIL;
    }

    ret = mbedtls_ecp_check_privkey(&ec.MBEDTLS_PRIVATE(grp), &ec.MBEDTLS_PRIVATE(d));
    if (ret != 0) {
        return T_COSE_ERR_FAIL;
    }

    /* Only the private part is filled. Calculate public part. */
    /* Initialize a local PRNG context */
    mbedtls_entropy_init(&entropy_ctx);
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hmac_drbg_init(&drbg_ctx);
    ret = mbedtls_hmac_drbg_seed(&drbg_ctx,
                    md_info,
                    mbedtls_entropy_func,
                    &entropy_ctx,
                    NULL, 0);
    if (ret) {
        mbedtls_hmac_drbg_free(&drbg_ctx);
        return T_COSE_ERR_FAIL;
    }

    ret = mbedtls_ecp_mul(&ec.MBEDTLS_PRIVATE(grp), &ec.MBEDTLS_PRIVATE(Q),
                            &ec.MBEDTLS_PRIVATE(d), &ec.MBEDTLS_PRIVATE(grp).G,
                            mbedtls_hmac_drbg_random, &drbg_ctx);
    mbedtls_hmac_drbg_free(&drbg_ctx);
    if (ret) {
        return T_COSE_ERR_FAIL;
    }

    key_pair->k.key_ptr = &ec;
    key_pair->crypto_lib   = T_COSE_CRYPTO_LIB_MBEDTLS;

    return T_COSE_SUCCESS;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
void free_ecdsa_key_pair(struct t_cose_key key_pair)
{
    memset(&ec, 0, sizeof(ec));
    return;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
int check_for_key_pair_leaks(void)
{
    return 0;
}

void t_cose_test_set_crypto_context(struct t_cose_sign1_sign_ctx *sign1_ctx)
{
    t_cose_sign1_set_crypto_context(sign1_ctx, &mbedtls_crypto_backend_ctx);
}
