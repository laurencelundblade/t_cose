/*
 *  t_cose_make_psa_test_key.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose_make_test_pub_key.h" /* The interface implemented here */
#include "t_cose/t_cose_standard_constants.h"
#include "psa/crypto.h"


/*
 * These are the same keys as in t_cose_make_openssl_test_key.c so that
 * messages made with openssl can be verified those made by mbedtls.
 * These were made with openssl as detailed in t_cose_make_openssl_test_key.c.
 * Then just the private key was pulled out to be put here because
 * mbedtls just needs the private key, unlike openssl for which there
 * is a full rfc5915 DER structure. These were pulled out of the DER
 * by identifying the key with openssl asn1parse and then finding those
 * bytes in the C variable holding the rfc5915 (perhaps there is a better
 * way, but this works).
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

#define KEY_hmac256 \
0x0b, 0x2d, 0x6f, 0x32, 0x53, 0x67, 0x86, 0xb3, 0x8f, 0x83, 0x56, 0xaa, \
0xe0, 0x8c, 0x05, 0x52, 0x79, 0x31, 0xdd, 0x43, 0xef, 0xe9, 0xf4, 0x12, \
0x0c, 0x28, 0x19, 0x01, 0xba, 0x1f, 0x89, 0x39

#define KEY_hmac384 \
0x3f, 0x39, 0xb4, 0xe0, 0x78, 0x3e, 0x4c, 0x54, 0x82, 0x4f, 0xed, 0xee, \
0x37, 0x9a, 0x79, 0x66, 0xfe, 0xfa, 0x1d, 0xf6, 0x35, 0x30, 0xc8, 0xcf, \
0x60, 0xac, 0xef, 0x9d, 0x72, 0x08, 0x8d, 0x47, 0x41, 0x88, 0xeb, 0x7d, \
0xc6, 0x5f, 0xff, 0x63, 0x6f, 0x99, 0x8a, 0xcc, 0x24, 0xa2, 0x2c, 0xd0

#define KEY_hmac512 \
0x99, 0xf7, 0xab, 0xc8, 0x3f, 0xe8, 0x73, 0x90, 0xa9, 0x9f, 0x83, 0xa7, \
0xd4, 0xc2, 0xa1, 0xa8, 0xad, 0x64, 0xed, 0x54, 0xbb, 0x99, 0x96, 0xb5, \
0xb4, 0xd8, 0xec, 0x17, 0x93, 0xa6, 0x1b, 0x84, 0x7a, 0xfd, 0xd3, 0xba, \
0x05, 0x32, 0xef, 0x55, 0xa4, 0x4f, 0xae, 0x4c, 0x95, 0x39, 0xdf, 0x28, \
0x82, 0x27, 0x78, 0xe2, 0x35, 0x14, 0x13, 0x0c, 0x9d, 0x33, 0x96, 0xaa, \
0x22, 0xe4, 0x72, 0x7d


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
enum t_cose_err_t make_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                      struct t_cose_key *key_pair)
{
    psa_key_type_t       key_type;
    psa_status_t         crypto_result;
    psa_key_handle_t     key_handle;
    psa_algorithm_t      key_alg;
    const uint8_t       *private_key;
    size_t               private_key_len;
    psa_key_attributes_t key_attributes;


    static const uint8_t private_key_256[] = {PRIVATE_KEY_prime256v1};
    static const uint8_t private_key_384[] = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[] = {PRIVATE_KEY_secp521r1};

    /* There is not a 1:1 mapping from COSE algorithm to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        private_key     = private_key_256;
        private_key_len = sizeof(private_key_256);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_ES384:
        private_key     = private_key_384;
        private_key_len = sizeof(private_key_384);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
        break;

    case T_COSE_ALGORITHM_ES512:
        private_key     = private_key_521;
        private_key_len = sizeof(private_key_521);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }


    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }


    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data (because the import is not of a format
     * like RFC 5915). The variable key_type contains
     * that information including the EC curve. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     */

    key_attributes = psa_key_attributes_init();

    /* The type of key including the EC curve */
    psa_set_key_type(&key_attributes, key_type);

    /* Say what algorithm and operations the key can be used with/for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);


    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. With ECDSA the public key is always
     * deterministically derivable from the private key.
     */
    crypto_result = psa_import_key(&key_attributes,
                                    private_key,
                                    private_key_len,
                                   &key_handle);

    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* This assignment relies on MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
     * not being defined. If it is defined key_handle is a structure.
     * This does not seem to be typically defined as it seems that is
     * for a PSA implementation architecture as a service rather than
     * an linked library. If it is defined, the structure will
     * probably be less than 64 bits, so it can still fit in a
     * t_cose_key. */
    key_pair->k.key_handle = key_handle;
    key_pair->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return T_COSE_SUCCESS;
}

enum t_cose_err_t make_hmac_key(uint8_t cose_alg, struct t_cose_key *res_key)
{
    psa_status_t         crypto_result;
    psa_key_handle_t     key_handle;
    psa_algorithm_t      key_alg;
    const uint8_t       *key;
    size_t               key_len;
    psa_key_attributes_t key_attributes;


    static const uint8_t key_256[] = {KEY_hmac256};
    static const uint8_t key_384[] = {KEY_hmac384};
    static const uint8_t key_512[] = {KEY_hmac512};

    switch(cose_alg) {
    case T_COSE_ALGORITHM_HMAC256:
        key      = key_256;
        key_len  = sizeof(key_256);
        key_alg  = PSA_ALG_HMAC(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_HMAC384:
        key     = key_384;
        key_len = sizeof(key_384);
        key_alg = PSA_ALG_HMAC(PSA_ALG_SHA_384);
        break;
    case T_COSE_ALGORITHM_HMAC512:
        key     = key_512;
        key_len = sizeof(key_512);
        key_alg = PSA_ALG_HMAC(PSA_ALG_SHA_512);
        break;
    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }


    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data (because the import is not of a format
     * like RFC 5915). The variable key_type contains
     * that information. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     */

    key_attributes = psa_key_attributes_init();

    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_HMAC);

    /* Say what algorithm and operations the key can be used with/for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);

    crypto_result = psa_import_key(&key_attributes,
                                    key,
                                    key_len,
                                   &key_handle);

    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* This assignment relies on MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
     * not being defined. If it is defined key_handle is a structure.
     * This does not seem to be typically defined as it seems that is
     * for a PSA implementation architecture as a service rather than
     * an linked library. If it is defined, the structure will
     * probably be less than 64 bits, so it can still fit in a
     * t_cose_key. */
    res_key->k.key_handle = key_handle;
    res_key->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return T_COSE_SUCCESS;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
void free_key(struct t_cose_key key_pair)
{
   psa_destroy_key((psa_key_handle_t)key_pair.k.key_handle);
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
int check_for_key_pair_leaks()
{
    return 0;
}
