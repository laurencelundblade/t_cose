/*
 * init_keys_psa.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_key.h"
#include "psa/crypto.h"


/*
 * Import a signing key. Not sure what all formats this actually
 * handles yet, but do know that just the private key works. Note that
 * the curve and algorithm type are specified here directly.
 */
static enum t_cose_err_t
init_signing_key_from_xx(int32_t               cose_algorithm_id,
                         struct q_useful_buf_c key_bytes,
                         struct t_cose_key    *key_pair)
{
    psa_key_type_t       key_type;
    psa_status_t         crypto_result;
    psa_key_handle_t     key_handle;
    psa_algorithm_t      key_alg;
    psa_key_attributes_t key_attributes;


    /* There is not a 1:1 mapping from COSE algorithm to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_ES384:
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
        break;

    case T_COSE_ALGORITHM_ES512:
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
        break;

    case T_COSE_ALGORITHM_PS256:
        key_type        = PSA_KEY_TYPE_RSA_KEY_PAIR;
        key_alg         = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_PS384:
        key_type        = PSA_KEY_TYPE_RSA_KEY_PAIR;
        key_alg         = PSA_ALG_RSA_PSS(PSA_ALG_SHA_384);
        break;

    case T_COSE_ALGORITHM_PS512:
        key_type        = PSA_KEY_TYPE_RSA_KEY_PAIR;
        key_alg         = PSA_ALG_RSA_PSS(PSA_ALG_SHA_512);
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
     * discovered from the raw data (because the import is not of a
     * format like RFC 5915). The variable key_type contains that
     * information including the EC curve. This is sufficient for
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
                                   key_bytes.ptr,
                                   key_bytes.len,
                                   &key_handle);

    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* This assignment relies on
     * MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER not being defined. If
     * it is defined key_handle is a structure.  This does not seem to
     * be typically defined as it seems that is for a PSA
     * implementation architecture as a service rather than an linked
     * library. If it is defined, the structure will probably be less
     * than 64 bits, so it can still fit in a t_cose_key. */
    key_pair->key.handle = key_handle;

    return T_COSE_SUCCESS;
}


/*
 * These are the same keys as in init_keys_ossl.c so that messages
 * made with openssl-based tests and examples can be verified those
 * made by mbedtls tests and examples.  These were made with openssl
 * as detailed in init_keys_ossl.c.  Then just the private key was
 * pulled out to be put here because mbedtls just needs the private
 * key, unlike openssl for which there is a full rfc5915 DER
 * structure. These were pulled out of the DER by identifying the key
 * with openssl asn1parse and then finding those bytes in the C
 * variable holding the rfc5915 (perhaps there is a better way, but
 * it worked).
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

/*
 * Public function, see init_keys.h
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair)
{
    struct q_useful_buf_c key_bytes;

    static const uint8_t private_key_256[]     = {PRIVATE_KEY_prime256v1};
    static const uint8_t private_key_384[]     = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[]     = {PRIVATE_KEY_secp521r1};
    static const uint8_t private_key_rsa2048[] = {
#include "rsa_test_key.h"
    };

    /* PSA doesn't support EdDSA so no keys for it here (OpenSSL does). */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_256);
        break;

    case T_COSE_ALGORITHM_ES384:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_384);
        break;

    case T_COSE_ALGORITHM_ES512:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_521);
        break;

    case T_COSE_ALGORITHM_PS256:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_rsa2048);
        break;

    case T_COSE_ALGORITHM_PS384:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_rsa2048);
        break;

    case T_COSE_ALGORITHM_PS512:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_rsa2048);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    return init_signing_key_from_xx(cose_algorithm_id, key_bytes, key_pair);
}


/*
 * Public function, see init_keys.h
 */
void free_fixed_signing_key(struct t_cose_key key_pair)
{
    psa_destroy_key((psa_key_handle_t)key_pair.key.handle);
}

/* Example Recipient ECC Public Key (P256r1) */
static const uint8_t fixed_test_p256r1_public_key[] = {
  0x04, 0x6d, 0x35, 0xe7, 0xa0, 0x75, 0x42, 0xc1, 0x2c, 0x6d, 0x2a, 0x0d,
  0x2d, 0x45, 0xa4, 0xe9, 0x46, 0x68, 0x95, 0x27, 0x65, 0xda, 0x9f, 0x68,
  0xb4, 0x7c, 0x75, 0x5f, 0x38, 0x00, 0xfb, 0x95, 0x85, 0xdd, 0x7d, 0xed,
  0xa7, 0xdb, 0xfd, 0x2d, 0xf0, 0xd1, 0x2c, 0xf3, 0xcc, 0x3d, 0xb6, 0xa0,
  0x75, 0xd6, 0xb9, 0x35, 0xa8, 0x2a, 0xac, 0x3c, 0x38, 0xa5, 0xb7, 0xe8,
  0x62, 0x80, 0x93, 0x84, 0x55
};

/* Example Recipient ECC Private Key (P256r1) */
static const uint8_t fixed_test_p256r1_private_key[] = {
  0x37, 0x0b, 0xaf, 0x20, 0x45, 0x17, 0x01, 0xf6, 0x64, 0xe1, 0x28, 0x57,
  0x4e, 0xb1, 0x7a, 0xd3, 0x5b, 0xdd, 0x96, 0x65, 0x0a, 0xa8, 0xa3, 0xcd,
  0xbd, 0xd6, 0x6f, 0x57, 0xa8, 0xcc, 0xe8, 0x09
};

/* Example Recipient ECC Public Key (P384r1) */
static const uint8_t fixed_test_p384r1_public_key[] = {
  0x04, 0x65, 0x5f, 0xba, 0xb3, 0x5c, 0x8e, 0x62, 0x79, 0x85, 0x29, 0xd1,
  0x9d, 0x69, 0x01, 0x85, 0x3c, 0x02, 0x60, 0x53, 0x2b, 0x67, 0xec, 0xd0,
  0x3a, 0x6d, 0xf8, 0x93, 0xe9, 0x26, 0xe3, 0x79, 0xeb, 0x13, 0x01, 0xcb,
  0x12, 0xb3, 0xc3, 0xca, 0xc8, 0xf6, 0x04, 0xba, 0xef, 0xe1, 0x54, 0x48,
  0xec, 0x60, 0x85, 0x25, 0xf3, 0x5e, 0xe1, 0xd9, 0xfd, 0x69, 0xc6, 0xf3,
  0x9e, 0x54, 0xf4, 0x62, 0xb0, 0x0e, 0x70, 0x70, 0x0b, 0xee, 0x62, 0x9f,
  0xef, 0xc7, 0x56, 0x64, 0xc8, 0x25, 0x26, 0x45, 0x87, 0xcf, 0xbd, 0x48,
  0x8f, 0xe0, 0x7a, 0x36, 0x1e, 0xf3, 0x41, 0x5a, 0x9a, 0x12, 0x4a, 0x92,
  0x2b
};

/* Example Recipient ECC Private Key (P384r1) */
static const uint8_t fixed_test_p384r1_private_key[] = {
  0xaa, 0x27, 0x7c, 0x2d, 0xa4, 0x75, 0xba, 0x16, 0x7a, 0x94, 0x8d, 0x60,
  0x54, 0x3c, 0x7a, 0x82, 0xfc, 0xca, 0x30, 0x69, 0x5f, 0x2c, 0x18, 0xf5,
  0x8f, 0x3d, 0x00, 0x23, 0xa0, 0xa7, 0x3d, 0x4a, 0x7a, 0x93, 0xa4, 0x9a,
  0x6f, 0xe5, 0xd6, 0x8f, 0x11, 0x9f, 0x27, 0x67, 0x10, 0x32, 0x7a, 0x35
};

/* Example Recipient ECC Public Key (P521r1) */
static const uint8_t fixed_test_p521r1_public_key[] = {
  0x04, 0x01, 0x5d, 0xe0, 0x72, 0xa9, 0x92, 0x9e, 0x22, 0xc9, 0x35, 0x5d,
  0x63, 0x03, 0x18, 0x13, 0x33, 0xf7, 0xb0, 0xe4, 0xcd, 0x5f, 0x2c, 0x5e,
  0x97, 0xd2, 0x97, 0xfd, 0x29, 0xa2, 0x05, 0x85, 0xe8, 0xf2, 0x7c, 0x40,
  0xc1, 0xd3, 0x4b, 0x9d, 0x45, 0x4e, 0x32, 0xa1, 0xd6, 0x2c, 0xb6, 0xa3,
  0xa2, 0x4c, 0xdd, 0x62, 0x32, 0x4f, 0x1e, 0xbe, 0x7a, 0xd1, 0x39, 0xb6,
  0x78, 0xa0, 0x70, 0xee, 0x0a, 0x68, 0x00, 0x01, 0x54, 0x1d, 0x4e, 0x94,
  0x83, 0x11, 0x04, 0x34, 0x71, 0x11, 0x5d, 0xd1, 0xd3, 0x8f, 0xbe, 0x1c,
  0x6d, 0xcb, 0x0d, 0x2b, 0x79, 0xbf, 0x95, 0x61, 0xd2, 0x48, 0xcb, 0xc8,
  0x13, 0x1e, 0xec, 0x94, 0x88, 0xd6, 0x1e, 0x39, 0xd0, 0x31, 0x71, 0x51,
  0xeb, 0xb8, 0xf6, 0xe8, 0x65, 0x1d, 0x86, 0x5d, 0x88, 0xd7, 0xac, 0xcf,
  0x2e, 0x3b, 0x41, 0xd7, 0x05, 0x94, 0x33, 0x74, 0x7c, 0x7d, 0xec, 0x78,
  0x1d
};

/* Example Recipient ECC Private Key (P521r1) */
static const uint8_t fixed_test_p521r1_private_key[] = {
  0x01, 0xed, 0x9f, 0x02, 0x6e, 0xe1, 0x54, 0x22, 0x58, 0x10, 0xc3, 0x12,
  0xda, 0x2a, 0xdc, 0x92, 0x54, 0x95, 0xdc, 0x36, 0xe3, 0x92, 0x9c, 0x97,
  0xa3, 0x98, 0x16, 0x53, 0xc3, 0x8b, 0xca, 0x03, 0x5c, 0x4a, 0xf5, 0xe7,
  0x46, 0x90, 0x6e, 0x5f, 0x6a, 0x39, 0x5a, 0xff, 0xae, 0xcf, 0xdb, 0x68,
  0x73, 0x45, 0x02, 0x29, 0xd8, 0x18, 0x0f, 0xf2, 0x54, 0xbb, 0xe0, 0x6c,
  0x84, 0x22, 0xc4, 0xae, 0x1d, 0x53
};

enum t_cose_err_t
init_fixed_test_encryption_key(uint32_t           cose_algorithm_id,
                               struct t_cose_key *public_key,
                               struct t_cose_key *private_key)
{
    psa_status_t status;
    psa_key_attributes_t pkR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t pkR_handle = PSA_KEY_HANDLE_INIT;

    psa_key_attributes_t skR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t skR_handle = PSA_KEY_HANDLE_INIT;
    psa_key_type_t type_public;
    psa_key_type_t type_private;
    uint32_t key_bitlen;
    const uint8_t *test_public_key;
    const uint8_t *test_private_key;
    uint32_t test_public_key_len;
    uint32_t test_private_key_len;

    psa_crypto_init();

    switch (cose_algorithm_id) {
    case T_COSE_ELLIPTIC_CURVE_P_256:
         type_public = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         type_private = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
         key_bitlen = 256;
         test_public_key = fixed_test_p256r1_public_key;
         test_public_key_len = sizeof(fixed_test_p256r1_public_key);
         test_private_key = fixed_test_p256r1_private_key;
         test_private_key_len = sizeof(fixed_test_p256r1_private_key);
         break;
    case T_COSE_ELLIPTIC_CURVE_P_384:
         type_public = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         type_private = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
         key_bitlen = 384;
         test_public_key = fixed_test_p384r1_public_key;
         test_public_key_len = sizeof(fixed_test_p384r1_public_key);
         test_private_key = fixed_test_p384r1_private_key;
         test_private_key_len = sizeof(fixed_test_p384r1_private_key);
         break;
    case T_COSE_ELLIPTIC_CURVE_P_521:
         type_public = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         type_private = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
         key_bitlen = 521;
         test_public_key = fixed_test_p521r1_public_key;
         test_public_key_len = sizeof(fixed_test_p521r1_public_key);
         test_private_key = fixed_test_p521r1_private_key;
         test_private_key_len = sizeof(fixed_test_p521r1_private_key);
         break;
    default:
         return T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG;
    }

    /* Set up the recipient's public key (pkR) */

    /* Import public key */
    psa_set_key_usage_flags(&pkR_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&pkR_attributes, PSA_ALG_ECDSA_ANY);
    psa_set_key_type(&pkR_attributes, type_public);
    psa_set_key_bits(&pkR_attributes, key_bitlen);

    status = psa_import_key(&pkR_attributes, /* in: attributes */
                            test_public_key, /* in: key bytes */
                            test_public_key_len, /* in: key length */
                            &pkR_handle); /* out: PSA key handle */
    if(status != PSA_SUCCESS) {
        return T_COSE_ERR_PUBLIC_KEY_IMPORT_FAILED;
    }

    public_key->key.handle = pkR_handle;

    /* Import private key */
    psa_set_key_usage_flags(&skR_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&skR_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&skR_attributes, type_private);
    psa_set_key_bits(&skR_attributes, key_bitlen);

    status = psa_import_key(&skR_attributes,
                             test_private_key,
                             test_private_key_len,
                             &skR_handle);

    if (status != PSA_SUCCESS) {
        return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
    }

    private_key->key.handle = skR_handle;

    return T_COSE_SUCCESS;
}


/*
 * Public function, see init_keys.h
 */
void
free_fixed_test_encryption_key(struct t_cose_key key_pair)
{
    psa_destroy_key((psa_key_handle_t)key_pair.key.handle);
}




/*
 * Public function, see init_keys.h
 */
int check_for_key_allocation_leaks(void)
{
    return 0;
}

