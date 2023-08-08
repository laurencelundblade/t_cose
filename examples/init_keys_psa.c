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
#include "example_keys.h"


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
 * Public function, see init_keys.h
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair)
{
    struct q_useful_buf_c key_bytes;

    /* PSA doesn't support EdDSA so no keys for it here (OpenSSL does). */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_256_priv_key_sec1);
        break;

    case T_COSE_ALGORITHM_ES384:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_384_priv_key_sec1);
        break;

    case T_COSE_ALGORITHM_ES512:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_521_priv_key_sec1);
        break;

    case T_COSE_ALGORITHM_PS256:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(RSA_2048_key_pair_der);
        break;

    case T_COSE_ALGORITHM_PS384:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(RSA_2048_key_pair_der);
        break;

    case T_COSE_ALGORITHM_PS512:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(RSA_2048_key_pair_der);
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




/*
 * Public function, see init_keys.h
 */
enum t_cose_err_t
init_fixed_test_ec_encryption_key(uint32_t           cose_ec_curve_id,
                                  struct t_cose_key *public_key,
                                  struct t_cose_key *private_key)
{
    psa_status_t          status;
    psa_key_attributes_t  attributes;
    psa_key_type_t        type_private;
    psa_key_type_t        type_public;
    uint32_t              key_bitlen;
    struct q_useful_buf_c priv_key_bytes;
    struct q_useful_buf_c pub_key_bytes;

    psa_crypto_init();

    switch (cose_ec_curve_id) {
    case T_COSE_ELLIPTIC_CURVE_P_256:
         type_private   = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
         type_public    = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         priv_key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cose_ex_P_256_priv_sec1);
         pub_key_bytes  = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cose_ex_P_256_pub_sec1);
         key_bitlen     = 256;
         break;

    case T_COSE_ELLIPTIC_CURVE_P_521:
         type_private   = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
         type_public    = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         priv_key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cose_ex_P_521_priv_sec1);
         pub_key_bytes  = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cose_ex_P_521_pub_sec1);
         key_bitlen     = 521;
         break;
    default:
         return T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG;
    }

    /* Import the private key from the SEC1 representation. It is
     * the only format supported by psa_import_key(). ASN.1/DER/PEM
     * formats are not supported.
     */
    attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, type_private);
    psa_set_key_bits(&attributes, key_bitlen);

    status = psa_import_key(&attributes,
                            priv_key_bytes.ptr, priv_key_bytes.len,
                            (mbedtls_svc_key_id_t *)(&private_key->key.handle));


    /* Import the public key from the SEC1 representation. It is
     * the only format supported by psa_import_key(). ASN.1/DER/PEM
     * formats are not supported.
     */
    attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, type_public);
    psa_set_key_bits(&attributes, key_bitlen);
    status = psa_import_key(&attributes,
                             pub_key_bytes.ptr, pub_key_bytes.len,
                             (mbedtls_svc_key_id_t *)(&public_key->key.handle));

    /*
     * With PSA, it is also possible to import the private key as
     * psa_import_key() will automatically derive the public key,
     * the key handle will the key pair and will be usable as a public key.
    attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, type_private);
    psa_set_key_bits(&attributes, key_bitlen);
    status = psa_import_key(&attributes,
                            key_bytes.ptr, key_bytes.len,
                            (mbedtls_svc_key_id_t *)(&public_key->key.handle));
    */


    if (status != PSA_SUCCESS) {
        psa_destroy_key((psa_key_handle_t)private_key->key.handle);
        return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
    }

    return T_COSE_SUCCESS;
}


/*
 * Public function, see init_keys.h
 */
void
free_fixed_test_ec_encryption_key(struct t_cose_key key)
{
    psa_destroy_key((psa_key_handle_t)key.key.handle);
}




/*
 * Public function, see init_keys.h
 */
int check_for_key_allocation_leaks(void)
{
    return 0;
}

