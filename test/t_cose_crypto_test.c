/*
 * t_cose_crypto_test.c
 *
 * Copyright 2022-2026, Laurence Lundblade
 * Created by Laurence Lundblade on 12/28/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include "t_cose_crypto_test.h"
#include "init_keys.h"
#include "t_cose/t_cose_private.h"
#include "t_cose/t_cose_standard_constants.h"



/* Maximum size ECC key used in tests here in bits */
#define ECC_MAX_CURVE_BITS 521

#define T_COSE_BITS_TO_BYTES(bits) (((bits) + 7) / 8)

/* Buffer size in bytes for max size ECC key used here */
#define EXPORT_PUBLIC_KEY_MAX_SIZE (2*T_COSE_BITS_TO_BYTES(ECC_MAX_CURVE_BITS)+1)


static const uint8_t test_key_0_128bit[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x010, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x010, 0x00};

/* Nonce / IV is typically 12 bytes for most usage */
static const uint8_t iv_0[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x010, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t aad[] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

#if 0
/* From the GCM standard, but it doesn't match. Would like to know why... */
static const uint8_t test_ciphertext[] = {
    0x72, 0x66, 0x23, 0x9A, 0x61, 0xCD, 0xB6, 0x6C, 0x3E, 0xB0, 0x8B, 0x58,
    0x72, 0x0D, 0x53, 0x4A, 0x0E, 0x4A, 0xEF, 0xC3, 0x55, 0xAC, 0x90, 0x4C,
    0x58, 0x1F
};
#endif


/* TODO: proper define to know about test crypto */
#ifndef T_COSE_USE_B_CON_SHA256
/* This is what is output by both OpenSSL and MbedTLS (but different than what is in the GCM standard). */
static const uint8_t expected_empty_tag[] = {
    0xC9, 0x4A, 0xA9, 0xF3, 0x22, 0x75, 0x73, 0x8C, 0xD5, 0xCC, 0x75, 0x01, 0xA4, 0x80, 0xBC, 0xF5};
#endif

int32_t aead_test(void)
{
    enum t_cose_err_t      err;
    int32_t                cose_algorithm_id;
    struct t_cose_key      key;
    struct q_useful_buf_c  ciphertext;
    MakeUsefulBufOnStack(  ciphertext_buffer, 300);
    MakeUsefulBufOnStack(  plaintext_buffer, 300);
    struct q_useful_buf_c  plaintext;
    const struct q_useful_buf_c empty = {"", 0};


    cose_algorithm_id = T_COSE_ALGORITHM_A128GCM;

    err = t_cose_private_tcrypto_make_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                                               UsefulBuf_FROM_BYTE_ARRAY_LITERAL(test_key_0_128bit),
                                                              &key);
    if(err) {
        return 1000 + (int32_t)err;
    }

    /* First the simplest case, no payload, no aad, just the tag */
    err = t_cose_private_tcrypto_aead_encrypt(cose_algorithm_id,
                                                  key,
                                                  Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                                  NULL_Q_USEFUL_BUF_C,
                                                  empty,
                                                  ciphertext_buffer,
                                                 &ciphertext);
    if(err) {
        return 2000 + (int32_t)err;
    }

    /* TODO: proper define to know about test crypto */
#ifndef T_COSE_USE_B_CON_SHA256
    /* Compare to the expected output.
     * PSA and OpenSSL are creating the same value here, but it doesn't
     * line up with the GCM test vectors from the GSM standard.
     * I don't know why. It seems like it should.
     */
    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_empty_tag), ciphertext)) {
        return -2001;
    }
#else
    /* It's not really necessary to test the test crypto, but it is
     * helpful to validate it some. But the above is disabled as it
     * doesn't produce real AES-GCM results even though it can
     * fake encryption and decryption. */
#endif

    err = t_cose_private_tcrypto_aead_decrypt(cose_algorithm_id,
                                                  key,
                                                  Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                                  NULL_Q_USEFUL_BUF_C,
                                                  ciphertext,
                                                  plaintext_buffer,
                                                 &plaintext);

    if(err) {
        return 3000 + (int32_t)err;
    }

    if(plaintext.len != 0) {
        return -3001;
    }


    /* Test with text and aad */
    err = t_cose_private_tcrypto_aead_encrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"),
                                     ciphertext_buffer,
                                     &ciphertext);
    if(err) {
        return 4000 + (int32_t)err;
    }

    err = t_cose_private_tcrypto_aead_decrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     ciphertext,
                                     plaintext_buffer,
                                     &plaintext);
    if(err) {
        return 5000 + (int32_t)err;
    }

    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"), plaintext)) {
        return -5001;
    }

    /* TODO: test a lot more conditions like size calculation, overflow, modified tags...
     * Most of these tests are aimed at OpenSSL because it has a terrible API and
     * documentation for AEAD. */

    t_cose_key_free_symmetric(key);

    return 0;
}

struct kw_test_case {
    int32_t                cose_kw_algorithm_id;
    int32_t                cose_key_algorithm_id;
    struct q_useful_buf_c  kek;
    struct q_useful_buf_c  to_be_wrapped;
    struct q_useful_buf_c  expected_wrap;
    enum t_cose_err_t      expected_wrap_result;
    enum t_cose_err_t      expected_unwrap_result;
};

static const struct kw_test_case s_kw_test_cases[] = {
    {
        T_COSE_ALGORITHM_A128KW,
        T_COSE_ALGORITHM_A128KW,
        {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16},
        {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16},
        {"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5", 24},
        T_COSE_SUCCESS,
        T_COSE_SUCCESS
    },
    {
        T_COSE_ALGORITHM_A128GCM, // Bad algorithm for key wrap
        T_COSE_ALGORITHM_A128KW,
        {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16},
        {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16},
        {"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5", 24},
        T_COSE_ERR_UNSUPPORTED_CIPHER_ALG,
        T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
    },

    {
        T_COSE_ALGORITHM_A192KW, // Bad key length
        T_COSE_ALGORITHM_A128KW,
        {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16},
        {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16},
        {"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5", 24},
        T_COSE_ERR_WRONG_TYPE_OF_KEY,
        T_COSE_ERR_WRONG_TYPE_OF_KEY
    },
    {
        T_COSE_ALGORITHM_A192KW,
        T_COSE_ALGORITHM_A192KW,
        {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17", 24},
        {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07", 24},
        {"\x03\x1D\x33\x26\x4E\x15\xD3\x32\x68\xF2\x4E\xC2\x60\x74\x3E\xDC\xE1\xC6\xC7\xDD\xEE\x72\x5A\x93\x6B\xA8\x14\x91\x5C\x67\x62\xD2", 32},
        T_COSE_SUCCESS,
        T_COSE_SUCCESS
    },
    {
        T_COSE_ALGORITHM_A256KW,
        T_COSE_ALGORITHM_A256KW,
        {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F", 32},
        {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 32},
        {"\x28\xC9\xF4\x04\xC4\xB8\x10\xF4\xCB\xCC\xB3\x5C\xFB\x87\xF8\x26\x3F\x57\x86\xE2\xD8\x0E\xD3\x26\xCB\xC7\xF0\xE7\x1A\x99\xF4\x3B\xFB\x98\x8B\x9B\x7A\x02\xDD\x21" , 40},
        T_COSE_SUCCESS,
        T_COSE_SUCCESS
    },
    { // wrap: to-be-wrapped is less than 16 bytes, unwrap: ciphertext is too short
        T_COSE_ALGORITHM_A128KW,
        T_COSE_ALGORITHM_A128KW,
        {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16},
        {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE", 15},
        {"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF", 23},
        T_COSE_ERR_KW_FAILED,
        T_COSE_ERR_KW_FAILED
    },
    { // wrap: to-be-wrapped is not multiple of 8, unwrap: ciphertext is too long
        T_COSE_ALGORITHM_A128KW,
        T_COSE_ALGORITHM_A128KW,
        {"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16},
        {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00", 17},
        {"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5\xDD", 25},
        T_COSE_ERR_KW_FAILED,
        T_COSE_ERR_KW_FAILED
    },

    {
        T_COSE_ALGORITHM_NONE
    }

};



int32_t kw_test(void)
{
    struct t_cose_key      kek;
    enum t_cose_err_t      err;
    struct q_useful_buf_c  ciphertext;
    struct q_useful_buf_c  plaintext;
    Q_USEFUL_BUF_MAKE_STACK_UB (ciphertext_buffer, 9 * 8); /* sized for 256-bit key with authentication tag */
    Q_USEFUL_BUF_MAKE_STACK_UB (plaintext_buffer, 8 * 8);  /* sized for 256-bit key */

    for(int i = 0; ; i++) {
        const struct kw_test_case *tc = &s_kw_test_cases[i];
        if(tc->cose_kw_algorithm_id == T_COSE_ALGORITHM_NONE) {
            break;
        }

        if(i == 1) {
            err = 0; // for break point
        }

        err = t_cose_private_tcrypto_make_symmetric_key_handle(tc->cose_key_algorithm_id,
                                                               tc->kek,
                                                              &kek);
        if(err != T_COSE_SUCCESS) {
            return 1;
        }

        err = t_cose_private_tcrypto_kw_wrap(tc->cose_kw_algorithm_id,
                                             kek,
                                             tc->to_be_wrapped,
                                             ciphertext_buffer,
                                             &ciphertext);
        if(err != tc->expected_wrap_result) {
            return 2;
        }

        if(err == T_COSE_SUCCESS) {
            /* TODO: proper define to know about test crypto */
#ifndef T_COSE_USE_B_CON_SHA256
            if(q_useful_buf_compare(ciphertext, tc->expected_wrap)) {
                return 3;
            }
#else
            /* It's not really necessary to test the test crypto, but it is
             * helpful to validate it some. But the above is disabled as it
             * doesn't produce real key wra results even though it can
             * fake wrap and unwrap. */
#endif
        } else {
            ciphertext = UsefulBuf_Copy(ciphertext_buffer, tc->expected_wrap);
        }

        err = t_cose_private_tcrypto_kw_unwrap(tc->cose_kw_algorithm_id,
                                               kek,
                                               ciphertext,
                                               plaintext_buffer,
                                              &plaintext);
        if(err != tc->expected_wrap_result) {
            return 4;
        }

        if(err == T_COSE_SUCCESS) {
            if(q_useful_buf_compare(tc->to_be_wrapped, plaintext)) {
                return 5;
            }

            /* Now modify the cipher text so the integrity check will fail.
             * It's only a test case so cheating by casting away const is not
             * too big of a crime. */
            ((uint8_t *)(uintptr_t)ciphertext.ptr)[ciphertext.len-1] += 1;

            err = t_cose_private_tcrypto_kw_unwrap(tc->cose_kw_algorithm_id,
                                                   kek,
                                                   ciphertext,
                                                   plaintext_buffer,
                                                  &plaintext);
            if(err != T_COSE_ERR_DATA_AUTH_FAILED) {
                return 6;
            }
        }

        t_cose_key_free_symmetric(kek);
    }

    return 0;
}




/* The following are one of the test vectors from RFC 5869. One is
 * enough as the goal is just to validate the adaptor layer, not fully
 * test the HKDF implementation as it was presumably tested when the
 * crypto library was released. */
static const uint8_t tc1_ikm_bytes[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const uint8_t tc1_salt_bytes[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const uint8_t tc1_info_bytes[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};

#ifndef T_COSE_USE_B_CON_SHA256
static const uint8_t tc1_okm_bytes[] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};
#endif

int32_t hkdf_test(void)
{
    Q_USEFUL_BUF_MAKE_STACK_UB(tc1_okm, 42);
    enum t_cose_err_t          err;
    struct q_useful_buf_c      okm;

    err = t_cose_private_tcrypto_hkdf(T_COSE_ALGORITHM_SHA_256,
                         Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_salt_bytes),
                         Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_ikm_bytes),
                         Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_info_bytes),
                         tc1_okm);
    if(err) {
        return 1;
    }

    okm.len = tc1_okm.len;
    okm.ptr = tc1_okm.ptr;

#ifndef T_COSE_USE_B_CON_SHA256
    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_okm_bytes),
                            okm)) {
        return 2;
    }
#else
    (void)okm;
#endif

    return 0;
}

#ifndef T_COSE_USE_B_CON_SHA256 /* test crypto doesn't support ECDH */

/* Expected result for cose_ex_P_256_key_pair_der. */
static const uint8_t expected_ecdh_p256[] = {
    0xE6, 0xBE, 0xF9, 0xB9, 0x91, 0x0C, 0xD1, 0x5A,
    0x20, 0xEF, 0x49, 0xB2, 0x40, 0x31, 0x0C, 0x8B,
    0xFC, 0x81, 0xDB, 0xAD, 0xBE, 0x63, 0x92, 0x7E,
    0xB2, 0x15, 0xB5, 0xAE, 0x01, 0x1E, 0x51, 0xEB};

int32_t ecdh_test(void)
{
    enum t_cose_err_t           err;
    struct t_cose_key           public_key;
    struct t_cose_key           private_key;
    struct q_useful_buf_c       shared_key;
    Q_USEFUL_BUF_MAKE_STACK_UB( shared_key_buf, EXPORT_PUBLIC_KEY_MAX_SIZE);


    err = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                           &public_key,
                                           &private_key);
    if(err != T_COSE_SUCCESS) {
        return -1;
    }

    err = t_cose_private_tcrypto_ecdh(private_key,
                             public_key,
                             shared_key_buf,
                            &shared_key);

    if(err != T_COSE_SUCCESS) {
        return (int32_t)err;
    }

    /* The main point of this test is that the same result comes from
     * all the crypto libraries integrated. */
    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_ecdh_p256), shared_key)) {
        return 44;
    }

    free_fixed_test_ec_encryption_key(public_key);
    free_fixed_test_ec_encryption_key(private_key);

    return 0;

}


/* X coordinate from cose_ex_P_256_key_pair_der. */
static const uint8_t x_coord_P_256[] = {
    0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba,
    0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a,
    0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d,
    0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d,
};

static const uint8_t y_coord_P_256[] = {
    0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7,
    0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d,
    0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c,
    0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c,
};

int32_t ec_import_export_test(void)
{
    enum t_cose_err_t      err;
    struct t_cose_key      public_key;
    struct t_cose_key      private_key;
    struct t_cose_key      public_key_next;
    MakeUsefulBufOnStack(  x_coord_buf, T_COSE_BITS_TO_BYTES(ECC_MAX_CURVE_BITS));
    MakeUsefulBufOnStack(  y_coord_buf, T_COSE_BITS_TO_BYTES(ECC_MAX_CURVE_BITS));
    struct q_useful_buf_c  x_coord;
    struct q_useful_buf_c  y_coord;
    bool                   y_sign;
    int32_t                curve;

    err = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                           &public_key,
                                           &private_key);
    if(err) {
        return 1;
    }

    err = t_cose_private_tcrypto_export_ec2_key(public_key,
                                      &curve,
                                       x_coord_buf,
                                      &x_coord,
                                       y_coord_buf,
                                      &y_coord,
                                      &y_sign);
    if(err) {
        return 2;
    }

    err = t_cose_private_tcrypto_import_ec2_pubkey(curve,
                                          x_coord,
                                          y_coord,
                                          y_sign,
                                          &public_key_next);
    if(err) {
        return 3;
    }

    err = t_cose_private_tcrypto_export_ec2_key(public_key_next,
                                      &curve,
                                       x_coord_buf,
                                      &x_coord,
                                       y_coord_buf,
                                      &y_coord,
                                      &y_sign);

    free_fixed_test_ec_encryption_key(public_key);
    free_fixed_test_ec_encryption_key(private_key);


    if(err) {
        return 4;
    }

    if(curve != T_COSE_ELLIPTIC_CURVE_P_256) {
        return 5;
    }

    if(q_useful_buf_compare(x_coord, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(x_coord_P_256) )) {
        return 6;
    }


    if(q_useful_buf_compare(y_coord, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(y_coord_P_256) )) {
        return 6;
    }

    return 0;
}


#endif /* ! T_COSE_USE_B_CON_SHA256 */
