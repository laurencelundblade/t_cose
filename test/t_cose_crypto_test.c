/*
 *  t_cose_crypto_test.c
 *
 * Copyright 2022, Laurence Lundblade
 * Created by Laurence Lundblade on 12/28/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "t_cose_crypto_test.h"

#include "../src/t_cose_crypto.h" /* NOT a public interface so this test can't run an installed library */

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



static const uint8_t test_ciphertext[] = {
    0x72, 0x66, 0x23, 0x9A, 0x61, 0xCD, 0xB6, 0x6C, 0x3E, 0xB0, 0x8B, 0x58,
    0x72, 0x0D, 0x53, 0x4A, 0x0E, 0x4A, 0xEF, 0xC3, 0x55, 0xAC, 0x90, 0x4C,
    0x58, 0x1F
};

static const uint8_t expected_empty_tag[] = {
    0xC9, 0x4A, 0xA9, 0xF3, 0x22, 0x75, 0x73, 0x8C, 0xD5, 0xCC, 0x75, 0x01, 0xA4, 0x80, 0xBC, 0xF5};


int_fast32_t aead_test(void)
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

    err = t_cose_crypto_make_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                                  UsefulBuf_FROM_BYTE_ARRAY_LITERAL(test_key_0_128bit),
                                                 &key);
    if(err) {
        return (int_fast32_t)err;
    }

    /* First the simplest case, no payload, no aad, just the tag */
    err = t_cose_crypto_aead_encrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     NULL_Q_USEFUL_BUF_C,
                                     empty,
                                     ciphertext_buffer,
                                     &ciphertext);
    if(err) {
        return (int_fast32_t)err;
    }

    /* TODO: proper define to know about test crypto */
#ifndef T_COSE_USE_B_CON_SHA256
    /* Compare to the expected output.
     * PSA and OpenSSL are creating the same value here, but it doesn't
     * line up with the GCM test vectors from the GSM standard.
     * I don't know why. It seems like it should.
     */
    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_empty_tag), ciphertext)) {
        return -99;
    }
#else
    /* It's not really necessary to test the test crypto, but it is
     * helpful to validate it some. But the above is disabled as it
     * doesn't produce real AES-GCM results even though it an
     * fake encryption and decryption. */
#endif

    err = t_cose_crypto_aead_decrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     NULL_Q_USEFUL_BUF_C,
                                     ciphertext,
                                     plaintext_buffer,
                                     &plaintext);

    if(err) {
        return (int_fast32_t)err;
    }

    if(plaintext.len != 0) {
        return -99;
    }



    /* Test with text and aad */
    err = t_cose_crypto_aead_encrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"),
                                     ciphertext_buffer,
                                     &ciphertext);
    if(err) {
        return (int_fast32_t)err;
    }

    err = t_cose_crypto_aead_decrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     ciphertext,
                                     plaintext_buffer,
                                     &plaintext);
    if(err) {
        return (int_fast32_t)err;
    }

    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"), plaintext)) {
        return -99;
    }

    
    return 0;
}

