//
//  t_cose_crypto_test.c
//  t_cose
//
//  Created by Laurence Lundblade on 12/28/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose_crypto_test.h"

#include "../src/t_cose_crypto.h" /* NOT a public interface so this test can't run an installed library */

static const uint8_t xkey[] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

static const uint8_t nonce[] = {
0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

static const uint8_t aad[] = {
0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

int_fast32_t aead_test(void)
{
    enum t_cose_err_t err;
    int32_t cose_algorithm_id;
    struct t_cose_key  key;
    struct q_useful_buf_c ciphertext;
    MakeUsefulBufOnStack(ciphertext_buffer, 300);
    MakeUsefulBufOnStack(plaintext_buffer, 300);
    struct q_useful_buf_c plaintext;


    cose_algorithm_id = T_COSE_ALGORITHM_A128GCM;

    err = t_cose_crypto_make_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                                  UsefulBuf_FROM_BYTE_ARRAY_LITERAL(xkey),
                                                 &key);
    if(err) {
        return (int_fast32_t)err;
    }

    err = t_cose_crypto_aead_encrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(nonce),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"),
                                     ciphertext_buffer,
                                     &ciphertext);

    err = t_cose_crypto_aead_decrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(nonce),
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

