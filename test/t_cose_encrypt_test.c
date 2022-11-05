//
//  t_cose_encrypt_test.c
//  t_cose
//
//  Created by Laurence Lundblade on 10/25/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose_encrypt_test.h"

#include "t_cose/t_cose_encrypt_enc.h"

#include "t_cose_make_test_pub_key.h"


/* PSKs */
uint8_t psk2[] = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb";

/* PSK IDs */
uint8_t psk_kid[] = "kid-1";


/* ID for public key id */
uint8_t pk_kid[] = "kid-2";



#define BUFFER_SIZE       1024


int test_cose_encrypt(uint32_t                    options,
                      const struct q_useful_buf_c plaintext,
                      struct q_useful_buf         cose_message_buffer,
                      int32_t                     body_alg_id,
                      int32_t                     key_exchange_alg_id,
                      struct t_cose_key           recipient_key,
                      const struct q_useful_buf_c kid,
                      struct q_useful_buf_c      *cose_message
                      )
{
    struct t_cose_encrypt_enc_ctx enc_ctx;
    enum t_cose_err_t             result;
    // TODO: this should be q_useful_buf_c (encrypt API has to change)
    struct q_useful_buf           detached_ciphertext = {0,0};

    MakeUsefulBufOnStack(detached_ciphertext_buffer, BUFFER_SIZE);

    /* Initialize encryption context */
    t_cose_encrypt_enc_init(&enc_ctx, options, body_alg_id);

    /* Add a recipient. */
    result = t_cose_encrypt_add_recipient(
                                          &enc_ctx,
                                          key_exchange_alg_id,
                                          recipient_key,
                                          kid);

    if (result != 0) {
        printf("error adding recipient (%d)\n", result);
        return(EXIT_FAILURE);
    }

    result = t_cose_encrypt_enc(
                                &enc_ctx,
                                /* Pointer and length of payload to be
                                 * encrypted.
                                 */
                                plaintext,
                                /* Non-const pointer and length of the
                                 * buffer where the encrypted payload
                                 * is written to. The length here is that
                                 * of the whole buffer. This is just
                                 * a scratch buffer that t_cose_encrypt_enc()
                                 * needs.
                                 */
                                detached_ciphertext_buffer,
                                /* Const pointer and actual length of
                                 * the encrypted payload.
                                 */
                                &detached_ciphertext,
                                /* Non-const pointer and length of the
                                 * buffer where the completed output is
                                 * written to. The length here is that
                                 * of the whole buffer.
                                 */
                                cose_message_buffer,
                                /* Const pointer and actual length of
                                 * the COSE_Encrypt message.
                                 * This structure points into the
                                 * output buffer and has the
                                 * lifetime of the output buffer.
                                 */
                                cose_message);

    if (result != 0) {
        printf("error encrypting (%d)\n", result);
        return(EXIT_FAILURE);
    }

    return(EXIT_SUCCESS);
}



int_fast32_t encrypt_test(void)
{
    struct q_useful_buf_c  firmware = Q_USEFUL_BUF_FROM_SZ_LITERAL("This is a real plaintext.");
    MakeUsefulBufOnStack(  cose_message_buffer, BUFFER_SIZE);
    struct q_useful_buf_c  cose_message;
    int32_t                res = 0;
    struct t_cose_key      recipient_key;

    make_symmetric_key(128, &recipient_key);

    res = test_cose_encrypt(T_COSE_OPT_COSE_ENCRYPT_DETACHED,
                            firmware,
                            cose_message_buffer,
                            COSE_ALGORITHM_A128GCM,
                            COSE_ALGORITHM_A128KW,
                            recipient_key,
                            Q_USEFUL_BUF_FROM_SZ_LITERAL(psk_kid),
                            &cose_message);

    if (res != EXIT_SUCCESS) {
        return(-1);
    }

    // Change name of free_ecdsa_key_pair -- it can destroy any key pair
    free_ecdsa_key_pair(recipient_key);


    return 0;
}
