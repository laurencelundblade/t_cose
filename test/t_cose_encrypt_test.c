//
//  t_cose_encrypt_test.c
//  t_cose
//
//  Created by Laurence Lundblade on 10/25/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose_encrypt_test.h"

#include "t_cose/t_cose_encrypt_enc.h"


/* PSKs */
uint8_t psk[] = "aaaaaaaaaaaaaaaa";
uint8_t psk2[] = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb";

/* PSK IDs */
uint8_t psk_kid[] = "kid-1";
uint8_t psk2_kid[] = "kid-1a";

/* Remove trailing null byte in the size calculations below */
size_t psk_key_len = sizeof(psk)-1;
size_t psk_kid_len = sizeof(psk_kid)-1;
size_t psk2_key_len = sizeof(psk2)-1;
size_t psk2_kid_len = sizeof(psk2_kid)-1;

/* Example ECC public key (P256r1) */
uint8_t public_key[] = {
    0x04, 0x6d, 0x35, 0xe7, 0xa0, 0x75, 0x42, 0xc1, 0x2c, 0x6d, 0x2a, 0x0d,
    0x2d, 0x45, 0xa4, 0xe9, 0x46, 0x68, 0x95, 0x27, 0x65, 0xda, 0x9f, 0x68,
    0xb4, 0x7c, 0x75, 0x5f, 0x38, 0x00, 0xfb, 0x95, 0x85, 0xdd, 0x7d, 0xed,
    0xa7, 0xdb, 0xfd, 0x2d, 0xf0, 0xd1, 0x2c, 0xf3, 0xcc, 0x3d, 0xb6, 0xa0,
    0x75, 0xd6, 0xb9, 0x35, 0xa8, 0x2a, 0xac, 0x3c, 0x38, 0xa5, 0xb7, 0xe8,
    0x62, 0x80, 0x93, 0x84, 0x55
};

/* Example ECC private key (P256r1) */
uint8_t private_key[] = {
    0x37, 0x0b, 0xaf, 0x20, 0x45, 0x17, 0x01, 0xf6, 0x64, 0xe1, 0x28, 0x57,
    0x4e, 0xb1, 0x7a, 0xd3, 0x5b, 0xdd, 0x96, 0x65, 0x0a, 0xa8, 0xa3, 0xcd,
    0xbd, 0xd6, 0x6f, 0x57, 0xa8, 0xcc, 0xe8, 0x09
};

/* ID for public key id */
uint8_t pk_kid[] = "kid-2";

/* Public key id length and Public key length */
size_t pk_key_len = sizeof(public_key);
size_t pk_kid_len = sizeof(pk_kid)-1;



#define BUFFER_SIZE       1024


int test_cose_encrypt(int options,
                      uint8_t *firmware, size_t firmware_len,
                      uint8_t *cose_encrypt_buf, size_t cose_encrypt_buf_len,
                      size_t *cose_encrypt_result_len,
                      uint8_t *encrypted_firmware, size_t encrypted_firmware_len,
                      size_t *encrypted_firmware_result_len,
                      uint32_t algorithm,
                      uint32_t key_exchange,
                      struct t_cose_key recipient_key,
                      struct q_useful_buf_c kid
                      )
{
    struct t_cose_encrypt_enc_ctx enc_ctx;
    enum t_cose_err_t result;
    struct q_useful_buf encrypted_firmware_final = {0,0};

    struct q_useful_buf_c encrypt_cose;

    /* Initialize encryption context */
    t_cose_encrypt_enc_init(&enc_ctx, options, algorithm);

    /* Add a recipient. */
    result = t_cose_encrypt_add_recipient(
                                          &enc_ctx,
                                          key_exchange,
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
                                (struct q_useful_buf_c)
                                {
                                    .ptr = firmware,
                                    .len = firmware_len
                                },
                                /* Non-const pointer and length of the
                                 * buffer where the encrypted payload
                                 * is written to. The length here is that
                                 * of the whole buffer.
                                 */
                                (struct q_useful_buf)
                                {
                                    .ptr = encrypted_firmware,
                                    .len = encrypted_firmware_len
                                },
                                /* Const pointer and actual length of
                                 * the encrypted payload.
                                 */
                                &encrypted_firmware_final,
                                /* Non-const pointer and length of the
                                 * buffer where the completed output is
                                 * written to. The length here is that
                                 * of the whole buffer.
                                 */
                                (struct q_useful_buf)
                                {
                                    .ptr = cose_encrypt_buf,
                                    .len = cose_encrypt_buf_len
                                },
                                /* Const pointer and actual length of
                                 * the COSE_Encrypt message.
                                 * This structure points into the
                                 * output buffer and has the
                                 * lifetime of the output buffer.
                                 */
                                &encrypt_cose);

    if (result != 0) {
        printf("error encrypting (%d)\n", result);
        return(EXIT_FAILURE);
    }

    *cose_encrypt_result_len = encrypt_cose.len;
    *encrypted_firmware_result_len = encrypted_firmware_final.len;

    return(EXIT_SUCCESS);
}



int_fast32_t encrypt_test(void)
{
    psa_status_t status;
    uint8_t firmware[] = "This is a real plaintext.";
    size_t firmware_len = sizeof(firmware);
    uint8_t encrypted_firmware[BUFFER_SIZE] = {0};
    size_t encrypted_firmware_len = sizeof(encrypted_firmware)-1;
    uint8_t buffer[BUFFER_SIZE] = {0};
    struct q_useful_buf cose_encrypt_buf = {buffer, sizeof(buffer)};
    size_t result_len;
    size_t encrypted_firmware_result_len;
    size_t key_length = 128;
    int32_t res = 0;
    enum t_cose_err_t ret;
    uint8_t plaintext[BUFFER_SIZE];
    size_t plaintext_output_len;
    psa_key_attributes_t psk_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t psk_handle = 0;

    struct t_cose_key t_cose_pkR_key;

    /* Key id for PSK */
    struct q_useful_buf_c kid1 = {psk_kid, psk_kid_len};
    /* Key id for public key */
    struct q_useful_buf_c kid2 = {pk_kid, pk_kid_len};
    /* Key id for PSK 2 */
    struct q_useful_buf_c kid3 = {psk2_kid, psk2_kid_len};
    

    res = test_cose_encrypt(T_COSE_OPT_COSE_ENCRYPT_DETACHED,
                            firmware, firmware_len,
                            buffer, sizeof(buffer),
                            &result_len,
                            encrypted_firmware, encrypted_firmware_len,
                            &encrypted_firmware_result_len,
                            COSE_ALGORITHM_A128GCM,
                            COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM,
                            t_cose_pkR_key,
                            kid2);

    if (res != EXIT_SUCCESS) {
        return(-1);
    }






    return 0;
}
