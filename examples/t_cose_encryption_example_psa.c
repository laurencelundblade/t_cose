/*
 *  t_cose_encryption_example_psa.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose_standard_constants.h"
#include "t_cose_parameters.h"
#include "psa/crypto.h"
#include "t_cose_crypto.h"

#define DETACHED_PAYLOAD     1
#define INCLUDED_PAYLOAD     0
#define BUFFER_SIZE       1024

static void print_bytestr(const uint8_t *bytes, size_t len)
{
    for(unsigned int idx = 0; idx<len; idx++)
    {
        printf("%02X",bytes[idx]);
    }
}

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

int test_cose_encrypt(int detached,
                      uint8_t *firmware, size_t firmware_len,
                      uint8_t *cose_encrypt_buf, size_t cose_encrypt_buf_len,
                      size_t *cose_encrypt_result_len,
                      uint8_t *encrypted_firmware, size_t encrypted_firmware_len,
                      size_t *encrypted_firmware_result_len,
                      uint32_t algorithm,
                      uint32_t key_exchange
                     )
{
    int res = 0;
    uint8_t buf[BUFFER_SIZE];
    size_t buf_len = sizeof(buf);

    struct t_cose_encrypt_enc_ctx enc_ctx;
    struct t_cose_encrypt_recipient_hpke_ctx recipient_ctx;
    size_t key_length;
    uint8_t cek[T_COSE_ENCRYPTION_MAX_KEY_LENGTH];
    size_t cek_len;
    psa_status_t status;
    int ret = 0;
    size_t pkE_len = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t pkE[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    /* Public Key Id structure */
    struct q_useful_buf_c kid = {pk_kid, pk_kid_len};

    enum t_cose_err_t result;
    psa_key_attributes_t skE_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t skE_handle = 0;
    psa_key_type_t type;

    /* Buffer for recipient */
    QCBOREncodeContext recipient1;
    uint8_t recipient1_buf[500] = {0};
    UsefulBuf r_buf = {recipient1_buf, sizeof(recipient1_buf)};
    UsefulBufC encoded_recipient;

    UsefulBuf cose_encrypt_struct = {.ptr = cose_encrypt_buf,.len = cose_encrypt_buf_len};
    UsefulBufC encoded_cose_encrypt;

    struct t_cose_key t_cose_ephemeral;
    psa_key_attributes_t pkR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t pkR_handle = 0;

    struct t_cose_key t_cose_recipient;
    QCBOREncodeContext EC;

    key_length = 128;

    /* Create recipient structure */
    t_cose_encrypt_hpke_recipient_init(&recipient_ctx,
                                       0,
                                       key_exchange);

    /* Create random CEK */
    status = psa_generate_random(cek, key_length/8);
    cek_len = key_length/8;

    if (status != PSA_SUCCESS) {
        printf("psa_generate_random failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_encrypt_hpke_set_encryption_key(&recipient_ctx, cek, cek_len);

    type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);

    /* generate ephemeral key pair: skE, pkE */
    psa_set_key_usage_flags(&skE_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&skE_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&skE_attributes, type);
    psa_set_key_bits(&skE_attributes, 256);

    status = psa_generate_key(&skE_attributes, &skE_handle);

    if (status != PSA_SUCCESS) {
        printf("psa_generate_key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_ephemeral.k.key_handle = skE_handle;
    t_cose_ephemeral.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_hpke_set_ephemeral_key(&recipient_ctx,
                                          t_cose_ephemeral);

    psa_set_key_usage_flags(&pkR_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&pkR_attributes, PSA_ALG_ECDSA_ANY);
    psa_set_key_type(&pkR_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pkR_attributes,
                            public_key, pk_key_len,
                            &pkR_handle);

    if (status != PSA_SUCCESS) {
        printf("psa_import_key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_recipient.k.key_handle = pkR_handle;
    t_cose_recipient.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_hpke_set_recipient_key(&recipient_ctx,
                                          t_cose_recipient,
                                          kid);

    QCBOREncode_Init(&recipient1, r_buf);

    result = t_cose_encrypt_hpke_create_recipient(&recipient_ctx,
                                                  &recipient1);

    if (result != 0) {
        printf("error creating recipient (%d)\n", result);
        return(EXIT_FAILURE);
    }

    /* Initialize CBOR encoder context with output buffer */
    QCBOREncode_Init(&EC, cose_encrypt_struct);

    t_cose_encrypt_enc_init(&enc_ctx, 0, algorithm);

    t_cose_encrypt_set_encryption_key(&enc_ctx, cek, cek_len);

    if (result != 0) {
        printf("error adding recipient (%d)\n", result);
        return(EXIT_FAILURE);
    }

    /* Export recipient structure */
    ret = QCBOREncode_Finish(&recipient1, &encoded_recipient);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_FAIL);
    }

    if (detached == 1) {
        result = t_cose_encrypt_enc_detached(&enc_ctx,
                                             &EC,
                                             (struct q_useful_buf_c)
                                             {
                                                .ptr = firmware,
                                                .len = firmware_len
                                             },
                                             (struct q_useful_buf)
                                             {
                                                .ptr = encrypted_firmware,
                                                .len = encrypted_firmware_len
                                             },
                                             encrypted_firmware_result_len
                                            );
    } else {
        result = t_cose_encrypt_enc(&enc_ctx,
                                    &EC,
                                    (struct q_useful_buf_c)
                                    {
                                       .ptr = firmware,
                                       .len = firmware_len
                                    },
                                    (struct q_useful_buf)
                                    {
                                       .ptr = encrypted_firmware,
                                       .len = encrypted_firmware_len
                                    }
                                 );
    }

    if (result != 0) {
        printf("error encrypting (%d)\n", result);
        return(EXIT_FAILURE);
    }

    result = t_cose_encrypt_add_recipient(&enc_ctx, &EC, &encoded_recipient);

    if (result != 0) {
        printf("error adding recipient (%d)\n", result);
        return(EXIT_FAILURE);
    }

    result = t_cose_encrypt_enc_finish(&enc_ctx, &EC);

    if (result != 0) {
        printf("error finishing encryption (%d)\n", result);
        return(EXIT_FAILURE);
    }

    /* Export COSE_Encrypt structure */
    ret = QCBOREncode_Finish(&EC, &encoded_cose_encrypt);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_FAIL);
    }

    *cose_encrypt_result_len = encoded_cose_encrypt.len;

    return(0);
}


int test_cose_encrypt0(int detached,
                       uint8_t *firmware, size_t firmware_len,
                       uint8_t *cose_encrypt_buf, size_t cose_encrypt_buf_len,
                       size_t *cose_encrypt_result_len,
                       uint8_t *encrypted_firmware, size_t encrypted_firmware_len,
                       size_t *encrypted_firmware_result_len,
                       uint8_t *cek,
                       size_t cek_len,
                       uint32_t algorithm,
                       struct q_useful_buf_c kid)
{
    int ret = 0;
    enum t_cose_err_t result;
    QCBOREncodeContext EC;
    struct t_cose_encrypt_enc_ctx enc_ctx;
    UsefulBuf cose_encrypt_struct = {.ptr = cose_encrypt_buf, .len = cose_encrypt_buf_len};
    UsefulBufC encoded_cose_encrypt;

    /* Initialize CBOR encoder context with output buffer */
    QCBOREncode_Init(&EC, cose_encrypt_struct);

    t_cose_encrypt_enc0_init(&enc_ctx, T_COSE_OPT_COSE_ENCRYPT0, algorithm, kid);

    t_cose_encrypt_set_encryption_key(&enc_ctx, cek, cek_len);

    if (detached == 1) {
        result = t_cose_encrypt_enc_detached(
                   &enc_ctx,
                   &EC,
                   (struct q_useful_buf_c) {.ptr = firmware, .len = firmware_len},
                   (struct q_useful_buf) {.ptr = encrypted_firmware, .len = encrypted_firmware_len},
                   encrypted_firmware_result_len);
    } else {
        result = t_cose_encrypt_enc(
                   &enc_ctx,
                   &EC,
                   (struct q_useful_buf_c) {.ptr = firmware, .len = firmware_len},
                   (struct q_useful_buf) {.ptr = encrypted_firmware, .len = encrypted_firmware_len});
    }

    if (result != 0) {
        printf("error encrypting (%d)\n", result);
        return(EXIT_FAILURE);
    }

    result = t_cose_encrypt_enc_finish(&enc_ctx, &EC);

    if (result != 0) {
        printf("error finishing encryption (%d)\n", result);
        return(EXIT_FAILURE);
    }

    /* Export cose encrypt structure */
    ret = QCBOREncode_Finish(&EC, &encoded_cose_encrypt);

    if (ret != QCBOR_SUCCESS ) {
      return(T_COSE_ERR_FAIL);
    }

    *cose_encrypt_result_len = encoded_cose_encrypt.len;

    return(0);
}


int main(void)
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
    int res = 0;
    enum t_cose_err_t ret;
    uint8_t plaintext[BUFFER_SIZE];
    size_t plaintext_output_len;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t key_handle = 0;

    /* Key id for PSK */
    struct q_useful_buf_c kid1 = {psk_kid, psk_kid_len};
    /* Key id for public key */
    struct q_useful_buf_c kid2 = {pk_kid, pk_kid_len};
    /* Key id for PSK 2 */
    struct q_useful_buf_c kid3 = {psk2_kid, psk2_kid_len};

    struct t_cose_key t_cose_own_key;
    struct t_cose_encrypt_dec_ctx dec_ctx;

    /* Initialize the PSA */
    status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

    /* -------------------------------------------------------------------------*/

    printf("\n-- 1. Create COSE_Encrypt structure with detached payload --\n\n");
    test_cose_encrypt(DETACHED_PAYLOAD,
                      firmware, firmware_len,
                      buffer, sizeof(buffer),
                      &result_len,
                      encrypted_firmware, encrypted_firmware_len,
                      &encrypted_firmware_result_len,
                      COSE_ALGORITHM_A128GCM,
                      COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM
                     );

    printf("COSE: ");
    print_bytestr(buffer, result_len);

    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_firmware, encrypted_firmware_result_len);
    printf("\n");

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&attributes,
                            private_key, sizeof(private_key),
                            &key_handle);

    if (status != PSA_SUCCESS) {
        printf("psa_import_key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_own_key.k.key_handle = key_handle;
    t_cose_own_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_HPKE);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_own_key, kid2);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
    psa_destroy_key( key_handle );

    /* -------------------------------------------------------------------------*/

    printf("\n-- 2. Create COSE_Encrypt structure with included payload --\n\n");
    test_cose_encrypt(INCLUDED_PAYLOAD,
                      firmware, firmware_len,
                      buffer, sizeof(buffer),
                      &result_len,
                      encrypted_firmware, encrypted_firmware_len,
                      &encrypted_firmware_result_len,
                      COSE_ALGORITHM_A128GCM,
                      COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM
                     );

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n");

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&attributes,
                            private_key, sizeof(private_key),
                            &key_handle);

    if (status != PSA_SUCCESS) {
        printf("Import of key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_own_key.k.key_handle = key_handle;
    t_cose_own_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_HPKE);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_own_key, kid2);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             NULL, 0,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
    psa_destroy_key(key_handle);

    /* -------------------------------------------------------------------------*/

    printf("\n-- 3. Create COSE_Encrypt0 structure with detached payload --\n\n");
    res = test_cose_encrypt0(DETACHED_PAYLOAD,
                             firmware, firmware_len,
                             buffer, sizeof(buffer),
                             &result_len,
                             encrypted_firmware, encrypted_firmware_len,
                             &encrypted_firmware_result_len,
                             psk, psk_key_len,
                             COSE_ALGORITHM_A128GCM,
                             (struct q_useful_buf_c) {psk_kid, psk_kid_len}
                            );

    if (res != 0) {
        printf("\nEncryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_firmware, encrypted_firmware_result_len);
    printf("\n");

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);

    status = psa_import_key(&attributes,
                            psk, psk_key_len,
                            &key_handle);

    if (status != PSA_SUCCESS) {
        printf("Importing key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_own_key.k.key_handle = key_handle;
    t_cose_own_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_DIRECT);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_own_key, kid1);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
    psa_destroy_key(key_handle);

    /* -------------------------------------------------------------------------*/

    printf("\n-- 4. Create COSE_Encrypt0 structure with included payload --\n\n");
    test_cose_encrypt0(INCLUDED_PAYLOAD,
                       firmware, firmware_len,
                       buffer, sizeof(buffer),
                       &result_len,
                       encrypted_firmware, encrypted_firmware_len,
                       &encrypted_firmware_result_len,
                       psk, psk_key_len,
                       COSE_ALGORITHM_A128GCM,
                       (struct q_useful_buf_c) {psk_kid, psk_kid_len}
                      );

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n");

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);

    status = psa_import_key(&attributes, psk, psk_key_len, &key_handle);

    if (status != PSA_SUCCESS) {
        printf("Importing key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_own_key.k.key_handle = key_handle;
    t_cose_own_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_DIRECT);
    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_own_key, kid1);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
    psa_destroy_key(key_handle);

    /* -------------------------------------------------------------------------*/

    printf("\n-- 5. Create COSE_Encrypt0 structure with detached payload (AES256-GCM) --\n\n");
    res = test_cose_encrypt0(DETACHED_PAYLOAD,
                             firmware, firmware_len,
                             buffer, sizeof(buffer),
                             &result_len,
                             encrypted_firmware, encrypted_firmware_len,
                             &encrypted_firmware_result_len,
                             psk2, psk2_key_len,
                             COSE_ALGORITHM_A256GCM,
                             (struct q_useful_buf_c) {psk2_kid, psk2_kid_len}
                            );

    if (res != 0) {
        printf("\nEncryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_firmware, encrypted_firmware_result_len);
    printf("\n");

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    status = psa_import_key(&attributes,
                            psk2, psk2_key_len,
                            &key_handle);

    if (status != PSA_SUCCESS) {
        printf("Importing key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_own_key.k.key_handle = key_handle;
    t_cose_own_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_DIRECT);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_own_key, kid3);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
    psa_destroy_key(key_handle);

    /* -------------------------------------------------------------------------*/

    printf("\n-- 6. Create COSE_Encrypt0 structure with included payload (AES256-GCM) --\n\n");
    test_cose_encrypt0(INCLUDED_PAYLOAD,
                       firmware, firmware_len,
                       buffer, sizeof(buffer),
                       &result_len,
                       encrypted_firmware, encrypted_firmware_len,
                       &encrypted_firmware_result_len,
                       psk2, psk2_key_len,
                       COSE_ALGORITHM_A256GCM,
                       (struct q_useful_buf_c) {psk2_kid, psk2_kid_len}
                      );

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n");

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    status = psa_import_key(&attributes,
                            psk2, psk2_key_len,
                            &key_handle);

    if (status != PSA_SUCCESS) {
        printf("Importing key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_own_key.k.key_handle = key_handle;
    t_cose_own_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_DIRECT);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_own_key, kid3);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
    psa_destroy_key(key_handle);

    return(0);
}