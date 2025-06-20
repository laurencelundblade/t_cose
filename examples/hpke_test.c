/*
 * \file hpke_test.c
 *
 * Copyright (c) 2024, Hannes Tschofenig. All rights reserved.
 *
 * Created by Hannes Tschofenig on 15/1/24
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_key.h"

#include <stdio.h>
#include "print_buf.h"
#include "init_keys.h"

#define PAYLOAD  "This is the payload"
#define TEST_SENDER_IDENTITY "sender"
#define TEST_RECIPIENT_IDENTITY "recipient"


#ifndef T_COSE_DISABLE_HPKE

#include "t_cose/t_cose_recipient_enc_hpke.h"
#include "t_cose/t_cose_recipient_dec_hpke.h"

int32_t hpke_encrypt(struct t_cose_key                pkR,
                     struct q_useful_buf_c            payload,
                     struct q_useful_buf_c            *cose_encrypted_message,
                     struct q_useful_buf              *cose_encrypt_message_buffer,
                     int32_t                          alg)
{
    struct t_cose_encrypt_enc        enc_ctx;
    enum t_cose_err_t                result;
    struct t_cose_recipient_enc_hpke recipient;

    /* Initialize the encryption context telling it we want
     * a COSE_Encrypt (not a COSE_Encrypt0) because we're doing HPKE with a
     * COSE_Recpipient. Also tell it the AEAD algorithm for the
     * body of the message.
     */
    t_cose_encrypt_enc_init(&enc_ctx,
                            T_COSE_OPT_MESSAGE_TYPE_ENCRYPT,
                            T_COSE_ALGORITHM_A128GCM);

    /* Create the recipient object telling it the algorithm and the public key
     * for the COSE_Recipient it's going to make. Then give that object
     * to the main encryption context. (Only one recipient is set here, but
     * there could be more)
     */
    t_cose_recipient_enc_hpke_init(&recipient,
                                    alg);

    t_cose_recipient_enc_hpke_set_key(&recipient,
                                       pkR,
                                       Q_USEFUL_BUF_FROM_SZ_LITERAL(TEST_RECIPIENT_IDENTITY));

    t_cose_encrypt_add_recipient(&enc_ctx,
                                 (struct t_cose_recipient_enc *)&recipient);

    /* Now do the actual encryption */
    result = t_cose_encrypt_enc(&enc_ctx, /* in: encryption context */
                                 payload, /* in: payload to encrypt */
                                 NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                *cose_encrypt_message_buffer, /* in: buffer for COSE_Encrypt */
                                 cose_encrypted_message); /* out: COSE_Encrypt */

    return (int32_t)result;
}


int32_t hpke_decrypt(struct q_useful_buf_c            cose_encrypted_message,
                     struct q_useful_buf_c           *plaintext_message,
                     struct q_useful_buf             *plaintext_buffer,
                     struct t_cose_key                skR)
{
    struct t_cose_recipient_dec_hpke dec_recipient;
    struct t_cose_encrypt_dec_ctx    dec_ctx;
    enum t_cose_err_t                result;

    /* Set up the decryption context, telling it what type of
     * message to expect if there's no tag (that part isn't quite implemented right yet anyway).
     */
    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT);


    /* Set up the recipient object with the key material. We happen to know
     * what the algorithm and key are in advance so we don't have to
     * decode the parameters first to figure that out (not that this part is
     * working yet). */
    t_cose_recipient_dec_hpke_init(&dec_recipient);
    t_cose_recipient_dec_hpke_set_skr(&dec_recipient,
                                      skR,
                                      Q_USEFUL_BUF_FROM_SZ_LITERAL(TEST_RECIPIENT_IDENTITY));

    t_cose_encrypt_dec_add_recipient(&dec_ctx, (struct t_cose_recipient_dec *)&dec_recipient);

    result = t_cose_encrypt_dec(&dec_ctx,
                                cose_encrypted_message, /* in: the COSE_Encrypt message */
                                NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                               *plaintext_buffer,
                                plaintext_message,
                                NULL);

    return (int32_t)result;
}

int save_file(const char *path, unsigned char *buf, size_t n)
{
    FILE *f;
    long size;

    if ((f = fopen(path, "w")) == NULL) {
        return 1;
    }

   size = fwrite(buf, 1, n, f);

    if (size != n) {
        fclose(f);
        return 1;
    }

    return 0;
}



int load_file(const char *path, unsigned char **buf, size_t *n)
{
    FILE *f;
    long size;

    if ((f = fopen(path, "rb")) == NULL) {
        return 1;
    }

    fseek(f, 0, SEEK_END);
    if ((size = ftell(f)) == -1) {
        fclose(f);
        return 1;
    }
    fseek(f, 0, SEEK_SET);

    *n = (size_t) size;

    if (*n + 1 == 0 ||
        (*buf = calloc(1, *n + 1)) == NULL) {
        fclose(f);
        return 1;
    }

    if (fread(*buf, 1, *n, f) != *n) {
        fclose(f);

        memset(*buf, 0, *n);
        free(*buf);

        return 1;
    }

    fclose(f);

    (*buf)[*n] = '\0';

    return 0;
}

#define USAGE \
    "\n usage: hpke_test param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    encrypt=%%d      default: 0 (encryption)\n"         \
    "    input_file=%%s      default: input.cbor\n"     \
    "    output_file=%%s     default: output.cbor\n"              \
    "    alg=%%d     default: 35 for T_COSE_HPKE_Base_P256_SHA256_AES128GCM \n"             \
    "\n"

/*
 * global options
 */
struct options {
    const char *input_file;     /* input filename                   */
    const char *output_file;    /* output filename                  */
    int encrypt;                /* encryption (0) or decryption (1) */
    int alg;                    /* algorithm                        */
} opt;

#define DFL_INPUT_FILE          "input.cbor"
#define DFL_OUTPUT_FILE         "output.cbor"
#define DFL_ENCRYPTION          0
#define DFL_ALGORITHM           35

int main(int argc, char *argv[])
{
    int ret = 0;
    int i;
    char *p, *q;
    struct t_cose_key                skR;
    struct t_cose_key                pkR;
    Q_USEFUL_BUF_MAKE_STACK_UB  (    cose_encrypt_message_buffer, 200);
    struct q_useful_buf_c            cose_encrypted_message;
    size_t n;
    unsigned char *payload;
    struct q_useful_buf_c            plaintext_message;
    Q_USEFUL_BUF_MAKE_STACK_UB  (    plaintext_buffer, 100);


    /* Default values */
    opt.encrypt            = DFL_ENCRYPTION;
    opt.input_file         = DFL_INPUT_FILE;
    opt.output_file        = DFL_OUTPUT_FILE;
    opt.alg                = DFL_ALGORITHM;
    
    p = q = NULL;
    if (argc < 2) {
usage:
        if (p != NULL && q != NULL) {
            printf("unrecognized value for '%s': '%s'\n", p, q);
        } else if (p != NULL && q == NULL) {
            printf("unrecognized param: '%s'\n", p);
        }

        printf(USAGE);

        if (ret == 0) {
            ret = 1;
        }
        goto exit;
    }

    for (i = 1; i < argc; i++) {
        p = argv[i];

        if (strcmp(p, "help") == 0) {
            printf(USAGE);

            ret = 0;
            goto exit;
        }


        if ((q = strchr(p, '=')) == NULL) {
            printf("param requires a value: '%s'\n", p);
            p = NULL; // avoid "unrecnognized param" message
            goto usage;
        }
        *q++ = '\0';


        if (strcmp(p, "encrypt") == 0) {
            opt.encrypt = atoi(q);
            if (opt.encrypt < 0 || opt.encrypt > 1) {
                goto usage;
            }
        } else if (strcmp(p, "alg") == 0) {
            opt.alg = atoi(q);
            if (opt.encrypt < 0 || opt.encrypt > 1) {
                goto usage;
            }
        } else if (strcmp(p, "input_file") == 0) {
            opt.input_file = q;
        } else if (strcmp(p, "output_file") == 0) {
            opt.output_file = q;
        } else {
            /* This signals that the problem is with p not q */
            q = NULL;
            goto usage;
        }
    }
    /* This signals that any further errors are not with a single option */
    p = q = NULL;

    ret = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                           &pkR, /* out: public key to be used for encryption */
                                           &skR); /* out: corresponding private key for decryption */
    if (ret != T_COSE_SUCCESS) {
        goto exit;
    }

    if (opt.encrypt == 0)
    {

        if ((ret = load_file(opt.input_file, &payload, &n)) != 0) {
            printf("Failure to load file!\n");
            goto usage;
        }

        ret = hpke_encrypt(pkR,
                           Q_USEFUL_BUF_FROM_SZ_LITERAL(payload), 
                           &cose_encrypted_message,
                           &cose_encrypt_message_buffer,
                           opt.alg);
            
        if (ret != T_COSE_SUCCESS) {
            goto exit;
        }

        print_useful_buf("COSE_Encrypt: ", cose_encrypted_message);

        if ((ret = save_file(opt.output_file, (unsigned char *) cose_encrypted_message.ptr, cose_encrypted_message.len)) != 0) {
            printf("Failure to save file!\n");
            goto usage;
        }


    } else {

        if ((ret = load_file(opt.input_file, &payload, &n)) != 0) {
            printf("Failure to load file!\n");
            goto usage;
        }

        ret =  hpke_decrypt( (struct q_useful_buf_c)
                            {.ptr = payload, .len = n},
                            &plaintext_message,
                            &plaintext_buffer,
                            skR);

        print_useful_buf("Plaintext: ", plaintext_message);

    }

exit:
    if (ret < 0) {
        ret = 1;
    }

    return (ret);
}

#else
void main()
{
  printf("HPKE not available!\n");
}
#endif /* !T_COSE_DISABLE_HPKE */
