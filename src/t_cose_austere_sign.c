//
//  t_cose_austere_sign.c
//  t_cose
//
//  Created by Laurence Lundblade on 5/2/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_austere_sign.h"
#include "t_cose/t_cose_common.h"

/*
 1) start the hash function

 2) hash the fixed byte string that is start of the Sig_structure

 3) hash the payload

 4) finish the hash

 5) copy the COSE_Sign1 stuff before the payload to the output.

 6) copy the payload to the output

 7) copy another fixed length string to the output, the bstr head for the signature

 7) call ECDA sign with the hash as input and output directly to the output buffer
 */


#include "t_cose_crypto.h"

// Adjust these for algorithm and payload length
#define PAYLOAD_LEN 128 // Only works for lengths > 24 and < 256
#define COSE_HASH   COSE_ALGORITHM_SHA_384
#define ENCODED_EC384 0x22 // Make sure this is the right encoding if you change this
#define ENCODED_EC384_SIG_LEN 96 // Make sure this is the right encoding if you change this


/* This has all sort of stuff packed in and hard coded, including the payload length.

     * Sig_structure = [
     *    context : "Signature" / "Signature1" / "CounterSignature",
     *    body_protected : empty_or_serialized_map,
     *    ? sign_protected : empty_or_serialized_map,
     *    external_aad : bstr,
     *    payload : bstr
     * ]

 */

static uint8_t start_sig_struct[] = {
    0x84,
    0x6A,
    'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
    0x44, 0xA1, 0x01, 0x38, ENCODED_EC384, // bstr wrapped protected header wtih algorithm ID
    0x40, // Empty bstr for aad
    0x58, PAYLOAD_LEN,
};

static uint8_t start_cose_sign1[] = {
    0x84,
    0x44, 0xA1, 0x01, 0x38, ENCODED_EC384, // bstr wrapped protected header wtih algorithm ID
    0xa0, // no unprotected headers, put some here if you want
    0x58, PAYLOAD_LEN,
};

static uint8_t cose_sign1_sig_start[] = {
    0x58, 96
};



enum t_cose_err_t
t_cose_austere_sign(const struct q_useful_buf_c payload,
                    struct t_cose_key           signing_key,
                    const struct q_useful_buf   output_buffer,
                    struct q_useful_buf_c      *output)
{

    struct t_cose_crypto_hash  hash_ctx;
    enum t_cose_err_t          err;
    struct q_useful_buf_c      computed_hash;
    struct q_useful_buf_c      signature;
    size_t                     cose_sign1_len;


    MakeUsefulBufOnStack(hash_output, 64); // TODO: correct size for selected hash

    /* --- hash the Sig_structure --- */
    err = t_cose_crypto_hash_start(&hash_ctx, COSE_ALGORITHM_SHA_384);

    t_cose_crypto_hash_update(&hash_ctx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(start_sig_struct));
    t_cose_crypto_hash_update(&hash_ctx, payload);

    err = t_cose_crypto_hash_finish(&hash_ctx, hash_output, &computed_hash);


    /* --- Copy first part of COSE_Sign1 to output buffer -- */
    cose_sign1_len = 0;

    const struct q_useful_buf_c xx = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(start_cose_sign1);
    q_useful_buf_copy(output_buffer, xx);

    cose_sign1_len += xx.len;

    /* -- Copy the payload to the output buffer -- */
    useful_buf_copy_offset(output_buffer, cose_sign1_len, payload);

    cose_sign1_len += payload.len;

    /* -- Do the signing and put it in the output buffer */
    const struct q_useful_buf_c yy = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_sign1_sig_start);

    useful_buf_copy_offset(output_buffer, cose_sign1_len, yy);

    cose_sign1_len += yy.len;

    struct q_useful_buf tmp = {(uint8_t *)output_buffer.ptr + cose_sign1_len,
                               output_buffer.len - cose_sign1_len};


    t_cose_crypto_sign(T_COSE_ALGORITHM_ES384,
                       signing_key,
                       computed_hash,
                       tmp,
                       &signature);

    cose_sign1_len += signature.len;

    output->ptr = output_buffer.ptr;
    output->len = cose_sign1_len;

    return 0;
}
