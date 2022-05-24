//
//  t_cose_mini_sign.c
//  t_cose
//
//  Created by Laurence Lundblade on 5/2/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_mini_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"

#include "qcbor/UsefulBuf.h"


#define T_COSE_MINI_SIGN_SELECT_ES384




#if defined(T_COSE_MINI_SIGN_SELECT_ES256)

#define MINI_SIGN_HASH           COSE_ALGORITHM_SHA_256
#define MINI_SIGN_HASH_LEN       T_COSE_CRYPTO_SHA256_SIZE
#define MINI_SIGN_ALG            T_COSE_ALGORITHM_ES256
#define MINI_SIGN_ALG_ID_BYTES   0x26 /* The literal byte that appears in the CBOR encoding */
#define MINI_SIGN_SIG_LEN        T_COSE_EC_P256_SIG_SIZE // Code below only works for lengths < 256

#elif defined(T_COSE_MINI_SIGN_SELECT_ES384)

#define MINI_SIGN_HASH           COSE_ALGORITHM_SHA_384
#define MINI_SIGN_HASH_LEN       T_COSE_CRYPTO_SHA384_SIZE
#define MINI_SIGN_ALG            T_COSE_ALGORITHM_ES384
#define MINI_SIGN_ALG_ID_BYTES   0x38, 0x22 /* The literal byte that appears in the CBOR encoding */
#define MINI_SIGN_SIG_LEN        T_COSE_EC_P384_SIG_SIZE // Code below only works for lengths < 256

#elif defined(T_COSE_MINI_SIGN_SELECT_ES512)

#define MINI_SIGN_HASH           COSE_ALGORITHM_SHA_512
#define MINI_SIGN_HASH_LEN       T_COSE_CRYPTO_SHA512_SIZE
#define MINI_SIGN_ALG            T_COSE_ALGORITHM_ES521
#define MINI_SIGN_ALG_ID_BYTES   0x38, 0x23 /* The literal byte that appears in the CBOR encoding */
#define MINI_SIGN_SIG_LEN        T_COSE_EC_P512_SIG_SIZE // Code below only works for lengths < 256

#endif

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
    0x6A,'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
    0x44, 0xA1, 0x01, MINI_SIGN_ALG_ID_BYTES, // bstr wrapped protected header wtih algorithm ID
    0x40, // Empty bstr for aad
};

static uint8_t start_cose_sign1[] = {
    0x84,
    0x44, 0xA1, 0x01, MINI_SIGN_ALG_ID_BYTES, // bstr wrapped protected header wtih algorithm ID
    0xa0, // no unprotected headers, put some here if you want
};

static uint8_t cose_sign1_sig_start[] = {
    0x58, MINI_SIGN_SIG_LEN
};




/* This maximum is for a CBOR head for a byte string no longer than
 * UINT16_MAX, not the general case for a CBOR head. */
#define MAX_CBOR_HEAD 3

/* Len < 65355 */
static inline struct q_useful_buf_c
encode_bstr_head(struct q_useful_buf b, size_t len)
{
    uint8_t *bb = b.ptr;

    if(b.len < MAX_CBOR_HEAD) {
        return NULLUsefulBufC;
    }

    if(len < 24 ) {
        bb[0] = 0x40 + (uint8_t)len;
        return (struct q_useful_buf_c){bb, 1};
    } else if(len < 256) {
        bb[0] = 0x58;
        bb[1] = (uint8_t)len;
        return (struct q_useful_buf_c){bb, 2};
    } else  if(len < UINT16_MAX) {
        bb[0] = 0x59;
        bb[1] = (uint8_t)(len / 8);
        bb[2] = (uint8_t)(len % 256);
        return (struct q_useful_buf_c){bb, 3};
    } else {
        return NULLUsefulBufC;
    }
}




enum t_cose_err_t
t_cose_mini_sign(const struct q_useful_buf_c payload,
                 struct t_cose_key           signing_key,
                 const struct q_useful_buf   output_buffer,
                 struct q_useful_buf_c      *output)
{
    struct t_cose_crypto_hash  hash_ctx;
    enum t_cose_err_t          err;
    struct q_useful_buf_c      computed_hash;
    struct q_useful_buf_c      signature;
    MakeUsefulBufOnStack(      hash_output, MINI_SIGN_HASH_LEN);
    MakeUsefulBufOnStack(      payload_head_buffer, MAX_CBOR_HEAD);
    struct q_useful_buf_c      payload_head;
    struct q_useful_buf        tmp;

    payload_head = encode_bstr_head(payload_head_buffer, payload.len);

    if(payload_head.ptr == NULL) {
        return 99; // TODO: error code
    }


    /* --- hash the Sig_structure --- */
    /* Don't actually have to create the Sig_structure fully in
     * memory. Just have to compute the hash of it. */
    err = t_cose_crypto_hash_start(&hash_ctx, MINI_SIGN_HASH);

    t_cose_crypto_hash_update(&hash_ctx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(start_sig_struct));
    t_cose_crypto_hash_update(&hash_ctx, payload_head);
    t_cose_crypto_hash_update(&hash_ctx, payload);

    err = t_cose_crypto_hash_finish(&hash_ctx, hash_output, &computed_hash);


    const size_t required_len = payload.len +
                                MAX_CBOR_HEAD +
                                sizeof(start_cose_sign1) +
                                sizeof(cose_sign1_sig_start);

    if(output_buffer.len < required_len) {
        return 0;
    }

    uint8_t *p;

    p = output_buffer.ptr;

    memcpy(p, start_cose_sign1, sizeof(start_cose_sign1));
    p += sizeof(start_cose_sign1);

    memcpy(p, payload_head.ptr, payload_head.len);
    p += payload_head.len;

    memcpy(p, payload_head.ptr, payload.len);
    p += payload.len;

    memcpy(p, cose_sign1_sig_start, sizeof(cose_sign1_sig_start));
    p += payload.len;

    struct q_useful_buf tmp2;
    tmp2.len = p - (uint8_t *)output_buffer.ptr ;
    tmp.ptr = p;


    t_cose_crypto_sign(MINI_SIGN_ALG,
                       signing_key,
                       computed_hash,
                       tmp,
                       &signature);

    output->ptr = output_buffer.ptr;
    output->len = tmp2.len + MINI_SIGN_SIG_LEN;


    return 0;
}

