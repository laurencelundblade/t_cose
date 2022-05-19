//
//  t_cose_austere_sign.c
//  t_cose
//
//  Created by Laurence Lundblade on 5/2/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_mini_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"

#include "qcbor/qcbor_encode.h" /* Only uses  the function QCBOREncode_EncodeHead()*/
#include "qcbor/UsefulBuf.h"

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
};

static uint8_t start_cose_sign1[] = {
    0x84,
    0x44, 0xA1, 0x01, 0x38, ENCODED_EC384, // bstr wrapped protected header wtih algorithm ID
    0xa0, // no unprotected headers, put some here if you want
};

static uint8_t cose_sign1_sig_start[] = {
    0x58, ENCODED_EC384_SIG_LEN
};


/* Len > 24 and < 65355 */
static inline struct q_useful_buf_c
EncodeBstrHead(struct q_useful_buf b, size_t len)
{
    uint8_t *bb = b.ptr;

    if(b.len < 3) {
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


typedef struct {
    UsefulBuf Storage;
    size_t uPosition;
} SAP;

static inline void
init(SAP *pOut, struct q_useful_buf o)
{
    pOut->Storage = o;
}

static inline void
simple_append(SAP *pOut, const UsefulBufC data)
{
    if(pOut->Storage.len - pOut->uPosition < data.len) {
        return;
    }

    memcpy((uint8_t *)(pOut->Storage.ptr) + pOut->uPosition, data.ptr, data.len);

    pOut->uPosition += data.len;
}

static inline struct q_useful_buf
get_place(SAP *pOut)
{
    return (struct q_useful_buf){(uint8_t *)(pOut->Storage.ptr) + pOut->uPosition,
        pOut->Storage.len - pOut->uPosition};
}


static inline void advance(SAP *pOut, size_t len)
{
    pOut->uPosition += len;
}

static inline struct q_useful_buf_c
geto(SAP *pOut)
{
    return (struct q_useful_buf_c){pOut->Storage.ptr, pOut->Storage.len};
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
    MakeUsefulBufOnStack(      hash_output, 64); // TODO: correct size for selected hash
    MakeUsefulBufOnStack(      payload_head_buffer, QCBOR_HEAD_BUFFER_SIZE);
    struct q_useful_buf_c      payload_head;
    struct q_useful_buf        tmp;

    payload_head = EncodeBstrHead(payload_head_buffer, payload.len);


    /* --- hash the Sig_structure --- */
    /* Don't actually have to create the Sig_structure fully in
     * memory. Just have to compute the hash of it. */
    err = t_cose_crypto_hash_start(&hash_ctx, COSE_ALGORITHM_SHA_384);

    t_cose_crypto_hash_update(&hash_ctx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(start_sig_struct));
    t_cose_crypto_hash_update(&hash_ctx, payload_head);
    t_cose_crypto_hash_update(&hash_ctx, payload);

    err = t_cose_crypto_hash_finish(&hash_ctx, hash_output, &computed_hash);


    if(output_buffer.len < payload.len + 4 + sizeof(start_cose_sign1) + sizeof(cose_sign1_sig_start)) {
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


    t_cose_crypto_sign(T_COSE_ALGORITHM_ES384,
                       signing_key,
                       computed_hash,
                       tmp,
                       &signature);

    output->ptr = output_buffer.ptr;
    output->len = tmp2.len + ENCODED_EC384_SIG_LEN;


    return 0;
}

int foo()
{
    return 99;
}


#ifdef NODEF
#if 0
/*
    SAP UBO;

    init(&UBO, output_buffer);

    simple_append(&UBO, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(start_cose_sign1));
    simple_append(&UBO, payload_head);
    simple_append(&UBO, payload);
    simple_append(&UBO, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cose_sign1_sig_start));

    // Output the signature directly into the output buffer.
    tmp = get_place(&UBO);

    t_cose_crypto_sign(T_COSE_ALGORITHM_ES384,
                       signing_key,
                       computed_hash,
                       tmp,
                       &signature);

    advance(&UBO, signature.len);

    *output = geto(&UBO);*/

#else


    UsefulOutBuf UBO;

    UsefulOutBuf_Init(&UBO, output_buffer);

    UsefulOutBuf_AppendUsefulBuf(&UBO, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(start_cose_sign1));
    UsefulOutBuf_AppendUsefulBuf(&UBO, payload_head);
    UsefulOutBuf_AppendUsefulBuf(&UBO, payload);
    UsefulOutBuf_AppendUsefulBuf(&UBO, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cose_sign1_sig_start));

    /* Output the signature directly into the output buffer. */
    tmp = UsefulOutBuf_GetOutPlace(&UBO);

    t_cose_crypto_sign(T_COSE_ALGORITHM_ES384,
                       signing_key,
                       computed_hash,
                       tmp,
                       &signature);

    UsefulOutBuf_Advance(&UBO, signature.len);

    *output = UsefulOutBuf_OutUBuf(&UBO);



//#else
    size_t cose_sign1_len;
    /* --- Copy first part of COSE_Sign1 to output buffer -- */
    cose_sign1_len = 0;

    const struct q_useful_buf_c xx = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(start_cose_sign1);
    q_useful_buf_copy(output_buffer,
                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(start_cose_sign1));
    cose_sign1_len += xx.len;


    useful_buf_copy_offset(output_buffer, cose_sign1_len, payload_head);
    cose_sign1_len += payload_head.len;


    /* -- Copy the payload to the output buffer -- */
    useful_buf_copy_offset(output_buffer, cose_sign1_len, payload);
    cose_sign1_len += payload.len;

    /* -- Do the signing and put it in the output buffer */
    const struct q_useful_buf_c yy = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_sign1_sig_start);
    useful_buf_copy_offset(output_buffer, cose_sign1_len, yy);
    cose_sign1_len += yy.len;

    tmp = (struct q_useful_buf){(uint8_t *)output_buffer.ptr + cose_sign1_len,
                               output_buffer.len - cose_sign1_len};


    t_cose_crypto_sign(T_COSE_ALGORITHM_ES384,
                       signing_key,
                       computed_hash,
                       tmp,
                       &signature);

    cose_sign1_len += signature.len;

    output->ptr = output_buffer.ptr;
    output->len = cose_sign1_len;

#endif
#endif
