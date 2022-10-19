/*
 *  t_cose_mini_sign1_sign.c
 *
 * Copyright 2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_mini_sign1_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"

#include "qcbor/UsefulBuf.h"

/*
 * This could be modified to support other header parameters like the
 * kid and the object code would still be bigger, but still very
 * small.
 *
 * Or on the other hand, this could be modified to support only a
 * fixed-size payload to make the object code even smaller.
 */


/*
 * The algorithm is set at compile time for mini sign and can't be
 * changed.  Define one of these to configure the algorithm.

#define T_COSE_MINI_SIGN_SELECT_ES256
#define T_COSE_MINI_SIGN_SELECT_ES384
#define T_COSE_MINI_SIGN_SELECT_ES512
*/

#define T_COSE_MINI_SIGN_SELECT_ES256


#if defined(T_COSE_MINI_SIGN_SELECT_ES256)

#define MINI_SIGN_HASH           COSE_ALGORITHM_SHA_256
#define MINI_SIGN_HASH_LEN       T_COSE_CRYPTO_SHA256_SIZE
#define MINI_SIGN_ALG            T_COSE_ALGORITHM_ES256
#define MINI_SIGN_ALG_ID_BYTES   0x26 /* The literal byte that appears in the CBOR encoding */
#define MINI_SIGN_SIG_LEN        T_COSE_EC_P256_SIG_SIZE

#elif defined(T_COSE_MINI_SIGN_SELECT_ES384)

#define MINI_SIGN_HASH           COSE_ALGORITHM_SHA_384
#define MINI_SIGN_HASH_LEN       T_COSE_CRYPTO_SHA384_SIZE
#define MINI_SIGN_ALG            T_COSE_ALGORITHM_ES384
#define MINI_SIGN_ALG_ID_BYTES   0x38, 0x22 /* The literal byte that appears in the CBOR encoding */
#define MINI_SIGN_SIG_LEN        T_COSE_EC_P384_SIG_SIZE

#elif defined(T_COSE_MINI_SIGN_SELECT_ES512)

#define MINI_SIGN_HASH           COSE_ALGORITHM_SHA_512
#define MINI_SIGN_HASH_LEN       T_COSE_CRYPTO_SHA512_SIZE
#define MINI_SIGN_ALG            T_COSE_ALGORITHM_ES521
#define MINI_SIGN_ALG_ID_BYTES   0x38, 0x23 /* The literal byte that appears in the CBOR encoding */
#define MINI_SIGN_SIG_LEN        T_COSE_EC_P512_SIG_SIZE

#endif


#if defined(T_COSE_MINI_SIGN_SELECT_ES256)
#define PROT_HEADER_START 0x43
#else
#define PROT_HEADER_START 0x44
#endif

#define PROT_HEADERS \
    PROT_HEADER_START, \
    0xA1, 0x01, \
    MINI_SIGN_ALG_ID_BYTES


/*
 * This is hard-coded bytes for the start of the CBOR for the following
 * CBOR that are the to-be-signed bytes. Hard coding like this saves
 * writing code to create it.
 *
 * Sig_structure = [
 *    context : "Signature" / "Signature1" / "CounterSignature",
 *    body_protected : empty_or_serialized_map,
 *    ? sign_protected : empty_or_serialized_map,
 *    external_aad : bstr,
 *    payload : bstr
 * ]
 */
static const uint8_t start_sig_struct[] = {
    0x84,
    0x6A,'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
    PROT_HEADERS, // bstr wrapped protected header wtih algorithm ID
    0x40, /* Empty bstr for aad */
};

/* The first part of a COSE_Sign1: the opening array,
 * the protected parameters and the unproteced parameters.
 */
static const uint8_t start_cose_sign1[] = {
    0x84,
    PROT_HEADERS, // bstr wrapped protected header wtih algorithm ID
    0xa0, /* no unprotected headers, put some here if you want */
};

/* The Hard coded bytes for the CBOR head for the signature. It is less
 * code to hard code than to encode using encode_bstr_head() */
static const uint8_t cose_sign1_sig_start[] = {
    0x58, MINI_SIGN_SIG_LEN
};

#if MINI_SIGN_SIG_LEN > 255
#error signature length is too long
#endif


/* This maximum is for a CBOR head for a byte string no longer than
 * UINT16_MAX, not the general case for a CBOR head. */
#define MAX_CBOR_HEAD 3


/*
 * @brief Encode a CBOR head for a byte string of given length.
 *
 * @param[in] len         The length to encode.
 * @param[in] out_buffer  Pointer and length to write to.
 *
 * @return   The pointer and length of the encoded CBOR head
 *           or \c NULL_Q_USEFUL_BUF_C if @c len is
 *           greater than 65355.
 *
 * This is a scaled-down version of QCBOREncode_EncodeHead()
 * in QCBOR.
 */
static inline struct q_useful_buf_c
encode_bstr_head(const size_t len, const struct q_useful_buf out_buffer)
{
    uint8_t *out_buf = out_buffer.ptr;

    if(out_buffer.len < MAX_CBOR_HEAD) {
        return NULL_Q_USEFUL_BUF_C;
    }

    if(len < 24) { /* 24 is a special number in CBOR */
        out_buf[0] = 0x40 + (uint8_t)len;
        return (struct q_useful_buf_c){out_buf, 1};
    } else if(len < 256) {
        out_buf[0] = 0x58;
        out_buf[1] = (uint8_t)len;
        return (struct q_useful_buf_c){out_buf, 2};
    } else  if(len < UINT16_MAX) {
        out_buf[0] = 0x59;
        out_buf[1] = (uint8_t)(len / 256);
        out_buf[2] = (uint8_t)(len % 256);
        return (struct q_useful_buf_c){out_buf, 3};
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}


/*
 * Public function.
 */
enum t_cose_err_t
t_cose_mini_sign1_sign(const struct q_useful_buf_c payload,
                       const struct t_cose_key     signing_key,
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
    struct q_useful_buf        signature_buffer;
    uint8_t                   *copy_ptr;

    /* --- Create a CBOR head for the payload ---- */
    payload_head = encode_bstr_head(payload.len, payload_head_buffer);

    if(payload_head.ptr == NULL) {
        /* The payload is too large (the only reason encode_bstr_head()
         * errors out.
         */
        return T_COSE_ERR_TOO_LONG;
    }


    /* --- hash the Sig_structure --- */
    /* Don't actually have to create the Sig_structure fully in
     * memory. Just have to compute the hash of it. */
    err = t_cose_crypto_hash_start(&hash_ctx, MINI_SIGN_HASH);
    if(err != T_COSE_SUCCESS) {
        goto Done;
    }

    t_cose_crypto_hash_update(&hash_ctx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(start_sig_struct));
    t_cose_crypto_hash_update(&hash_ctx, payload_head);
    t_cose_crypto_hash_update(&hash_ctx, payload);

    err = t_cose_crypto_hash_finish(&hash_ctx, hash_output, &computed_hash);
    if(err != T_COSE_SUCCESS) {
        goto Done;
    }

    /* ---- Size check ---- */
    /* Calculate the length of the output buffer required. It is
     * just the payload plus a constant. This one check covers
     * all the memcpy() calls below.
     */
    const size_t required_len = sizeof(start_cose_sign1) +
                                MAX_CBOR_HEAD +
                                payload.len +
                                sizeof(cose_sign1_sig_start) +
                                MINI_SIGN_SIG_LEN;

    if(output_buffer.len < required_len) {
        return T_COSE_ERR_TOO_SMALL;
    }

    /* ---- Output the COSE_Sign1 ---- */
    copy_ptr = output_buffer.ptr;

    memcpy(copy_ptr, start_cose_sign1, sizeof(start_cose_sign1));
    copy_ptr += sizeof(start_cose_sign1);

    memcpy(copy_ptr, payload_head.ptr, payload_head.len);
    copy_ptr += payload_head.len;

    memcpy(copy_ptr, payload.ptr, payload.len);
    copy_ptr += payload.len;

    memcpy(copy_ptr, cose_sign1_sig_start, sizeof(cose_sign1_sig_start));
    copy_ptr += sizeof(cose_sign1_sig_start);

    const size_t u_len = (size_t)(copy_ptr - (uint8_t *)output_buffer.ptr);


    /* This won't go negative because of the check against required_len above
     * so the cast is safe.
     */
    signature_buffer.len = output_buffer.len - u_len;
    signature_buffer.ptr = copy_ptr;


    err = t_cose_crypto_sign(MINI_SIGN_ALG,
                             signing_key,
                             computed_hash,
                             signature_buffer,
                            &signature);

    output->ptr = output_buffer.ptr;
    output->len = u_len + signature.len;

    /* I wrote this code without using UsefulBuf to save object code.
     * It works and I saved object code, but I made about four
     * mistakes with pointer math that I wouldn't have made with
     * UsefulBuf that took a few hours of debugging to find.  Or maybe
     * I'm not as sharp as I used to be...
     *
     * Or said another way, this code doesn't have the same security /
     * buffer level that QCBOR has, but it should be safe enough.
     */

Done:
    return err;
}
