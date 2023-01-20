/*
 *  t_cose_util.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_util.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"



/**
 * \file t_cose_util.c
 *
 * \brief Implementation of t_cose utility functions.
 *
 * These are some functions common to signing and verification,
 * primarily the to-be-signed bytes hashing.
 */


/*
 * Public function.
 *
 * This is declared in t_cose_common.h, but there is no t_cose_common.c,
 * so this little function is put here as linkage glue to the
 * crypto adaptor layer. */
bool
t_cose_is_algorithm_supported(int32_t cose_algorithm_id)
{
    return t_cose_crypto_is_algorithm_supported(cose_algorithm_id);
}


/*
 * Public function. See t_cose_util.h
 */
// TODO: make this a private function by not calling from test.
// Then the compiler will probably inline it.
int32_t
hash_alg_id_from_sig_alg_id(int32_t cose_algorithm_id)
{
    /* If other hashes, particularly those that output bigger hashes
     * are added here, various other parts of this code have to be
     * changed to have larger buffers, in particular
     * \ref T_COSE_CRYPTO_MAX_HASH_SIZE.
     */
    // TODO: allows disabling ES256

    /* Private-use algorithm IDs, those less than -65536, won't fit in
     * the int16_t values in this table so a switch statement like
     * that for T_COSE_ALGORITHM_SHORT_CIRCUIT_XXX will be needed.
     */
    static const int16_t hash_alg_map[][2] = {
        { T_COSE_ALGORITHM_ES256 , T_COSE_ALGORITHM_SHA_256 },
#ifndef T_COSE_DISABLE_ES384
        { T_COSE_ALGORITHM_ES384 , T_COSE_ALGORITHM_SHA_384 },
#endif
#ifndef T_COSE_DISABLE_ES512
        { T_COSE_ALGORITHM_ES512 , T_COSE_ALGORITHM_SHA_512},
#endif
#ifndef T_COSE_DISABLE_PS256
        { T_COSE_ALGORITHM_PS256 , T_COSE_ALGORITHM_SHA_256 },
#endif
#ifndef T_COSE_DISABLE_PS384
        { T_COSE_ALGORITHM_PS384 , T_COSE_ALGORITHM_SHA_384},
#endif
#ifndef T_COSE_DISABLE_PS512
        { T_COSE_ALGORITHM_PS512 , T_COSE_ALGORITHM_SHA_512 },
#endif
        { INT16_MIN ,              T_COSE_INVALID_ALGORITHM_ID}
    };

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    /* T_COSE_ALGORITHM_SHORT_CIRCUIT_256 and related are outside of
     * the standard allocation space and outside the range of int16_t
     * so they are handled by a case statement (which usually optimize
     * well).
     */
    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_SHORT_CIRCUIT_256: return T_COSE_ALGORITHM_SHA_256;
        case T_COSE_ALGORITHM_SHORT_CIRCUIT_384: return T_COSE_ALGORITHM_SHA_384;
        case T_COSE_ALGORITHM_SHORT_CIRCUIT_512: return T_COSE_ALGORITHM_SHA_512;
        default: break;/* intentional fall through */
    }
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


#ifndef T_COSE_DISABLE_USE_GUARDS
    /* This check can be disabled for tested apps using t_cose because
     * they won't pass in bad algorithm IDs outside the range of an
     * int16_t and even if they did it is unlikely it would fold into
     * a valid ID and further unlikely it would be the hash required.
     * It's pretty safe to disable this check even with use cases that
     * arent' tested. */
    if(cose_algorithm_id > INT16_MAX || cose_algorithm_id < INT16_MIN) {
        return T_COSE_INVALID_ALGORITHM_ID;
    }
#endif

    /* Cast to int16_t is safe because of check above */
    return (int32_t)t_cose_int16_map(hash_alg_map, (int16_t)(cose_algorithm_id));
}


#ifndef T_COSE_DISABLE_MAC0
// TODO: try to combine with create_tbs_hash so that no buffer for headers
// is needed. Make sure it doesn't make sign-only or mac-only object code big
enum t_cose_err_t
create_tbm(const struct t_cose_sign_inputs *sign_inputs,
           struct q_useful_buf              tbm_first_part_buf,
           struct q_useful_buf_c           *tbm_first_part)
{
    QCBOREncodeContext cbor_encode_ctx;
    QCBORError         qcbor_result;

    /* This builds the CBOR-format to-be-maced bytes */
    QCBOREncode_Init(&cbor_encode_ctx, tbm_first_part_buf);
    QCBOREncode_OpenArray(&cbor_encode_ctx);
    /* context */
    QCBOREncode_AddBytes(&cbor_encode_ctx, Q_USEFUL_BUF_FROM_SZ_LITERAL(COSE_MAC_CONTEXT_STRING_MAC0));
    /* body_protected */
    QCBOREncode_AddBytes(&cbor_encode_ctx, sign_inputs->body_protected);

    /* external_aad. There is none so an empty bstr */
    QCBOREncode_AddBytes(&cbor_encode_ctx, NULL_Q_USEFUL_BUF_C);

    /* The short fake payload. */
    QCBOREncode_AddBytesLenOnly(&cbor_encode_ctx, sign_inputs->payload);

    /* Close of the array */
    QCBOREncode_CloseArray(&cbor_encode_ctx);

    /* get the encoded results, except for payload */
    qcbor_result = QCBOREncode_Finish(&cbor_encode_ctx, tbm_first_part);
    if(qcbor_result) {
        /* Mainly means that the protected_headers were too big
         * (which should never happen)
         */
        return T_COSE_ERR_SIG_STRUCT;
    }

    return T_COSE_SUCCESS;
}
#endif /* !T_COSE_DISABLE_MAC0 */


#ifndef T_COSE_DISABLE_EDDSA
/*
 * Public function. See t_cose_util.h
 */
enum t_cose_err_t
create_tbs(const struct t_cose_sign_inputs *sign_inputs,
           struct q_useful_buf              buffer_for_tbs,
           struct q_useful_buf_c           *tbs)
{
    QCBOREncodeContext    cbor_context;
    struct q_useful_buf_c s1;

    QCBOREncode_Init(&cbor_context, buffer_for_tbs);

    QCBOREncode_OpenArray(&cbor_context);
    if(q_useful_buf_c_is_null(sign_inputs->sign_protected)) {
        s1 = Q_USEFUL_BUF_FROM_SZ_LITERAL(COSE_SIG_CONTEXT_STRING_SIGNATURE1);
    } else {
        s1 = Q_USEFUL_BUF_FROM_SZ_LITERAL(COSE_SIG_CONTEXT_STRING_SIGNATURE);
    }
    QCBOREncode_AddText(&cbor_context, s1);
    QCBOREncode_AddBytes(&cbor_context, sign_inputs->body_protected);
    if(!q_useful_buf_c_is_null(sign_inputs->sign_protected)) {
        QCBOREncode_AddBytes(&cbor_context, sign_inputs->sign_protected);
    }
    QCBOREncode_AddBytes(&cbor_context, sign_inputs->aad);
    QCBOREncode_AddBytes(&cbor_context, sign_inputs->payload);
    QCBOREncode_CloseArray(&cbor_context);

    QCBORError cbor_err = QCBOREncode_Finish(&cbor_context, tbs);
    if (cbor_err == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return T_COSE_ERR_TOO_SMALL;
    } else if (cbor_err != QCBOR_SUCCESS) {
        return T_COSE_ERR_CBOR_FORMATTING;
    } else {
        return T_COSE_SUCCESS;
    }
}
#endif /* !T_COSE_DISABLE_EDDSA */


/**
 * \brief Hash an encoded bstr without actually encoding it in memory.
 *
 * @param hash_ctx  Hash context to hash it into.
 * @param bstr      Bytes of the bstr.
 *
 * If \c bstr is \c NULL_Q_USEFUL_BUF_C, a zero-length bstr will be
 * hashed into the output.
 */
static void hash_bstr(struct t_cose_crypto_hash *hash_ctx,
                      struct q_useful_buf_c      bstr)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   buffer_for_encoded                             9           9
     *   useful_buf                                    16           8
     *   hash function (a guess! variable!)        16-512      16-512
     *   TOTAL                                     41-537      23-529
     */

    /* make a struct q_useful_buf on the stack of size QCBOR_HEAD_BUFFER_SIZE */
    Q_USEFUL_BUF_MAKE_STACK_UB (buffer_for_encoded_head, QCBOR_HEAD_BUFFER_SIZE);
    struct q_useful_buf_c       encoded_head;

    encoded_head = QCBOREncode_EncodeHead(buffer_for_encoded_head,
                                          CBOR_MAJOR_TYPE_BYTE_STRING,
                                          0,
                                          bstr.len);

    /* An encoded bstr is the CBOR head with its length followed by the bytes */
    t_cose_crypto_hash_update(hash_ctx, encoded_head);
    t_cose_crypto_hash_update(hash_ctx, bstr);
}


/*
 * Public function. See t_cose_util.h
 */
enum t_cose_err_t
create_tbs_hash(const int32_t                    cose_algorithm_id,
                const struct t_cose_sign_inputs *sign_inputs,
                const struct q_useful_buf        buffer_for_hash,
                struct q_useful_buf_c           *hash)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    24          14
     *   hash_ctx                                   8-224       8-224
     *   hash function (a guess! variable!)        16-512      16-512
     *   TOTAL                                     48-760      38-750
     */
    enum t_cose_err_t           return_value;
    int32_t                     hash_alg_id;
    struct q_useful_buf_c       first_part;
    struct t_cose_crypto_hash   hash_ctx;

    /* Start the hashing */
    hash_alg_id = hash_alg_id_from_sig_alg_id(cose_algorithm_id);
    // TODO: possibly remove this check and let t_cose_crypto_hash_start()
    // handle this error. The problem right now is that it returns
    // UNSUPPORTED HASH, not T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
    // The removal of the check is just to save object code.
    if (hash_alg_id == T_COSE_INVALID_ALGORITHM_ID) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    return_value = t_cose_crypto_hash_start(&hash_ctx, hash_alg_id);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /*
     * Format of to-be-signed bytes.  This is defined in COSE RFC 9052
     * section 4.4. It is the input to the hash.
     *
     * Sig_structure = [
     *    context : "Signature" / "Signature1" / "CounterSignature",
     *    body_protected : empty_or_serialized_map,
     *    ? sign_protected : empty_or_serialized_map,
     *    external_aad : bstr,
     *    payload : bstr
     * ]
     *
     * body_protected refers to the protected parameters from the main
     * COSE_Sign1 structure. This is a little hard to to understand in
     * the spec.
     *
     * sign_protected is not used with COSE_Sign1 so it is sometimes
     * NULL.
     *
     * external_aad allows external data to be covered by the
     * signature, but may be a NULL_Q_USEFUL_BUF_C in which case a
     * zero-length bstr will be correctly hashed into the result.
     *
     * Instead of formatting the TBS bytes in one buffer, they are
     * formatted in chunks and fed into the hash. If actually
     * formatted, the TBS bytes are slightly larger than the payload,
     * so this saves a lot of memory. This also puts no limit on the
     * size of protected headers.
     */

    /* Hand-constructed CBOR for the enclosing array and the context string */
    if(!q_useful_buf_c_is_null(sign_inputs->sign_protected)) {
        /* 0x85 is array of 5, 0x69 is length of a 9 byte string in CBOR */
        first_part = Q_USEFUL_BUF_FROM_SZ_LITERAL("\x85\x69" COSE_SIG_CONTEXT_STRING_SIGNATURE);
    } else {
        /* 0x84 is array of 4, 0x6a is length of a 10 byte string in CBOR */
        first_part = Q_USEFUL_BUF_FROM_SZ_LITERAL("\x84\x6A" COSE_SIG_CONTEXT_STRING_SIGNATURE1);
    }
    t_cose_crypto_hash_update(&hash_ctx, first_part);

    /* body_protected */
    hash_bstr(&hash_ctx, sign_inputs->body_protected);

    /* sign_protected */
    if(!q_useful_buf_c_is_null(sign_inputs->sign_protected)) {
        hash_bstr(&hash_ctx, sign_inputs->sign_protected);
    }

    /* external_aad */
    hash_bstr(&hash_ctx, sign_inputs->aad);

    /* payload */
    hash_bstr(&hash_ctx, sign_inputs->payload);

    /* Finish the hash and set up to return it */
    return_value = t_cose_crypto_hash_finish(&hash_ctx,
                                             buffer_for_hash,
                                             hash);
Done:
    return return_value;
}



#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/* This is a random hard coded kid (key ID) that is used to indicate
 * short-circuit signing. It is OK to hard code this as the
 * probability of collision with this ID is very low and the same as
 * for collision between any two key IDs of any sort.
 */

static const uint8_t defined_short_circuit_kid[] = {
    0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70,
    0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
    0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6,
    0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6};

static struct q_useful_buf_c short_circuit_kid;


/*
 * Public function. See t_cose_util.h
 */
struct q_useful_buf_c get_short_circuit_kid(void)
{
    short_circuit_kid.len = sizeof(defined_short_circuit_kid);
    short_circuit_kid.ptr = defined_short_circuit_kid;

    return short_circuit_kid;
}

#endif


/*
 * Public function. See t_cose_util.h
 */
enum t_cose_err_t
qcbor_decode_error_to_t_cose_error(QCBORError qcbor_error, enum t_cose_err_t format_error)
{
    if(qcbor_error == QCBOR_ERR_TOO_MANY_TAGS) {
        return T_COSE_ERR_TOO_MANY_TAGS;
    }
    if(QCBORDecode_IsNotWellFormedError(qcbor_error)) {
        return T_COSE_ERR_CBOR_NOT_WELL_FORMED;
    }
    if(qcbor_error == QCBOR_ERR_UNEXPECTED_TYPE || qcbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
        return format_error;
    }
    if(qcbor_error != QCBOR_SUCCESS) {
        return T_COSE_ERR_CBOR_DECODE;
    }
    return T_COSE_SUCCESS;
}


/*
 * Public function. See t_cose_util.h
 */
bool
t_cose_check_list(int32_t cose_algorithm_id, const int32_t *list)
{
    while(*list != T_COSE_ALGORITHM_NONE) {
        if(*list == cose_algorithm_id) {
            return true;
        }
        list++;
    }
    return false;
}


/*
 * Public function. See t_cose_util.h
 */
int16_t t_cose_int16_map(const int16_t map[][2], int16_t query)
{
    int i;
    for(i = 0; ; i++) {
        if(map[i][0] == query || map[i][0] == INT16_MIN) {
            return map[i][1];
        }
    }
}
