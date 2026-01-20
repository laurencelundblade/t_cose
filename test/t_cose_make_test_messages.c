/*
 * t_cose_make_test_messages.c
 *
 * Copyright (c) 2019-2026, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_make_test_messages.h"
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_private.h"
#include "t_cose/t_cose_signature_main.h"


/**
 * \file t_cose_make_test_messages.c
 *
 * This makes \c COSE_Sign1 messages of various sorts for testing
 * verification. Some of them are badly formed to test various
 * verification failures.
 *
 * This is essentially a hacked-up version of t_cose_sign1_sign.c.
 */

#define T_COSE_INVALID_ALGORITHM_ID T_COSE_ALGORITHM_RESERVED


static int16_t
test_private_int16_map(const int16_t map[][2], int16_t query)
{
    int i;
    for(i = 0; ; i++) {
        if(map[i][0] == query || map[i][0] == INT16_MIN) {
            return map[i][1];
        }
    }
}

static int32_t
test_private_hash_alg_id_from_sig_alg_id(int32_t cose_algorithm_id)
{
    /* If other hashes, particularly those that output bigger hashes
     * are added here, various other parts of this code have to be
     * changed to have larger buffers, in particular
     * \ref T_COSE_XXX_MAX_HASH_SIZE.
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
    return (int32_t)test_private_int16_map(hash_alg_map, (int16_t)(cose_algorithm_id));
}



/**
 * \brief Hash an encoded bstr without actually encoding it in memory.
 *
 * @param hash_ctx  Hash context to hash it into.
 * @param bstr      Bytes of the bstr.
 *
 * If \c bstr is \c NULL_Q_USEFUL_BUF_C, a zero-length bstr will be
 * hashed into the output.
 */
static void
test_private_hash_bstr(struct t_cose_private_test_crypto_hash *hash_ctx,
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
    t_cose_private_test_crypto_hash_update(hash_ctx, encoded_head);
    t_cose_private_test_crypto_hash_update(hash_ctx, bstr);
}


/*
 * Public function. See t_cose_util.h
 */
enum t_cose_err_t
test_private_create_tbs_hash(const int32_t                    cose_algorithm_id,
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
    struct t_cose_private_test_crypto_hash   hash_ctx;

    /* Start the hashing */
    hash_alg_id = test_private_hash_alg_id_from_sig_alg_id(cose_algorithm_id);
    // TODO: possibly remove this check and let t_cose_crypto_hash_start()
    // handle this error. The problem right now is that it returns
    // UNSUPPORTED HASH, not T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
    // The removal of the check is just to save object code.
    if (hash_alg_id == T_COSE_INVALID_ALGORITHM_ID) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    return_value = t_cose_private_test_crypto_hash_start(&hash_ctx, hash_alg_id);
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
    t_cose_private_test_crypto_hash_update(&hash_ctx, first_part);

    /* body_protected */
    test_private_hash_bstr(&hash_ctx, sign_inputs->body_protected);

    /* sign_protected */
    if(!q_useful_buf_c_is_null(sign_inputs->sign_protected)) {
        test_private_hash_bstr(&hash_ctx, sign_inputs->sign_protected);
    }

    /* external_aad */
    test_private_hash_bstr(&hash_ctx, sign_inputs->ext_sup_data);

    /* payload */
    test_private_hash_bstr(&hash_ctx, sign_inputs->payload);

    /* Finish the hash and set up to return it */
    return_value = t_cose_private_test_crypto_hash_finish(&hash_ctx,
                                             buffer_for_hash,
                                             hash);
Done:
    return return_value;
}




/**
 * \brief  Makes various protected parameters for various tests
 *
 * \param[in] test_message_options  Flags to select test modes.
 * \param[in] cose_algorithm_id     The algorithm ID to put in the parameters.
 * \param[in] buffer_for_protected_parameters  Pointer and length into which
 *                                             the resulting encoded protected
 *                                             parameters is put.
 *
 * \return The pointer and length of the protected parameters is
 * returned, or \c NULL_Q_USEFUL_BUF_C if this fails.
 *
 * The protected parameters are returned in fully encoded CBOR format as
 * they are added to the \c COSE_Sign1 as a binary string. This is
 * different from the unprotected parameters which are not handled this
 * way.
 *
 * This returns \c NULL_Q_USEFUL_BUF_C if buffer_for_protected_parameters was
 * too small. See also definition of
 * \c T_COSE_SIGN1_MAX_SIZE_PROTECTED_PARAMETERS.
 */
static inline struct q_useful_buf_c
encode_protected_parameters(uint32_t            test_message_options,
                            int32_t             cose_algorithm_id,
                            struct q_useful_buf buffer_for_protected_parameters)
{
    /* approximate stack use on 32-bit machine:
     * local use: 170
     * with calls: 210
     */
    struct q_useful_buf_c protected_parameters;
    QCBORError            qcbor_result;
    QCBOREncodeContext    cbor_encode_ctx;
    struct q_useful_buf_c return_value;

    if(test_message_options & T_COSE_TEST_EMPTY_PROTECTED_PARAMETERS) {
        /* An empty q_useful_buf_c */
        return (struct q_useful_buf_c){buffer_for_protected_parameters.ptr, 0};
    }


    if(test_message_options & T_COSE_TEST_UNCLOSED_PROTECTED) {
        *(uint8_t *)(buffer_for_protected_parameters.ptr) = 0xa1;
        return (struct q_useful_buf_c){buffer_for_protected_parameters.ptr, 1};
    }

    QCBOREncode_Init(&cbor_encode_ctx, buffer_for_protected_parameters);

    if(test_message_options & T_COSE_TEST_BAD_PROTECTED) {
        QCBOREncode_OpenArray(&cbor_encode_ctx);
        QCBOREncode_AddInt64(&cbor_encode_ctx, 42);
        QCBOREncode_CloseArray(&cbor_encode_ctx);
        goto Finish;
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_OpenMapIndefiniteLength(&cbor_encode_ctx);
    } else {
        QCBOREncode_OpenMap(&cbor_encode_ctx);
    }
    QCBOREncode_AddInt64ToMapN(&cbor_encode_ctx,
                               T_COSE_HEADER_PARAM_ALG,
                               cose_algorithm_id);

    if(test_message_options & T_COSE_TEST_UNKNOWN_CRIT_UINT_PARAMETER) {
        /* This is the parameter that will be unknown */
        QCBOREncode_AddInt64ToMapN(&cbor_encode_ctx, 42, 43);
        /* This is the critical labels parameter */
        if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
            QCBOREncode_OpenArrayIndefiniteLengthInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        } else {
            QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        }
        QCBOREncode_AddInt64(&cbor_encode_ctx, 42);
        QCBOREncode_AddInt64(&cbor_encode_ctx, 43);
        QCBOREncode_AddInt64(&cbor_encode_ctx, 44);
        if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
            QCBOREncode_CloseArrayIndefiniteLength(&cbor_encode_ctx);
        } else {
            QCBOREncode_CloseArray(&cbor_encode_ctx);
        }
    }

    if(test_message_options & T_COSE_TEST_UNKNOWN_CRIT_TSTR_PARAMETER) {
        /* This is the parameter that will be unknown */
        QCBOREncode_AddInt64ToMap(&cbor_encode_ctx, "hh", 43);
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        QCBOREncode_AddSZString(&cbor_encode_ctx, "hh");
        QCBOREncode_AddSZString(&cbor_encode_ctx, "h");
        QCBOREncode_AddSZString(&cbor_encode_ctx, "hhh");
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_BAD_CRIT_LABEL) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        QCBOREncode_AddBool(&cbor_encode_ctx, true);
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_CRIT_PARAMETER_EXIST) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        int i;
        /* Add the maxium */
        for(i = 0; i < T_COSE_MAX_CRITICAL_PARAMS; i++) {
            QCBOREncode_AddInt64(&cbor_encode_ctx, i + 10);
        }
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_MANY_CRIT_PARAMETER_EXIST) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        int i;
        /* One more than the maximum */
        for(i = 0; i < T_COSE_MAX_CRITICAL_PARAMS+1; i++) {
            QCBOREncode_AddInt64(&cbor_encode_ctx, i + 10);
        }
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_MANY_TSTR_CRIT_LABLELS) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        int i;
        /* One more than the maximum */
        for(i = 0; i < T_COSE_MAX_CRITICAL_PARAMS+1; i++) {
            QCBOREncode_AddSZString(&cbor_encode_ctx, "");
        }
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_BAD_CRIT_PARAMETER) {
        QCBOREncode_AddSZStringToMapN(&cbor_encode_ctx,
                                      T_COSE_HEADER_PARAM_CRIT, "hi");
    }

    if(test_message_options & T_COSE_TEST_EMPTY_CRIT_PARAMETER) {
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_KID_IN_PROTECTED) {
        QCBOREncode_AddBytesToMapN(&cbor_encode_ctx,
                                   T_COSE_HEADER_PARAM_KID,
                                   Q_USEFUL_BUF_FROM_SZ_LITERAL("kid"));
    }

    if(test_message_options & T_COSE_TEST_DUP_CONTENT_ID) {
        QCBOREncode_AddUInt64ToMapN(&cbor_encode_ctx,
                                    T_COSE_HEADER_PARAM_CONTENT_TYPE,
                                    3);
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_CloseMapIndefiniteLength(&cbor_encode_ctx);
    } else {
        QCBOREncode_CloseMap(&cbor_encode_ctx);
    }

Finish:
    qcbor_result = QCBOREncode_Finish(&cbor_encode_ctx, &protected_parameters);

    if(qcbor_result == QCBOR_SUCCESS) {
        return_value = protected_parameters;
    } else {
        return_value = NULL_Q_USEFUL_BUF_C;
    }

    return return_value;
}


/**
 * \brief Add the unprotected parameters to a CBOR encoding context
 *
 * \param[in] test_message_options  Flags to select test modes.
 * \param[in] cbor_encode_ctx       CBOR encoding context to output to.
 * \param[in] kid                   The key ID to go into the kid parameter.
 *
 * No error is returned. If an error occurred it will be returned when
 * \c QCBOR_Finish() is called on \c cbor_encode_ctx.
 *
 * The unprotected parameters added by this are the key ID plus
 * lots of different test parameters.
 */
static inline void
add_unprotected_parameters(uint32_t              test_message_options,
                           QCBOREncodeContext   *cbor_encode_ctx,
                           struct q_useful_buf_c kid)
{
    if(test_message_options & T_COSE_TEST_UNPROTECTED_NOT_MAP) {
        QCBOREncode_OpenArray(cbor_encode_ctx);
        QCBOREncode_AddBytes(cbor_encode_ctx, kid);
        QCBOREncode_CloseArray(cbor_encode_ctx);
        return; /* skip the rest for this degenerate test */
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_OpenMapIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_OpenMap(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_NOT_WELL_FORMED_1) {
        QCBOREncode_AddEncoded(cbor_encode_ctx,
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("xxxxxx"));
    }

    /* Put in a byte string (not a text string) for the parameter label */
    if(test_message_options & T_COSE_TEST_PARAMETER_LABEL) {
        QCBOREncode_AddBytes(cbor_encode_ctx, kid);
        QCBOREncode_AddBytes(cbor_encode_ctx, kid);
    }

    if(test_message_options & T_COSE_TEST_EXTRA_PARAMETER) {
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, 55);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 66, "hi");
        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_KID_IN_PROTECTED) {
        /* Duplicate here to be sure there is a dup parameter. */
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx,
                                   T_COSE_HEADER_PARAM_KID,
                                   Q_USEFUL_BUF_FROM_SZ_LITERAL("kid"));
    }


    if(test_message_options & T_COSE_TEST_NOT_WELL_FORMED_2) {
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, 55);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 66, "hi");
        /* 0xff is a break outside of anything indefinite and thus
         * not-well-formed, This test used to use a 0x3d before
         * spiffy decode, but spiffy decode can traverse that
         * without error because it is not an
         * QCBORDecode_IsUnrecoverableError().
         * Improvement: add a test case for the 3d error back in
         */
        QCBOREncode_AddEncoded(cbor_encode_ctx,
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("\xff"));
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 67, "bye");

        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_CRIT_NOT_PROTECTED) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, T_COSE_HEADER_PARAM_CRIT);
        int i;
        /* Add the maxium */
        for(i = 0; i < T_COSE_MAX_CRITICAL_PARAMS; i++) {
            QCBOREncode_AddInt64(cbor_encode_ctx, i + 100);
            QCBOREncode_AddSZString(cbor_encode_ctx, "xxxx");
        }
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_MANY_UNKNOWN) {
        int i;
        for(i = 0; i < T_COSE_MAX_CRITICAL_PARAMS + 1; i++ ) {
            QCBOREncode_AddBoolToMapN(cbor_encode_ctx, i+10, true);
        }
    }

    if(!q_useful_buf_c_is_null_or_empty(kid)) {
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx, T_COSE_HEADER_PARAM_KID, kid);
    }

    if(test_message_options & T_COSE_TEST_ALL_PARAMETERS) {
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx,
                                   T_COSE_HEADER_PARAM_IV,
                                   Q_USEFUL_BUF_FROM_SZ_LITERAL("iv"));
        QCBOREncode_AddInt64ToMapN(cbor_encode_ctx,
                                   T_COSE_HEADER_PARAM_CONTENT_TYPE,
                                   1);
        /* A slighly complex unknown header parameter */
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, 55);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 66, "hi");
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 67, "bye");
        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_OpenArray(cbor_encode_ctx);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_LARGE_CONTENT_TYPE) {
        QCBOREncode_AddInt64ToMapN(cbor_encode_ctx,
                                   T_COSE_HEADER_PARAM_CONTENT_TYPE,
                                   UINT16_MAX+1);
    }

    if(test_message_options & T_COSE_TEST_DUP_CONTENT_ID) {
        QCBOREncode_AddUInt64ToMapN(cbor_encode_ctx,
                                    T_COSE_HEADER_PARAM_CONTENT_TYPE,
                                    3);
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_CloseMapIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_CloseMap(cbor_encode_ctx);
    }
}


/*
 * Buffer for the protected parameters. There used to be a buffer in
 * t_cose_sign1_sign_ctx but it was removed when code was improved.
 * This needs to be carried between encoding the header and doing
 * the signatured, so a buffer is needed. The size is that of the
 * largest test protected header and some padding.
 */
static uint8_t s_protected_params[40];

/**
 * Replica of t_cose_sign1_encode_parameters() with modifications to
 * output various good and bad messages for testing verification.
 */
static enum t_cose_err_t
t_cose_sign1_test_message_encode_parameters(struct t_cose_sign1_sign_ctx *me,
                                            uint32_t                       test_mess_options,
                                            QCBOREncodeContext           *cbor_encode_ctx)
{
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  kid;
    int32_t                hash_alg_id;
    struct q_useful_buf    buffer_for_protected_parameters;


    /* Check the cose_algorithm_id now by getting the hash alg as an early
     * error check even though it is not used until later.
     */
    hash_alg_id = test_private_hash_alg_id_from_sig_alg_id(me->cose_algorithm_id);
    if(hash_alg_id == T_COSE_INVALID_ALGORITHM_ID) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Add the CBOR tag indicating COSE_Sign1 */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, CBOR_TAG_COSE_SIGN1);
    }

    /* Get started with the tagged array that holds the four parts of
     * a cose single signed message */
    if(test_mess_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_OpenArrayIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_OpenArray(cbor_encode_ctx);
    }

    /* The protected parameters, which are added as a wrapped bstr  */
    if( ! (test_mess_options & T_COSE_TEST_NO_PROTECTED_PARAMETERS)) {
        buffer_for_protected_parameters = Q_USEFUL_BUF_FROM_BYTE_ARRAY(s_protected_params);

        me->protected_parameters = encode_protected_parameters(test_mess_options,
                                                               me->cose_algorithm_id,
                                                               buffer_for_protected_parameters);
        QCBOREncode_AddBytes(cbor_encode_ctx, me->protected_parameters);
    }

    /* The Unprotected parameters */
    /* Get the key id because it goes into the parameters that are about
     to be made. */

        kid = me->kid;

    if( ! (test_mess_options & T_COSE_TEST_NO_UNPROTECTED_PARAMETERS)) {
        add_unprotected_parameters(test_mess_options, cbor_encode_ctx, kid);
    }

    QCBOREncode_BstrWrap(cbor_encode_ctx);

    /* Any failures in CBOR encoding will be caught in finish when the
     * CBOR encoding is closed off. No need to track here as the CBOR
     * encoder tracks it internally. */

    return_value = T_COSE_SUCCESS;

    return return_value;
}


/**
 * Replica of t_cose_sign1_output_signature() with modifications to
 * output various good and bad messages for testing verification.
 */
static enum t_cose_err_t
t_cose_sign1_test_message_output_signature(struct t_cose_sign1_sign_ctx *me,
                                           uint32_t                      test_mess_options,
                                           QCBOREncodeContext           *cbor_encode_ctx)
{
    /* approximate stack use on 32-bit machine:
     *   32 bytes local use
     *   220 to 434 for calls dependin on hash implementation
     *   32 to 64 bytes depending on hash alg (SHA256, 384 or 512)
     *   64 to 260 depending on EC alg
     *   348 to 778 depending on hash and EC alg
     *   Also add stack use by EC and hash functions
     */
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    /* pointer and length of the completed tbs hash */
    struct q_useful_buf_c        tbs_hash;
    /* Pointer and length of the completed signature */
    struct q_useful_buf_c        signature;
    /* Pointer and length of the buffer for the signature */
    struct q_useful_buf          buffer_for_signature;
    /* Buffer for the tbs hash. */
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_tbs_hash, T_COSE_MAIN_MAX_HASH_SIZE);
    struct q_useful_buf_c        signed_payload;
    struct t_cose_sign_inputs           sign_inputs;

    QCBOREncode_CloseBstrWrap2(cbor_encode_ctx, false, &signed_payload);

    /* Check there are no CBOR encoding errors before proceeding with
     * hashing and signing. This is not actually necessary as the
     * errors will be caught correctly later, but it does make it a
     * bit easier for the caller to debug problems.
     */
    cbor_err = QCBOREncode_GetErrorState(cbor_encode_ctx);
    if(cbor_err == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return_value = T_COSE_ERR_TOO_SMALL;
        goto Done;
    } else if(cbor_err != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CBOR_FORMATTING;
        goto Done;
    }

    /* Create the hash of the to-be-signed bytes. Inputs to the hash
     * are the protected parameters, the payload that is getting signed, the
     * cose signature alg from which the hash alg is determined. The
     * cose_algorithm_id was checked in t_cose_sign1_init() so it
     * doesn't need to be checked here.
     */
    sign_inputs.body_protected = me->protected_parameters;
    sign_inputs.ext_sup_data   = NULL_Q_USEFUL_BUF_C;
    sign_inputs.sign_protected = NULL_Q_USEFUL_BUF_C;
    sign_inputs.payload        = signed_payload;

    return_value = test_private_create_tbs_hash(me->cose_algorithm_id,
                                   &sign_inputs,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* The signature gets written directly into the output buffer.
     * The matching QCBOREncode_CloseBytes call further down still needs do a
     * memmove to make space for the CBOR header, but at least we avoid the need
     * to allocate an extra buffer.
     */
    QCBOREncode_OpenBytes(cbor_encode_ctx, &buffer_for_signature);


    /* Normal, non-short-circuit signing */
    return_value = t_cose_private_test_crypto_sign(me->cose_algorithm_id,
                                      me->signing_key,
                                      NULL, /* no crypto-context here */
                                      tbs_hash,
                                      buffer_for_signature,
                                     &signature);

    if(return_value) {
        goto Done;
    }

    /* Add signature to CBOR and close out the array */
    QCBOREncode_CloseBytes(cbor_encode_ctx, signature.len);

    if(test_mess_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_CloseArrayIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    /* The layer above this must check for and handle CBOR encoding
     * errors CBOR encoding errors.  Some are detected at the start of
     * this function, but they cannot all be deteced there.
     */
Done:
    return return_value;
}


/*
 * Public function. See t_cose_make_test_messages.h
 */
enum t_cose_err_t
t_cose_test_message_sign1_sign(struct t_cose_sign1_sign_ctx *me,
                               uint32_t                    test_message_options,
                               struct q_useful_buf_c         payload,
                               struct q_useful_buf           out_buf,
                               struct q_useful_buf_c        *result)
{
    QCBOREncodeContext  encode_context;
    enum t_cose_err_t   return_value;

    /* -- Initialize CBOR encoder context with output buffer */
    QCBOREncode_Init(&encode_context, out_buf);

    /* -- Output the header parameters into the encoder context -- */
    return_value = t_cose_sign1_test_message_encode_parameters(me, test_message_options, &encode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- Output the payload into the encoder context -- */
    /* Payload may or may not actually be CBOR format here. This
     * function does the job just fine because it just adds bytes to
     * the encoded output without anything extra.
     */
    QCBOREncode_AddEncoded(&encode_context, payload);

    /* -- Sign and put signature in the encoder context -- */
    return_value = t_cose_sign1_test_message_output_signature(me,
                                                              test_message_options,
                                                              &encode_context);
    if(return_value) {
        goto Done;
    }

    /* -- Close off and get the resulting encoded CBOR -- */
    if(QCBOREncode_Finish(&encode_context, result)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

Done:
    return return_value;
}

