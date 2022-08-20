//
//  t_cose_sign_mini_verify.c
//
//  Created by Laurence Lundblade on 8/17/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_sign_mini_verify.h"
#include "t_cose_crypto.h"


/*
 This has only two external dependencies.

 First is just the definition of struct useful_buf and struct useful_buf_c.
 These are simpler each containing only a pointer and length.
 There is no code generated from these.

 The second is the crypto adapter layer for the hash
 and signature verification algorithms.


 WARNING: at this point this code is not tested or carefully
 reviewed for issues with pointer manipulation. It does not
 use the UsefulBuf functions so gains little memory safety
 from the use of struct useful_buf.

 That said, this code was
 derived from QCBOR and t_cose which are highly tested, but
 this should be reviewed, fuzzed and such to be sure before
 use in critical commercial applications like boot
 verification.

 */


/*
 * This is configured only for ES-384 (but can be changed for other)
 */
#define HASH_ALG_TO_USE  -43 /* IANA registration for SHA 384 */
#define SIG_ALG_TO_USE   T_COSE_ALGORITHM_ES384
#define HASH_LENGTH      48  /* Length of SHA 384 */


/*
 * Hard coded CBOR fragments used both for comparison to expected
 * input and for makeing the Sig_structure.
 */
#define PROT_HEADERS_FRAG  "\x44\xA1\x01\x38\x22" // For ES384
#define NULL_BSTR_FRAG     "\x40"
#define ARRAY_OF_FOUR_FRAG "\x84"
#define EMPTY_MAP_FRAG     "\xa0"



static inline enum t_cose_err_t
create_tbs_hash(struct q_useful_buf_c  encoded_payload,
                struct q_useful_buf    buffer_for_hash,
                struct q_useful_buf_c *hash)
{
    enum t_cose_err_t           return_value;
    struct t_cose_crypto_hash   hash_ctx;

    return_value = t_cose_crypto_hash_start(&hash_ctx, HASH_ALG_TO_USE);
    if(return_value) {
        goto Done;
    }

    /*
     * Format of to-be-signed bytes.  This is defined in COSE (RFC
     * 8152) section 4.4. It is the input to the hash.
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
     * COSE_Sign1 structure. This is a little hard to to understand in the
     * spec.
     *
     * sign_protected is not used with COSE_Sign1 since there is no
     * signer chunk.
     *
     * external_aad allows external data to be covered by the
     * signature, but may be a NULL_Q_USEFUL_BUF_C in which case a
     * zero-length bstr will be correctly hashed into the result.
     *
     * Instead of formatting the TBS bytes in one buffer, they are
     * formatted in chunks and fed into the hash. If actually
     * formatted, the TBS bytes are slightly larger than the payload,
     * so this saves a lot of memory.
     */

    /* Hand-constructed CBOR everything but the payload. */
    t_cose_crypto_hash_update(&hash_ctx,
                              Q_USEFUL_BUF_FROM_SZ_LITERAL(
                                 ARRAY_OF_FOUR_FRAG
                                 "\x6A"
                                 COSE_SIG_CONTEXT_STRING_SIGNATURE1
                                 PROT_HEADERS_FRAG
                                 NULL_BSTR_FRAG));

    /* The payload is passed in encoded as a bstr so use it directly. */
    t_cose_crypto_hash_update(&hash_ctx, encoded_payload);


    /* Finish the hash and set up to return it */
    return_value = t_cose_crypto_hash_finish(&hash_ctx,
                                             buffer_for_hash,
                                             hash);
Done:
    return return_value;
}




/* Standard CBOR Major type for positive integers of various lengths */
#define CBOR_MAJOR_TYPE_POSITIVE_INT 0

/* Standard CBOR Major type for negative integer of various lengths */
#define CBOR_MAJOR_TYPE_NEGATIVE_INT 1

/* Standard CBOR Major type for an array of arbitrary 8-bit bytes. */
#define CBOR_MAJOR_TYPE_BYTE_STRING  2

/* Standard CBOR Major type for a UTF-8 string. Note this is true 8-bit UTF8
 with no encoding and no NULL termination */
#define CBOR_MAJOR_TYPE_TEXT_STRING  3

/* Standard CBOR Major type for an ordered array of other CBOR data items */
#define CBOR_MAJOR_TYPE_ARRAY        4

/* Standard CBOR Major type for CBOR MAP. Maps an array of pairs. The
 first item in the pair is the "label" (key, name or identfier) and the second
 item is the value.  */
#define CBOR_MAJOR_TYPE_MAP          5

/* Standard CBOR major type for a tag number. This creates a CBOR "tag" that
 * is the tag number and a data item that follows as the tag content.
 *
 * Note that this was called an optional tag in RFC 7049, but there's
 * not really anything optional about it. It was misleading. It is
 * renamed in RFC 8949.
 */
#define CBOR_MAJOR_TYPE_TAG          6
#define CBOR_MAJOR_TYPE_OPTIONAL     6

/* Standard CBOR extra simple types like floats and the values true and false */
#define CBOR_MAJOR_TYPE_SIMPLE       7

/*
 These are special values for the AdditionalInfo bits that are part of
 the first byte.  Mostly they encode the length of the data item.
 */
#define LEN_IS_ONE_BYTE    24
#define LEN_IS_TWO_BYTES   25
#define LEN_IS_FOUR_BYTES  26
#define LEN_IS_EIGHT_BYTES 27
#define ADDINFO_RESERVED1  28
#define ADDINFO_RESERVED2  29
#define ADDINFO_RESERVED3  30
#define LEN_IS_INDEFINITE  31

/*
 *  The expects a CBOR byte string at the start of
 * input_cbor. Anything else will result in an error.
 *
 * The pointer and length of the decoded byte string
 * is returned in decoded_byte_string.
 *
 * This is derived/copied from the core of QCBOR. It is specifically
 * for decoding only byte strings. The byte string must less than UINT32_MAX
 * in length. This choice is made so the code is smaller on 32-bit machines
 * with no need for 64-bit ints.
 *
 * This is called twice so don't inline.
 *
 * WARNING: the pointer manipulation here needs review,
 * fuzzing and testing.
 */
enum t_cose_err_t
decode_byte_string(struct q_useful_buf_c   input_cbor,
                   struct q_useful_buf_c  *decoded_byte_string,
                   struct q_useful_buf_c  *encoded_byte_string )
{
    uint32_t byte_string_length;

    const uint8_t *p = input_cbor.ptr;
    const uint8_t * const p_end = (const uint8_t *)input_cbor.ptr + input_cbor.len;

    if(input_cbor.len < 1) {
        return T_COSE_ERR_CBOR_NOT_WELL_FORMED;
    }
    const int nInitialByte    = (int)*p;
    const int nTmpMajorType   = nInitialByte >> 5;
    const int nAdditionalInfo = nInitialByte & 0x1f;

    if(nTmpMajorType != CBOR_MAJOR_TYPE_BYTE_STRING) {
        return T_COSE_ERR_SIGN1_FORMAT; // Not a byte string
    }

    p++;
    if(nAdditionalInfo >= LEN_IS_ONE_BYTE && nAdditionalInfo <= LEN_IS_FOUR_BYTES) {
       /* Need to get 1,2 or 4 additional argument bytes. Map
        * LEN_IS_ONE_BYTE..LEN_IS_FOUR_BYTES to actual length.
        */
        static const uint8_t aIterate[] = {1,2,4};

       /* Loop getting all the bytes in the argument */
       byte_string_length = 0;
       for(int i = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE]; i; i--) {
          /* This shift and add gives the endian conversion. */
          byte_string_length = (byte_string_length << 8) + *p;
           p++;
           if(p > p_end) {
               return T_COSE_ERR_CBOR_NOT_WELL_FORMED; /* off end of input */
           }
       }
    } else if(nAdditionalInfo >= LEN_IS_EIGHT_BYTES && nAdditionalInfo <= LEN_IS_INDEFINITE) {
       /* The reserved and thus-far unused additional info values,
        * indefinite length strings and 8-byte length strings.
        */
       return T_COSE_ERR_CBOR_FORMATTING;
    } else {
       /* Less than 24, additional info is argument or 31, an
        * indefinite-length.  No more bytes to get.
        */
       byte_string_length = (uint32_t)nAdditionalInfo;
    }

    if(p + byte_string_length > p_end) {
        // String contents is off the end.
        return T_COSE_ERR_CBOR_NOT_WELL_FORMED;
    }

    decoded_byte_string->ptr = p;
    decoded_byte_string->len = byte_string_length;

    encoded_byte_string->ptr = input_cbor.ptr;
    encoded_byte_string->len = (size_t)(p - (const uint8_t *)input_cbor.ptr) + byte_string_length;

    return T_COSE_SUCCESS;
}



/* Static string that is the first part of the COSE_Sign1
 * with the header parameters that have the algorithm.
 * The expected algorithm ID is here and compiled in.
 */
static uint8_t first_part[] = ARRAY_OF_FOUR_FRAG PROT_HEADERS_FRAG EMPTY_MAP_FRAG;


/*
 * The main public entry point.
 */
enum t_cose_err_t
t_cose_sign1_mini_verify(struct q_useful_buf_c   cose_sign1,
                         struct t_cose_key       verification_key,
                         struct q_useful_buf_c  *payload)
{
    struct q_useful_buf_c        signature;
    struct q_useful_buf_c        encoded_byte_string;
    struct q_useful_buf_c        in;
    Q_USEFUL_BUF_MAKE_STACK_UB(  hash_buf, HASH_LENGTH);
    struct q_useful_buf_c        tbs_hash;
    enum t_cose_err_t            return_value;


    /* --- The opening of the array and header params --- */
    /* The first part of the input is just checked by
     * a memcmp(). No decoding is done. It is always the
     * same -- an array of 4, the compiled-in protected
     * header with the signing algorithm identifier and the
     * empty unprotected header.
     */
    if(cose_sign1.len < sizeof(first_part)-1) {
        /* Input is too short */
        return T_COSE_ERR_SIGN1_FORMAT;
    }

    if(memcmp(first_part, cose_sign1.ptr, sizeof(first_part)-1)) {
        /* Badly formatted CBOR input or not the algorithm
         * we are hear */
        return T_COSE_ERR_SIGN1_FORMAT;
    }

    /* there would be less pointer math by using
     * UsefulInBuf, but the objective here is minimal
     * lines of code and dependency for both code size
     * and ease of security analysis.
     *
     * Or probably this pointer math could be made
     * pretty and easier to understand with a little more work.
     */
    in      = cose_sign1;
    in.ptr  = (uint8_t *)in.ptr + sizeof(first_part)-1;
    in.len -= sizeof(first_part)-1;


    /* --- The payload ---- */
    decode_byte_string(in, payload, &encoded_byte_string);

    in.ptr  = (uint8_t *)in.ptr + encoded_byte_string.len;
    in.len -= encoded_byte_string.len;

    /* A nice trick here is that we can use the CBOR-
     * encoded payload from the input CBOR as direct input to
     * the TBS calculation because they are both the same
     * CBOR-encoded byte string. This only works because of
     * the incremental hashing used inside create_tbs_hash().
     */
    return_value = create_tbs_hash(encoded_byte_string,
                                   hash_buf,
                                   &tbs_hash);
    if(return_value) {
        return return_value;
    }


    /* --- The signature --- */
    decode_byte_string(in, &signature, &encoded_byte_string);

    if((in.len - encoded_byte_string.len) != 0) {
        /* All the bytes in the input were not used. */
        return T_COSE_ERR_SIGN1_FORMAT;
    }

   return t_cose_crypto_verify(SIG_ALG_TO_USE,
                               verification_key,
                               NULL_Q_USEFUL_BUF_C, /* No key id */
                               tbs_hash,
                               signature);
}
