/*
 * t_cose_common.h
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2020-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_COMMON_H__
#define __T_COSE_COMMON_H__

#include <stdint.h>
#include <stdbool.h>
#include "t_cose/q_useful_buf.h" /* For t_cose_key and t_cose_sign_inputs */


#ifdef __cplusplus
extern "C" {
#endif


/*
 * API Design Overview
 * 
 * t_cose is made up of a collection of objects (in the
 * object-oriented programming sense) that correspond to the main
 * objects defined in CDDL by the COSE standard (RFC 9052). These
 * objects come in pairs, one for the sending/signing/encrypting
 * side and the other for the receiving/verifying/decrypting
 * side. Following is a high-level description of all of these and how
 * they connect up to each other.
 *
 * Some of this is implemented and some of this is a design proposal,
 * so it is subject to some change, renaming and such as the
 * implementation completes.
 *
 *
 * COSE_Sign and COSE_Sign1
 *
 * t_cose_sign_sign() and t_cose_sign_verify() are the pair that
 * implements both COSE_Sign and COSE_Sign1 COSE messages.
 *
 * They rely on implementations of t_cose_signature_sign and
 * t_cose_signature_verify to create and to verify the
 * COSE_Signature(s) that are in a COSE_Sign. They are also used to
 * create the signature for COSE_Sign1. These two are an abstract
 * base class they are just an interface without an implementation.
 *
 * t_cose_headers_decode() and t_cose_headers_encode() are also used
 * by the t_cose_sign pair. These process both the protected and
 * unprotected header parameter buckets called Headers in COSE.
 *
 *
 * COSE_Encrypt and COSE_Encrypt0
 *
 * t_cose_encrypt_enc() and t_cose_encrypt_dec() are the pair for
 * COSE_Encrypt and COSE_Encrypt0.
 *
 * t_cose_headers_decode() and t_cose_headers_encode() are used for
 * the header parameters.
 *
 * This makes use of implementations of t_cose_recipient_enc and
 * t_cose_recipient_dec for COSE_recipient used by COSE_Encrypt. They
 * are not needed for COSE_Encrypt0.
 *
 *
 * COSE_Mac and COSE_Mac0
 *
 * t_cose_mac_auth() and t_cose_mac_check() are the pair for COSE_Mac
 * and COSE_Mac0.
 *
 * t_cose_headers_decode() and t_cose_headers_encode() are used for
 * the header parameters.
 *
 * For COSE_Mac, t_cose_recipient_enc() and t_cose_recipient_dec()
 * implement COSE_recipient. (I’m pretty sure sharing t_cose_recipient
 * between COSE_MAC and COSE_Encrypt can work, but this needs to be
 * checked by actually designing and implementing it). These are not
 * needed for COSE_Mac0.
 *
 * 
 * COSE_Message
 *
 * t_cose_message_create() and t_cose_message_decode handle
 * COSE_Message. This is for handling COSE messages that might be signed,
 * encrypted, MACed or some combination of these. In the simplest case
 * they decode the CBOR tag number and switch off to one of the
 * above handlers. In more complicated cases they recursively handle
 * nested signing, encrypting and MACing. (Lots of work to do on
 * this…)
 *
 *
 * Headers
 *
 * t_cose_headers_decode() and t_cose_headers_encode() handle the
 * protected and unprotected header parameter buckets that are used by
 * all the COSE messages.
 *
 * This also defines a data structure, t_cose_header_parameter that
 * holds one single parameter, for example an algorithm ID or a
 * kid. This structure is used to pass the parameters in and out of
 * all the methods above. It facilitates the general header
 * parameter implementation and allows for custom and specialized
 * headers.
 *
 *
 * COSE_signature
 *
 * t_cose_signature_sign and t_cose_signature_verify are abstract
 * bases classes for a set of implementations of COSE_Signature. This
 * design is chosen because there are a variety of signature schemes
 * to implement. Mostly these correspond to different signing
 * algorithms, but there is enough variation from algorithm to
 * algorithm that the use of an abstract base class here makes sense.
 *
 * Currently there is a "main" signer/verify that supports RSA
 * and ECDSA. There is another one for EdDSA, because it is
 * structurally different in not using a hash. Future
 * signer/verifiers might include one for counter signatures
 * and one for PQ.
 *
 * The user of t_cose will create instances of t_cose_signature and
 * configure them into t_cose_sign_sign() and t_cose_sign_verify().
 *
 *
 * COSE_recipient
 *
 * t_cose_recipient_enc and t_cose_recipient_dec are abstract base
 * classes for the set of concrete implementations of
 * COSE_recipient. Because the variation in one type of COSE_recipient
 * to another is so varied, this is whe *re the abstract base class is
 * necessary.
 *
 * Note that this use object-orientation here gives some very nice
 * modularity and extensibility. New types of COSE_recipient can be
 * added to COSE_Encrypt and COSE_Mac without changing their
 * implementation at all. It is als *o possible to add new types of
 * recipients without even modifying the main t_cose library.
 *
 * 
 * COSE_Key 
 *
 * Some formats of COSE_recipient have parameters that are in the
 * COSE_key format. It would be useful to have some library code to
 * handle these, in particular to encode and decode from the key data
 * structure used by the cr *ypto library (OpenSSL, PSA, …).
 */


  
/**
 * \file t_cose_common.h
 *
 * \brief This file contains definitions common to all public t_cose
 * interfaces.
 *
 * t_cose_common.h contains the definitions common to all public
 * t_cose interfaces, particularly the error codes, algorithm
 * identification constants and the structure containing a key.
 *
 * **Compile Time Configuration Options**
 *
 * \c T_COSE_DISABLE_SHORT_CIRCUIT_SIGN -- This disables short-circuit
 * signing test mode. This saves a small amount of object code
 *
 * \c T_COSE_DISABLE_ES512 -- Disables the COSE algorithm ES512
 * algorithm. This saves a tiny amount of code and a few hundred bytes
 * of stack. It saves more than \c T_COSE_DISABLE_ES384.
 *
 * \c T_COSE_DISABLE_ES384 -- Disables the COSE algorithm ES384
 * algorithm. This saves a tiny amount of code and a few hundred bytes
 * of stack. No stack will be saved if \c T_COSE_DISABLE_ES512 is not
 * also defined.
 *
 * \c T_COSE_DISABLE_PS256 -- Disables the COSE algorithm PS256
 * algorithm.
 *
 * \c T_COSE_DISABLE_PS384 -- Disables the COSE algorithm PS384
 * algorithm.
 *
 * \c T_COSE_DISABLE_PS512 -- Disables the COSE algorithm PS512
 * algorithm.
 *
 * \c T_COSE_DISABLE_CONTENT_TYPE -- Disables the content type
 * parameters for both signing and verifying.
 */


/**
 * This indicates this is t_cose 2.x, not 1.x. It should be forward compatible
 * with 1.x, but this is available in case it is not.
 */
#define T_COSE_2


/* Definition of algorithm IDs is moved to t_cose_standard_constants.h */


/**
 * Indicates the cryptographic library the \ref t_cose_key is intended
 * for. Usually only one cryptographic library is integrated so this
 * serves as a cross-check.
 */
enum t_cose_crypto_lib_t {
    /** can be used for integrations
     * that don't have or don't want to have any cross-check.
     */
    T_COSE_CRYPTO_LIB_UNIDENTIFIED = 0,
    /** \c key_ptr points to a malloced OpenSSL EC_KEY. The caller
     * needs to free it after the operation is done. */
    T_COSE_CRYPTO_LIB_OPENSSL = 1,
     /** \c key_handle is a \c psa_key_handle_t in Arm's Platform Security
      * Architecture */
    T_COSE_CRYPTO_LIB_PSA = 2,

    /** These are for the test crypto adapter layer. They are mostly fake, but useful
     * for testing without a library and for testing some error conditions. */
    T_COSE_CRYPTO_LIB_TEST = 3

};


// TODO: this may not belong in common.h
enum t_cose_key_usage_flags {
    T_COSE_KEY_USAGE_FLAG_NONE = 0,
    T_COSE_KEY_USAGE_FLAG_DECRYPT = 1,
    T_COSE_KEY_USAGE_FLAG_ENCRYPT = 2
};

// TODO: this probably doesn't belong in common.h because it is HPKE-specific
/*!
 * \brief HPKE ciphersuite
 */
struct t_cose_crypto_hpke_suite_t {
    uint16_t    kem_id;  // Key Encryption Method id
    uint16_t    kdf_id;  // Key Derivation Function id
    uint16_t    aead_id; // Authenticated Encryption with Associated Data id
};

/**
 * This structure is used to indicate or pass a key through the t_cose
 * implementation to the underlying, platform-specific cryptography
 * libraries for signing and verifying signature. You must know the
 * cryptographic library that is integrated with t_cose to know how to
 * fill in this data structure.
 *
 * For example, in the OpenSSL integration, \ref key_ptr should point
 * to an OpenSSL \c EVP_KEY type.
 */
struct t_cose_key {
    /** Identifies the crypto library this key was created for.  The
     * crypto library knows if it uses the handle or the pointer so
     * this indirectly selects the union member. */
    enum t_cose_crypto_lib_t crypto_lib;
    union {
        /** For libraries that use a pointer to the key or key
         * handle. \c NULL indicates empty. */
        void *key_ptr;
        /** For libraries that use an integer handle to the key */
        uint64_t key_handle;
        /** For pointer and length of actual key bytes. Length is a uint16_t to keep the
         * size of this struct down because it occurs on the stack. */
        struct q_useful_buf_c key_buffer;
    } k;
};


/** An empty or \c NULL \c t_cose_key */
/*
 * This has to be definied differently in C than C++ because there is
 * no common construct for a literal structure.
 *
 * In C compound literals are used.
 *
 * In C++ list initalization is used. This only works
 * in C++11 and later.
 *
 * Note that some popular C++ compilers can handle compound
 * literals with on-by-default extensions, however
 * this code aims for full correctness with strict
 * compilers so they are not used.
 */
#ifdef __cplusplus
#define T_COSE_NULL_KEY {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}}
#else
#define T_COSE_NULL_KEY \
    ((struct t_cose_key){T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}})
#endif


/* Private value. Intentionally not documented for Doxygen.
 * This is the size allocated for the encoded protected headers.  It
 * needs to be big enough for make_protected_header() to succeed. It
 * currently sized for one header with an algorithm ID up to 32 bits
 * long -- one byte for the wrapping map, one byte for the label, 5
 * bytes for the ID. If this is made accidentially too small, QCBOR will
 * only return an error, and not overrun any buffers.
 *
 * 9 extra bytes are added, rounding it up to 16 total, in case some
 * other protected header is to be added.
 */
#define T_COSE_MAC0_MAX_SIZE_PROTECTED_PARAMETERS (1 + 1 + 5 + 9)

/* Six: an alg id, a kid, an iv, a content type, one custom, crit list */
#define T_COSE_NUM_VERIFY_DECODE_HEADERS 6


/**
 * Error codes return by t_cose.
 */
/*
 * Do not reorder these. It is OK to add new ones at the end.
 *
 * Explicit values are included because some tools like debuggers show
 * only the value, not the symbol, and it is hard to count up through
 * 35 lines to figure out the actual value.
 */
enum t_cose_err_t {
    /** Operation completed successfully. */
    T_COSE_SUCCESS = 0,

    /** The requested signing algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_SIGNING_ALG = 1,

    /** Internal error when encoding protected parameters, usually
     * because they are too big. It is internal because the caller
     * can't really affect the size of the protected parameters. */
    T_COSE_ERR_MAKING_PROTECTED = 2,

    /** The hash algorithm needed is not supported. Note that the
     * signing algorithm identifier identifies the hash algorithm. */
    T_COSE_ERR_UNSUPPORTED_HASH = 3,

    /** Some system failure when running the hash algorithm. */
    T_COSE_ERR_HASH_GENERAL_FAIL = 4,

    /** The buffer to receive a hash result is too small. */
    T_COSE_ERR_HASH_BUFFER_SIZE = 5,

    /** The buffer to receive result of a signing operation is too
     * small. */
    T_COSE_ERR_SIG_BUFFER_SIZE = 6,

    /** When verifying a \c COSE_Sign1, the CBOR is "well-formed", but
     * something is wrong with the format of the CBOR outside of the
     * header parameters. For example, it is missing something like
     * the payload or something is of an unexpected type. */
    T_COSE_ERR_SIGN1_FORMAT = 8,

    /** When decoding some CBOR like a \c COSE_Sign1, the CBOR was not
     * "well-formed". Most likely what was supposed to be CBOR is
     * either not or is corrupted. The CBOR is can't be decoded. */
    T_COSE_ERR_CBOR_NOT_WELL_FORMED = 9,

    /** The CBOR is "well-formed", but something is wrong with format
     * in the header parameters.  For example, a parameter is labeled
     * with other than an integer or string or the value is an integer
     * when a byte string is expected. */
    T_COSE_ERR_PARAMETER_CBOR = 10,

    /** No algorithm ID was found when one is needed. For example,
     * when verifying a \c COSE_Sign1. */
    T_COSE_ERR_NO_ALG_ID = 11,

    /** No kid (key ID) was found when one is needed. For example,
     * when verifying a \c COSE_Sign1. */
    T_COSE_ERR_NO_KID = 12,

    /** Signature verification or data authentication failed. For
     * example, the cryptographic operations completed successfully
     * but hash wasn't as expected. */
    T_COSE_ERR_SIG_VERIFY = 13,
    T_COSE_ERR_DATA_AUTH_FAILED = 13,

    /** Verification of a short-circuit signature failed. */
    T_COSE_ERR_BAD_SHORT_CIRCUIT_KID = 14,

    /** Some (unspecified) argument was not valid. */
    T_COSE_ERR_INVALID_ARGUMENT = 15,

    /** Out of heap memory. This originates in crypto library as
     * t_cose does not use malloc. */
    T_COSE_ERR_INSUFFICIENT_MEMORY = 16,

    /** General unspecific failure. */
    T_COSE_ERR_FAIL = 17,

    /** Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED. */
    T_COSE_ERR_TAMPERING_DETECTED = 18,

    /** The key identified by a \ref t_cose_key or a key ID was not
     * found. */
    T_COSE_ERR_UNKNOWN_KEY = 19,

    /** The key was found, but it was the wrong type for the
      * operation. */
    T_COSE_ERR_WRONG_TYPE_OF_KEY = 20,

    /** Error constructing the COSE \c Sig_structure when signing or
     *  verify. */
    T_COSE_ERR_SIG_STRUCT = 21,

    /** Signature was short-circuit. The option \ref
     * T_COSE_OPT_ALLOW_SHORT_CIRCUIT to allow verification of
     * short-circuit signatures was not set.  */
    T_COSE_ERR_SHORT_CIRCUIT_SIG = 22,

    /** Something generally went wrong in the crypto adaptor when
      * signing or verifying. */
    T_COSE_ERR_SIG_FAIL = 23,

    /** Something went wrong formatting the CBOR.  Possibly the
     * payload has maps or arrays that are not closed when using
     * t_cose_sign1_encode_parameters() and
     * t_cose_sign1_encode_signature() to sign a \c COSE_Sign1. */
    T_COSE_ERR_CBOR_FORMATTING = 24,

     /** The buffer passed in to receive the output is too small. */
    T_COSE_ERR_TOO_SMALL = 25,

    /** More than \ref T_COSE_MAX_CRITICAL_PARAMS parameters
     * listed in the "crit" parameter.
     */
    T_COSE_ERR_TOO_MANY_PARAMETERS = 26,

    /** A parameter was encountered that was unknown and also listed in
      * the crit labels parameter. */
    T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER = 27,

    /** A request was made to signed with a short-circuit sig, \ref
     * T_COSE_OPT_SHORT_CIRCUIT_SIG, but short circuit signature are
     * disabled (compiled out) for this implementation.  */
    T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED = 28,

    /** The key type in a \ref t_cose_key is wrong for the
     * cryptographic library used by this integration of t_cose.
     */
    T_COSE_ERR_INCORRECT_KEY_FOR_LIB = 29,

    /** This implementation only handles integer COSE algorithm IDs with
     * values less than \c INT32_MAX. */
    T_COSE_ERR_NON_INTEGER_ALG_ID = 30,

    /** The content type parameter contains a content type that is
     * neither integer or text string or it is an integer not in the
     * range of 0 to \c UINT16_MAX. */
    T_COSE_ERR_BAD_CONTENT_TYPE = 31,

    /** If the option \ref T_COSE_OPT_TAG_REQUIRED is set for
     * t_cose_sign1_verify() and the tag is absent, this error is
     * returned. */
    T_COSE_ERR_INCORRECTLY_TAGGED = 32,

    /** The signing or verification key given is empty. */
    T_COSE_ERR_EMPTY_KEY = 33,

    /** A header parameter occurs twice, perhaps once in protected and
     * once in unprotected. Duplicate header parameters are not
     * allowed in COSE.
     */
    T_COSE_ERR_DUPLICATE_PARAMETER = 34,

    /** A header parameter that should be protected (alg id or crit)
     * is not. This occurs when verifying a \c COSE_Sign1 that is
     * improperly constructed. */
    T_COSE_ERR_PARAMETER_NOT_PROTECTED = 35,

    /** Something is wrong with the crit parameter. */
    T_COSE_ERR_CRIT_PARAMETER = 36,

    /** More than \ref T_COSE_MAX_TAGS_TO_RETURN unprocessed tags when
     * verifying a signature. */
    T_COSE_ERR_TOO_MANY_TAGS = 37,

    /** When decoding a header parameter that is not a string, integer or boolean
     * was encountered with no callback set handle it. See t_cose_ignore_param_cb()
     * and related. */
    T_COSE_ERR_UNHANDLED_HEADER_PARAMETER = 38,

    /** When encoding parameters, struct t_cose_header_parameter.parameter_type
     * is not a valid type.
     */
    T_COSE_ERR_INVALID_PARAMETER_TYPE = 39,

    /** Can't put critical parameters in the non-protected
     * header bucket per section 3.1 of RFC 9052. */
    T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED = 40,

    T_COSE_ERR_INSUFFICIENT_SPACE_FOR_PARAMETERS = 41,

    /* A header parameter with a string label occurred and there
     * is no support enabled for string labeled header parameters.
     */
    T_COSE_ERR_STRING_LABELED_PARAM = 42,

    /** No signers as in struct t_cose_signature_sign are  configured.
     */
    T_COSE_ERR_NO_SIGNERS = 43,

    /** More than one signer configured when signing a
     * COSE_Sign1 (multiple signers are OK for COSE_SIGN). */
    T_COSE_ERR_TOO_MANY_SIGNERS = 44,

    /** Mostly a verifier that is configured to look for kids
     * before it acts didn't match the kid in the message. */
    T_COSE_ERR_KID_UNMATCHED = 45,

    /** General CBOR decode error. */
    T_COSE_ERR_CBOR_DECODE = 46,

    /** A COSE_Signature contains unexected data or types. */
    T_COSE_ERR_SIGNATURE_FORMAT = 47,

    /**
     * When verifying a \c COSE_Mac0, something is wrong with the
     * format of the CBOR. For example, it is missing something like
     * the payload.
     */
    T_COSE_ERR_MAC0_FORMAT = 48,

  /** The requested key exchange algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG = 46,

    /** The requested encryption algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_ENCRYPTION_ALG = 47,

    /** The requested key length is not supported.  */
    T_COSE_ERR_UNSUPPORTED_KEY_LENGTH = 48,

    /** Adding a recipient to the COSE_Encrypt0 structure is not allowed.  */
    T_COSE_ERR_RECIPIENT_CANNOT_BE_ADDED = 49,

    /** The requested cipher algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_CIPHER_ALG = 50,

    /** Something went wrong in the crypto adaptor when
     * encrypting data. */
    T_COSE_ERR_ENCRYPT_FAIL = 51,

    /** Something went wrong in the crypto adaptor when
     * decrypting data. */
    T_COSE_ERR_DECRYPT_FAIL = 52,

    /** Something went wrong in the crypto adaptor when
     * invoking HPKE to encrypt data. */
    T_COSE_ERR_HPKE_ENCRYPT_FAIL = 53,

    /** Something went wrong in the crypto adaptor when
     * invoking HPKE to decrypt data. */
    T_COSE_ERR_HPKE_DECRYPT_FAIL = 54,

    /** When decoding a CBOR structure, a mandatory field
     *  was not found. */
    T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING = 55,

    /** When decoding the ephemeral key structure, the included
     * public key is of incorrect or unexpected size. */
    T_COSE_ERR_EPHEMERAL_KEY_SIZE_INCORRECT = 56,

    /** Cryptographic operations may require a key usage flags
     * to be indicated. If the provided flags are unsupported,
     * this error is returned. */
    T_COSE_ERR_UNSUPPORTED_KEY_USAGE_FLAGS = 57,

    /** The key import failed. */
    T_COSE_ERR_KEY_IMPORT_FAILED = 58,

    /** Obtaining random bytes failed. */
    T_COSE_ERR_RNG_FAILED = 59,

    /** Export of the public key failed. */
    T_COSE_ERR_PUBLIC_KEY_EXPORT_FAILED = 60,

    /** Generating asymmetric key pair failed. */
    T_COSE_ERR_KEY_GENERATION_FAILED = 61,

    /** Export of the key failed. */
    T_COSE_ERR_KEY_EXPORT_FAILED = 62,

    /** Something went wrong with AES Key Wrap. */
    T_COSE_ERR_KW_FAILED = 63,
    /** The signature algorithm needs an extra buffer, but none was provided.
     * See \ref t_cose_sign1_verify_set_auxiliary_buffer for more details.
     */
    T_COSE_ERR_NEED_AUXILIARY_BUFFER = 64,

    /** The auxiliary buffer is too small */
    T_COSE_ERR_AUXILIARY_BUFFER_SIZE = 65,

    T_COSE_ERR_NO_VERIFIERS = 66,
};


/**
 * TODO: this may not be implmented correctly yet
 *
 * In this tag decoding mode, there must be a tag number present in
 * the input CBOR. That tag number solely determines the COSE message
 * type that decoding expects.
 *
 * It is an error if there is no tag number.
 *
 * If a message type option like \ref T_COSE_OPT_MESSAGE_TYPE_SIGN is
 * set in the options, it is ignored.
 *
 * If there are nested tags, the inner most tag number, the one
 * closest to the array item (all COSE messages are arrays) is used.
 *
 * See also \ref T_COSE_OPT_TAG_PROHIBITED for another tag decoding
 * mode.
 *
 * If neither this or \ref T_COSE_OPT_TAG_PROHIBITED is set then the
 * message type will be determined by either the tag or or message
 * type option like \ref T_COSE_OPT_MESSAGE_TYPE_SIGN.  If neither are
 * available, then it is an error as the message type can't be
 * determined. If both are set, then the message type option overrules
 * the tag number. This is the default, but it is discouraged by
 * the CBOR standard as it is a bit ambigous and protocol definitions
 * should clearly state which they use. It is left as the default
 * here in t_cose because it will usually work out of the box.
 *
 * See t_cose_sign1_get_nth_tag() to get further tags that enclose
 * the COSE message.
 */
#define T_COSE_OPT_TAG_REQUIRED  0x00000100


/**
 * TODO: this may not be implmented correctly yet
 *
 * In this tag decoding mode, there must be no tag number present in
 * the input CBOR.  Message type options like \ref
 * T_COSE_OPT_MESSAGE_TYPE_SIGN are solely relied on.
 *
 * If a tag number is present, then \ref T_COSE_ERR_INCORRECTLY_TAGGED
 * is returned.
 *
 * If no Message type options like \ref T_COSE_OPT_MESSAGE_TYPE_SIGN
 * is set the TODO error is returned.
 *
 * See discussion on @ref T_COSE_OPT_TAG_REQUIRED.
 */
#define T_COSE_OPT_TAG_PROHIBITED  0x00000200


/**
 * An \c option_flag to not add the CBOR type 6 tag number when
 * encoding a COSE message.  Some uses of COSE may require this tag
 * number be absent because its COSE message type is known from
 * surrounding context.
 *
 * Or said another way \c COSE_Xxxx_Tagged message is produced by
 * default and a \c COSE_Xxxx is produced when this flag is set (where
 * COSE_Xxxx is COSE_Sign, COSE_Mac0, ... as specified in CDDL in RFC
 * 9052).  The only difference is the presence of the CBOR tag number.
 */
#define T_COSE_OPT_OMIT_CBOR_TAG 0x00000400

  
/**
 * When verifying or signing a COSE message, cryptographic operations
 * like verification and decryption will not be performed. Keys needed
 * for these operations are not needed. This is useful to decode a
 * COSE message to get the header parameter(s) to lookup/find/identify
 * the required key(s) (e.g., the kid parameter).  Then the key(s)
 * are/is configured and the message is decoded again without this
 * option.
 *
 * Note that anything returned (parameters, payload) will not have
 * been verified and should be considered untrusted.
 */
#define T_COSE_OPT_DECODE_ONLY  0x00000800


/* The lower 8 bits of the options give the type of the
 * COSE message to decode.
 * TODO: this may not be implmented correctly yet
 */
#define T_COSE_OPT_MESSAGE_TYPE_MASK 0x000000ff

/* The following are possble values for the lower 8 bits
 * of option_flags. They are used to indicated what
 * type of messsage to output and what type of message
 * to expect when decoding and the tag number is
 * absent or being overriden. */
#define T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED 00
#define T_COSE_OPT_MESSAGE_TYPE_SIGN        98
#define T_COSE_OPT_MESSAGE_TYPE_SIGN1       18
#define T_COSE_OPT_MESSAGE_TYPE_ENCRYPT     96
#define T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0    16
#define T_COSE_OPT_MESSAGE_TYPE_MAC         97
#define T_COSE_OPT_MESSAGE_TYPE_MAC0        17

// TODO: more meaningful names
#define T_COSE_OPT_IS_SIGN1(opts) \
   ((T_COSE_OPT_MESSAGE_TYPE_MASK & opts) == T_COSE_OPT_MESSAGE_TYPE_SIGN1)

#define T_COSE_OPT_IS_SIGN(opts) \
((T_COSE_OPT_MESSAGE_TYPE_MASK & opts) == T_COSE_OPT_MESSAGE_TYPE_SIGN)

/* Not expecting any more. */


/**
 * The error \ref T_COSE_ERR_NO_KID is returned if the kid parameter
 * is missing. Note that the kid parameter is primarily passed on to
 * the crypto layer so the crypto layer can look up the key. If the
 * verification key is determined by other than the kid, then it is
 * fine if there is no kid.
 */
#define T_COSE_OPT_REQUIRE_KID 0x00001000


/**
 * \brief  Check whether an algorithm is supported.
 *
 * \param[in] cose_algorithm_id        COSE Integer algorithm ID.
 *
 * \returns \c true if algorithm is supported, \c false if not.
 *
 * Algorithms identifiers are from COSE algorithm registry:
 *   https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 *
 * A primary use for this is to determine whether or not to run a test case.
 * It is often unneccessary for regular use, because all the APIs will return
 * T_COSE_ERR_UNSUPPORTED_XXXX if the algorithm is not supported.
 */
bool
t_cose_is_algorithm_supported(int32_t cose_algorithm_id);


/* Structure that holds all the inputs for signing that is
 * used in a few places (so it ends up in t_cose_common.h).
 * It is public because it is part of the signer/verify
 * call back interface. It is also used for MAC.
 *
 * These are the inputs to create a Sig_structure
 * from section 4.4 in RFC 9052.
 *
 * aad and sign_protected may be \ref NULL_Q_USEFUL_BUF_C.
 *
 * payload is a CBOR encoded byte string that may
 * contain CBOR or other.
 *
 * body_protected are the byte-string wrapped protected
 * header parameters from the COSE_Sign or COSE_Sign1.
 */
struct t_cose_sign_inputs {
    struct q_useful_buf_c  body_protected;
    struct q_useful_buf_c  aad;
    struct q_useful_buf_c  sign_protected;
    struct q_useful_buf_c  payload;
};



#ifdef __cplusplus
}
#endif


#endif /* __T_COSE_COMMON_H__ */
