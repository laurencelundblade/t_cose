/*
 * t_cose_parameters.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2022 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_parameters_h
#define t_cose_parameters_h

#include <stdint.h>
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"
#include "qcbor/qcbor.h"

// TODO: this file probably needs some re ordering and re organizing

/**
 * @file t_cose_parameters.h
 *
 * @brief Parameter encoding and decoding.
 *
 * Parameter encoding and decoding hinges around \ref t_cose_parameter
 * and functions for encoding and decoding arrays of it. Users of the
 * t_cose public APIs for verifying signing, encrypting, decrypting
 * and MACing will mainly use struct t_cose_parameter, not the
 * encoding and decoding functions.
 *
 * Struct \ref t_cose_parameter holds a single header parameter that
 * is to be encoded or has been decoded. The same structure is used
 * for both. Most parameter values are either integers or strings and
 * are held directly in struct t_cose_parameter. A callback is used
 * for more complex parameters.
 *
 * Only integer parameter labels are supported (so far).
 *
 * For many encoding use cases the needed header parameters will be
 * automatically generated and there is no need for use of anything in
 * this file.
 *
 * When decoding a COSE message (verification, decryption, ...) the
 * full set of header parameters decoded are returned as an array of
 * struct t_cose_parameter. In many cases the caller will not need to
 * examine what is returned.
 *
 * If the caller wishes to examine them, they can iterate over the
 * array searching by label. The data type, protected-ness and
 * criticality of the parameters in the returned array is not
 * checked. It is up to the caller examining these to check.  Some
 * functions for examining headers in the array are provided. See
 * t_cose_find_parameter(), t_cose_find_parameter_kid(), etc… These do
 * fully check the protected-ness, criticality and type of the
 * parameter.
 *
 * Some COSE messages, COSE_Sign1, COSE_Mac0 and COSE_Encrypt0 have
 * just one set of headers those for the main body. The other
 * messages, COSE_Sign, COSE_Encrypt and COSE_Mac have body headers
 * and additionally headers per recipient or signer. The data
 * structures and functions here handle all of those cases.
 *
 * When encoding, the multiple header sets are handled in the
 * interface for signing, encrypting and such. There are separate
 * functions for passing in the body header and the header per signer
 * and per recipient.
 *
 * When decoding all the headers for the entire message are returned
 * in one. The caller can know which parameters are for the body and
 * an index number for the recipient or signer. Even the nesting of
 * recipients within recipients is indicated.
 *
 * The APIs for decoding here don't allocate any storage for decoded
 * parameters, but the callers of these APIs need to.  A convention is
 * for the decoder (verifier, decryptor,...) context to contain
 * storage for a moderate number of parameters so those APIs are
 * simpler to use for the caller.
 */




/* Forward declaration. See actual definition below. */
struct t_cose_parameter;


/**
 * \brief Type of callback to output the encoded CBOR of a parameter.
 *
 * \param[in] parameter      A single parameter to encode
 * \param[in] qcbor_encoder  The encoder instance to output to
 *
 * A callback pointer of this type is placed in struct
 * t_cose_parameter. It is called back when t_cose_encode_headers()
 * gets to encoding the particular parameter. It is typically used for
 * encoding parameters that are not integers or strings, but can be
 * used for them too. For most use cases, this is not needed.
 *
 * When called it should output the CBOR for the header parameter to
 * the encoder context including the header label.
 *
 * If it returns an error, encoding of the COSE message will stop and
 * error out with the error it returned.
 *
 * If desired there can be several implementations of this for several
 * different parameters.
 */
typedef enum t_cose_err_t
t_cose_parameter_encode_callback(const struct t_cose_parameter  *parameter,
                                 QCBOREncodeContext             *qcbor_encoder);


/**
 * \brief Type of callback to decode the QCBOR of a parameter.
 *
 * \param[in] callback_context  Context for callback
 * \param[in] qcbor_decoder     QCBOR decoder to pull from.
 * \param[in,out] parameter     On input, label and other. On output
 *                              the decoded value.
 *
 * This is called back from t_cose_decode_headers() when a parameter
 * that is not an integer or string is encountered. The callback must
 * consume all the CBOR that makes up the particular parameter and no
 * more.
 *
 * On input, the label, protected, critical and value_type are set
 * based on peeking at the first data item in the header. The value is
 * not set.
 *
 * On exit, this function must set the value_type and the value.
 *
 * Unlike t_cose_parameter_encode_callback() there is just one
 * implementation of this that switches on the label.
 */
typedef enum t_cose_err_t
t_cose_parameter_decode_callback(void                    *callback_context,
                                 QCBORDecodeContext      *qcbor_decoder,
                                 struct t_cose_parameter *parameter);


/** Where in a COSE message a header was found. */
struct t_cose_header_location {
    /** 0 means the body, 1 means the first level of signer/recipient, 2,
     * the second level.*/
    uint8_t  nesting;
    /* For signers and recipients, the index within the nesting level
     * starting from 0. */
    uint8_t  index;
};




/**
 * This holds one parameter such as an algorithm ID or kid. When that
 * one parameter is not an integer or string, this holds a callback to
 * output it. It typically takes up 32 bytes.
 *
 * This is used both for to-be-encoded parameters and decoded
 * parameters. It is also used for header parameters and key
 * parameters.
 */
struct t_cose_parameter {
    /** Label indicating which parameter it is. Typically, one of
     * COSE_HEADER_PARAM_XXXXX, such as \ref COSE_HEADER_PARAM_ALG
     */
    int64_t label;

    /** Indicates parameter is to be encoded in the protected header
     * bucket or was decoded from the protected header bucket. */
    bool    protected;
    /** Indicates parameter should be listed in the critical headers
     * when encoding. Not used while decoding.*/
    bool    critical;
    /** When decoding the location. Ignored when encoding. */
    struct t_cose_header_location location;

    /** One of \ref T_COSE_PARAMETER_TYPE_INT64, ... This is the
     * selector for the contents of the value union. On encoding, the
     * caller fills this in to say what they want encoded.  On
     * decoding it is filled in by the decoder for strings and
     * integers. When it is not a string or integer, the decode call
     * back is called and it is filled in by the decode callback. */
    uint8_t value_type;

    /** The value of the parameter. */
    union {
        int64_t               i64;
        struct q_useful_buf_c string;
        void                 *ptr;
        uint8_t               little_buf[8];
        struct { /* Used only for encoding */
            void                             *context;
            t_cose_parameter_encode_callback *callback;
        } custom_encoder;
    } value;
};


#define T_COSE_PARAMETER_TYPE_NONE         0
#define T_COSE_PARAMETER_TYPE_INT64        2
#define T_COSE_PARAMETER_TYPE_BYTE_STRING  6
#define T_COSE_PARAMETER_TYPE_TEXT_STRING  7
#define T_COSE_PARAMETER_TYPE_PTR        100
#define T_COSE_PARAMETER_TYPE_LITTLE_BUF 101
#define T_COSE_PARAMETER_TYPE_CALLBACK   102
// TODO: add a parameters type to recursively encode because COSE_Keys are
// parameter sets too and they go into headers.


/**
 * The maximum number of critical header parameters that can be
 * handled during decoding (e.g., during verification, decryption,
 * ...). \ref T_COSE_ERR_TOO_MANY_PARAMETERS will be returned if the
 * input message has more.
 *
 * There can be both \ref T_COSE_MAX_CRITICAL_PARAMS integer-labeled
 * parameters and \ref T_COSE_MAX_CRITICAL_PARAMS string-labeled
 * parameters.
 *
 * This is a hard maximum so the implementation doesn't need
 * malloc. This constant can be increased if needed. Doing so will
 * increase stack usage.
 */
#define T_COSE_MAX_CRITICAL_PARAMS 4


/**
 * The value of an unsigned integer content type indicating no content
 * type.  See \ref t_cose_parameters.
 */
#define T_COSE_EMPTY_UINT_CONTENT_TYPE UINT16_MAX+1




/* These are struct t_cose_header_parameter initializers for the standard
 * header parameters. They set the type and typical protection level.
 *
 * Example use:
 *    struct t_cose_parameter params[2];
 *    params[0] = T_COSE_MAKE_ALG_ID_PARAM(T_COSE_ALGORITHM_ES256);
 *    params[1] = T_COSE_END_PARAM;
 */
#define T_COSE_MAKE_ALG_ID_PARAM(x) \
    (struct t_cose_parameter){COSE_HEADER_PARAM_ALG, \
                                 true,\
                                 false,\
                                 {0,0},\
                                 T_COSE_PARAMETER_TYPE_INT64,\
                                 .value.i64 = x }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
#define T_COSE_CT_UINT_PARAM(content_type) \
    (struct t_cose_parameter){COSE_HEADER_PARAM_CONTENT_TYPE, \
                              false,\
                              false,\
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_INT64,\
                              .value.i64 = content_type }

#define T_COSE_CT_TSTR_PARAM(content_type) \
   (struct t_cose_parameter){COSE_HEADER_PARAM_CONTENT_TYPE, \
                             false,\
                             false,\
                             {0,0},\
                             T_COSE_PARAMETER_TYPE_TEXT_STRING,\
                             .value.string = content_type }
#endif /* T_COSE_DISABLE_CONTENT_TYPE */

#define T_COSE_KID_PARAM(kid) \
    (struct t_cose_parameter){COSE_HEADER_PARAM_KID, \
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_BYTE_STRING, \
                              .value.string = kid }

#define T_COSE_IV_PARAM(iv) \
    (struct t_cose_parameter){COSE_HEADER_PARAM_IV, \
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_BYTE_STRING, \
                              .value.string = iv }

#define T_COSE_PARTIAL_IV_PARAM(partial_iv) \
    (struct t_cose_parameter){COSE_HEADER_PARAM_PARTIAL_IV, \
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_BYTE_STRING, \
                              .value.string = partial_iv }

#define T_COSE_END_PARAM  \
    (struct t_cose_parameter){0,\
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_NONE, \
                              .value.string = NULL_Q_USEFUL_BUF_C }


/* A structure to hold an array of struct t_cose_header_param
 * of a given length, typically an empty structure that is
 * not yet terminated by T_COSE_PARAMETER_TYPE_NONE. */
struct t_cose_parameter_storage {
    size_t                   storage_size;
    struct t_cose_parameter *storage;
};




/**
 * \brief Encode both the protected and unprotected header buckets.
 *
 * \param[in] encode_context         Encoder context for header output.
 * \param[in] parameters             The vector of parameters to output.
 * \param[out] protected_parameters  Place to put pointer and length of
 *                                   encoded protected headers. May be NULL.
 *
 * This encodes COSE "Headers" that are used in COSE_Sign, COSE_Sign1,
 * COSE_Signature, COSE_Encrypt, COSE_Encrypt0, COSE_Mac, COSE_Mac0
 * and COSE_Recipient
 *
 * The input to this is a set of struct t_cose_parameter containing
 * both protected and unprotected header parameters. They will be
 * encoded and output to the encoder context into first the protected
 * header bucket and then the unprotected header bucket.
 *
 * The input set is in the form of an array of pointers to arrays of
 * struct t_cose_parameter (i.e. a vector or scatter/gather list). The
 * array of pointers is terminated by a NULL pointer. The arrays of
 * struct t_cose_parameter are terminated by a value_type of type \ref
 * T_COSE_PARAMETER_TYPE_NONE.
 *
 * t_cose_parameter.protected indicated whether the parameter should
 * go into the protected or unprotected bucket. The order of the
 * parameters in the input doesn't matter as to whether the protected
 * parameters go first or not.
 *
 * Each parameter has a label, data type and value.  Only integer
 * label types are supported (so far). Most header parameters will be
 * either an integer or string, (T_COSE_PARAMETER_TYPE_INT64,
 * T_COSE_PARAMETER_TYPE_BYTE_STRING or
 * T_COSE_PARAMETER_TYPE_TEXT_STRING).
 *
 * The parameter type may also be T_COSE_PARAMETER_TYPE_CALLBACK in
 * which case the a callback function and context are supplied that
 * will be called when it is time to encode that parameter. This is
 * typically needed for parameter types that are not integers or
 * strings, but can be used for them too.
 *
 * The crit header parameter will be automatically added if there are
 * any protected parameters that are marked as critical. If there are
 * none, then it will not be added. There is no limit to the number of
 * critical parameters to encode, but there is a limit of xxxx for
 * decoding by t_cose_headers_decode().
 *
 * A pointer and length of the protected header byte string is
 * returned so that it can be covered by what ever protection
 * mechanism is in used (e.g., hashing or AEAD encryption).
 */
enum t_cose_err_t
t_cose_encode_headers(QCBOREncodeContext                    *encode_context,
                      const struct t_cose_parameter * const *parameters,
                      struct q_useful_buf_c                 *protected_parameters);



/**
 * \brief Decode both protected and unprotected header buckets.
 *
 * \param[in] decode_context          QCBOR decoder to decode from.
 * \param[in] location                Location in message of the parameters.
 * \param[in] callback                Callback for non-integer and
 *                                    non-string parameters.
 * \param[in] callback_context        Context for the above callback
 * \param[in,out] parameters          On input storage for parameters, on
 *                                    output the decoded parameters.
 * \param[out] protected_parameters   Pointer and length of encoded protected
 *                                    parameters.
 *
 * Use this to decode "Headers" that occurs throughout COSE. The QCBOR
 * decoder should be positioned so the protected header bucket is the
 * next item to be decoded. This then consumes the CBOR for the two
 * headers leaving the decoder position for what ever comes after.
 *
 * The decoded headers are placed in an array of struct
 * t_cose_parameter which is in the function parameter named \c
 * parameters. Params functions as an [in,out]. The decoded COSE
 * header params are in params.storage terminated by TYPE_NONE.
 *
 * The number of parameters list in the crit parameter is limited to
 * XX for each bucket of headers. T_COSE_ERR_TOO_MANY_PARAMETERS is
 * returned if this is exceeded and the decode of all the header ends.
 * Note that this only the limit for one header bucket, not the
 * aggregation of all the headers buckets. For example it limits the
 * crit list in for one COSE_Signer, not the the total of all
 * COSE_Signers. This is a hard limt that can only be increased by
 * changing the size and re building the t_cose library.
 *
 * In order to handle parameters that are not integers or strings a
 * callback of type \ref t_cose_parameter_decode_callback must be
 * configured. There is only one of these callbacks for all the
 * non-integer and non-string header parameters. It typically switches
 * on the parameter label.
 *
 * When parameters that are not integers or strings occur and there is
 * no callback configured, critical parameters will result in an error
 * and non-critical parameters will be ignored.
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext                   *decode_context,
                      struct t_cose_header_location         location,
                      t_cose_parameter_decode_callback     *callback,
                      void                                 *callback_context,
                      const struct t_cose_parameter_storage parameters,
                      struct q_useful_buf_c                *protected_parameters);



// TODO: finish documentation for functions below
/* Find a parameter by label in array of parameters returned by verify */
const struct t_cose_parameter *
t_cose_find_parameter(const struct t_cose_parameter *p, int64_t label);


/*
 * TODO: finish documentation
 * This returns T_COSE_ALGORITHM_NONE for all errors decoding
 * the algorithm ID including it not being present and not being
 * a protected parameter.
 */
int32_t
t_cose_find_parameter_alg_id(const struct t_cose_parameter *p);

#ifndef T_COSE_DISABLE_CONTENT_TYPE

/* This returns NULL_Q_USEFUL_BUF_C for all errors including it
* not being present and not being the right type.
*/
struct q_useful_buf_c
t_cose_find_parameter_content_type_tstr(const struct t_cose_parameter *p);

/*
 * This returns T_COSE_EMPTY_UINT_CONTENT_TYPE for all errors include it
 * not being present and it being larger than UINT16_MAX (the largest allowed
 * value for a CoAP content type).
 */
uint32_t
t_cose_find_parameter_content_type_int(const struct t_cose_parameter *p);

#endif /* T_COSE_DISABLE_CONTENT_TYPE */


/* This returns NULL_Q_USEFUL_BUF_C for all errors including it
 * not being present and not being the right type.
 */
struct q_useful_buf_c
t_cose_find_parameter_kid(const struct t_cose_parameter *p);


/* This returns NULL_Q_USEFUL_BUF_C for all errors including it
* not being present and not being the right type.
*/
struct q_useful_buf_c
t_cose_find_parameter_iv(const struct t_cose_parameter *p);


/* This returns NULL_Q_USEFUL_BUF_C for all errors including it
* not being present and not being the right type.
*/
struct q_useful_buf_c
t_cose_find_parameter_partial_iv(const struct t_cose_parameter *p);


#endif /* t_cose_parameters_h */
