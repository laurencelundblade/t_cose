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

/*
 * TODO: move this documentation to the right functions
 * Header parameter encoding and decoding hinges around struct
 * t_cose_header_param plus primary functions for encoding and decoding
 * the header. Users of the t_cose public API for verifying signing,
 * encrypting, decrypting and MACing will mainly use struct
 * t_cose_header_param.
 *
 * Struct t_cose_header_param holds a single header parameter that is
 * to be encoded or has been decoded. The same structure is used for
 * both. Most parameters are either integers or strings and
 * are held directly in struct t_cose_header_param. A callback is used
 * for more complex parameters.
 *
 * The struct t_cose_header_param also holds:
 *   * Whether the parameter is protected or not
 *   * Whether the parameter is critical
 *   * The label for the parameter
 *   * The data type of the parameter
 *   * The location of the parameter in the COSE message
 *
 * Only integer parameter labels are supported.
 *
 * When encoding a COSE message and only the kid and algorithm id are
 * needed, there is no need to use the header parameter structure as
 * those are handled internally. If further parameters are needed when
 * encoding further the caller creates an TODO: vector array of struct
 * t_cose_header_param passes it in with xxxx_add_parameters(). This
 * array is terminated by a header parameter structure with type
 * T_COSE_PARAMETER_TYPE_NONE. This array can contain only one, or a large number of
 * parameters, can contain protected or unprotected headers, critical
 * or not-critical headers and headers of any data type.
 *
 * If the data type to encode is complex, for example the parameter
 * itself is a map, then an encoding callback must be implemented that
 * will output the parameter to a QCBOR encode context.  The pointer to
 * this function goes in the struct t_cose_header_param. It will be
 * called back during the encoding of the COSE message.
 *
 * If any header parameters for encoding are marked critical, the crit
 * header parameter will be automatically added to the COSE message.
 *
 * When decoding a COSE message (verification or decryption) the full
 * set of header parameters decoded are returned as a pointer to an
 * array of struct t_cose_header_param terminated by one with the type
 * T_COSE_PARAMETER_TYPE_NONE. In many cases the caller will not need to examine what is
 * returned.
 *
 * If the caller wishes to examine them, they can iterate over the
 * array searching by label to find the parameter of interest. The data
 * type, protected-ness and criticality of the parameters is not
 * checked. It is up to the caller examining these to check.
 *
 * Some functions for examining headers in the array are provided. See
 * t_cose_find_parameter(), t_cose_find_parameter_kid(), etc… These do
 * fully check the protected-ness, criticality and type of the
 * parameter.
 *
 * When the data type of the header parameter is not an integer,
 * string or boolean, then a read callback must be supplied. This will
 * be called during the decoding of the COSE message with a QCBOR
 * decode context. The callback must alway correctly consume the whole
 * encoded CBOR. The callback can store what it decodes in a
 * context. The callback must do checking for criticality and
 * protractedness of the parameter and error out if they are not
 * correct.
 *
 * If fewer than 10 (TBD) header parameters are in the COSE message,
 * then storage for the returned header parameter structures is
 * provided from the verifier/decryptor context. If more are
 * encountered, the message decode will error out.
 *
 * If it is expected that more than 10 parameters may occur, the
 * caller should provide a larger storage array for header parameters
 * by calling t_cose_xxxx_add_parameter_storage().
 *
 * Some COSE messages, COSE_Sign1, COSE_Mac0 and COSE_Encrypt0 have
 * just one set of headers those for the main body. The other messages,
 * COSE_Sign, COSE_Encrypt and COSE_Mac have body headers and
 * additionally headers per recipient or signer. These scenarios are
 * also handled here.
 *
 * When encoding, the multiple header sets are handled in the
 * interface for signing, encrypting and such. There are separate
 * functions for passing in the body header and the header per signer
 * and per recipient.
 *
 * When decoding all the headers for the entire message are returned
 * in one. The caller can know which parameters are for the body and an
 * index number for the recipient or signer. Even the nesting of
 * recipients within recipients is indicated.
 *
 * Note that decoding messages with many signers or recipients is when
 * you will probably have to add storage for header parameters. Even
 * though the algorithm ID is handled internally, there is still
 * storage needed for it for every signer or recipient.
 *
 * As mentioned in the beginning there is one main function for
 * encoding headers, t_cose_encode_headers() and a complimentary one
 * for decoding headers, t_cose_decode_headers(). These are mostly used
 * internally to implement the main public APIs for signing, encrypting
 * and MACing, but they are also available publicly for add-on
 * implementations of different types of signers and recipients.
 *
 * The primary input to t_cose_encode_headers() is a list of struct
 * t_cose_header_param to encode and the QCBOR encoder context to
 * output them too. Similarly the primary input to
 * t_cose_decode_headers() is a QCBOR decoder context to decode from
 * the output is an array of struct t_cose_header_param. Both of these
 * functions handle both the protected and unprotected headers all in
 * one call (since they always occur together in COSE).
 *
 * Is it "header parameter" or "parameter"? From looking at RFC
 * 9052 it seems there are two kinds of parameters, "header parameters"
 * and "key parameters". Header parameters occur in the Headers
 * section of COSE_Sign, COSE_Encrypt and such. Key parameters
 * occur in COSE_Keys. When the context is known, they might
 * just be refered to as "parameter".

 */



/* Forward declaration. See actual definition below. */
// TODO: rename to header_parameter ? Yes, but maybe wait until encrypt is merged
struct t_cose_parameter;



/*
 * Callback to output the encoded CBOR of a header parameter
 *
 * This callback pointer is placed in struct t_cose_header_param. It is called
 * back when t_cose_encode_headers() gets to encoding
 * the particular parameter. It is typically used for
 * encoding parameters that are not integers or strings,
 * but can be used for them too. For most
 * use cases, this is not needed.
 *
 * When called it should output the QCBOR for the headers
 * parameter to the encoder context including the
 * header label.
 *
 * If it returns an error encoding of the COSE message
 * will stop and error out with the error it returned.
 * For CBOR
 */
typedef enum t_cose_err_t
t_cose_parameter_encode_callback(const struct t_cose_parameter  *parameter,
                                 QCBOREncodeContext             *qcbor_encoder);


/*
 *
 * This is called back from t_cose_decode_headers() when
 * a parameter that is not an integer or string is
 * encountered. The call back must consume all the CBOR
 * that makes up the particular parameter and no more.
 *
 * The label, prot, crit and type are set based on peeking
 * at the first data item in the header. The value is
 * not set.
 *
 * On exit, this function must set the type and the value.
 *
 * Typically this function will switch on the label to
 * know what to decode.
 */
typedef enum t_cose_err_t
t_cose_parameter_decode_callback(void                    *callback_context,
                                 QCBORDecodeContext      *qcbor_decoder,
                                 struct t_cose_parameter *parameter); // [in,out] parameter


/* Where in a COSE message a header was found. */
struct header_location {
    /* 0 means the body, 1 means the first level of signer/recipient, 2,
     * the second level.*/
    uint8_t  nesting;
    /* For signers and recipienets, the index within the nesting level
     * starting from 0. */
    uint8_t  index;
};



/*
 * This holds one parameter such as an algorithm ID
 * or kid. When that one parameter is not an
 * integer or string, this holds a callback to
 * output it. It typically takes up 32 bytes.
 */
struct t_cose_parameter {
    /* Label indicating which parameter it is. One of COSE_HEADER_PARAM_ALG,
     * ...
     */
    int64_t label;

    /* Indicates parameter is to be encoded in the protected header
     * bucket was decoded from the protected header bucket. */
    bool    protected;
    /* Indicates parameter should be listed in the critical headers
     * when encoding. Not used while decoding.*/
    bool    critical;
    /* When decoding the location. Ignored when encoding. */
    struct header_location location;

    /* One of T_COSE_PARAMETER_TYPE_INT64, ... This is the selector
     * for the contents of the value union. On encoding, the
     * caller fills this in to say what they want encoded.
     * On decoding it is filled in by the decoder for strings
     * and integers. When it is not a string or integer,
     * the decode call back is called and it is filled in by
     * the decode callback. */
    uint8_t value_type;

    /* The value of the parameter. */
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
 * The maximum number of header parameters that can be handled during
 * verification of a \c COSE_Sign1 message. \ref
 * T_COSE_ERR_TOO_MANY_PARAMETERS will be returned by
 * t_cose_sign1_verify() if the input message has more.
 *
 * There can be both \ref T_COSE_PARAMETER_LIST_MAX integer-labeled
 * parameters and \ref T_COSE_PARAMETER_LIST_MAX string-labeled
 * parameters.
 *
 * This is a hard maximum so the implementation doesn't need
 * malloc. This constant can be increased if needed. Doing so will
 * increase stack usage.
 */
#define T_COSE_PARAMETER_LIST_MAX 10

/**
 * The value of an unsigned integer content type indicating no content
 * type.  See \ref t_cose_parameters.
 */
#define T_COSE_EMPTY_UINT_CONTENT_TYPE UINT16_MAX+1



// TODO: these maybe should be *HEADER*_PARAMETERS (not KEY PARAMETERS).
/* These are struct t_cose_header_parameter initializers for the standard
 * header parameters. They set the type and typical protection level.
 *
 * Example use:
 *    struct t_cose_header_param params[2];
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
    size_t                      storage_size;
    struct t_cose_parameter *storage;
};




/*
 * \brief Encode both the protected and unprotected Headers
 *
 * The input to this is a set of struct t_cose_header_param containing both
 * protected and unprotected header parameters. They will
 * be encoded and output to the encoder context into
 * first the protected header bucket and then the unprotected
 * header bucket.
 *
 * The input set is in the form of an array of pointers to arrays of
 * xxxxx (i.e. a scatter/gather list). The array of pointers is
 * terminated by a NULL pointer. The arrays of xxxx are terminated
 * by a xxxx of type xxxx_NONE.
 *
 * Xxxxx.prot indicated whether the parameter should go into
 * the protected or unprotected bucket. The order of the parameters
 * in the input doesn't matter as to whether the protected
 * parameters go first or not.
 *
 * Each parameter has a label, data type and value.
 * Only integer label types are supported. Most
 * header parameters will be either an integer, string or Boolean.
 * Types are provided for these.
 *
 * The parameter type may also be yyyy in which case the
 * a callback function and context are supplied that will be
 * called when it is time to encode that parameter. This is
 * typically needed for parameter types tha are not integers,
 * strings or booleans, but can be used for them too.
 *
 * The crit header parameter will be automatically added
 * if there are any protected parameters that are marked
 * as critical. If there are none, then it will not be
 * added.
 *
 * A pointer and length of the protected header byte string
 * is returned so that it can be covered by what ever protection
 * mechanism is in used (e.g., hashing or AEAD encryption).
 */
enum t_cose_err_t
t_cose_encode_headers(QCBOREncodeContext                    *encode_context,
                      const struct t_cose_parameter * const *parameters,
                      struct q_useful_buf_c                 *protected_parameters);



/*
 * \brief Decode both protected and unprotected Headers.
 *
 * Use this to decode "Headers" that occurs
 * through out COSE. The QCBOR decoder should be positioned
 * so the protected header bucket is the next item to
 * be decoded. This then consumes the CBOR for the two headers
 * leaving the decoder position for what ever comes after.
 *
 * The decoded headers are placed in an array of
 * struct t_cose_header_param which is in the
 * function parameter named params. Params
 * is functions as [in,out]. The decoded
 * COSE header params are in params.storage
 * terminated by TYPE_NONE.
 *
 * The number of parameters list in the crit
 * parameter is limited to XX for each bucket
 * of headers. T_COSE_ERR_TOO_MANY_PARAMETERS is returned
 * if this is exceeded and the decode of all the
 * header ends.  Note that this only the limit
 * for one header bucket, not the aggregation of
 * all the headers buckets. For example it limits
 * the crit list in for one COSE_Signer, not the
 * the total of all COSE_Signers. This is a hard
 * limt that can only be increased by changing
 * the size and re building the t_cose library.
 *
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext                   *decode_context,
                      struct header_location                location,
                      t_cose_parameter_decode_callback     *cb,
                      void                                 *cb_context,
                      const struct t_cose_parameter_storage params,
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




/* Convenience callback to ignore headers that are not understood.
 *
 * This does NOT ignore critical parameters. (But you
 * can write your own version of this function that does
 * ignore critical parameters if you want). */
enum t_cose_err_t
t_cose_ignore_param_cb(void                  *callback_context,
                       QCBORDecodeContext    *decode_context,
                       struct header_location location,
                       bool                   is_protected,
                       bool                   is_crit);









/* TODO: remove these design notes
A callback supply by the caller that is called for 1) body and signer headers
 and 2) protected and unprotected headers.

It is called repeatedely for each until the call back says done.

 It is given a decode context to output the headers to

 It is given a headers gen context that is caller defined


 More simply the caller may fill in a simple_header struct and
 call register header.

 Have to distinguish which header goes with which signer.
 TODO: how should this work?

On verifying...

 Can register a call back that is called on every header. Two
 types of call backs
  - One for those that need decoding
  - One for those can be presented as a simple_header


 A header set object?
 - protected and non protected
 - a list of headers
 - some are data structures with pointers
 - some have to be done with call back for reading and writing





 When writing parameters,
 - Fill in HP structure, protected or not
 - - Can be specific like algID
 - - Can be general (label and value)
 - - Can be a function that writes them out

 - Add them to the recipient, signer or body instance

 Memory for HP's is allocated by the caller


 When reading parameters, it is more complicated...
 - 4 are supplied by default
 - The caller supplies an array of HP structures
 - They are filled in
 - There is an error if enough are not supplied

 Call back while verifying and/or while decoding-only. Will
 have to seek to value or caller has to get the
 label in the call back.

5 parameters supported by default -- adds about 150 bytes
 to memory requirements.

 Allow supplying of a bigger buffer if needed.

 Which is it
  - linked list
  - array is cleanest
  - accessor function


 What about decoding complicated headers?

 - Could return a bstr with the header value, but that would require
 a change to QCBOR. The caller has to run a new QCBORDecoder on it,
 but otherwise it is very clean. It can go into the header
 structure we have. No call backs needed!

 - Could have a callback with the decoder context positioned to read the
 header. They would get the label and value. They have to
 consume the whole header correctly to not mess up the decode.

 return a decoder context and expect the caller to
 decode. It would be hard to stop the decoder at the value.
 They'd get the label and the value. Could be fixed with a change
 to QCBOR.

 -


 */

/*
 Call back to decode a header parameter.

 Internal loop
   - First call internal processor
   - - It will process algorithm ID
   - - It will bundle others into the generic header parameter
   - In some cases this call back will be run
     - when the stuff is too complicate
     - when the caller requests it



 Just loop over items in the header maps calling this.



 Context 0 is the body.



 */






#endif /* t_cose_parameters_h */
