/*
 * t_cose_parameters.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_parameters.h"
#include "t_cose_standard_constants.h"
#include "qcbor/qcbor_spiffy_decode.h"



/**
 * \file t_cose_parameters.c
 *
 * \brief Implementation of COSE header parameter decoding.
 *
 */


// TODO:  Needs to be larger and dynamically sizeable
// now that we're doing multiple signers and recpients.
struct t_cose_label_list {
    /* Terminated by value LABEL_LIST_TERMINATOR */
    int64_t int_labels[T_COSE_PARAMETER_LIST_MAX+1];
    /*  Terminated by a NULL_Q_USEFUL_BUF_C */
    struct q_useful_buf_c tstr_labels[T_COSE_PARAMETER_LIST_MAX+1];
};


/*
 * The IANA COSE Header Parameters registry lists label 0 as
 * "reserved". This means it can be used, but only by a revision of
 * the COSE standard if it is deemed necessary for some large and good
 * reason. It cannot just be allocated by IANA as any normal
 * assignment. See [IANA COSE Registry]
 * (https://www.iana.org/assignments/cose/cose.xhtml).  It is thus
 * considered safe to use as the list terminator.
 */
#define LABEL_LIST_TERMINATOR 0


/**
 * \brief Clear a label list to empty.
 *
 * \param[in,out] list The list to clear.
 */
inline static void clear_label_list(struct t_cose_label_list *list)
{
    memset(list, 0, sizeof(struct t_cose_label_list));
}




/*
 * Cross-check to make sure public definition of algorithm
 * IDs matches the internal ones.
 */
#if T_COSE_ALGORITHM_ES256 != COSE_ALGORITHM_ES256
#error COSE algorithm identifier definitions are in error
#endif

#if T_COSE_ALGORITHM_ES384 != COSE_ALGORITHM_ES384
#error COSE algorithm identifier definitions are in error
#endif

#if T_COSE_ALGORITHM_ES512 != COSE_ALGORITHM_ES512
#error COSE algorithm identifier definitions are in error
#endif




static inline uint8_t
cbor_type_2_parameter_type(uint8_t qcbor_data_type)
{
    // improvement: maybe this can be optimized to use less object code.
    switch(qcbor_data_type) {
        case QCBOR_TYPE_INT64:
        case QCBOR_TYPE_UINT64:
        case QCBOR_TYPE_TEXT_STRING:
        case QCBOR_TYPE_BYTE_STRING:
        case QCBOR_TYPE_TRUE:
            /* parameter types picked so they map directly from QCBOR types */
            return qcbor_data_type;

        case QCBOR_TYPE_FALSE:
            return T_COSE_PARAMETER_TYPE_BOOL;

        default:
            return T_COSE_PARAMETER_TYPE_NONE;
    }
}


/**
 * \brief Indicate whether label list is clear or not.
 *
 * \param[in,out] list  The list to check.
 *
 * \return true if the list is clear.
 */
inline static bool
is_label_list_clear(const struct t_cose_label_list *list)
{
    return list->int_labels[0] == 0 &&
               q_useful_buf_c_is_null_or_empty(list->tstr_labels[0]);
}


/**
 * \brief Decode the parameter containing the labels of parameters considered
 *        critical.
 *
 * \param[in,out]  decode_context          Decode context to read critical
 *                                         parameter list from.
 * \param[out]     critical_labels         List of labels of critical
 *                                         parameters.
 *
 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED  Undecodable CBOR.
 * \retval T_COSE_ERR_TOO_MANY_PARAMETERS   More critical labels than this
 *                                          implementation can handle.
 * \retval T_COSE_ERR_PARAMETER_CBOR        Unexpected CBOR data type.
 */
static inline enum t_cose_err_t
decode_critical_parameter(QCBORDecodeContext       *decode_context,
                          struct t_cose_label_list *critical_labels)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   QCBORItem                                     56          52
     *   local vars                                    32          16
     *   TOTAL                                         88          68
     */
    QCBORItem         item;
    uint_fast8_t      num_int_labels;
    uint_fast8_t      num_tstr_labels;
    enum t_cose_err_t return_value;
    QCBORError        cbor_result;

    /* Assume that decoder has been entered into the parameters map */

    /* Find and enter the array that is the critical parameters parameter */
    QCBORDecode_EnterArrayFromMapN(decode_context, COSE_HEADER_PARAM_CRIT);

    cbor_result = QCBORDecode_GetAndResetError(decode_context);
    if(cbor_result == QCBOR_ERR_LABEL_NOT_FOUND) {
        /* Critical paratmeters parameter doesn't exist */
        return_value = T_COSE_SUCCESS;
        goto Done;
    } else if(cbor_result != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CRIT_PARAMETER;
        goto Done;
    }

    num_int_labels  = 0;
    num_tstr_labels = 0;

    while(1) {
        cbor_result = QCBORDecode_GetNext(decode_context, &item);
        if(cbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            /* successful exit from loop */
            break;
        }
        if(cbor_result != QCBOR_SUCCESS) {
            return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
            goto Done;
        }

        if(item.uDataType == QCBOR_TYPE_INT64) {
            if(num_int_labels >= T_COSE_PARAMETER_LIST_MAX) {
                return_value = T_COSE_ERR_CRIT_PARAMETER;
                goto Done;
            }
            critical_labels->int_labels[num_int_labels++] = item.val.int64;
        } else if(item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            if(num_tstr_labels >= T_COSE_PARAMETER_LIST_MAX) {
                return_value = T_COSE_ERR_CRIT_PARAMETER;
                goto Done;
            }
            critical_labels->tstr_labels[num_tstr_labels++] = item.val.string;
        } else {
            return_value = T_COSE_ERR_CRIT_PARAMETER;
            goto Done;
        }
    }

    /* Exit out of array back up to parameters map */
    QCBORDecode_ExitArray(decode_context);

    if(is_label_list_clear(critical_labels)) {
        /* Per RFC 8152 crit parameter can't be empty */
        return_value = T_COSE_ERR_CRIT_PARAMETER;
        goto Done;
    }

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


bool
is_in_list(const struct t_cose_label_list *critical_labels, int64_t label)
{
    for(int num_critical = 0;
        critical_labels->int_labels[num_critical];
        num_critical++) {
        if(critical_labels->int_labels[num_critical] == label) {
            return true;
        }
    }

    return false;
}




/* Critical header cases

 It would be dumb to list a critical header in the list
and actually have the header. If it happens, it is OK and will be ignored.

 Only error out if a header is present, critical and not
 understood.

 If there is no returning of headers to the caller, then
 the crit error must be handled here.

 If there is returning of headers to the caller, then there are
 two options 1) all handling is on the caller or 2) the caller
 tells t_cose which they handled and t_cose errors out. Maybe 3)
 a combo of the two?


  -

 */
static enum t_cose_err_t
decode_parameters_bucket(QCBORDecodeContext   *decode_context,
                         struct header_location   location,
                         bool                  is_protected,
                         t_cose_header_reader  cb,
                         void                 *cb_context,
                         struct header_param_storage  param_storage)
{
    enum t_cose_err_t         return_value;
    struct t_cose_label_list  critical_parameter_labels;

    QCBORDecode_EnterMap(decode_context, NULL);

#if 0
    if(is_protected) {
        // TODO: should there be an error check for crit
        // parameter occuring in an unprotected bucket?
        clear_label_list(&critical_parameter_labels);
        return_value = decode_critical_parameter(decode_context,
                                                &critical_parameter_labels);
    }
#endif

    size_t param_index = 0;
    struct t_cose_header_param *params = param_storage.storage;

    while(1) {
        QCBORItem item;
        QCBORDecode_VPeekNext(decode_context, &item);
        QCBORError err;
        err = QCBORDecode_GetAndResetError(decode_context);
        if(err == QCBOR_ERR_NO_MORE_ITEMS) {
            /* End of list */
            break;
        }

        if(param_index > param_storage.storage_size) {
            return_value = 99; // TODO: error code
            break;
        }

        if(item.uLabelType != T_COSE_PARAMETER_TYPE_INT64) {
            return_value = 88; // TODO: error code
            break;
        }

        bool crit = is_in_list(&critical_parameter_labels, item.label.int64);

        const uint8_t header_type = cbor_type_2_parameter_type(item.uDataType);

        if(header_type != T_COSE_PARAMETER_TYPE_NONE) {
            params->parameter_type = header_type;
            params->location       = location;
            params->label          = item.label.int64;
            params->prot           = is_protected;
            params->critical       = crit;

            switch (item.uDataType) {
                case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                    params->value.string = item.val.string;
                    break;

                case T_COSE_PARAMETER_TYPE_INT64:
                    params->value.i64 = item.val.int64;
                    break;

                case T_COSE_PARAMETER_TYPE_UINT64:
                    params->value.u64 = item.val.uint64;
                    break;

                case T_COSE_PARAMETER_TYPE_BOOL:
                    params->value.b = (item.uDataType == QCBOR_TYPE_TRUE ? true : false);
                    break;
            }

            /* Actually consume it */
            QCBORDecode_GetNext(decode_context, &item);
            params++;

        } else {
            return_value = (cb)(cb_context, decode_context, location, is_protected, crit);
            if(return_value != T_COSE_SUCCESS) {
                break;
            }
        }
    }

    QCBORDecode_ExitMap(decode_context);

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}




enum t_cose_err_t
t_cose_decode_headers(QCBORDecodeContext *decode_context,
                      struct header_location      location,
                      t_cose_header_reader        cb,
                      void                        *cb_context,
                      struct header_param_storage  param_storage,
                      struct q_useful_buf_c       *protected_parameters)
{
    enum t_cose_err_t return_value;

    param_storage.storage[0].parameter_type = T_COSE_PARAMETER_TYPE_NONE;

    /* --- The protected parameters --- */
     QCBORDecode_EnterBstrWrapped(decode_context,
                                  QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                  protected_parameters);

     if(protected_parameters->len) {
         return_value = decode_parameters_bucket(decode_context,
                                           location,
                                           true,
                                           cb, /* TBD callback */
                                           cb_context, /* TBD callback */
                                           param_storage);

         if(return_value != T_COSE_SUCCESS) {
             goto Done;
         }
     }
     QCBORDecode_ExitBstrWrapped(decode_context);

    /* Count the params filled in by protected headers */
    size_t count;
    for(count = 0; param_storage.storage[count].parameter_type != QCBOR_TYPE_NONE; count++);

    param_storage.storage += count;
    param_storage.storage_size -= count;


     /* ---  The unprotected parameters --- */
    return_value = decode_parameters_bucket(decode_context,
                                        location,
                                        false,
                                        cb,
                                        cb_context,
                                        param_storage);

Done:
    return return_value;
}



static enum t_cose_err_t
encode_parameters_bucket(QCBOREncodeContext                *encode_context,
                         const struct t_cose_header_param * const *parameters,
                         bool                               is_protected_header)
{
    const struct t_cose_header_param * const *p1;
    const struct t_cose_header_param         *p2;
    bool                               are_criticals;
    enum t_cose_err_t                  return_value;

    QCBOREncode_OpenMap(encode_context);

    are_criticals = false;
    for(p1 = parameters; *p1 != NULL; p1++) {
        for(p2 = *p1; p2->parameter_type != T_COSE_PARAMETER_TYPE_NONE; p2++) {
            if(is_protected_header) {
                if(!p2->prot) {
                    continue;
                }
            } else {
                if(p2->prot) {
                    continue;
                }
            }

            switch(p2->parameter_type) {
                case T_COSE_PARAMETER_TYPE_INT64:
                    QCBOREncode_AddInt64ToMapN(encode_context, p2->label, p2->value.i64);
                    break;

                case T_COSE_PARAMETER_TYPE_UINT64:
                    QCBOREncode_AddUInt64ToMapN(encode_context, p2->label, p2->value.u64);
                    break;

                case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                    QCBOREncode_AddTextToMapN(encode_context, p2->label, p2->value.string);
                    break;

                case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                    QCBOREncode_AddBytesToMapN(encode_context, p2->label, p2->value.string);
                    break;

                case T_COSE_PARAMETER_TYPE_BOOL:
                    QCBOREncode_AddBoolToMapN(encode_context, p2->label, p2->value.b);
                    break;

                case T_COSE_PARAMETER_TYPE_CALLBACK:
                    (p2->value.writer.call_back)(p2, encode_context);
                    break;

                default:
                    // Caller is asking us to encode a bogus parameter
                    return_value = 99; // TODO: error code
                    goto Done;
            }

            if(p2->critical) {
                are_criticals = true;
            }
        }
    }

    if(is_protected_header && are_criticals) {
        QCBOREncode_OpenArrayInMapN(encode_context, COSE_HEADER_PARAM_CRIT);
        for(p1 = parameters; *p1 != NULL; p1++) {
            for(p2 = *p1; p2->parameter_type != T_COSE_PARAMETER_TYPE_NONE; p2++) {
                if(p2->critical) {
                    QCBOREncode_AddInt64(encode_context, p2->label);
                }
            }
        }
        QCBOREncode_CloseMap(encode_context);
    }

    QCBOREncode_CloseMap(encode_context);

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


enum t_cose_err_t
t_cose_encode_headers(QCBOREncodeContext                *encode_context,
                      const struct t_cose_header_param * const *parameters,
                      struct q_useful_buf_c             *protected_parameters)
{
    enum t_cose_err_t return_value;

    /* --- Protected Headers --- */
    QCBOREncode_BstrWrap(encode_context);
    return_value = encode_parameters_bucket(encode_context,
                                            parameters,
                                            true);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    QCBOREncode_CloseBstrWrap2(encode_context, false, protected_parameters);


    /* --- Unprotected Parameters --- */
    return_value = encode_parameters_bucket(encode_context,
                                            parameters,
                                            false);
    
Done:
    return return_value;
}


const struct t_cose_header_param *
t_cose_find_parameter(const struct t_cose_header_param *p, int64_t label)
{
    while(p->parameter_type != T_COSE_PARAMETER_TYPE_NONE) {
        if(p->label == label) {
            return p;
        }
        p++;
    }

    return NULL;
}


int32_t
t_cose_find_parameter_alg_id(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found = t_cose_find_parameter(p, 1 /* TODO: COSE_HEADER_PARAM_ALG */);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_INT64 &&
       p_found->prot &&
       p_found->value.i64 < INT32_MAX) {
        return (int32_t)p_found->value.i64;
    } else {
        return T_COSE_ALGORITHM_NONE;
    }
}


UsefulBufC
t_cose_find_parameter_kid(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found = t_cose_find_parameter(p, 1 /* TODO: COSE_HEADER_PARAM_KID */);
    if(p_found != NULL && p_found->parameter_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
        // TODO: type check
        return p_found->value.string;
    } else {
        return NULLUsefulBufC;
    }
}
