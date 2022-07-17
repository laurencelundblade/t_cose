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


/**
 * \brief Add a new label to the end of the label list.
 *
 * \param[in] item             Data item to add to the label list.
 * \param[in,out] label_list   The list to add to.
 *
 * \retval T_COSE_SUCCESS                  If added correctly.
 * \retval T_COSE_ERR_TOO_MANY_PARAMETERS  Label list is full.
 * \retval T_COSE_ERR_PARAMETER_CBOR       The item to add doesn't have a label
 *                                         type that is understood
 *
 * The label / key from \c item is added to \c label_list.
 */
static inline enum t_cose_err_t
add_label_to_list(const QCBORItem *item, struct t_cose_label_list *label_list)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    16           8
     *   TOTAL                                         16           8
     */
    /* Stack use: 16 bytes for 64-bit */
    enum t_cose_err_t return_value;
    uint_fast8_t      n;

    /* Assume success until an error adding is encountered. */
    return_value = T_COSE_SUCCESS;

    if(item->uLabelType == QCBOR_TYPE_INT64) {
        /* Add an integer-labeled parameter to the end of the list */
        for(n = 0; label_list->int_labels[n] != LABEL_LIST_TERMINATOR; n++);
        if(n == T_COSE_PARAMETER_LIST_MAX) {
            /* List is full -- error out */
            return_value = T_COSE_ERR_TOO_MANY_PARAMETERS;
            goto Done;
        }
        label_list->int_labels[n] = item->label.int64;

    } else if(item->uLabelType == QCBOR_TYPE_TEXT_STRING) {
        /* Add a string-labeled parameter to the end of the list */
        for(n = 0; !q_useful_buf_c_is_null(label_list->tstr_labels[n]); n++);
        if(n == T_COSE_PARAMETER_LIST_MAX) {
            /* List is full -- error out */
            return_value = T_COSE_ERR_TOO_MANY_PARAMETERS;
            goto Done;
        }
        label_list->tstr_labels[n] = item->label.string;

    } else {
        /* error because label is neither integer or string */
        /* Should never occur because this is caught earlier, but
         * leave it to be safe and because inlining and optimization
         * should take out any unneeded code
         */
        return_value = T_COSE_ERR_PARAMETER_CBOR;
    }

Done:
    return return_value;
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


static bool
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

    if(critical_labels == NULL) {
        /* crit parameter occuring in non-protected bucket */
        return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
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


/**
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
check_critical_labels(const struct t_cose_label_list *critical_labels,
                      const struct t_cose_label_list *unknown_labels)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    24          12
     *   TOTAL                                         24          12
     */
    enum t_cose_err_t return_value;
    uint_fast8_t      num_unknown;
    uint_fast8_t      num_critical;

    /* Assume success until an unhandled critical label is found */
    return_value = T_COSE_SUCCESS;

    /* Iterate over unknown integer parameters */
    for(num_unknown = 0; unknown_labels->int_labels[num_unknown]; num_unknown++) {
        /* Iterate over critical int labels looking for the unknown label */
        for(num_critical = 0;
            critical_labels->int_labels[num_critical];
            num_critical++) {
            if(critical_labels->int_labels[num_critical] == unknown_labels->int_labels[num_unknown]) {
                /* Found a critical label that is unknown to us */
                return_value = T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
                goto Done;
            }
        }
        /* Exit from loop here means all no unknown label was critical */
    }

    /* Iterate over unknown string labels */
    for(num_unknown = 0; !q_useful_buf_c_is_null(unknown_labels->tstr_labels[num_unknown]); num_unknown++) {
        /* iterate over critical string labels looking for the unknown param */
        for(num_critical = 0; !q_useful_buf_c_is_null(critical_labels->tstr_labels[num_critical]); num_critical++) {
            if(!q_useful_buf_compare(critical_labels->tstr_labels[num_critical],
                                     unknown_labels->tstr_labels[num_unknown])){
                /* Found a critical label that is unknown to us */
                return_value = T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
                goto Done;
            }
        }
        /* Exit from loop here means all no unknown label was critical */
    }

Done:
    return return_value;
}


struct cb_context {
    struct t_cose_label_list *unknown_labels;
    enum t_cose_err_t         return_value;
};

/**
 * \brief Add unknown parameter to unknown labels list
 *
 * \param[in] pCallbackCtx   Callback context.
 * \param[in] pItem          The data item for the unknown parameter.
 *
 * \returns On failure to add to the list (because it is full) this returns
 *          \ref QCBOR_ERR_CALLBACK_FAIL to signal an error in traversal.
 *          The error details is in \c context->return_value.
 *
 * This gets called through QCBORDecode_GetItemsInMapWithCallback() on
 * any parameter that is not recognized. (Maybe someday this will call
 * out further to allow t_cose to handle custom parameters).
 */
static QCBORError header_parameter_callback(void *pCallbackCtx, const QCBORItem *pItem)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    16          8
     *   TOTAL                                         16          8
     */
    struct cb_context *context = (struct cb_context *)pCallbackCtx;
    enum t_cose_err_t result;

    if(pItem->uLabelType == QCBOR_TYPE_INT64 &&
        pItem->label.int64 == COSE_HEADER_PARAM_CRIT) {
           /* header parameters that are not processed through the
            * call to QCBORDecode_GetItemsInMapWithCallback show up
            * here, but are not unknown header parameters. There is
            * only one: COSE_HEADER_PARAM_CRIT
            */
           result = T_COSE_SUCCESS;
    } else {
        /* Add an unknown header parameter to the list or unknowns */
        result = add_label_to_list(pItem, context->unknown_labels);
    }

    context->return_value = result;

    if(result == T_COSE_SUCCESS) {
        return QCBOR_SUCCESS;
    } else {
        return QCBOR_ERR_CALLBACK_FAIL;
    }
}


/**
 * \brief Parse some COSE header parameters.
 *
 * \param[in] decode_context        The QCBOR decode context to read from.
 * \param[out] parameters           The parsed parameters being returned.
 * \param[out] critical_labels      The parsed list of critical labels if
 *                                  parameter is present.
 * \param[out] unknown_labels       The list of labels that were not recognized.
 *
 * \retval T_COSE_SUCCESS                     The parameters were decoded
 *                                            correctly.
 * \retval T_COSE_ERR_PARAMETER_CBOR          CBOR is parsable, but not the
 *                                            right structure (e.g. array
 *                                            instead of a map)
 * \retval T_COSE_ERR_TOO_MANY_PARAMETERS     More than
 *                                            \ref T_COSE_PARAMETER_LIST_MAX
 *                                            parameters.
 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED    The CBOR is not parsable.
 * \retval T_COSE_ERR_NON_INTEGER_ALG_ID      The algorithm ID is not an
 *                                            integer. This implementation
 *                                            doesn't support string algorithm
 *                                            IDs.
 * \retval T_COSE_ERR_BAD_CONTENT_TYPE        Error in content type parameter.
 * \retval T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER   A label marked critical is
 *                                                 present and not understood.
 *
 * No header parameters are mandatory. Which parameters were present
 * or not is indicated in \c returned_parameters.  It is OK for there
 * to be no parameters at all.
 *
 * The first item to be read from the decode_context must be the map
 * data item that contains the parameters.
 */
enum t_cose_err_t
parse_cose_header_parameters(QCBORDecodeContext        *decode_context,
                             struct t_cose_parameters  *parameters,
                             struct t_cose_label_list  *critical_labels,
                             struct t_cose_label_list  *unknown_labels)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    32          16
     *   header_items                                 336         312
     *   MAX (GetItemsInMapWithCallback+CB 432  316
     *        decode_critical               88   68)  432         316
     *   TOTAL                                        768         628
     */
    enum t_cose_err_t  return_value;
    QCBORError         qcbor_result;
    struct cb_context  callback_context = {unknown_labels, 0};

    /* Get all the non-aggregate headers in one fell swoop with
     * QCBORDecode_GetItemsInMapWithCallback().
     */
#define ALG_INDEX            0
#define KID_INDEX            1
#define IV_INDEX             2
#define PARTIAL_IV_INDEX     3
#define CONTENT_TYPE         4
#define END_INDEX            5
    QCBORItem         header_items[END_INDEX+1];

    QCBORDecode_EnterMap(decode_context, NULL);

    header_items[ALG_INDEX].label.int64 = COSE_HEADER_PARAM_ALG;
    header_items[ALG_INDEX].uLabelType  = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType   = QCBOR_TYPE_INT64;

    header_items[KID_INDEX].label.int64 = COSE_HEADER_PARAM_KID;
    header_items[KID_INDEX].uLabelType  = QCBOR_TYPE_INT64;
    header_items[KID_INDEX].uDataType   = QCBOR_TYPE_BYTE_STRING;

    header_items[IV_INDEX].label.int64 = COSE_HEADER_PARAM_IV;
    header_items[IV_INDEX].uLabelType  = QCBOR_TYPE_INT64;
    header_items[IV_INDEX].uDataType   = QCBOR_TYPE_BYTE_STRING;

    header_items[PARTIAL_IV_INDEX].label.int64 = COSE_HEADER_PARAM_PARTIAL_IV;
    header_items[PARTIAL_IV_INDEX].uLabelType  = QCBOR_TYPE_INT64;
    header_items[PARTIAL_IV_INDEX].uDataType   = QCBOR_TYPE_BYTE_STRING;

    header_items[CONTENT_TYPE].label.int64 = COSE_HEADER_PARAM_CONTENT_TYPE;
    header_items[CONTENT_TYPE].uLabelType  = QCBOR_TYPE_INT64;
    header_items[CONTENT_TYPE].uDataType   = QCBOR_TYPE_ANY;

    header_items[END_INDEX].uLabelType  = QCBOR_TYPE_NONE;

    /* This call takes care of duplicate detection in the map itself.
     *
     * COSE has the notion of critical parameters that can't be
     * ignored, so the callback has to be set up to catch items in
     * this map that are not handled by code here.
     */
    QCBORDecode_GetItemsInMapWithCallback(decode_context,
                                          header_items,
                                          &callback_context,
                                          header_parameter_callback);
    qcbor_result = QCBORDecode_GetError(decode_context);
    if(qcbor_result == QCBOR_ERR_CALLBACK_FAIL) {
        return_value = callback_context.return_value;
        goto Done;
    } else if(qcbor_result != QCBOR_SUCCESS) {
        if(QCBORDecode_IsNotWellFormedError(qcbor_result)) {
            return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        } else {
            return_value = T_COSE_ERR_PARAMETER_CBOR;
        }
        goto Done;
    }

    /* The following few clauses copy the parameters out of the
     * QCBORItems retrieved into the returned parameters
     * structure.
     *
     * Duplicate detection between protected and unprotected parameter
     * headers is performed by erroring out if a parameter has already
     * been filled in.
     *
     * Much of the type checking was performed by
     * QCBORDecode_GetItemsInMapWithCallback() but not all so the rest
     * is done here.
     */

    /* COSE_HEADER_PARAM_ALG */
    if(header_items[ALG_INDEX].uDataType != QCBOR_TYPE_NONE) {
        if(critical_labels == NULL) {
            /* Algorithm parameter must be protected */
            return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
            goto Done;
        }
        if(header_items[ALG_INDEX].val.int64 == COSE_ALGORITHM_RESERVED ||
           header_items[ALG_INDEX].val.int64 > INT32_MAX) {
            return_value = T_COSE_ERR_NON_INTEGER_ALG_ID;
            goto Done;
        }
        parameters->cose_algorithm_id = (int32_t)header_items[ALG_INDEX].val.int64;
    }

    /* COSE_HEADER_PARAM_KID */
    if(header_items[KID_INDEX].uDataType != QCBOR_TYPE_NONE) {
        if(q_useful_buf_c_is_null(parameters->kid)) {
            parameters->kid = header_items[KID_INDEX].val.string;
        } else {
            return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
            goto Done;
        }
    }

    /* COSE_HEADER_PARAM_IV */
    if(header_items[IV_INDEX].uDataType != QCBOR_TYPE_NONE) {
        if(q_useful_buf_c_is_null(parameters->iv)) {
            parameters->iv = header_items[IV_INDEX].val.string;
        } else {
            return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
            goto Done;
        }
    }

    /* COSE_HEADER_PARAM_PARTIAL_IV */
    if(header_items[PARTIAL_IV_INDEX].uDataType != QCBOR_TYPE_NONE) {
        if(q_useful_buf_c_is_null(parameters->partial_iv)) {
            parameters->partial_iv = header_items[PARTIAL_IV_INDEX].val.string;
        } else {
            return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
            goto Done;
        }
    }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /* COSE_HEADER_PARAM_CONTENT_TYPE */
    if(header_items[CONTENT_TYPE].uDataType == QCBOR_TYPE_TEXT_STRING) {
        if(!q_useful_buf_c_is_null_or_empty(parameters->content_type_tstr)) {
            return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
            goto Done;
        }
        parameters->content_type_tstr = header_items[CONTENT_TYPE].val.string;
    } else if(header_items[CONTENT_TYPE].uDataType == QCBOR_TYPE_INT64) {
        if(header_items[CONTENT_TYPE].val.int64 < 0 ||
           header_items[CONTENT_TYPE].val.int64 > UINT16_MAX) {
            return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
            goto Done;
        }
        if(parameters->content_type_uint != T_COSE_EMPTY_UINT_CONTENT_TYPE) {
            return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
            goto Done;
        }
        parameters->content_type_uint = (uint32_t)header_items[CONTENT_TYPE].val.int64;
    } else if(header_items[CONTENT_TYPE].uDataType != QCBOR_TYPE_NONE) {
        return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
        goto Done;
    }
#endif

    /* COSE_HEADER_PARAM_CRIT */
    return_value = decode_critical_parameter(decode_context, critical_labels);

    QCBORDecode_ExitMap(decode_context);

Done:
    return return_value;
}



static void
encode_crit_parameter(QCBOREncodeContext                      *encode_context,
                      const struct t_cose_header_param *const *parameters)
{
    const struct t_cose_header_param *const *p1;
    const struct t_cose_header_param        *p2;

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





static inline uint8_t
cbor_type_to_parameter_type(uint8_t qcbor_data_type)
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



static enum t_cose_err_t
decode_parameters_bucket(QCBORDecodeContext         *decode_context,
                         struct header_location      location,
                         bool                        is_protected,
                         t_cose_header_reader       *cb,
                         void                       *cb_context,
                         struct header_param_storage param_storage)
{
    enum t_cose_err_t         return_value;
    struct t_cose_label_list  critical_parameter_labels;

    clear_label_list(&critical_parameter_labels);
    QCBORDecode_EnterMap(decode_context, NULL);

#ifdef CRIT_PARAM_FIXED
    /* TODO: There is a bug in QCBOR where mixing of get by
     * label and traversal don't work together right.
     * When it is fixed, this code can be re enabled.
     * For now there is no decoding of crit.
     */
    if(is_protected) {
        // TODO: should there be an error check for crit
        // parameter occuring in an unprotected bucket?
        clear_label_list(&critical_parameter_labels);
        return_value = decode_critical_parameter(decode_context,
                                                &critical_parameter_labels);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }
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
            return_value = T_COSE_ERR_INSUFFICIENT_SPACE_FOR_PARAMETERS;
            break;
        }

        if(item.uLabelType != T_COSE_PARAMETER_TYPE_INT64) {
            return_value = 88; // TODO: error code
            break;
        }

        bool crit = is_in_list(&critical_parameter_labels, item.label.int64);

        const uint8_t header_type = cbor_type_to_parameter_type(item.uDataType);

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

        } else if (item.label.int64 == COSE_HEADER_PARAM_CRIT) {
            /* ignore crit param because it was already processed .*/
            continue;

        } else {
            // TODO: an option to ignore non-critical parameters
            // that are not understood?
            if(cb == NULL) {
                return_value = T_COSE_ERR_UNHANDLED_HEADER_PARAMETER;
                goto Done;
            }
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


/*
* Public function. See t_cose_parameters.h
*/
enum t_cose_err_t
t_cose_ignore_param_cb(void *cb,
                       QCBORDecodeContext *decode_context,
                       struct header_location location,
                       bool is_protected,
                       bool is_crit)
{
    (void)cb;
    (void)decode_context;
    (void)location;
    (void)is_protected;
    /* If the caller wants to ignore critical parameters, they
     * have to do the work to implement there own function. */
    return is_crit ? T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER : T_COSE_SUCCESS;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext          *decode_context,
                      struct header_location       location,
                      t_cose_header_reader        *cb,
                      void                        *cb_context,
                      struct header_param_storage  param_storage,
                      struct q_useful_buf_c       *protected_parameters)
{
    enum t_cose_err_t return_value;
    size_t            count;

    param_storage.storage[0].parameter_type = T_COSE_PARAMETER_TYPE_NONE;

    /* --- The protected parameters --- */
     QCBORDecode_EnterBstrWrapped(decode_context,
                                  QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                  protected_parameters);

     if(protected_parameters->len) {
         return_value = decode_parameters_bucket(decode_context,
                                                 location,
                                                 true,
                                                 cb,
                                                 cb_context,
                                                 param_storage);

         if(return_value != T_COSE_SUCCESS) {
             goto Done;
         }
     }
     QCBORDecode_ExitBstrWrapped(decode_context);

    /* Count the params filled in by protected headers */
    for(count = 0; param_storage.storage[count].parameter_type != QCBOR_TYPE_NONE; count++);

    param_storage.storage      += count;
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
encode_parameters_bucket(QCBOREncodeContext                       *encode_context,
                         const struct t_cose_header_param * const *parameters,
                         bool                                      is_protected_header)
{
    const struct t_cose_header_param * const *p1;
    const struct t_cose_header_param         *p2;
    bool                                      are_criticals;
    enum t_cose_err_t                         return_value;

    /* Protected and unprotected parameters are a map of label/value pairs */
    QCBOREncode_OpenMap(encode_context);

    are_criticals = false;
    /* Loop over vector of pointers to arrays */
    for(p1 = parameters; *p1 != NULL; p1++) {

        /* loop over array of parameters */
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
                    /* Intentionally no check for NULL callback pointer to
                     * save a little object code. Caller should never
                     * indicate a callback without supplying the pointer
                     */
                    return_value = (p2->value.writer.call_back)(p2, encode_context);
                    if(return_value != T_COSE_SUCCESS) {
                        goto Done;
                    }
                    break;

                default:
                    return_value = T_COSE_ERR_INVALID_PARAMETER_TYPE;
                    goto Done;
            }

            if(p2->critical) {
                are_criticals = true;
            }
        }
    }

    if(are_criticals) {
        if(is_protected_header) {
            encode_crit_parameter(encode_context, parameters);
        } else {
            /* Asking for critical parameters unprotected header bucket */
            return_value = T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED;
            goto Done;
        }
    }

    QCBOREncode_CloseMap(encode_context);

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_encode_headers(QCBOREncodeContext                       *encode_context,
                      const struct t_cose_header_param * const *parameters,
                      struct q_useful_buf_c                    *protected_parameters)
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


/*
 * Public function. See t_cose_parameters.h
 */
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


/*
 * Public function. See t_cose_parameters.h
 */
int32_t
t_cose_find_parameter_alg_id(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_ALG);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_INT64 &&
       p_found->prot &&
       p_found->value.i64 < INT32_MAX) {
        return (int32_t)p_found->value.i64;
    } else {
        return T_COSE_ALGORITHM_NONE;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
UsefulBufC
t_cose_find_parameter_kid(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_KID );
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
        return p_found->value.string;
    } else {
        return NULLUsefulBufC;
    }
}
