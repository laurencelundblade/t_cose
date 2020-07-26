/*
 * t_cose_parameters.c
 *
 * Copyright 2019-2020, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose_parameters.h"
#include "t_cose_standard_constants.h"


/**
 * \file t_cose_parameters.c
 *
 * \brief Implementation of the header parsing functions.
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
    /* Stack use 64-bit: 56 + 40 = 96
     *           32-bit: 52 + 20 = 72
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
    if(cbor_result == QCBOR_ERR_NOT_FOUND) {
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
        if(cbor_result != QCBOR_ERR_NO_MORE_ITEMS) {
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
inline enum t_cose_err_t
check_critical_labels(const struct t_cose_label_list *critical_labels,
                      const struct t_cose_label_list *unknown_labels)
{
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
    struct t_cose_parameters *parameters;
    enum t_cose_err_t         return_value;
} ;

/**
 * \brief Add unknown parameter to unknown labels list and fully consume it
 * TODO: doc
 * \param[in] pCallbackCtx       CBOR decode context to read from.
 * \param[in] pItem    The data item for the unknown parameter.
*                                 fetched. Helps to know if at end of list.
 *

 */
static QCBORError header_parameter_callback(void *pCallbackCtx, const QCBORItem *pItem)
{
    enum t_cose_err_t return_value;
    struct cb_context *context = (struct cb_context *)pCallbackCtx;

    if(pItem->uLabelType == QCBOR_TYPE_INT64 && pItem->label.int64 == COSE_HEADER_PARAM_CONTENT_TYPE) {
        struct t_cose_parameters *returned_parameters = context->parameters;

        if(pItem->uDataType == QCBOR_TYPE_TEXT_STRING) {
            if(!q_useful_buf_c_is_null_or_empty(returned_parameters->content_type_tstr)) {
                context->return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
                goto Done;
            }
            returned_parameters->content_type_tstr = pItem->val.string;
        } else if(pItem->uDataType == QCBOR_TYPE_INT64) {
            if(pItem->val.int64 < 0 || pItem->val.int64 > UINT16_MAX) {
                context->return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
                goto Done;
            }
            if(returned_parameters->content_type_uint != T_COSE_EMPTY_UINT_CONTENT_TYPE) {
                context->return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
                goto Done;
            }
            returned_parameters->content_type_uint = (uint32_t)pItem->val.int64;
        } else {
            return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
            goto Done;
        }
    } else {
        context->return_value = add_label_to_list(pItem, context->unknown_labels);
    }
Done:
    return context->return_value == T_COSE_SUCCESS ? QCBOR_SUCCESS : QCBOR_ERR_CALLBACK_FAIL;
}


/**
 * \brief Parse some COSE header parameters.
 *
 * \param[in] decode_context        The QCBOR decode context to read from.
 * \param[out] returned_parameters  The parsed parameters being returned.
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
 * No header parameters are mandatory. Which parameters were present or not
 * is indicated in \c returned_parameters.  It is OK for there to be
 * no parameters at all.
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
    /* Local stack use 64-bit: 5 * 56 + 4 + 2 * 8 = 300
     * Local stack use 32-bit: 5 * 52 + 4 + 2 * 4 = 272
     * Total stack use 64-bit:
     * Total stack use 32-bit:
     */
    enum t_cose_err_t  return_value;
    QCBORError         qcbor_result;
    struct cb_context callback_context = {unknown_labels, parameters};

    QCBORDecode_EnterMap(decode_context);

    /* Get all the non-aggregate headers in one fell swoop
       with QCBORDecode_GetItemsInMap()
     */

#define ALG_INDEX            0
#define KID_INDEX            1
#define IV_INDEX             2
#define PARTIAL_IV_INDEX     3
#define PARTIAL_CONTENT_TYPE 4
#define END_INDEX            5

    QCBORItem header_items[END_INDEX+1];

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

    header_items[PARTIAL_CONTENT_TYPE].label.int64 = COSE_HEADER_PARAM_CONTENT_TYPE;
    header_items[PARTIAL_CONTENT_TYPE].uLabelType  = QCBOR_TYPE_INT64;
    header_items[PARTIAL_CONTENT_TYPE].uDataType   = QCBOR_TYPE_ANY;

    header_items[END_INDEX].uLabelType  = QCBOR_TYPE_NONE;

    /* This call takes care of duplicate detection */
    qcbor_result = QCBORDecode_GetItemsInMapWithCallback(decode_context,
                                                         header_items,
                                                         &callback_context,
                                                         header_parameter_callback);
    if(qcbor_result == QCBOR_ERR_CALLBACK_FAIL) {
        return_value = callback_context.return_value;
        goto Done;
    } else if(qcbor_result != QCBOR_SUCCESS) {
        if(QCBORDecode_IsNotWellFormed(qcbor_result)) {
            return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        } else {
            return_value = T_COSE_ERR_PARAMETER_CBOR;
        }
        goto Done;
    }

    /* The following few clauses copies the parameters out of the QCBORItems
     * retrieved to the returned parameters structure. Duplicate detection
     * between protected and unprotected parameter headers is performed as
     * well as type checking for a few cases
     */

    // TODO: more duplicate detection across protected and unprotected
    
    /* COSE_HEADER_PARAM_ALG */
    if(header_items[ALG_INDEX].uDataType != QCBOR_TYPE_NONE) {
        if(critical_labels == NULL) {
            /* Algorithm parameter must be protected */
            return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
            goto Done;
        }
        if(header_items[ALG_INDEX].val.int64 == COSE_ALGORITHM_RESERVED || header_items[ALG_INDEX].val.int64 > INT32_MAX) {
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
    if(header_items[PARTIAL_CONTENT_TYPE].uDataType == QCBOR_TYPE_TEXT_STRING) {
        if(!q_useful_buf_c_is_null_or_empty(parameters->content_type_tstr)) {
            return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
            goto Done;
        }
        parameters->content_type_tstr = header_items[PARTIAL_CONTENT_TYPE].val.string;
    } else if(header_items[PARTIAL_CONTENT_TYPE].uDataType == QCBOR_TYPE_INT64) {
        if(header_items[PARTIAL_CONTENT_TYPE].val.int64 < 0 ||
           header_items[PARTIAL_CONTENT_TYPE].val.int64 > UINT16_MAX) {
            return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
            goto Done;
        }
        if(parameters->content_type_uint != T_COSE_EMPTY_UINT_CONTENT_TYPE) {
            return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
            goto Done;
        }
        parameters->content_type_uint = (uint32_t)header_items[PARTIAL_CONTENT_TYPE].val.int64;
    } else if(header_items[PARTIAL_CONTENT_TYPE].uDataType != QCBOR_TYPE_NONE) {
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
