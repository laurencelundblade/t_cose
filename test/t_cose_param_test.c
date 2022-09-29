//
//  t_cose_param_test.c
//  t_cose_test
//
//  Created by Laurence Lundblade on 9/20/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose_param_test.h"

#include "t_cose/t_cose_parameters.h"

#include <limits.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "UsefulBuf.h"


/* Param with label 44 carries a single float. This test
 * encodes the value of 3.14 and expects that when decoding
 */
static enum t_cose_err_t
encode_44(const struct t_cose_parameter  *param,
          QCBOREncodeContext                *qcbor_encoder)
{
    QCBOREncode_AddDoubleToMapN(qcbor_encoder, param->label,  3.14);
    return T_COSE_SUCCESS;
}

enum t_cose_err_t
decode_44(void                       *call_back_context,
          QCBORDecodeContext         *qcbor_decoder,
          struct t_cose_parameter *p)
{
    double  d;

    QCBORDecode_GetDouble(qcbor_decoder, &d);
    // Stuff the double into the little buf
    // because that's what we're doing for label 44 floats.
    memcpy(p->value.little_buf, &d, sizeof(d));
    p->value_type = T_COSE_PARAMETER_TYPE_LITTLE_BUF;
    return T_COSE_SUCCESS;
}

int32_t
check_44(struct t_cose_parameter *param)
{
    if(param->label != 44) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_LITTLE_BUF) {
        return 2;
    }
    /* Have to have some comparision function in the test case. */
    double d;
    memcpy(&d, param->value.little_buf, sizeof(d));

    if(d != 3.14) {
        return 3;
    }

    return 0;
}



static enum t_cose_err_t
header_writer(const struct t_cose_parameter  *param,
              QCBOREncodeContext             *qcbor_encoder)
{
    switch(param->label) {
        case 44:
            return encode_44(param, qcbor_encoder);

        case 55:
            /* The point of this one is to fail */
            return T_COSE_ERR_FAIL;

        case 66:
            /* Intentionally don't close the map */
            QCBOREncode_OpenMapInMapN(qcbor_encoder, param->label);
            return T_COSE_SUCCESS;

        default:
            return T_COSE_ERR_FAIL;
    }
}



enum t_cose_err_t
header_reader(void                   *call_back_context,
                     QCBORDecodeContext     *qcbor_decoder,
                     struct t_cose_parameter *param)
{
    switch(param->label) {
        case 44:
            return decode_44(call_back_context, qcbor_decoder, param);

        default:
            return T_COSE_ERR_FAIL;
    }
}




struct param_test {
    struct q_useful_buf_c       encoded;
    struct t_cose_parameter  unencoded;
    enum t_cose_err_t           encode_result;
    enum t_cose_err_t           decode_result;
    int32_t                     (*check_cb)(struct t_cose_parameter *param);
    QCBORError                  qcbor_encode_result;

};


static const uint8_t x1[] = {0x50, 0xA2, 0x18, 0x2C, 0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F, 0x02, 0x81, 0x18, 0x2C, 0xA0};

static const uint8_t x2[] = {0x41, 0xA0, 0xA1, 0x18, 0x21, 0x43, 0x01, 0x02, 0x03};

static const uint8_t b1[] = {0x01, 0x02, 0x03};

static const uint8_t x3[] = {0x47, 0xA1, 0x0B, 0x3A, 0x7F, 0xFF, 0xFF, 0xFF, 0xA0};

#define UBX(x) {x, sizeof(x)}


static const struct param_test param_tests[] = {
    /* 0. Critical, protected floating point parameter made by call back. */
    {
        UBX(x1),
        {44, true, true, {0,0}, T_COSE_PARAMETER_TYPE_CALLBACK, .value.custom_encoder = {NULL, header_writer} },
        T_COSE_SUCCESS,
        T_COSE_SUCCESS,
        check_44,
        QCBOR_SUCCESS
    },

    /* 1. Simple unprotected byte string parameter. */
    {
        UBX(x2),
        {33, false, false, {0,0}, T_COSE_PARAMETER_TYPE_BYTE_STRING,
            .value.string = UBX(b1)},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        NULL,
        QCBOR_SUCCESS
    },

    /* 2. Trying to make a parameter of an unknown type. */
    {
        {x2, 0}, // Unused
        {22, false, false, {0,0}, 200 /* Unknown type */, .value.i64 = 11},
        T_COSE_ERR_INVALID_PARAMETER_TYPE,
        0,
        NULL,
        QCBOR_SUCCESS
    },


    /* 3. A protected negative integer parameter. */
    {
        UBX(x3), /* CBOR encoded header params */
        {11, true, false, {0,0}, T_COSE_PARAMETER_TYPE_INT64, .value.i64 = INT32_MIN},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 4. Attempt to encode a critical unprotected parameter. */
    {
        {x2, 0}, // Unused
        {101, false, true, {0,0}, T_COSE_PARAMETER_TYPE_INT64, .value.i64 = INT32_MIN},
        T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED, /* Expected encode result */
        0, /* Expected decode result */
        NULL, /* Call back for decode check */
        0 /* Expected CBOR encode result */
    },

    /* 5. Encoder callback returns an error. */
    {
        {x2, 0}, // Unused
        {55, true, true, {0,0}, T_COSE_PARAMETER_TYPE_CALLBACK, .value.custom_encoder = {NULL, header_writer} },
        T_COSE_ERR_FAIL, /* Expected encode result */
        0, /* Expected decode result */
        NULL, /* Call back for decode check */
        0 /* Expected CBOR encode result */
    },

    /* 6. Encoder callback produces invalid CBOR. */
    {
        {x2, 0}, // Unused
        {66, true, true, {0,0}, T_COSE_PARAMETER_TYPE_CALLBACK, .value.custom_encoder = {NULL, header_writer} },
        T_COSE_SUCCESS, /* Expected encode result */
        0, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN /* Expected CBOR encode result */
    },

    /* */
    {
        NULL_Q_USEFUL_BUF_C
    }

};


struct param_test_combo {
    struct q_useful_buf_c  encoded;
    int                   *combo_list; // Index into param_tests. Terminated by MAX_INT
    enum t_cose_err_t      header_encode_result;
    QCBORError             qcbor_encode_result;
};

static  struct param_test_combo xx[] = {
    /* 0. Encode duplicate parameters */
    {
        UBX(x2),
        (int []){0, 0, INT_MAX},
        T_COSE_ERR_DUPLICATE_PARAMETER,
        QCBOR_SUCCESS,
    },
    {
        NULL_Q_USEFUL_BUF_C,
        NULL
    }
};









int_fast32_t
param_test(void)
{
    struct t_cose_parameter p[20];
    const struct t_cose_parameter *vector[20]; // TODO: manage this
    struct q_useful_buf_c  output;
    enum t_cose_err_t      t_cose_result;
    QCBORError q;
    QCBOREncodeContext         qcbor_encoder;
    MakeUsefulBufOnStack(      B,    200);

    const struct param_test *p_test;

    /* The single parameter tests */
    for(int i = 0; ; i++) {
        p_test = &param_tests[i];
        if(q_useful_buf_c_is_null(p_test->encoded)) {
            break;
        }

        if(i == 6) {
            t_cose_result = 0; // Exists just for a break point for a test number
        }

        /* Encode test */
        p[0] = p_test->unencoded;
        p[1].value_type = T_COSE_PARAMETER_TYPE_NONE;
        vector[0] = p;
        vector[1] = NULL;
        QCBOREncode_Init(&qcbor_encoder, B);
        t_cose_result = t_cose_encode_headers(&qcbor_encoder,
                                              vector,
                                              NULL);

        if(t_cose_result != p_test->encode_result) {
            return i * 1000 + 1;
        }

        if(t_cose_result == T_COSE_SUCCESS) {
            q = QCBOREncode_Finish(&qcbor_encoder, &output);
            if(q != p_test->qcbor_encode_result) {
                return i * 1000 + 6;
            }

            if(q == QCBOR_SUCCESS) {
                if(q_useful_buf_compare(output, p_test->encoded)) {
                    return i * 1000 + 2;
                }
            }
        }

        /* Decode test */
        if(!q_useful_buf_c_is_empty(p_test->encoded)) {
            struct t_cose_parameter_storage ll;

            ll.storage_size = sizeof(p);
            ll.storage = p;
            p[0].value_type = T_COSE_PARAMETER_TYPE_NONE;

            QCBORDecodeContext decode_context;

            QCBORDecode_Init(&decode_context, p_test->encoded, 0);

            struct q_useful_buf_c p_p;

            t_cose_result = t_cose_headers_decode(&decode_context,
                                                  (struct header_location){0,0},
                                                  header_reader, NULL,
                                                  ll,
                                                 &p_p);

            if(t_cose_result != p_test->decode_result) {
                return i * 1000 + 3;
            }

            struct t_cose_parameter decoded = ll.storage[0];

            if(p_test->check_cb) {
                int32_t r;
                r = p_test->check_cb(&decoded);
                if(r) {
                    return i * 1000 + 10 + r;
                }
            } else {
                if(decoded.value_type != p_test->unencoded.value_type) {
                    return i * 1000;
                }
                switch(decoded.value_type) {
                    case T_COSE_PARAMETER_TYPE_INT64:
                        if(decoded.value.i64 != p_test->unencoded.value.i64) {
                            return i * 1000;
                        }
                        break;

                    case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                    case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                        if(q_useful_buf_compare(decoded.value.string, p_test->unencoded.value.string)) {
                            return i * 1000;
                        }
                        break;
                }
            }
        }
    }

    /* The multiple parameter tests */

    for(int i = 0; ; i++) {
        struct param_test_combo *ppp = &xx[i];

        if(ppp->combo_list == NULL) {
            break;
        }

        int j;
        for(j = 0; ppp->combo_list[j] != INT_MAX; j++) {
            p[j] = param_tests[ppp->combo_list[j]].unencoded;
        }
        p[j].value_type = T_COSE_PARAMETER_TYPE_NONE;
        vector[0] = p;
        vector[1] = NULL;


        QCBOREncode_Init(&qcbor_encoder, B);
        t_cose_result = t_cose_encode_headers(&qcbor_encoder,
                                              vector,
                                              NULL);

        if(t_cose_result != ppp->header_encode_result) {
            return i * 1000 + 1;
        }

        q = QCBOREncode_Finish(&qcbor_encoder, &output);
        if(q != ppp->qcbor_encode_result) {
            return i * 1000 + 1;
        }

        if(t_cose_result == T_COSE_SUCCESS && q == QCBOR_SUCCESS) {
            if(q_useful_buf_compare(output, ppp->encoded)) {
                return i * 1000 + 2;
            }
        }
    }

    (void)param_tests;

    return 0;
}
