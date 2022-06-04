/*
 * t_cose_openssl_crypto.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

/**
 * \file t_cose_openssl_crypto.h
 *
 * \brief Public interface of the openssl Crypto adapter
 *
 */

#ifndef __T_COSE_OPENSSL_CRYPTO_H__
#define __T_COSE_OPENSSL_CRYPTO_H__

#include "openssl/evp.h"

#include "t_cose/t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct t_cose_openssl_crypto_context {
    EVP_MD_CTX  *evp_ctx;
    int          update_error; /* Used to track error return by SHAXXX_Update() */
    int32_t      cose_hash_alg_id; /* COSE integer ID for the hash alg */
};

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_OPENSSL_CRYPTO_H__ */