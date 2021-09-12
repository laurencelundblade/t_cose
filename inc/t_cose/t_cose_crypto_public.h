/*
 * t_cose_crypto_public.h
 *
 * Copyright 2019, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#ifndef __T_COSE_CRYPTO_PUBLIC_H__
#define __T_COSE_CRYPTO_PUBLIC_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The context for use by crypto backends. Its content is crypto backend
 * specific.
 */
struct t_cose_crypto_backend_ctx {
#ifdef T_COSE_USE_MBEDTLS_CRYPTO
    uint32_t unused; /* To prevent empty structure warning */

#elif defined (T_COSE_USE_PSA_CRYPTO)
    uint32_t unused; /* To prevent empty structure warning */

#elif defined(T_COSE_USE_OPENSSL_CRYPTO)
    uint32_t unused; /* To prevent empty structure warning */

#else
    uint32_t unused; /* To prevent empty structure warning */

#endif /* T_COSE_USE_MBEDTLS_CRYPTO */
};


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_CRYPTO_PUBLIC_H__ */
