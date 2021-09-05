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


/**
 * The size of the output of SHA-256.
 *
 * (It is safe to define these independently here as they are
 * well-known and fixed. There is no need to reference
 * platform-specific headers and incur messy dependence.)
 */
#define T_COSE_CRYPTO_SHA256_SIZE 32

/**
 * The size of the output of SHA-384 in bytes.
 */
#define T_COSE_CRYPTO_SHA384_SIZE 48

/**
 * The size of the output of SHA-512 in bytes.
 */
#define T_COSE_CRYPTO_SHA512_SIZE 64


/**
 * The maximum needed to hold a hash. It is smaller and less stack is needed
 * if the larger hashes are disabled.
 */
#ifndef T_COSE_DISABLE_ES512
    #define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA512_SIZE
#else
    #ifndef T_COSE_DISABLE_ES384
        #define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA384_SIZE
    #else
        #define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA256_SIZE
    #endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_CRYPTO_PUBLIC_H__ */
