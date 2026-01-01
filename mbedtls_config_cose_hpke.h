/* Minimal PSA-first config for COSE HPKE on Mbed TLS 3.6.5 */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* Platform basics */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
//#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS /* drop if you want stdalloc */
//#define MBEDTLS_MEMORY_BUFFER_ALLOC_C     /* or remove if using system alloc */

/* Randomness */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
/* If your platform lacks a TRNG, keep default entropy sources or add your own. */

/* PSA Crypto core */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CONFIG         /* use psa/crypto_config.h to slim algs */
//#define MBEDTLS_PSA_CRYPTO_STORAGE_C      /* needed for persistent keys; drop if not */
//#define MBEDTLS_PSA_ITS_FILE_C            /* file-based ITS backend */
//#define MBEDTLS_PSA_CRYPTO_DRIVERS        /* keep if you might use HW drivers */

/* Hash / KDF */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C                  /* drop if HPKE suites only need SHA-256 */
#define MBEDTLS_HKDF_C

#define MBEDTLS_NIST_KW_C   /* AES Key Wrap (RFC 3394/5649) */

/* AEADs for HPKE */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CCM_C                     /* optional; drop if not used */
#define MBEDTLS_CIPHER_C                  /* glue for PSA <-> cipher layer */

#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/* EC for KEM (P-256 / X25519) */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_CURVE448_ENABLED

/*
 * PSA algorithms and key types are controlled via psa/crypto_config.h when
 * MBEDTLS_PSA_CRYPTO_CONFIG is set. Do not redefine MBEDTLS_PSA_BUILTIN_* here
 * to avoid clashes with config_adjust_legacy_from_psa.h.
 */

/* Optional: trim bignum/certs/SSL entirely */
//#define MBEDTLS_NO_PLATFORM_ENTROPY /* if you inject your own entropy source */
/* Intentionally NOT enabling:
   MBEDTLS_SSL_*, MBEDTLS_X509_*, MBEDTLS_PK_C, MBEDTLS_RSA_C, etc.
*/
//crypto_config_custom.h

#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "psa/crypto_config.h"


#endif /* MBEDTLS_CONFIG_H */
