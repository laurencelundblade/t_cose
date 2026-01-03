/* hpke_cli.c
 *
 * COSE HPKE encrypt/decrypt CLI using t_cose + QCBOR + PSA Crypto.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "psa/crypto.h"

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_recipient_enc_hpke.h"
#include "t_cose/t_cose_recipient_dec_hpke.h"
#include "t_cose/t_cose_sign_sign.h"
#include "t_cose/t_cose_signature_sign_main.h"
#include "t_cose/t_cose_key.h"
#include "hpke.h"
#include "t_cose_util.h"

/* PSA adapter include path differs across t_cose versions */
#if defined(__has_include)
#  if __has_include("t_cose/crypto_adapters/t_cose_psa_crypto.h")
#    include "t_cose/crypto_adapters/t_cose_psa_crypto.h"
#  elif __has_include("t_cose/t_cose_psa_crypto.h")
#    include "t_cose/t_cose_psa_crypto.h"
#  endif
#endif

#include "qcbor/qcbor.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

/* ============================================================
 * COSE_Key parsing for ECC (EC2 / OKP)
 * ============================================================ */

#define COSE_KEY_LABEL_KTY   1
#define COSE_KEY_LABEL_KID   2
#define COSE_KEY_LABEL_ALG   3

#define COSE_KEY_LABEL_CRV  -1
#define COSE_KEY_LABEL_X    -2
#define COSE_KEY_LABEL_Y    -3
#define COSE_KEY_LABEL_D    -4

struct hpke_ecc_key_material {
    int64_t               kty;
    int64_t               crv;
    bool                  has_private;
    struct q_useful_buf_c x;
    struct q_useful_buf_c y;
    struct q_useful_buf_c d;
};

/* ============================================================
 * Helpers: Wrap PSA key_id into t_cose_key
 * ============================================================ */

/*
 * Wrapper function to convert a PSA key ID to a t_cose_key.
 *
 * For MbedTLS/PSA, t_cose_key holds a uint64_t handle field that
 * contains the psa_key_id_t. No additional wrapper function exists
 * in standard t_cose, so we initialize it directly.
 */
static inline struct t_cose_key tcose_key_from_psa(psa_key_id_t key_id)
{
    struct t_cose_key k;
    memset(&k, 0, sizeof(k));

    /* PSA key handles fit in the uint64_t handle field of t_cose_key */
    k.key.handle = (uint64_t)key_id;

    return k;
}


/* ============================================================
 * HPKE suite decomposition and mapping to COSE AEAD
 * ============================================================ */

typedef struct {
    uint16_t kem_id;
    uint16_t kdf_id;
    uint16_t aead_id; /* HPKE AEAD ID */
} hpke_suite_components_t;

/* Map COSE-HPKE suite alg -> KEM/KDF/AEAD (HPKE IDs) */
static bool hpke_alg_to_components(int32_t hpke_alg, hpke_suite_components_t *out)
{
    if(!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    switch(hpke_alg) {
    case T_COSE_HPKE_Base_P256_SHA256_AES128GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P256;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128;
        return true;

    case T_COSE_HPKE_Base_P384_SHA384_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P384;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA384;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;

    case T_COSE_HPKE_Base_P521_SHA512_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P521;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;

    case T_COSE_HPKE_Base_X25519_SHA256_AES128GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_25519;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128;
        return true;

    case T_COSE_HPKE_Base_X25519_SHA256_CHACHA20POLY1305:
        out->kem_id  = T_COSE_HPKE_KEM_ID_25519;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305;
        return true;

    case T_COSE_HPKE_Base_X448_SHA512_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_448;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;

    case T_COSE_HPKE_Base_X448_SHA512_CHACHA20POLY1305:
        out->kem_id  = T_COSE_HPKE_KEM_ID_448;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        out->aead_id = T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305;
        return true;

    case T_COSE_HPKE_Base_P256_SHA256_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P256;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;

    /* Key Encryption variants map to same KEM/KDF/AEAD */
    case T_COSE_HPKE_KE_P256_SHA256_AES128GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P256;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128;
        return true;
    case T_COSE_HPKE_KE_P384_SHA384_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P384;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA384;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;
    case T_COSE_HPKE_KE_P521_SHA512_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P521;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;
    case T_COSE_HPKE_KE_X25519_SHA256_AES128GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_25519;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_128;
        return true;
    case T_COSE_HPKE_KE_X25519_SHA256_CHACHA20POLY1305:
        out->kem_id  = T_COSE_HPKE_KEM_ID_25519;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305;
        return true;
    case T_COSE_HPKE_KE_X448_SHA512_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_448;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;
    case T_COSE_HPKE_KE_X448_SHA512_CHACHA20POLY1305:
        out->kem_id  = T_COSE_HPKE_KEM_ID_448;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA512;
        out->aead_id = T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305;
        return true;
    case T_COSE_HPKE_KE_P256_SHA256_AES256GCM:
        out->kem_id  = T_COSE_HPKE_KEM_ID_P256;
        out->kdf_id  = T_COSE_HPKE_KDF_ID_HKDF_SHA256;
        out->aead_id = T_COSE_HPKE_AEAD_ID_AES_GCM_256;
        return true;

    default:
        return false;
    }
}

static bool is_hpke_integrated_alg(int32_t alg)
{
    switch(alg) {
    case T_COSE_HPKE_Base_P256_SHA256_AES128GCM:
    case T_COSE_HPKE_Base_P384_SHA384_AES256GCM:
    case T_COSE_HPKE_Base_P521_SHA512_AES256GCM:
    case T_COSE_HPKE_Base_X25519_SHA256_AES128GCM:
    case T_COSE_HPKE_Base_X25519_SHA256_CHACHA20POLY1305:
    case T_COSE_HPKE_Base_X448_SHA512_AES256GCM:
    case T_COSE_HPKE_Base_X448_SHA512_CHACHA20POLY1305:
    case T_COSE_HPKE_Base_P256_SHA256_AES256GCM:
        return true;
    default:
        return false;
    }
}

static bool is_hpke_ke_alg(int32_t alg)
{
    switch(alg) {
    case T_COSE_HPKE_KE_P256_SHA256_AES128GCM:
    case T_COSE_HPKE_KE_P384_SHA384_AES256GCM:
    case T_COSE_HPKE_KE_P521_SHA512_AES256GCM:
    case T_COSE_HPKE_KE_X25519_SHA256_AES128GCM:
    case T_COSE_HPKE_KE_X25519_SHA256_CHACHA20POLY1305:
    case T_COSE_HPKE_KE_X448_SHA512_AES256GCM:
    case T_COSE_HPKE_KE_X448_SHA512_CHACHA20POLY1305:
    case T_COSE_HPKE_KE_P256_SHA256_AES256GCM:
        return true;
    default:
        return false;
    }
}

static int32_t hpke_aead_id_to_tcose_alg(uint16_t hpke_aead_id)
{
    switch(hpke_aead_id) {
    case T_COSE_HPKE_AEAD_ID_AES_GCM_128:
        return T_COSE_ALGORITHM_A128GCM;
    case T_COSE_HPKE_AEAD_ID_AES_GCM_256:
        return T_COSE_ALGORITHM_A256GCM;
    case T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305:
        return T_COSE_ALGORITHM_CHACHA20_POLY1305;
    default:
        return 0;
    }
}

static int32_t hpke_suite_to_tcose_aead(int32_t hpke_alg)
{
    hpke_suite_components_t c;
    if(!hpke_alg_to_components(hpke_alg, &c)) {
        return 0;
    }
    return hpke_aead_id_to_tcose_alg(c.aead_id);
}

static bool is_hpke_alg(int32_t alg)
{
    switch(alg) {
    case T_COSE_HPKE_Base_P256_SHA256_AES128GCM:
    case T_COSE_HPKE_Base_P384_SHA384_AES256GCM:
    case T_COSE_HPKE_Base_P521_SHA512_AES256GCM:
    case T_COSE_HPKE_Base_X25519_SHA256_AES128GCM:
    case T_COSE_HPKE_Base_X25519_SHA256_CHACHA20POLY1305:
    case T_COSE_HPKE_Base_X448_SHA512_AES256GCM:
    case T_COSE_HPKE_Base_X448_SHA512_CHACHA20POLY1305:
    case T_COSE_HPKE_Base_P256_SHA256_AES256GCM:
        return true;
    default:
        return false;
    }
}

/* ============================================================
 * PSA helpers
 * ============================================================ */

/* Map COSE (kty,crv) to PSA key type + bits. Returns false if unsupported. */
static bool cose_curve_to_psa_attrs(int64_t kty,
                                    int64_t crv,
                                    psa_key_type_t *out_type_pub,
                                    psa_key_type_t *out_type_pair,
                                    size_t *out_bits)
{
    if(!out_type_pub || !out_type_pair || !out_bits) {
        return false;
    }

    if(kty == T_COSE_KEY_TYPE_EC2) {
        switch(crv) {
        case T_COSE_ELLIPTIC_CURVE_P_256:
            *out_bits      = 256;
            *out_type_pub  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
            *out_type_pair = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            return true;
        case T_COSE_ELLIPTIC_CURVE_P_384:
            *out_bits      = 384;
            *out_type_pub  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
            *out_type_pair = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            return true;
        case T_COSE_ELLIPTIC_CURVE_P_521:
            *out_bits      = 521;
            *out_type_pub  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
            *out_type_pair = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            return true;
        default:
            return false;
        }
    }

    if(kty == T_COSE_KEY_TYPE_OKP) {
        switch(crv) {
        case T_COSE_ELLIPTIC_CURVE_X25519:
            *out_bits      = 255;
            *out_type_pub  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY);
            *out_type_pair = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
            return true;
        case T_COSE_ELLIPTIC_CURVE_X448:
            *out_bits      = 448;
            *out_type_pub  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY);
            *out_type_pair = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
            return true;
        default:
            return false;
        }
    }

    return false;
}

/* Build PSA public key bytes from COSE_Key (x,y):
 * - EC2: uncompressed point: 0x04 || X || Y
 * - OKP: raw X
 *
 * Returns 0 on success; caller must free(*out_pub_buf).
 */
static int build_psa_public_key_bytes(const struct hpke_ecc_key_material *km,
                                      uint8_t **out_pub_buf,
                                      size_t *out_pub_len)
{
    if(!km || !out_pub_buf || !out_pub_len) {
        return -1;
    }

    *out_pub_buf = NULL;
    *out_pub_len = 0;

    if(km->kty == T_COSE_KEY_TYPE_EC2) {
        if(km->x.len == 0 || km->y.len == 0) {
            return -1;
        }
        size_t len = 1 + km->x.len + km->y.len;
        uint8_t *buf = (uint8_t *)malloc(len);
        if(!buf) {
            return -1;
        }
        buf[0] = 0x04;
        memcpy(buf + 1, km->x.ptr, km->x.len);
        memcpy(buf + 1 + km->x.len, km->y.ptr, km->y.len);

        *out_pub_buf = buf;
        *out_pub_len = len;
        return 0;
    }

    if(km->kty == T_COSE_KEY_TYPE_OKP) {
        if(km->x.len == 0) {
            return -1;
        }
        uint8_t *buf = (uint8_t *)malloc(km->x.len);
        if(!buf) {
            return -1;
        }
        memcpy(buf, km->x.ptr, km->x.len);
        *out_pub_buf = buf;
        *out_pub_len = km->x.len;
        return 0;
    }

    return -1;
}

/* ============================================================
 * Utility: file IO
 * ============================================================ */

static int read_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if(!f) {
        perror("fopen");
        return -1;
    }
    if(fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if(sz < 0) {
        perror("ftell");
        fclose(f);
        return -1;
    }
    rewind(f);

    uint8_t *tmp = (uint8_t *)malloc((size_t)sz);
    if(!tmp) {
        fprintf(stderr, "Out of memory reading %s\n", path);
        fclose(f);
        return -1;
    }

    size_t n = fread(tmp, 1, (size_t)sz, f);
    fclose(f);
    if(n != (size_t)sz) {
        fprintf(stderr, "Short read from %s\n", path);
        free(tmp);
        return -1;
    }

    *buf = tmp;
    *len = (size_t)sz;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if(!f) {
        perror("fopen");
        return -1;
    }
    size_t n = fwrite(buf, 1, len, f);
    fclose(f);
    if(n != len) {
        fprintf(stderr, "Short write to %s\n", path);
        return -1;
    }
    return 0;
}

/* ============================================================
 * HPKE suite <-> curve validation
 * ============================================================ */

static bool hpke_key_matches_kem(int64_t kty, int64_t crv, uint16_t kem_id)
{
    switch(kem_id) {
    case T_COSE_HPKE_KEM_ID_P256:
        return (kty == T_COSE_KEY_TYPE_EC2 && crv == T_COSE_ELLIPTIC_CURVE_P_256);
    case T_COSE_HPKE_KEM_ID_P384:
        return (kty == T_COSE_KEY_TYPE_EC2 && crv == T_COSE_ELLIPTIC_CURVE_P_384);
    case T_COSE_HPKE_KEM_ID_P521:
        return (kty == T_COSE_KEY_TYPE_EC2 && crv == T_COSE_ELLIPTIC_CURVE_P_521);
    case T_COSE_HPKE_KEM_ID_25519:
        return (kty == T_COSE_KEY_TYPE_OKP && crv == T_COSE_ELLIPTIC_CURVE_X25519);
    case T_COSE_HPKE_KEM_ID_448:
        return (kty == T_COSE_KEY_TYPE_OKP && crv == T_COSE_ELLIPTIC_CURVE_X448);
    default:
        return false;
    }
}

/*
 * In your setup, the t_cose HPKE suite constants equal the COSE-HPKE alg value.
 * So: validate suite<->curve and return it.
 */
static bool map_to_tcose_hpke_suite(int32_t recipient_alg,
                                   int64_t kty,
                                   int64_t crv,
                                   int32_t *out_tcose_suite)
{
    if(!out_tcose_suite) {
        return false;
    }

    hpke_suite_components_t comps;
    if(!hpke_alg_to_components(recipient_alg, &comps)) {
        return false;
    }

    if(!hpke_key_matches_kem(kty, crv, comps.kem_id)) {
        return false;
    }

    *out_tcose_suite = recipient_alg;
    return true;
}

/* ============================================================
 * Parse COSE_Key -> hpke_ecc_key_material
 * ============================================================ */

static enum t_cose_err_t
parse_ecc_cose_key(const struct q_useful_buf_c       cose_key_buf,
                   struct hpke_ecc_key_material     *out_key,
                   struct q_useful_buf_c            *out_kid,
                   int32_t                          *out_alg)
{
    QCBORDecodeContext dc;
    QCBORItem          item;
    QCBORError         qc_err;

    memset(out_key, 0, sizeof(*out_key));
    if(out_kid) {
        *out_kid = NULL_Q_USEFUL_BUF_C;
    }
    if(out_alg) {
        *out_alg = 0;
    }

    QCBORDecode_Init(&dc, cose_key_buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterMap(&dc, NULL);
    if(QCBORDecode_GetError(&dc) != QCBOR_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    int64_t kty = 0;
    int64_t crv = 0;
    struct q_useful_buf_c kid = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c x   = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c y   = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c d   = NULL_Q_USEFUL_BUF_C;
    int64_t alg_int = 0;
    bool    alg_present = false;
    bool    has_private = false;

    while((qc_err = QCBORDecode_GetNext(&dc, &item)) == QCBOR_SUCCESS) {
        if(item.uLabelType != QCBOR_TYPE_INT64) {
            continue;
        }

        int64_t label = item.label.int64;

        switch(label) {
        case COSE_KEY_LABEL_KTY:
            if(item.uDataType == QCBOR_TYPE_INT64) {
                kty = item.val.int64;
            }
            break;

        case COSE_KEY_LABEL_KID:
            if(item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                kid = item.val.string;
            }
            break;

        case COSE_KEY_LABEL_ALG:
            if(item.uDataType == QCBOR_TYPE_INT64) {
                alg_int = item.val.int64;
                alg_present = true;
            }
            break;

        case COSE_KEY_LABEL_CRV:
            if(item.uDataType == QCBOR_TYPE_INT64) {
                crv = item.val.int64;
            }
            break;

        case COSE_KEY_LABEL_X:
            if(item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                x = item.val.string;
            }
            break;

        case COSE_KEY_LABEL_Y:
            if(item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                y = item.val.string;
            }
            break;

        case COSE_KEY_LABEL_D:
            if(item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                d = item.val.string;
                has_private = true;
            }
            break;

        default:
            break;
        }
    }

    if(qc_err != QCBOR_ERR_NO_MORE_ITEMS) {
        return T_COSE_ERR_FAIL;
    }

    QCBORDecode_ExitMap(&dc);
    if(QCBORDecode_GetError(&dc) != QCBOR_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    qc_err = QCBORDecode_Finish(&dc);
    if(qc_err != QCBOR_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    if(kty != T_COSE_KEY_TYPE_EC2 && kty != T_COSE_KEY_TYPE_OKP) {
        return T_COSE_ERR_FAIL;
    }
    if(crv == 0) {
        return T_COSE_ERR_FAIL;
    }
    if(!has_private && x.len == 0) {
        return T_COSE_ERR_FAIL;
    }
    if(has_private && d.len == 0) {
        return T_COSE_ERR_FAIL;
    }

    out_key->kty         = kty;
    out_key->crv         = crv;
    out_key->has_private = has_private;
    out_key->x           = x;
    out_key->y           = y;
    out_key->d           = d;

    if(out_alg && alg_present) {
        *out_alg = (int32_t)alg_int;
    }
    if(out_kid) {
        *out_kid = kid;
    }

    return T_COSE_SUCCESS;
}

/* ============================================================
 * COSE_Key load + PSA import -> t_cose_key
 * ============================================================ */

enum t_cose_err_t
load_cose_key_from_file(const char                   *path,
                        struct t_cose_key            *out_key,
                        struct q_useful_buf_c        *out_kid,
                        int32_t                      *out_alg,
                        struct hpke_ecc_key_material *out_parsed)
{
    uint8_t *file_buf = NULL;
    size_t   file_len = 0;
    enum t_cose_err_t t_err;

    if(!path || !out_key) {
        fprintf(stderr, "load_cose_key_from_file: invalid args\n");
        return T_COSE_ERR_FAIL;
    }

    if(read_file(path, &file_buf, &file_len) != 0) {
        fprintf(stderr, "load_cose_key_from_file: read_file failed for %s\n", path);
        return T_COSE_ERR_FAIL;
    }

//    fprintf(stderr, "load_cose_key_from_file: read %zu bytes from %s\n", file_len, path);

    struct q_useful_buf_c cose_key_buf = { file_buf, file_len };

    struct hpke_ecc_key_material km;
    struct q_useful_buf_c        kid = NULL_Q_USEFUL_BUF_C;
    int32_t                      alg = 0;

    t_err = parse_ecc_cose_key(cose_key_buf, &km, &kid, &alg);
    if(t_err != T_COSE_SUCCESS) {
        fprintf(stderr, "load_cose_key_from_file: parse_ecc_cose_key failed (%d)\n", t_err);
        free(file_buf);
        return t_err;
    }

    if(out_parsed) {
        /* IMPORTANT: x/y/d point into file_buf. Don’t pass those pointers out. */
        memset(out_parsed, 0, sizeof(*out_parsed));
        out_parsed->kty         = km.kty;
        out_parsed->crv         = km.crv;
        out_parsed->has_private = km.has_private;
        out_parsed->x = NULL_Q_USEFUL_BUF_C;
        out_parsed->y = NULL_Q_USEFUL_BUF_C;
        out_parsed->d = NULL_Q_USEFUL_BUF_C;
    }

    /* Copy kid into heap memory owned by the caller */
    if(out_kid) {
        if(kid.len > 0) {
            uint8_t *kid_copy = (uint8_t *)malloc(kid.len);
            if(!kid_copy) {
                free(file_buf);
                return T_COSE_ERR_FAIL;
            }
            memcpy(kid_copy, kid.ptr, kid.len);
            out_kid->ptr = kid_copy;
            out_kid->len = kid.len;
        } else {
            *out_kid = NULL_Q_USEFUL_BUF_C;
        }
    }

    if(out_alg) {
        *out_alg = alg;
    }

    /* ---------------- PSA IMPORT ---------------- */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         key_id = 0;

    psa_key_type_t psa_type_pub  = 0;
    psa_key_type_t psa_type_pair = 0;
    size_t         bits          = 0;

    if(!cose_curve_to_psa_attrs(km.kty, km.crv, &psa_type_pub, &psa_type_pair, &bits)) {
        fprintf(stderr, "Unsupported COSE_Key kty/crv for PSA import: kty=%lld crv=%lld\n",
                (long long)km.kty, (long long)km.crv);
        free(file_buf);
        return T_COSE_ERR_FAIL; /* (was T_COSE_ERR_UNSUPPORTED_ALG) */
    }

    psa_set_key_bits(&attr, bits);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

    /* HPKE KEM uses ECDH. */
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);

    psa_status_t st;

    if(km.has_private) {
        psa_set_key_type(&attr, psa_type_pair);

        st = psa_import_key(&attr,
                            (const uint8_t *)km.d.ptr, km.d.len,
                            &key_id);
        if(st != PSA_SUCCESS) {
            fprintf(stderr, "psa_import_key(keypair) failed: %d\n", (int)st);
            free(file_buf);
            return T_COSE_ERR_FAIL;
        }
    } else {
        psa_set_key_type(&attr, psa_type_pub);

        uint8_t *pub_bytes = NULL;
        size_t   pub_len   = 0;

        if(build_psa_public_key_bytes(&km, &pub_bytes, &pub_len) != 0) {
            fprintf(stderr, "Failed to build PSA public key encoding\n");
            free(file_buf);
            return T_COSE_ERR_FAIL;
        }

        st = psa_import_key(&attr, pub_bytes, pub_len, &key_id);
        free(pub_bytes);

        if(st != PSA_SUCCESS) {
            fprintf(stderr, "psa_import_key(public) failed: %d\n", (int)st);
            free(file_buf);
            return T_COSE_ERR_FAIL;
        }
    }

    /* Wrap PSA key into t_cose_key (non-empty now) */
    *out_key = tcose_key_from_psa(key_id);

    free(file_buf);
    return T_COSE_SUCCESS;
}

/* ============================================================
 * Encrypt flow
 * ============================================================ */

static int do_encrypt(int argc, char **argv)
{
    const char *mode           = NULL;  /* "encrypt0" or "encrypt" */
    const char *recipient_file = NULL;  /* COSE_Key recipient */
    const char *sender_file    = NULL;  /* COSE_Key signer */
    const char *sender_id      = NULL;
    const char *aad_file       = NULL;
    const char *info_file      = NULL;
    const char *payload_file   = NULL;
    const char *out_file       = NULL;
    const char *ct_out_file    = NULL;
    const char *psk_file       = NULL;
    const char *psk_id_str     = NULL;
    int         detached       = 0;

    for(int i = 2; i < argc; i++) {
        if(strcmp(argv[i], "--mode") == 0 && i+1 < argc) {
            mode = argv[++i];
        } else if(strcmp(argv[i], "--recipient-key") == 0 && i+1 < argc) {
            recipient_file = argv[++i];
        } else if(strcmp(argv[i], "--sender-key") == 0 && i+1 < argc) {
            sender_file = argv[++i];
        } else if(strcmp(argv[i], "--sender-id") == 0 && i+1 < argc) {
            sender_id = argv[++i];
        } else if(strcmp(argv[i], "--aad") == 0 && i+1 < argc) {
            aad_file = argv[++i];
        } else if(strcmp(argv[i], "--info") == 0 && i+1 < argc) {
            info_file = argv[++i];
        } else if(strcmp(argv[i], "--payload") == 0 && i+1 < argc) {
            payload_file = argv[++i];
        } else if(strcmp(argv[i], "--out") == 0 && i+1 < argc) {
            out_file = argv[++i];
        } else if(strcmp(argv[i], "--ciphertext-out") == 0 && i+1 < argc) {
            ct_out_file = argv[++i];
        } else if(strcmp(argv[i], "--detached") == 0) {
            detached = 1;
        } else if(strcmp(argv[i], "--attach") == 0) {
            detached = 0;
        } else if(strcmp(argv[i], "--psk") == 0 && i+1 < argc) {
            psk_file = argv[++i];
        } else if(strcmp(argv[i], "--psk-id") == 0 && i+1 < argc) {
            psk_id_str = argv[++i];
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            return 1;
        }
    }

    if(!mode || !recipient_file || !payload_file || !out_file) {
        fprintf(stderr,
                "Missing required parameters for encrypt.\n"
                "Required: --mode, --recipient-key, --payload, --out\n");
        return 1;
    }

    uint8_t *payload = NULL;
    size_t   payload_len = 0;
    if(read_file(payload_file, &payload, &payload_len) != 0) {
        return 1;
    }
    struct q_useful_buf_c payload_ub = { payload, payload_len };

    uint8_t *aad = NULL;
    size_t   aad_len = 0;
    struct q_useful_buf_c aad_ub = NULL_Q_USEFUL_BUF_C;
    if(aad_file) {
        if(read_file(aad_file, &aad, &aad_len) != 0) {
            free(payload);
            return 1;
        }
        aad_ub = (struct q_useful_buf_c){ aad, aad_len };
    }

    uint8_t *info = NULL;
    size_t   info_len = 0;
    struct q_useful_buf_c info_ub = NULL_Q_USEFUL_BUF_C;
    if(info_file) {
        if(read_file(info_file, &info, &info_len) != 0) {
            free(payload);
            free(aad);
            return 1;
        }
        info_ub = (struct q_useful_buf_c){ info, info_len };
    }

    uint8_t *psk_buf = NULL;
    size_t   psk_len = 0;
    struct q_useful_buf_c psk_ub = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c psk_id_ub = NULL_Q_USEFUL_BUF_C;
    if(psk_file) {
        if(read_file(psk_file, &psk_buf, &psk_len) != 0) {
            free(payload); free(aad); free(info);
            return 1;
        }
        psk_ub = (struct q_useful_buf_c){ psk_buf, psk_len };
    }
    if(psk_id_str) {
        psk_id_ub = (struct q_useful_buf_c){ psk_id_str, strlen(psk_id_str) };
    }

    struct t_cose_key       recipient_key;
    struct q_useful_buf_c   recipient_kid = NULL_Q_USEFUL_BUF_C;
    int32_t                 recipient_alg = 0;
    struct hpke_ecc_key_material recipient_parsed = {0};
    enum t_cose_err_t       terr;

    terr = load_cose_key_from_file(recipient_file,
                                   &recipient_key,
                                   &recipient_kid,
                                   &recipient_alg,
                                   &recipient_parsed);
    if(terr != T_COSE_SUCCESS) {
        fprintf(stderr, "Failed to load recipient key\n");
        free(payload);
        free(aad);
        free(info);
        return 1;
    }

    struct t_cose_key       signer_key;
    struct q_useful_buf_c   signer_kid = NULL_Q_USEFUL_BUF_C;
    int32_t                 signer_alg = 0;
    int                     have_signer = 0;

    if(sender_file) {
        terr = load_cose_key_from_file(sender_file,
                                       &signer_key,
                                       &signer_kid,
                                       &signer_alg,
                                       NULL);
        if(terr != T_COSE_SUCCESS) {
            fprintf(stderr, "Failed to load signer key\n");
            free(payload);
            free(aad);
            free(info);
            return 1;
        }
        have_signer = 1;
    }

    uint8_t cose_buf_mem[4096];
    uint8_t ct_buf_mem[4096];

    struct q_useful_buf   cose_buf = Q_USEFUL_BUF_FROM_BYTE_ARRAY(cose_buf_mem);
    struct q_useful_buf   ct_buf   = Q_USEFUL_BUF_FROM_BYTE_ARRAY(ct_buf_mem);
    struct q_useful_buf_c cose_msg = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c ct_ub    = NULL_Q_USEFUL_BUF_C;

    if(strcmp(mode, "encrypt") == 0) {
        struct t_cose_encrypt_enc         enc_ctx;
        struct t_cose_recipient_enc_hpke  recip;

        int32_t aead_alg = hpke_suite_to_tcose_aead(recipient_alg);
        if(aead_alg == 0) {
            fprintf(stderr, "Unsupported HPKE suite alg=%d for Encrypt body\n", recipient_alg);
            free(payload);
            free(aad);
            free(info);
            return 1;
        }
        if(!is_hpke_ke_alg(recipient_alg)) {
            fprintf(stderr, "HPKE Key Encryption requires HPKE-*-KE alg IDs (46-53)\n");
            free(payload);
            free(aad);
            free(info);
            return 1;
        }
        t_cose_encrypt_enc_init(&enc_ctx,
                                T_COSE_OPT_MESSAGE_TYPE_ENCRYPT,
                                aead_alg);

        int32_t tcose_hpke_suite = 0;
        if(!map_to_tcose_hpke_suite(recipient_alg,
                                    recipient_parsed.kty,
                                    recipient_parsed.crv,
                                    &tcose_hpke_suite)) {
            hpke_suite_components_t comps;
            if(hpke_alg_to_components(recipient_alg, &comps)) {
                fprintf(stderr,
                        "Unsupported HPKE suite/key combination:\n"
                        "  alg=%d\n"
                        "  key: kty=%lld crv=%lld\n"
                        "  suite: KEM=0x%04x KDF=0x%04x AEAD=0x%04x\n",
                        recipient_alg,
                        (long long)recipient_parsed.kty,
                        (long long)recipient_parsed.crv,
                        (unsigned)comps.kem_id,
                        (unsigned)comps.kdf_id,
                        (unsigned)comps.aead_id);
            } else {
                fprintf(stderr,
                        "Unsupported HPKE suite/key combination: alg=%d kty=%lld crv=%lld\n",
                        recipient_alg,
                        (long long)recipient_parsed.kty,
                        (long long)recipient_parsed.crv);
            }
            free(payload);
            free(aad);
            free(info);
            return 1;
        }

        t_cose_recipient_enc_hpke_init(&recip, tcose_hpke_suite);

        t_cose_recipient_enc_hpke_set_key(&recip,
                                          recipient_key,
                                          recipient_kid);
        t_cose_recipient_enc_hpke_set_psk(&recip, psk_ub, psk_id_ub);
        t_cose_recipient_enc_hpke_set_info(&recip, info_ub);

        t_cose_encrypt_add_recipient(&enc_ctx,
                                     (struct t_cose_recipient_enc *)&recip);

        if(detached) {
            terr = t_cose_encrypt_enc_detached(&enc_ctx,
                                               payload_ub,
                                               aad_ub,
                                               ct_buf,
                                               cose_buf,
                                               &ct_ub,
                                               &cose_msg);
        } else {
            terr = t_cose_encrypt_enc(&enc_ctx,
                                      payload_ub,
                                      aad_ub,
                                      cose_buf,
                                      &cose_msg);
        }

        if(terr != T_COSE_SUCCESS) {
            fprintf(stderr, "HPKE encryption failed: %d\n", terr);
            free(payload);
            free(aad);
            free(info);
            return 1;
        }

    } else if(strcmp(mode, "encrypt0") == 0) {
        /* HPKE Integrated Encryption (COSE_Encrypt0 with HPKE alg) */
        struct t_cose_encrypt_enc         enc_ctx;
        struct t_cose_recipient_enc_hpke  recip;

        if(!is_hpke_integrated_alg(recipient_alg)) {
            fprintf(stderr, "HPKE Integrated Encryption requires HPKE-0..7 alg IDs (35-45)\n");
            free(payload);
            free(aad);
            free(info);
            return 1;
        }

        /* payload algorithm IS the HPKE suite id */
        t_cose_encrypt_enc_init(&enc_ctx,
                                T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0,
                                recipient_alg);
        enc_ctx.hpke_info = info_ub;

        /* recipient carries pkR + suite */
        t_cose_recipient_enc_hpke_init(&recip, recipient_alg);
        t_cose_recipient_enc_hpke_set_key(&recip,
                                          recipient_key,
                                          recipient_kid);
        t_cose_recipient_enc_hpke_set_psk(&recip, psk_ub, psk_id_ub);
        t_cose_encrypt_add_recipient(&enc_ctx,
                                     (struct t_cose_recipient_enc *)&recip);

        if(detached) {
            terr = t_cose_encrypt_enc_detached(&enc_ctx,
                                               payload_ub,
                                               aad_ub,
                                               ct_buf,
                                               cose_buf,
                                               &ct_ub,
                                               &cose_msg);
        } else {
            terr = t_cose_encrypt_enc(&enc_ctx,
                                      payload_ub,
                                      aad_ub,
                                      cose_buf,
                                      &cose_msg);
        }

        if(terr != T_COSE_SUCCESS) {
            fprintf(stderr, "HPKE Encrypt0 encryption failed: %d\n", terr);
            free(payload);
            free(aad);
            free(info);
            return 1;
        }

    } else {
        fprintf(stderr, "Unknown mode: %s (use encrypt0 or encrypt)\n", mode);
        free(payload);
        free(aad);
        free(info);
        return 1;
    }

    struct q_useful_buf_c final_out = cose_msg;
    uint8_t signed_buf_mem[4096];
    struct q_useful_buf signed_buf = Q_USEFUL_BUF_FROM_BYTE_ARRAY(signed_buf_mem);

    if(have_signer) {
        struct t_cose_sign_sign_ctx       sign_ctx;
        struct t_cose_signature_sign_main main_signer;

        t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);
        t_cose_signature_sign_main_init(&main_signer, signer_alg);

        struct q_useful_buf_c id_ub =
            sender_id
            ? (struct q_useful_buf_c){ sender_id, strlen(sender_id) }
            : signer_kid;

        t_cose_signature_sign_main_set_signing_key(&main_signer,
                                                   signer_key,
                                                   id_ub);
        t_cose_sign_add_signer(&sign_ctx,
                               t_cose_signature_sign_from_main(&main_signer));

        struct q_useful_buf_c signed_cose;
        terr = t_cose_sign_sign(&sign_ctx,
                                NULL_Q_USEFUL_BUF_C,
                                cose_msg,
                                signed_buf,
                                &signed_cose);
        if(terr != T_COSE_SUCCESS) {
            fprintf(stderr, "Signing failed: %d\n", terr);
            free(payload);
            free(aad);
            free(info);
            return 1;
        }
        final_out = signed_cose;
    }

    if(write_file(out_file,
                  (const uint8_t *)final_out.ptr,
                  final_out.len) != 0) {
        free(payload);
        free(aad);
        free(info);
        return 1;
    }

    if(detached) {
        if(!ct_out_file) {
            fprintf(stderr,
                    "Detached mode selected but no --ciphertext-out given.\n");
            free(payload);
            free(aad);
            free(info);
            return 1;
        }
        if(write_file(ct_out_file,
                      (const uint8_t *)ct_ub.ptr,
                      ct_ub.len) != 0) {
            free(payload);
            free(aad);
            free(info);
            return 1;
        }
    }

    free(payload);
    free(aad);
    free(info);
    free(psk_buf);
    return 0;
}

/* ============================================================
 * Decrypt flow
 * ============================================================ */

static int do_decrypt(int argc, char **argv)
{
    const char *mode_arg     = NULL;       /* optional override; otherwise auto-detect */
    const char *my_key_file   = NULL;
    const char *aad_file      = NULL;
    const char *info_file     = NULL;
    const char *cose_file     = NULL;
    const char *ct_file       = NULL;
    const char *out_file      = NULL;
    const char *psk_file      = NULL;
    const char *psk_id_str    = NULL;

    for(int i = 2; i < argc; i++) {
        if(strcmp(argv[i], "--mode") == 0 && i+1 < argc) {
            mode_arg = argv[++i]; /* encrypt0 or encrypt (HPKE) */
        } else if(strcmp(argv[i], "--my-key") == 0 && i+1 < argc) {
            my_key_file = argv[++i];
        } else if(strcmp(argv[i], "--aad") == 0 && i+1 < argc) {
            aad_file = argv[++i];
        } else if(strcmp(argv[i], "--info") == 0 && i+1 < argc) {
            info_file = argv[++i];
        } else if(strcmp(argv[i], "--in") == 0 && i+1 < argc) {
            cose_file = argv[++i];
        } else if(strcmp(argv[i], "--ciphertext-in") == 0 && i+1 < argc) {
            ct_file = argv[++i];
        } else if(strcmp(argv[i], "--out") == 0 && i+1 < argc) {
            out_file = argv[++i];
        } else if(strcmp(argv[i], "--psk") == 0 && i+1 < argc) {
            psk_file = argv[++i];
        } else if(strcmp(argv[i], "--psk-id") == 0 && i+1 < argc) {
            psk_id_str = argv[++i];
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            return 1;
        }
    }

    if(!my_key_file || !cose_file || !out_file) {
        fprintf(stderr,
                "Missing required parameters for decrypt.\n"
                "Required: --my-key, --in, --out\n");
        return 1;
    }

    struct t_cose_key       my_key;
    struct q_useful_buf_c   my_kid = NULL_Q_USEFUL_BUF_C;
    int32_t                 my_alg = 0;
    struct hpke_ecc_key_material my_parsed = {0};
    enum t_cose_err_t       terr;

    terr = load_cose_key_from_file(my_key_file,
                                   &my_key,
                                   &my_kid,
                                   &my_alg,
                                   &my_parsed);
    if(terr != T_COSE_SUCCESS) {
        fprintf(stderr, "Failed to load my key\n");
        return 1;
    }

    uint8_t *cose_data = NULL;
    size_t   cose_len = 0;
    if(read_file(cose_file, &cose_data, &cose_len) != 0) {
        return 1;
    }
    struct q_useful_buf_c cose_msg = { cose_data, cose_len };

    uint8_t *aad = NULL;
    size_t   aad_len = 0;
    struct q_useful_buf_c aad_ub = NULL_Q_USEFUL_BUF_C;
    if(aad_file) {
        if(read_file(aad_file, &aad, &aad_len) != 0) {
            free(cose_data);
            return 1;
        }
        aad_ub = (struct q_useful_buf_c){ aad, aad_len };
    }

    uint8_t *info = NULL;
    size_t   info_len = 0;
    struct q_useful_buf_c info_ub = NULL_Q_USEFUL_BUF_C;
    if(info_file) {
        if(read_file(info_file, &info, &info_len) != 0) {
            free(cose_data);
            free(aad);
            return 1;
        }
        info_ub = (struct q_useful_buf_c){ info, info_len };
    }

    uint8_t *ct = NULL;
    size_t   ct_len = 0;
    struct q_useful_buf_c ct_ub = NULL_Q_USEFUL_BUF_C;
    if(ct_file) {
        if(read_file(ct_file, &ct, &ct_len) != 0) {
            free(cose_data);
            free(aad);
            free(info);
            return 1;
        }
        ct_ub = (struct q_useful_buf_c){ ct, ct_len };
    }

    uint8_t plaintext_buf_mem[4096];
    struct q_useful_buf plaintext_buf =
        Q_USEFUL_BUF_FROM_BYTE_ARRAY(plaintext_buf_mem);
    struct q_useful_buf_c plaintext = NULL_Q_USEFUL_BUF_C;
    uint8_t *psk_buf = NULL;
    size_t   psk_len = 0;
    struct q_useful_buf_c psk_ub = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c psk_id_ub = NULL_Q_USEFUL_BUF_C;
    if(psk_file) {
        if(read_file(psk_file, &psk_buf, &psk_len) != 0) {
            free(cose_data); free(aad); free(info); free(ct);
            return 1;
        }
        psk_ub = (struct q_useful_buf_c){ psk_buf, psk_len };
    }
    if(psk_id_str) {
        psk_id_ub = (struct q_useful_buf_c){ psk_id_str, strlen(psk_id_str) };
    }

    /* ------------------------------------------------------------
     * Detect message type (Encrypt0 vs Encrypt) if not provided
     * ------------------------------------------------------------ */
    bool is_encrypt0_detected = false;
    bool detected = false;
    bool alg_is_hpke = false;
    int64_t alg_in_msg = 0;
    {
        QCBORDecodeContext dc;
        QCBORItem          it;
        QCBORDecode_Init(&dc, cose_msg, QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_GetNext(&dc, &it);
        if(QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && it.uDataType == QCBOR_TYPE_ARRAY) {
            if(it.val.uCount == 3) {
                is_encrypt0_detected = true;
                detected = true;
            } else if(it.val.uCount == 4) {
                is_encrypt0_detected = false;
                detected = true;
            }
        }

        /* Try to decode protected headers to get alg */
        QCBORDecode_Init(&dc, cose_msg, QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_EnterArray(&dc, NULL);
        if(QCBORDecode_GetError(&dc) == QCBOR_SUCCESS) {
            QCBORItem prot;
            QCBORDecode_GetNext(&dc, &prot);
            if(QCBORDecode_GetError(&dc) == QCBOR_SUCCESS &&
               prot.uDataType == QCBOR_TYPE_BYTE_STRING) {
                QCBORDecodeContext dc_prot;
                QCBORDecode_Init(&dc_prot, prot.val.string, QCBOR_DECODE_MODE_NORMAL);
                QCBORDecode_EnterMap(&dc_prot, NULL);
                if(QCBORDecode_GetError(&dc_prot) == QCBOR_SUCCESS) {
                    while(QCBORDecode_GetNext(&dc_prot, &it) == QCBOR_SUCCESS) {
                        if(it.uLabelType == QCBOR_TYPE_INT64 && it.label.int64 == 1) { /* alg */
                            if(it.uDataType == QCBOR_TYPE_INT64) {
                                alg_in_msg = it.val.int64;
                                if(is_hpke_alg((int32_t)alg_in_msg)) {
                                    alg_is_hpke = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /* Decide mode: arg overrides detection; if no arg, use detection or fall back to encrypt0 */
    bool use_encrypt0 = true;
    if(mode_arg) {
        if(strcmp(mode_arg, "encrypt0") == 0) {
            use_encrypt0 = true;
        } else if(strcmp(mode_arg, "encrypt") == 0) {
            use_encrypt0 = false;
        } else {
            fprintf(stderr, "Unknown mode for decrypt: %s (use encrypt0 or encrypt)\n", mode_arg);
            free(cose_data); free(aad); free(ct);
            return 1;
        }
    } else if(detected) {
        use_encrypt0 = is_encrypt0_detected;
    }
    if(alg_is_hpke) {
        use_encrypt0 = true; /* HPKE alg implies integrated Encrypt0 */
    } /* else default stays encrypt0 for backward compatibility */

    if(use_encrypt0) {
        if(is_hpke_ke_alg(alg_in_msg) && !mode_arg) {
            fprintf(stderr, "Alg ID %lld is HPKE-KE; treating message as Key Encryption, not Encrypt0\n", (long long)alg_in_msg);
            use_encrypt0 = false;
        }
        if(alg_is_hpke) {
            /* HPKE integrated Encrypt0: use library decrypt */
            struct t_cose_encrypt_dec_ctx dec_ctx;
            t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0);
            t_cose_encrypt_dec_set_hpke_recipient_key(&dec_ctx,
                                                      my_key,
                                                      info_ub);
            t_cose_encrypt_dec_set_hpke_psk(&dec_ctx, psk_ub, psk_id_ub);

            terr = t_cose_encrypt_dec_detached(&dec_ctx,
                                               cose_msg,
                                               aad_ub,
                                               ct_file ? ct_ub : NULL_Q_USEFUL_BUF_C,
                                               plaintext_buf,
                                               &plaintext,
                                               NULL);
            if(terr != T_COSE_SUCCESS) {
                fprintf(stderr, "Decryption failed: %d (t_cose_encrypt_dec)\n", terr);
                free(cose_data); free(aad); free(ct);
                free(info);
                free(psk_buf);
                return 1;
            }
        } else {
            fprintf(stderr,
                    "Decrypt mode encrypt0 requires an HPKE integrated alg (got alg=%lld)\n",
                    (long long)alg_in_msg);
            free(cose_data); free(aad); free(ct);
            free(info);
            free(psk_buf);
            return 1;
        }
    } else {
        /* HPKE COSE_Encrypt path */
        if(!my_parsed.has_private) {
            fprintf(stderr, "HPKE decrypt needs a private key in --my-key\n");
            free(cose_data);
            free(aad);
            free(ct);
            free(info);
            return 1;
        }

        int32_t tcose_hpke_suite = 0;
        if(!map_to_tcose_hpke_suite(my_alg, my_parsed.kty, my_parsed.crv, &tcose_hpke_suite)) {
            hpke_suite_components_t comps;
            if(hpke_alg_to_components(my_alg, &comps)) {
                fprintf(stderr,
                        "Unsupported HPKE suite/key for decrypt:\n"
                        "  alg=%d kty=%lld crv=%lld\n"
                        "  suite: KEM=0x%04x KDF=0x%04x AEAD=0x%04x\n",
                        my_alg,
                        (long long)my_parsed.kty,
                        (long long)my_parsed.crv,
                        (unsigned)comps.kem_id,
                        (unsigned)comps.kdf_id,
                        (unsigned)comps.aead_id);
            } else {
                fprintf(stderr,
                        "Unsupported HPKE suite/key for decrypt: alg=%d kty=%lld crv=%lld\n",
                        my_alg,
                        (long long)my_parsed.kty,
                        (long long)my_parsed.crv);
            }
            free(cose_data);
            free(aad);
            free(ct);
            free(info);
            return 1;
        }

        struct t_cose_encrypt_dec_ctx    dec_ctx;
        struct t_cose_recipient_dec_hpke dec_recipient;

        t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT);
        t_cose_recipient_dec_hpke_init(&dec_recipient);
        t_cose_recipient_dec_hpke_set_skr(&dec_recipient, my_key, my_kid);
        t_cose_recipient_dec_hpke_set_psk(&dec_recipient, psk_ub, psk_id_ub);
        t_cose_recipient_dec_hpke_set_info(&dec_recipient, info_ub);
        t_cose_encrypt_dec_add_recipient(&dec_ctx,
                                         (struct t_cose_recipient_dec *)&dec_recipient);

        if(ct_file) {
            terr = t_cose_encrypt_dec_detached(&dec_ctx,
                                               cose_msg,
                                               aad_ub,
                                               ct_ub,
                                               plaintext_buf,
                                               &plaintext,
                                               NULL);
        } else {
            terr = t_cose_encrypt_dec(&dec_ctx,
                                      cose_msg,
                                      aad_ub,
                                      plaintext_buf,
                                      &plaintext,
                                      NULL);
        }
    }
    if(terr != T_COSE_SUCCESS) {
        fprintf(stderr, "Decryption failed: %d\n", terr);
        free(cose_data);
        free(aad);
        free(ct);
        free(info);
        return 1;
    }

    if(write_file(out_file,
                  (const uint8_t *)plaintext.ptr,
                  plaintext.len) != 0) {
        free(cose_data);
        free(aad);
        free(ct);
        free(info);
        free(psk_buf);
        return 1;
    }

    free(cose_data);
    free(aad);
    free(ct);
    free(info);
    free(psk_buf);
    return 0;
}

/* ============================================================
 * main()
 * ============================================================ */

int main(int argc, char **argv)
{
    if(argc < 2) {
        fprintf(stderr,
                "Usage:\n"
                "  %s encrypt [options]\n"
                "  %s decrypt [options]\n",
                argv[0], argv[0]);
        return 1;
    }

    psa_status_t st = psa_crypto_init();
    if(st != PSA_SUCCESS) {
        fprintf(stderr, "psa_crypto_init failed: %d\n", (int)st);
        return 1;
    }

    if(strcmp(argv[1], "encrypt") == 0) {
        return do_encrypt(argc, argv);
    } else if(strcmp(argv[1], "decrypt") == 0) {
        return do_decrypt(argc, argv);
    } else {
        fprintf(stderr, "Unknown command: %s (use encrypt or decrypt)\n", argv[1]);
        return 1;
    }
}
