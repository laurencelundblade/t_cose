/*
 * cose_key_gen.c
 *
 * Always generates two COSE_Key CBOR files:
 *   1) Public COSE_Key (contains only public parameters)
 *   2) Full COSE_Key   (contains public parameters + private d)
 *
 * Valid parameters:
 *   --alg HPKE-0..HPKE-7 or HPKE-0-KE..HPKE-7-KE
 *   --kid KID
 *   --pub-out  <file>   (public COSE_Key)
 *   --full-out <file>   (public+private COSE_Key)
 *
 * Note: Works only with the PSA Crypto API
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include "psa/crypto.h"
#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include "t_cose/t_cose_standard_constants.h"

/* Some COSE labels are not (currently) defined in t_cose_standard_constants.h */
#ifndef T_COSE_KEY_COMMON_ALG
#define T_COSE_KEY_COMMON_ALG 3 /* COSE_Key "alg" label */
#endif

typedef struct {
    int32_t        cose_alg;  /* COSE HPKE suite alg */
    int32_t        cose_kty;  /* T_COSE_KEY_TYPE_EC2 / T_COSE_KEY_TYPE_OKP */
    int32_t        cose_crv;  /* T_COSE_ELLIPTIC_CURVE_* */
    psa_key_type_t psa_type;  /* PSA key type */
    size_t         key_bits;  /* bits */
} suite_params_t;


/* Parse "--alg HPKE-*" -> COSE HPKE alg ID */
static bool parse_hpke_alg_name(const char *name, int32_t *out_alg)
{
    if(!name || !out_alg) return false;

    if(strcmp(name, "HPKE-0") == 0) { *out_alg = T_COSE_HPKE_Base_P256_SHA256_AES128GCM; return true; }
    if(strcmp(name, "HPKE-1") == 0) { *out_alg = T_COSE_HPKE_Base_P384_SHA384_AES256GCM; return true; }
    if(strcmp(name, "HPKE-2") == 0) { *out_alg = T_COSE_HPKE_Base_P521_SHA512_AES256GCM; return true; }
    if(strcmp(name, "HPKE-3") == 0) { *out_alg = T_COSE_HPKE_Base_X25519_SHA256_AES128GCM; return true; }
    if(strcmp(name, "HPKE-4") == 0) { *out_alg = T_COSE_HPKE_Base_X25519_SHA256_CHACHA20POLY1305; return true; }
    if(strcmp(name, "HPKE-5") == 0) { *out_alg = T_COSE_HPKE_Base_X448_SHA512_AES256GCM; return true; }
    if(strcmp(name, "HPKE-6") == 0) { *out_alg = T_COSE_HPKE_Base_X448_SHA512_CHACHA20POLY1305; return true; }
    if(strcmp(name, "HPKE-7") == 0) { *out_alg = T_COSE_HPKE_Base_P256_SHA256_AES256GCM; return true; }

    if(strcmp(name, "HPKE-0-KE") == 0) { *out_alg = T_COSE_HPKE_KE_P256_SHA256_AES128GCM; return true; }
    if(strcmp(name, "HPKE-1-KE") == 0) { *out_alg = T_COSE_HPKE_KE_P384_SHA384_AES256GCM; return true; }
    if(strcmp(name, "HPKE-2-KE") == 0) { *out_alg = T_COSE_HPKE_KE_P521_SHA512_AES256GCM; return true; }
    if(strcmp(name, "HPKE-3-KE") == 0) { *out_alg = T_COSE_HPKE_KE_X25519_SHA256_AES128GCM; return true; }
    if(strcmp(name, "HPKE-4-KE") == 0) { *out_alg = T_COSE_HPKE_KE_X25519_SHA256_CHACHA20POLY1305; return true; }
    if(strcmp(name, "HPKE-5-KE") == 0) { *out_alg = T_COSE_HPKE_KE_X448_SHA512_AES256GCM; return true; }
    if(strcmp(name, "HPKE-6-KE") == 0) { *out_alg = T_COSE_HPKE_KE_X448_SHA512_CHACHA20POLY1305; return true; }
    if(strcmp(name, "HPKE-7-KE") == 0) { *out_alg = T_COSE_HPKE_KE_P256_SHA256_AES256GCM; return true; }

    return false;
}


/* Derive key generation parameters from HPKE suite alg */
static bool suite_params_from_hpke_alg(int32_t cose_hpke_alg, suite_params_t *out)
{
    if(!out) return false;
    memset(out, 0, sizeof(*out));
    out->cose_alg = cose_hpke_alg;

    switch(cose_hpke_alg) {
    case T_COSE_HPKE_Base_P256_SHA256_AES128GCM:
        out->cose_kty = T_COSE_KEY_TYPE_EC2;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_P_256;
        out->key_bits = 256;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        return true;

    case T_COSE_HPKE_Base_P384_SHA384_AES256GCM:
        out->cose_kty = T_COSE_KEY_TYPE_EC2;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_P_384;
        out->key_bits = 384;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        return true;

    case T_COSE_HPKE_Base_P521_SHA512_AES256GCM:
        out->cose_kty = T_COSE_KEY_TYPE_EC2;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_P_521;
        out->key_bits = 521;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        return true;

    case T_COSE_HPKE_Base_X25519_SHA256_AES128GCM:
    case T_COSE_HPKE_Base_X25519_SHA256_CHACHA20POLY1305:
        out->cose_kty = T_COSE_KEY_TYPE_OKP;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_X25519;
        out->key_bits = 255;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        return true;

    case T_COSE_HPKE_Base_X448_SHA512_AES256GCM:
    case T_COSE_HPKE_Base_X448_SHA512_CHACHA20POLY1305:
        out->cose_kty = T_COSE_KEY_TYPE_OKP;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_X448;
        out->key_bits = 448;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        return true;
    case T_COSE_HPKE_Base_P256_SHA256_AES256GCM:
        out->cose_kty = T_COSE_KEY_TYPE_EC2;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_P_256;
        out->key_bits = 256;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        return true;
    /* KE variants share same key params as base suites */
    case T_COSE_HPKE_KE_P256_SHA256_AES128GCM:
    case T_COSE_HPKE_KE_P256_SHA256_AES256GCM:
        out->cose_kty = T_COSE_KEY_TYPE_EC2;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_P_256;
        out->key_bits = 256;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        return true;
    case T_COSE_HPKE_KE_P384_SHA384_AES256GCM:
        out->cose_kty = T_COSE_KEY_TYPE_EC2;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_P_384;
        out->key_bits = 384;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        return true;
    case T_COSE_HPKE_KE_P521_SHA512_AES256GCM:
        out->cose_kty = T_COSE_KEY_TYPE_EC2;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_P_521;
        out->key_bits = 521;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        return true;
    case T_COSE_HPKE_KE_X25519_SHA256_AES128GCM:
    case T_COSE_HPKE_KE_X25519_SHA256_CHACHA20POLY1305:
        out->cose_kty = T_COSE_KEY_TYPE_OKP;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_X25519;
        out->key_bits = 255;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        return true;
    case T_COSE_HPKE_KE_X448_SHA512_AES256GCM:
    case T_COSE_HPKE_KE_X448_SHA512_CHACHA20POLY1305:
        out->cose_kty = T_COSE_KEY_TYPE_OKP;
        out->cose_crv = T_COSE_ELLIPTIC_CURVE_X448;
        out->key_bits = 448;
        out->psa_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        return true;

    default:
        return false;
    }
}


static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --alg HPKE-0..HPKE-7 or HPKE-0-KE..HPKE-7-KE --kid KID --pub-out FILE --full-out FILE\n"
        "\n"
        "Options:\n"
        "  -a, --alg       HPKE ciphersuite label (HPKE-0..HPKE-7 or HPKE-0-KE..HPKE-7-KE)\n"
        "  -k, --kid       Key ID (ASCII, stored as bstr)\n"
        "      --pub-out   Output file for PUBLIC COSE_Key\n"
        "      --full-out  Output file for FULL COSE_Key (public+private)\n"
        "\n"
        "Example:\n"
        "  %s -a HPKE-0 -k 01 --pub-out hpke0_pub.cbor --full-out hpke0_full.cbor\n",
        prog, prog);
}


/* Write buffer to file (supports "-" for stdout) */
static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = NULL;

    if(strcmp(path, "-") == 0) {
        f = stdout;
    } else {
        f = fopen(path, "wb");
        if(!f) {
            fprintf(stderr, "Error opening '%s': %s\n", path, strerror(errno));
            return -1;
        }
    }

    if(fwrite(buf, 1, len, f) != len) {
        fprintf(stderr, "Error writing '%s': %s\n", path, strerror(errno));
        if(f != stdout) fclose(f);
        return -1;
    }

    if(f != stdout) fclose(f);
    return 0;
}


/*
 * Generate PSA key pair and export private/public parts.
 * Caller must free(*priv) and *pub.
 */
static int generate_psa_keypair(const suite_params_t *suite,
                                uint8_t **priv, size_t *priv_len,
                                uint8_t **pub,  size_t *pub_len)
{
    psa_status_t status;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    size_t priv_buf_len = 0;
    size_t pub_buf_len  = 0;
    uint8_t *priv_buf = NULL;
    uint8_t *pub_buf  = NULL;

    psa_set_key_type(&attr, suite->psa_type);
    psa_set_key_bits(&attr, suite->key_bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&attr, &key_id);
    if(status != PSA_SUCCESS) {
        fprintf(stderr, "psa_generate_key failed: %d\n", status);
        return -1;
    }

    /* Private key length: ceil(bits/8) */
    priv_buf_len = (suite->key_bits + 7) / 8;
    priv_buf = (uint8_t *)malloc(priv_buf_len);
    if(!priv_buf) {
        fprintf(stderr, "Out of memory\n");
        goto error;
    }

    status = psa_export_key(key_id, priv_buf, priv_buf_len, priv_len);
    if(status != PSA_SUCCESS) {
        fprintf(stderr, "psa_export_key failed: %d\n", status);
        goto error;
    }

    /* Public key length:
     *  - EC2: uncompressed point: 0x04 || X || Y
     *  - OKP: raw public key bytes
     */
    if(suite->cose_kty == T_COSE_KEY_TYPE_EC2) {
        size_t coord_len = (suite->key_bits + 7) / 8;
        pub_buf_len = 1 + 2 * coord_len;
    } else {
        pub_buf_len = (suite->key_bits + 7) / 8;
    }

    pub_buf = (uint8_t *)malloc(pub_buf_len);
    if(!pub_buf) {
        fprintf(stderr, "Out of memory\n");
        goto error;
    }

    status = psa_export_public_key(key_id, pub_buf, pub_buf_len, pub_len);
    if(status != PSA_SUCCESS) {
        fprintf(stderr, "psa_export_public_key failed: %d\n", status);
        goto error;
    }

    psa_destroy_key(key_id);

    *priv = priv_buf;
    *pub  = pub_buf;
    return 0;

error:
    if(key_id != 0) {
        psa_destroy_key(key_id);
    }
    free(priv_buf);
    free(pub_buf);
    return -1;
}


/* ============================================================
 * (4) Validation helpers: format & lengths after export
 * ============================================================ */

static bool validate_exported_key_material(const suite_params_t *suite,
                                          const uint8_t *priv, size_t priv_len,
                                          const uint8_t *pub,  size_t pub_len,
                                          size_t *out_coord_len /* EC2 only */)
{
    if(!suite || !priv || !pub) return false;

    size_t exp_priv_len = (suite->key_bits + 7) / 8;

    if(priv_len != exp_priv_len) {
        fprintf(stderr,
                "Unexpected private key length: got %zu, expected %zu\n",
                priv_len, exp_priv_len);
        return false;
    }

    if(suite->cose_kty == T_COSE_KEY_TYPE_EC2) {
        size_t coord_len = (suite->key_bits + 7) / 8;
        size_t exp_pub_len = 1 + 2 * coord_len;

        if(pub_len != exp_pub_len) {
            fprintf(stderr,
                    "Unexpected EC2 public key length: got %zu, expected %zu\n",
                    pub_len, exp_pub_len);
            return false;
        }
        if(pub[0] != 0x04) {
            fprintf(stderr,
                    "Unexpected EC2 public key format: first byte 0x%02x (expected 0x04)\n",
                    pub[0]);
            return false;
        }

        if(out_coord_len) *out_coord_len = coord_len;
        return true;
    }

    /* OKP */
    if(suite->cose_kty == T_COSE_KEY_TYPE_OKP) {
        size_t exp_pub_len = (suite->key_bits + 7) / 8;

        if(pub_len != exp_pub_len) {
            fprintf(stderr,
                    "Unexpected OKP public key length: got %zu, expected %zu\n",
                    pub_len, exp_pub_len);
            return false;
        }

        /* For OKP: private scalar length should match too (already checked) */
        if(out_coord_len) *out_coord_len = 0;
        return true;
    }

    fprintf(stderr, "Unknown kty=%d\n", suite->cose_kty);
    return false;
}


/* ============================================================
 * (1)(2) Minimal COSE_Key encoders (no key_ops)
 * ============================================================ */

/* Encode EC2 COSE_Key (public or full) - minimal fields only */
static int encode_cose_ec2_key(const suite_params_t *suite,
                               const uint8_t *kid, size_t kid_len,
                               const uint8_t *x,   size_t x_len,
                               const uint8_t *y,   size_t y_len,
                               const uint8_t *d,   size_t d_len,
                               bool include_private,
                               UsefulBuf out_buf,
                               UsefulBufC *out_cbor)
{
    QCBOREncodeContext ec;
    QCBOREncode_Init(&ec, out_buf);

    QCBOREncode_OpenMap(&ec);

    /* Minimal mandatory/expected fields */
    QCBOREncode_AddInt64ToMapN(&ec, T_COSE_KEY_COMMON_KTY, suite->cose_kty);

    UsefulBufC kid_ub = { kid, kid_len };
    QCBOREncode_AddBytesToMapN(&ec, T_COSE_KEY_COMMON_KID, kid_ub);

    QCBOREncode_AddInt64ToMapN(&ec, T_COSE_KEY_COMMON_ALG, suite->cose_alg);

    QCBOREncode_AddInt64ToMapN(&ec, T_COSE_KEY_PARAM_CRV, suite->cose_crv);

    UsefulBufC x_ub = { x, x_len };
    UsefulBufC y_ub = { y, y_len };
    QCBOREncode_AddBytesToMapN(&ec, T_COSE_KEY_PARAM_X_COORDINATE, x_ub);
    QCBOREncode_AddBytesToMapN(&ec, T_COSE_KEY_PARAM_Y_COORDINATE, y_ub);

    if(include_private && d && d_len > 0) {
        UsefulBufC d_ub = { d, d_len };
        QCBOREncode_AddBytesToMapN(&ec, T_COSE_KEY_PARAM_PRIVATE_D, d_ub);
    }

    QCBOREncode_CloseMap(&ec);

    QCBORError err = QCBOREncode_Finish(&ec, out_cbor);
    if(err != QCBOR_SUCCESS) {
        fprintf(stderr, "QCBOREncode_Finish EC2 failed: %d\n", err);
        return -1;
    }
    return 0;
}


/* Encode OKP COSE_Key (public or full) - minimal fields only */
static int encode_cose_okp_key(const suite_params_t *suite,
                               const uint8_t *kid, size_t kid_len,
                               const uint8_t *x,   size_t x_len,
                               const uint8_t *d,   size_t d_len,
                               bool include_private,
                               UsefulBuf out_buf,
                               UsefulBufC *out_cbor)
{
    QCBOREncodeContext ec;
    QCBOREncode_Init(&ec, out_buf);

    QCBOREncode_OpenMap(&ec);

    /* Minimal mandatory/expected fields */
    QCBOREncode_AddInt64ToMapN(&ec, T_COSE_KEY_COMMON_KTY, suite->cose_kty);

    UsefulBufC kid_ub = { kid, kid_len };
    QCBOREncode_AddBytesToMapN(&ec, T_COSE_KEY_COMMON_KID, kid_ub);

    QCBOREncode_AddInt64ToMapN(&ec, T_COSE_KEY_COMMON_ALG, suite->cose_alg);

    QCBOREncode_AddInt64ToMapN(&ec, T_COSE_KEY_PARAM_CRV, suite->cose_crv);

    UsefulBufC x_ub = { x, x_len };
    QCBOREncode_AddBytesToMapN(&ec, T_COSE_KEY_PARAM_X_COORDINATE, x_ub);

    if(include_private && d && d_len > 0) {
        UsefulBufC d_ub = { d, d_len };
        QCBOREncode_AddBytesToMapN(&ec, T_COSE_KEY_PARAM_PRIVATE_D, d_ub);
    }

    QCBOREncode_CloseMap(&ec);

    QCBORError err = QCBOREncode_Finish(&ec, out_cbor);
    if(err != QCBOR_SUCCESS) {
        fprintf(stderr, "QCBOREncode_Finish OKP failed: %d\n", err);
        return -1;
    }
    return 0;
}


int main(int argc, char *argv[])
{
    const char *alg_name = NULL;
    const char *kid_str  = NULL;
    const char *pub_out  = NULL;
    const char *full_out = NULL;

    static struct option long_opts[] = {
        { "alg",      required_argument, 0, 'a' },
        { "kid",      required_argument, 0, 'k' },
        { "pub-out",  required_argument, 0,  0  },
        { "full-out", required_argument, 0,  0  },
        { 0, 0, 0, 0 }
    };

    int opt;
    int opt_index = 0;
    while((opt = getopt_long(argc, argv, "a:k:", long_opts, &opt_index)) != -1) {
        switch(opt) {
        case 'a':
            alg_name = optarg;
            break;
        case 'k':
            kid_str = optarg;
            break;
        case 0:
            if(strcmp(long_opts[opt_index].name, "pub-out") == 0) {
                pub_out = optarg;
            } else if(strcmp(long_opts[opt_index].name, "full-out") == 0) {
                full_out = optarg;
            }
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if(!alg_name || !kid_str || !pub_out || !full_out) {
        usage(argv[0]);
        return 1;
    }

    int32_t hpke_alg = 0;
    if(!parse_hpke_alg_name(alg_name, &hpke_alg)) {
        fprintf(stderr, "Unsupported alg '%s'. Use HPKE-0..HPKE-6.\n", alg_name);
        return 1;
    }

    suite_params_t suite;
    if(!suite_params_from_hpke_alg(hpke_alg, &suite)) {
        fprintf(stderr, "Internal error: cannot derive suite params for alg=%d\n", hpke_alg);
        return 1;
    }

    psa_status_t st = psa_crypto_init();
    if(st != PSA_SUCCESS) {
        fprintf(stderr, "psa_crypto_init failed: %d\n", st);
        return 1;
    }

    uint8_t *priv = NULL, *pub = NULL;
    size_t   priv_len = 0, pub_len = 0;

    if(generate_psa_keypair(&suite, &priv, &priv_len, &pub, &pub_len) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    /* (4) Validate exported material right away */
    size_t coord_len = 0;
    if(!validate_exported_key_material(&suite, priv, priv_len, pub, pub_len, &coord_len)) {
        fprintf(stderr, "Exported key material validation failed\n");
        free(priv);
        free(pub);
        return 1;
    }

    const uint8_t *kid_bytes = (const uint8_t *)kid_str;
    size_t kid_len = strlen(kid_str);

    /* (3) Larger CBOR buffers */
    uint8_t pub_cbor_storage[1024];
    uint8_t full_cbor_storage[1024];
    UsefulBuf pub_buf  = { pub_cbor_storage,  sizeof(pub_cbor_storage) };
    UsefulBuf full_buf = { full_cbor_storage, sizeof(full_cbor_storage) };

    int rc = 0;

    if(suite.cose_kty == T_COSE_KEY_TYPE_EC2) {
        const uint8_t *x = pub + 1;
        const uint8_t *y = pub + 1 + coord_len;

        UsefulBufC pub_cbor;
        if(encode_cose_ec2_key(&suite,
                               kid_bytes, kid_len,
                               x, coord_len,
                               y, coord_len,
                               NULL, 0,
                               false,
                               pub_buf,
                               &pub_cbor) != 0) {
            rc = 1;
            goto cleanup;
        }
        if(write_file(pub_out, pub_cbor.ptr, pub_cbor.len) != 0) {
            rc = 1;
            goto cleanup;
        }

        UsefulBufC full_cbor;
        if(encode_cose_ec2_key(&suite,
                               kid_bytes, kid_len,
                               x, coord_len,
                               y, coord_len,
                               priv, priv_len,
                               true,
                               full_buf,
                               &full_cbor) != 0) {
            rc = 1;
            goto cleanup;
        }
        if(write_file(full_out, full_cbor.ptr, full_cbor.len) != 0) {
            rc = 1;
            goto cleanup;
        }

    } else { /* OKP */
        UsefulBufC pub_cbor;
        if(encode_cose_okp_key(&suite,
                               kid_bytes, kid_len,
                               pub, pub_len,
                               NULL, 0,
                               false,
                               pub_buf,
                               &pub_cbor) != 0) {
            rc = 1;
            goto cleanup;
        }
        if(write_file(pub_out, pub_cbor.ptr, pub_cbor.len) != 0) {
            rc = 1;
            goto cleanup;
        }

        UsefulBufC full_cbor;
        if(encode_cose_okp_key(&suite,
                               kid_bytes, kid_len,
                               pub, pub_len,
                               priv, priv_len,
                               true,
                               full_buf,
                               &full_cbor) != 0) {
            rc = 1;
            goto cleanup;
        }
        if(write_file(full_out, full_cbor.ptr, full_cbor.len) != 0) {
            rc = 1;
            goto cleanup;
        }
    }

    printf("Generated COSE_Key (public) -> %s\n", pub_out);
    printf("Generated COSE_Key (full)   -> %s\n", full_out);
//    printf("Suite=%s (alg=%d) kid='%s'\n", alg_name, (int)hpke_alg, kid_str);

cleanup:
    free(priv);
    free(pub);
    return rc;
}
