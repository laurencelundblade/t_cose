/*
 * hpke_rfc9180_vectors.c
 *
 * RFC 9180 Appendix A test vectors for HPKE (single-shot encrypt/decrypt).
 *
 * This program expects the test vectors in examples/rfc9180_vectors.h.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "psa/crypto.h"
#include "t_cose/t_cose_standard_constants.h"
#include "hpke.h"

#include "rfc9180_vectors.h"


static void hexdump(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    printf("%s (%zu): ", label, len);
    for(i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}


static int import_private_key(int kem_id,
                              const uint8_t *sk,
                              size_t sk_len,
                              psa_key_handle_t *out_handle)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_type_t type = 0;
    size_t bits = 0;
    psa_status_t st;

    switch(kem_id) {
    case T_COSE_HPKE_KEM_ID_P256:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        bits = 256;
        break;
    case T_COSE_HPKE_KEM_ID_P384:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        bits = 384;
        break;
    case T_COSE_HPKE_KEM_ID_P521:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        bits = 521;
        break;
    case T_COSE_HPKE_KEM_ID_25519:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        bits = 255;
        break;
    case T_COSE_HPKE_KEM_ID_448:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        bits = 448;
        break;
    default:
        return -1;
    }

    psa_set_key_type(&attr, type);
    psa_set_key_bits(&attr, bits);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    st = psa_import_key(&attr, sk, sk_len, out_handle);
    if(st != PSA_SUCCESS) {
        fprintf(stderr, "psa_import_key failed (kem=%d, status=%d)\n", kem_id, (int)st);
        return -1;
    }
    return 0;
}


static int run_vector(const struct hpke_rfc9180_vector *v)
{
    int ret = 0;
    psa_key_handle_t skR = 0;
    psa_key_handle_t skS = 0;
    psa_key_handle_t skE = 0;

    hpke_suite_t suite;
    suite.kem_id = (uint16_t)v->kem_id;
    suite.kdf_id = (uint16_t)v->kdf_id;
    suite.aead_id = (uint16_t)v->aead_id;

    if(v->skRm_len == 0 || v->pkRm_len == 0 || v->skEm_len == 0 || v->enc_len == 0) {
        fprintf(stderr, "Missing mandatory fields for %s / %s\n", v->suite_name, v->mode_name);
        return -1;
    }

    if(import_private_key(v->kem_id, v->skRm, v->skRm_len, &skR) != 0) {
        return -1;
    }
    if(v->skSm_len > 0) {
        if(import_private_key(v->kem_id, v->skSm, v->skSm_len, &skS) != 0) {
            psa_destroy_key(skR);
            return -1;
        }
    }
    if(import_private_key(v->kem_id, v->skEm, v->skEm_len, &skE) != 0) {
        psa_destroy_key(skR);
        if(skS) psa_destroy_key(skS);
        return -1;
    }

    for(size_t i = 0; i < v->encs_len; i++) {
        const struct hpke_rfc9180_enc *e = &v->encs[i];
        if(e->pt_len == 0 || e->ct_len == 0) {
            fprintf(stderr, "Missing pt/ct for %s / %s (enc %zu)\n", v->suite_name, v->mode_name, i);
            ret = -1;
            break;
        }
        uint8_t enc_buf[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
        size_t enc_len = sizeof(enc_buf);
        size_t ct_len = e->ct_len + 32;
        size_t pt_len = e->pt_len + 32;
        uint8_t *ct_buf = (uint8_t *)malloc(ct_len);
        uint8_t *pt_buf = (uint8_t *)malloc(pt_len);
        if(!ct_buf || !pt_buf) {
            free(ct_buf);
            free(pt_buf);
            ret = -1;
            break;
        }

        /* Encrypt with deterministic skE (vector skEm) */
        fprintf(stderr, "  enc start (enc %zu)\n", i);
        ret = mbedtls_hpke_encrypt(
            v->mode, suite,
            v->psk_id_len, v->psk_id_len ? v->psk_id : NULL,
            v->psk_len, (uint8_t *)v->psk,
            v->pkRm_len, (uint8_t *)v->pkRm,
            skS,
            e->pt_len, e->pt,
            e->aad_len, (uint8_t *)e->aad,
            v->info_len, (uint8_t *)v->info,
            skE,
            &enc_len, enc_buf,
            &ct_len, ct_buf);

        if(ret != 0) {
            fprintf(stderr, "Encrypt failed: %s / %s (enc %zu)\n", v->suite_name, v->mode_name, i);
            ret = -1;
            free(ct_buf);
            free(pt_buf);
            break;
        }
        fprintf(stderr, "  enc ok (enc %zu)\n", i);

        if(enc_len != v->enc_len || memcmp(enc_buf, v->enc, enc_len) != 0) {
            fprintf(stderr, "Enc mismatch: %s / %s (enc %zu)\n", v->suite_name, v->mode_name, i);
            hexdump("expected enc", v->enc, v->enc_len);
            hexdump("actual enc", enc_buf, enc_len);
            ret = -1;
            free(ct_buf);
            free(pt_buf);
            break;
        }
        if(ct_len != e->ct_len || memcmp(ct_buf, e->ct, ct_len) != 0) {
            fprintf(stderr, "CT mismatch: %s / %s (enc %zu)\n", v->suite_name, v->mode_name, i);
            hexdump("expected ct", e->ct, e->ct_len);
            hexdump("actual ct", ct_buf, ct_len);
            ret = -1;
            free(ct_buf);
            free(pt_buf);
            break;
        }

        /* Decrypt */
        fprintf(stderr, "  dec start (enc %zu)\n", i);
        ret = mbedtls_hpke_decrypt(
            v->mode, suite,
            v->psk_id_len, v->psk_id_len ? v->psk_id : NULL,
            v->psk_len, (uint8_t *)v->psk,
            v->pkSm_len, (uint8_t *)v->pkSm,
            skR,
            v->enc_len, (const uint8_t *)v->enc,
            e->ct_len, (const uint8_t *)e->ct,
            e->aad_len, (uint8_t *)e->aad,
            v->info_len, (uint8_t *)v->info,
            &pt_len, pt_buf);

        if(ret != 0) {
            fprintf(stderr, "Decrypt failed: %s / %s (enc %zu)\n", v->suite_name, v->mode_name, i);
            ret = -1;
            free(ct_buf);
            free(pt_buf);
            break;
        }
        fprintf(stderr, "  dec ok (enc %zu)\n", i);
        if(pt_len != e->pt_len || memcmp(pt_buf, e->pt, pt_len) != 0) {
            fprintf(stderr, "PT mismatch: %s / %s (enc %zu)\n", v->suite_name, v->mode_name, i);
            hexdump("expected pt", e->pt, e->pt_len);
            hexdump("actual pt", pt_buf, pt_len);
            ret = -1;
            free(ct_buf);
            free(pt_buf);
            break;
        }

        free(ct_buf);
        free(pt_buf);
    }

    psa_destroy_key(skR);
    if(skS) psa_destroy_key(skS);
    if(skE) psa_destroy_key(skE);
    return ret;
}


int main(void)
{
    psa_status_t st = psa_crypto_init();
    if(st != PSA_SUCCESS) {
        fprintf(stderr, "psa_crypto_init failed: %d\n", (int)st);
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    size_t start_idx = 0;
    size_t end_idx = hpke_rfc9180_vectors_len ? (hpke_rfc9180_vectors_len - 1) : 0;
    const char *start_env = getenv("HPKE_VECTOR_START");
    const char *end_env = getenv("HPKE_VECTOR_END");
    if(start_env && *start_env) {
        start_idx = (size_t)strtoul(start_env, NULL, 10);
    }
    if(end_env && *end_env) {
        end_idx = (size_t)strtoul(end_env, NULL, 10);
    }

    size_t passed = 0;
    for(size_t i = 0; i < hpke_rfc9180_vectors_len; i++) {
        if(i < start_idx || i > end_idx) {
            continue;
        }
        const struct hpke_rfc9180_vector *v = &hpke_rfc9180_vectors[i];
        fprintf(stderr, "Running vector %zu\n", i);
        printf("Vector %zu: %s / %s\n", i, v->suite_name, v->mode_name);
        fflush(stdout);
        if(run_vector(v) == 0) {
            passed++;
        } else {
            fprintf(stderr, "Vector failed: %s / %s\n", v->suite_name, v->mode_name);
        }
    }

    printf("RFC 9180 vectors: %zu/%zu passed\n", passed, hpke_rfc9180_vectors_len);
    return (passed == hpke_rfc9180_vectors_len) ? 0 : 1;
}
