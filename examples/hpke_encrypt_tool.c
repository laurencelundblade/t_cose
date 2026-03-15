/*
 * hpke_encrypt_tool.c
 *
 * Read key=value inputs and perform HPKE encrypt using t_cose HPKE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"
#include "hpke.h"


struct input_data {
    unsigned int mode;
    hpke_suite_t suite;
    unsigned char *psk; size_t psk_len;
    unsigned char *psk_id; size_t psk_id_len;
    unsigned char *pkR; size_t pkR_len;
    unsigned char *skE; size_t skE_len;
    unsigned char *skS; size_t skS_len;
    unsigned char *aad; size_t aad_len;
    unsigned char *info; size_t info_len;
    unsigned char *pt; size_t pt_len;
};

static int hex2bin(const char *hex, unsigned char **out, size_t *out_len)
{
    size_t len;
    size_t i;
    unsigned char *buf;

    if(hex == NULL || *hex == '\0') {
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    len = strlen(hex);
    if(len % 2 != 0) return -1;
    buf = (unsigned char *)malloc(len / 2);
    if(!buf) return -1;
    for(i = 0; i < len; i += 2) {
        char hi = hex[i];
        char lo = hex[i + 1];
        unsigned char v = 0;
        if(hi >= '0' && hi <= '9') v = (unsigned char)(hi - '0') << 4;
        else if(hi >= 'a' && hi <= 'f') v = (unsigned char)(hi - 'a' + 10) << 4;
        else if(hi >= 'A' && hi <= 'F') v = (unsigned char)(hi - 'A' + 10) << 4;
        else { free(buf); return -1; }
        if(lo >= '0' && lo <= '9') v |= (unsigned char)(lo - '0');
        else if(lo >= 'a' && lo <= 'f') v |= (unsigned char)(lo - 'a' + 10);
        else if(lo >= 'A' && lo <= 'F') v |= (unsigned char)(lo - 'A' + 10);
        else { free(buf); return -1; }
        buf[i/2] = v;
    }
    *out = buf;
    *out_len = len / 2;
    return 0;
}

static int import_private_key(int kem_id,
                              const unsigned char *sk,
                              size_t sk_len,
                              psa_key_handle_t *out_handle)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_type_t type = 0;
    size_t bits = 0;
    psa_status_t st;

    switch(kem_id) {
    case HPKE_KEM_ID_P256:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        bits = 256;
        break;
    case HPKE_KEM_ID_P384:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        bits = 384;
        break;
    case HPKE_KEM_ID_P521:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        bits = 521;
        break;
    case HPKE_KEM_ID_25519:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        bits = 255;
        break;
    case HPKE_KEM_ID_448:
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

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;
    printf("%s=", label);
    for(i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void)
{
    struct input_data in;
    char line[8192];
    psa_key_handle_t skE = 0;
    psa_key_handle_t skS = 0;
    int ret = 1;

    memset(&in, 0, sizeof(in));
    while(fgets(line, sizeof(line), stdin) != NULL) {
        char *eq = strchr(line, '=');
        if(!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        size_t len = strlen(val);
        if(len > 0 && val[len - 1] == '\n') val[len - 1] = '\0';

        if(strcmp(key, "mode") == 0) in.mode = (unsigned int)strtoul(val, NULL, 10);
        else if(strcmp(key, "kem_id") == 0) in.suite.kem_id = (uint16_t)strtoul(val, NULL, 10);
        else if(strcmp(key, "kdf_id") == 0) in.suite.kdf_id = (uint16_t)strtoul(val, NULL, 10);
        else if(strcmp(key, "aead_id") == 0) in.suite.aead_id = (uint16_t)strtoul(val, NULL, 10);
        else if(strcmp(key, "psk") == 0) hex2bin(val, &in.psk, &in.psk_len);
        else if(strcmp(key, "psk_id") == 0) hex2bin(val, &in.psk_id, &in.psk_id_len);
        else if(strcmp(key, "pkR") == 0) hex2bin(val, &in.pkR, &in.pkR_len);
        else if(strcmp(key, "skE") == 0) hex2bin(val, &in.skE, &in.skE_len);
        else if(strcmp(key, "skS") == 0) hex2bin(val, &in.skS, &in.skS_len);
        else if(strcmp(key, "aad") == 0) hex2bin(val, &in.aad, &in.aad_len);
        else if(strcmp(key, "info") == 0) hex2bin(val, &in.info, &in.info_len);
        else if(strcmp(key, "pt") == 0) hex2bin(val, &in.pt, &in.pt_len);
    }

    if(psa_crypto_init() != PSA_SUCCESS) {
        fprintf(stderr, "psa_crypto_init failed\n");
        return 1;
    }

    if(import_private_key(in.suite.kem_id, in.skE, in.skE_len, &skE) != 0) {
        goto cleanup;
    }
    if(in.skS_len > 0 && import_private_key(in.suite.kem_id, in.skS, in.skS_len, &skS) != 0) {
        goto cleanup;
    }

    {
        unsigned char enc[512];
        size_t enc_len = sizeof(enc);
        unsigned char ct[2048];
        size_t ct_len = sizeof(ct);
        int res = mbedtls_hpke_encrypt(
            in.mode, in.suite,
            in.psk_id_len, in.psk_id_len ? in.psk_id : NULL,
            in.psk_len, in.psk,
            in.pkR_len, in.pkR,
            skS,
            in.pt_len, in.pt,
            in.aad_len, in.aad,
            in.info_len, in.info,
            skE,
            &enc_len, enc,
            &ct_len, ct);
        if(res != 0) {
            fprintf(stderr, "mbedtls_hpke_encrypt failed: %d\n", res);
            goto cleanup;
        }

        print_hex("enc", enc, enc_len);
        print_hex("ct", ct, ct_len);

        if(skS != 0) {
            unsigned char pkS[512];
            size_t pkS_len = sizeof(pkS);
            if(psa_export_public_key(skS, pkS, sizeof(pkS), &pkS_len) == PSA_SUCCESS) {
                print_hex("pkS", pkS, pkS_len);
            }
        }
    }

    ret = 0;
cleanup:
    if(skE) psa_destroy_key(skE);
    if(skS) psa_destroy_key(skS);
    free(in.psk);
    free(in.psk_id);
    free(in.pkR);
    free(in.skE);
    free(in.skS);
    free(in.aad);
    free(in.info);
    free(in.pt);
    return ret;
}
