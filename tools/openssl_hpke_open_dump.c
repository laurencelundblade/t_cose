/*
 * openssl_hpke_open_dump.c
 *
 * Decrypt HPKE enc/ct via OpenSSL for a given suite and inputs.
 * Outputs: pt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>


struct input_data {
    int mode;
    uint16_t kem_id;
    uint16_t kdf_id;
    uint16_t aead_id;
    unsigned char *ikmR; size_t ikmR_len;
    unsigned char *psk; size_t psk_len;
    unsigned char *psk_id; size_t psk_id_len;
    unsigned char *pkS; size_t pkS_len;
    unsigned char *skR; size_t skR_len;
    unsigned char *enc; size_t enc_len;
    unsigned char *ct; size_t ct_len;
    unsigned char *aad; size_t aad_len;
    unsigned char *info; size_t info_len;
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
    if(len % 2 != 0) {
        return -1;
    }
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

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;
    printf("%s=", label);
    for(i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static EVP_PKEY *import_raw_private(OSSL_LIB_CTX *libctx, uint16_t kem_id,
                                    const unsigned char *buf, size_t len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    char *group_name = NULL;
    BIGNUM *bn = NULL;
    unsigned char *bn_buf = NULL;
    int bn_len = 0;

    switch(kem_id) {
    case OSSL_HPKE_KEM_ID_X25519:
        return EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL, buf, len);
    case OSSL_HPKE_KEM_ID_X448:
        return EVP_PKEY_new_raw_private_key_ex(libctx, "X448", NULL, buf, len);
    case OSSL_HPKE_KEM_ID_P256:
        group_name = "P-256";
        break;
    case OSSL_HPKE_KEM_ID_P384:
        group_name = "P-384";
        break;
    case OSSL_HPKE_KEM_ID_P521:
        group_name = "P-521";
        break;
    default:
        return NULL;
    }

    pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    if(pctx == NULL) {
        return NULL;
    }
    if(EVP_PKEY_fromdata_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    bn = BN_bin2bn(buf, (int)len, NULL);
    if(bn == NULL) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    bn_len = BN_num_bytes(bn);
    if(bn_len <= 0) {
        BN_free(bn);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    bn_buf = OPENSSL_malloc((size_t)bn_len);
    if(bn_buf == NULL) {
        BN_free(bn);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    if(BN_bn2binpad(bn, bn_buf, bn_len) != bn_len) {
        OPENSSL_free(bn_buf);
        BN_free(bn);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    params[1] = OSSL_PARAM_construct_BN(
        OSSL_PKEY_PARAM_PRIV_KEY, bn_buf, (size_t)bn_len);
    params[2] = OSSL_PARAM_construct_end();

    if(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        OPENSSL_free(bn_buf);
        BN_free(bn);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    OPENSSL_free(bn_buf);
    BN_free(bn);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

int main(void)
{
    struct input_data in;
    char line[8192];
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *openctx = NULL;
    EVP_PKEY *skR = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *defprov = NULL;
    OSSL_PROVIDER *nullprov = NULL;
    char *psk_id_cstr = NULL;
    unsigned char pt[4096];
    size_t ptlen = sizeof(pt);

    memset(&in, 0, sizeof(in));
    while(fgets(line, sizeof(line), stdin) != NULL) {
        char *eq = strchr(line, '=');
        if(!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        size_t len = strlen(val);
        if(len > 0 && val[len - 1] == '\n') val[len - 1] = '\0';

        if(strcmp(key, "mode") == 0) in.mode = atoi(val);
        else if(strcmp(key, "kem_id") == 0) in.kem_id = (uint16_t)strtoul(val, NULL, 10);
        else if(strcmp(key, "kdf_id") == 0) in.kdf_id = (uint16_t)strtoul(val, NULL, 10);
        else if(strcmp(key, "aead_id") == 0) in.aead_id = (uint16_t)strtoul(val, NULL, 10);
        else if(strcmp(key, "ikmR") == 0) hex2bin(val, &in.ikmR, &in.ikmR_len);
        else if(strcmp(key, "psk") == 0) hex2bin(val, &in.psk, &in.psk_len);
        else if(strcmp(key, "psk_id") == 0) hex2bin(val, &in.psk_id, &in.psk_id_len);
        else if(strcmp(key, "pkS") == 0) hex2bin(val, &in.pkS, &in.pkS_len);
        else if(strcmp(key, "skR") == 0) hex2bin(val, &in.skR, &in.skR_len);
        else if(strcmp(key, "enc") == 0) hex2bin(val, &in.enc, &in.enc_len);
        else if(strcmp(key, "ct") == 0) hex2bin(val, &in.ct, &in.ct_len);
        else if(strcmp(key, "aad") == 0) hex2bin(val, &in.aad, &in.aad_len);
        else if(strcmp(key, "info") == 0) hex2bin(val, &in.info, &in.info_len);
    }

    libctx = OSSL_LIB_CTX_new();
    if(libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new failed\n");
        return 1;
    }
    defprov = OSSL_PROVIDER_load(libctx, "default");
    if(defprov == NULL) {
        fprintf(stderr, "OSSL_PROVIDER_load(default) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    nullprov = OSSL_PROVIDER_load(libctx, "null");

    suite.kem_id = in.kem_id;
    suite.kdf_id = in.kdf_id;
    suite.aead_id = in.aead_id;

    if(in.ikmR_len > 0) {
        unsigned char pubR[512];
        size_t pubR_len = sizeof(pubR);
        if(!OSSL_HPKE_keygen(suite, pubR, &pubR_len, &skR,
                             in.ikmR, in.ikmR_len, libctx, "provider=default")) {
            fprintf(stderr, "OSSL_HPKE_keygen(skR) failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
    } else {
        skR = import_raw_private(libctx, in.kem_id, in.skR, in.skR_len);
        if(skR == NULL) {
            fprintf(stderr, "import skR failed (kem_id=%u)\n", (unsigned)in.kem_id);
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    openctx = OSSL_HPKE_CTX_new(in.mode, suite, OSSL_HPKE_ROLE_RECEIVER, libctx, "provider=default");
    if(openctx == NULL) {
        fprintf(stderr, "OSSL_HPKE_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if(in.psk_len && in.psk_id_len) {
        psk_id_cstr = (char *)malloc(in.psk_id_len + 1);
        if(psk_id_cstr == NULL) {
            fprintf(stderr, "malloc failed for psk_id\n");
            return 1;
        }
        memcpy(psk_id_cstr, in.psk_id, in.psk_id_len);
        psk_id_cstr[in.psk_id_len] = '\0';
        if(!OSSL_HPKE_CTX_set1_psk(openctx, psk_id_cstr, in.psk, in.psk_len)) {
            fprintf(stderr, "OSSL_HPKE_CTX_set1_psk failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    if(in.pkS_len > 0) {
        if(!OSSL_HPKE_CTX_set1_authpub(openctx, in.pkS, in.pkS_len)) {
            fprintf(stderr, "OSSL_HPKE_CTX_set1_authpub failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    if(!OSSL_HPKE_decap(openctx, in.enc, in.enc_len, skR, in.info, in.info_len)) {
        fprintf(stderr, "OSSL_HPKE_decap failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if(!OSSL_HPKE_open(openctx, pt, &ptlen, in.aad, in.aad_len, in.ct, in.ct_len)) {
        fprintf(stderr, "OSSL_HPKE_open failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    print_hex("pt", pt, ptlen);

    OSSL_HPKE_CTX_free(openctx);
    EVP_PKEY_free(skR);
    if(nullprov) OSSL_PROVIDER_unload(nullprov);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(libctx);
    free(psk_id_cstr);
    free(in.psk);
    free(in.psk_id);
    free(in.ikmR);
    free(in.pkS);
    free(in.skR);
    free(in.enc);
    free(in.ct);
    free(in.aad);
    free(in.info);
    return 0;
}
