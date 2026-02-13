/*
 * openssl_hpke_seal_dump.c
 *
 * Generate HPKE enc/ct via OpenSSL for a given suite and inputs.
 * Outputs: enc, ct, pkRm, skRm (if exportable).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/bn.h>


struct input_data {
    int mode;
    uint16_t kem_id;
    uint16_t kdf_id;
    uint16_t aead_id;
    unsigned char *ikmR; size_t ikmR_len;
    unsigned char *ikmE; size_t ikmE_len;
    unsigned char *ikmAuth; size_t ikmAuth_len;
    unsigned char *psk; size_t psk_len;
    unsigned char *psk_id; size_t psk_id_len;
    unsigned char *info; size_t info_len;
    unsigned char *aad; size_t aad_len;
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

static int export_pub(EVP_PKEY *pkey, unsigned char *out, size_t *outlen)
{
    return EVP_PKEY_get_octet_string_param(
        pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out, *outlen, outlen);
}

static int export_priv_raw(EVP_PKEY *pkey, uint16_t kem_id,
                           unsigned char *out, size_t *outlen)
{
    BIGNUM *bn = NULL;
    size_t need = 0;

    if(EVP_PKEY_get_octet_string_param(
            pkey, OSSL_PKEY_PARAM_PRIV_KEY, out, *outlen, outlen)) {
        return 1;
    }
    if(EVP_PKEY_get_raw_private_key(pkey, out, outlen)) {
        return 1;
    }

    switch(kem_id) {
    case OSSL_HPKE_KEM_ID_P256: need = 32; break;
    case OSSL_HPKE_KEM_ID_P384: need = 48; break;
    case OSSL_HPKE_KEM_ID_P521: need = 66; break;
    default: need = 0; break;
    }
    if(need != 0 && *outlen >= need &&
       EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn)) {
        if(BN_bn2binpad(bn, out, (int)need) == (int)need) {
            *outlen = need;
            BN_free(bn);
            return 1;
        }
        BN_free(bn);
    }

    return 0;
}

int main(void)
{
    struct input_data in;
    char line[8192];
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *sealctx = NULL;
    EVP_PKEY *skR = NULL;
    EVP_PKEY *skS = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *defprov = NULL;
    OSSL_PROVIDER *nullprov = NULL;
    unsigned char enc[512];
    size_t enclen = sizeof(enc);
    unsigned char ct[2048];
    size_t ctlen = sizeof(ct);
    unsigned char pkR[512];
    size_t pkR_len = sizeof(pkR);
    unsigned char skR_raw[512];
    size_t skR_raw_len = sizeof(skR_raw);
    unsigned char pkS[512];
    size_t pkS_len = sizeof(pkS);

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
        else if(strcmp(key, "ikmE") == 0) hex2bin(val, &in.ikmE, &in.ikmE_len);
        else if(strcmp(key, "ikmAuth") == 0) hex2bin(val, &in.ikmAuth, &in.ikmAuth_len);
        else if(strcmp(key, "psk") == 0) hex2bin(val, &in.psk, &in.psk_len);
        else if(strcmp(key, "psk_id") == 0) hex2bin(val, &in.psk_id, &in.psk_id_len);
        else if(strcmp(key, "info") == 0) hex2bin(val, &in.info, &in.info_len);
        else if(strcmp(key, "aad") == 0) hex2bin(val, &in.aad, &in.aad_len);
        else if(strcmp(key, "pt") == 0) hex2bin(val, &in.pt, &in.pt_len);
    }

    libctx = OSSL_LIB_CTX_new();
    if(libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new failed\n");
        return 1;
    }
    defprov = OSSL_PROVIDER_load(libctx, "default");
    if(defprov == NULL) {
        fprintf(stderr, "OSSL_PROVIDER_load(default) failed\n");
        return 1;
    }
    nullprov = OSSL_PROVIDER_load(libctx, "null");

    suite.kem_id = in.kem_id;
    suite.kdf_id = in.kdf_id;
    suite.aead_id = in.aead_id;

    if(!OSSL_HPKE_keygen(suite, pkR, &pkR_len, &skR,
            in.ikmR, in.ikmR_len, libctx, "provider=default")) {
        fprintf(stderr, "OSSL_HPKE_keygen(skR) failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    /* Let OpenSSL generate ephemeral key pair internally (skip deterministic ikmE) */
    if(in.ikmAuth_len) {
        unsigned char pubS[512];
        size_t pubS_len = sizeof(pubS);
        if(!OSSL_HPKE_keygen(suite, pubS, &pubS_len, &skS,
                in.ikmAuth, in.ikmAuth_len, libctx, "provider=default")) {
            fprintf(stderr, "OSSL_HPKE_keygen(skS) failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
        pkS_len = sizeof(pkS);
        if(!export_pub(skS, pkS, &pkS_len)) {
            fprintf(stderr, "export pkS failed\n");
            return 1;
        }
    }

    sealctx = OSSL_HPKE_CTX_new(in.mode, suite, OSSL_HPKE_ROLE_SENDER, libctx, "provider=default");
    if(sealctx == NULL) {
        fprintf(stderr, "OSSL_HPKE_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    /* No explicit ikmE set; OpenSSL will generate ephemeral keys */
    if(in.psk_len && in.psk_id_len) {
        if(!OSSL_HPKE_CTX_set1_psk(sealctx, (const char *)in.psk_id,
                                   in.psk, in.psk_len)) {
            fprintf(stderr, "OSSL_HPKE_CTX_set1_psk failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }
    if(skS != NULL) {
        if(!OSSL_HPKE_CTX_set1_authpriv(sealctx, skS)) {
            fprintf(stderr, "OSSL_HPKE_CTX_set1_authpriv failed\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }
    if(!OSSL_HPKE_encap(sealctx, enc, &enclen, pkR, pkR_len,
                        in.info, in.info_len)) {
        fprintf(stderr, "OSSL_HPKE_encap failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if(!OSSL_HPKE_seal(sealctx, ct, &ctlen,
                       in.aad, in.aad_len,
                       in.pt, in.pt_len)) {
        fprintf(stderr, "OSSL_HPKE_seal failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    print_hex("enc", enc, enclen);
    print_hex("ct", ct, ctlen);
    print_hex("pkRm", pkR, pkR_len);
    if(skS != NULL) {
        print_hex("pkSm", pkS, pkS_len);
    }
    if(export_priv_raw(skR, in.kem_id, skR_raw, &skR_raw_len)) {
        print_hex("skRm", skR_raw, skR_raw_len);
    } else {
        fprintf(stderr, "export skR failed\n");
        return 2;
    }

    OSSL_HPKE_CTX_free(sealctx);
    EVP_PKEY_free(skR);
    EVP_PKEY_free(skS);
    if(nullprov) OSSL_PROVIDER_unload(nullprov);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(libctx);
    free(in.ikmR);
    free(in.ikmE);
    free(in.ikmAuth);
    free(in.psk);
    free(in.psk_id);
    free(in.info);
    free(in.aad);
    free(in.pt);
    return 0;
}
