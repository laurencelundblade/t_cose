/*
 * examples_main.c
 *
 * Copyright 2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 2/21/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include <stdbool.h>
#include <stdio.h>

#include "signing_examples.h"
#include "encryption_examples.h"


#ifndef T_COSE_DISABLE_HPKE
#include "encryption_examples.h"
#endif /* T_COSE_DISABLE_HPKE */


typedef int32_t (test_fun_t)(void);

#define TEST_ENTRY(test_name)  {#test_name, test_name, true}

typedef struct {
    const char  *szTestName;
    test_fun_t  *test_fun;
    bool         bEnabled;
} test_entry;

static test_entry s_tests[] = {

    /* ES256 Sign1: single-call path */
    TEST_ENTRY(one_step_sign_example),
    /* ES256 Sign1: explicit header and payload steps */
    TEST_ENTRY(two_step_sign_example),
    /* COSE_Sign with ES384 + PS256, detached payload */
    TEST_ENTRY(one_step_multi_sign_detached_example),
    /* Legacy one-step Sign1 example */
    TEST_ENTRY(old_one_step_sign_example),
    /* Legacy two-step Sign1 example */
    TEST_ENTRY(old_two_step_sign_example),
    
#ifndef T_COSE_DISABLE_KEYWRAP
    /* AES-KW wrapping CEK; detached payload */
    TEST_ENTRY(key_wrap_example),
#endif /* !T_COSE_DISABLE_KEYWRAP */

    /* ECDH-ES with attached ciphertext */
    TEST_ENTRY(esdh_example),
    /* ECDH-ES with detached ciphertext */
    TEST_ENTRY(esdh_example_detached),

    /* A128GCM Encrypt0 with detached ciphertext (non-HPKE) */
    TEST_ENTRY(encrypt0_example),

#ifndef T_COSE_DISABLE_HPKE
    /* HPKE key-encryption mode: Base P-256 / HKDF-SHA256 / AES-128-GCM, attached ciphertext */
    TEST_ENTRY(hpke0_example),
    /* HPKE key-encryption mode: Base P-384 / HKDF-SHA384 / AES-256-GCM, attached ciphertext */
    TEST_ENTRY(hpke1_example),
    /* HPKE key-encryption mode: Base P-521 / HKDF-SHA512 / AES-256-GCM, attached ciphertext */
    TEST_ENTRY(hpke2_example),
    /* HPKE key-encryption mode: Base P-256 with detached ciphertext */
    TEST_ENTRY(hpke_example_detached),
    /* HPKE integrated mode: Encrypt0 with embedded ciphertext, no decrypt path */
    TEST_ENTRY(encrypt0_hpke_example),
#endif /* T_COSE_DISABLE_HPKE */
};



int main(int argc, const char * argv[])
{
    (void)argc; /* Avoid unused parameter error */
    (void)argv;
    int nTestsFailed = 0;
    int nTestsRun = 0;

    test_entry *t;
    const test_entry *s_tests_end = s_tests + sizeof(s_tests)/sizeof(test_entry);

    for(t = s_tests; t < s_tests_end; t++) {
        /* Could bring in command line arges from run_tests.c here */

        int32_t nTestResult = (int32_t)(t->test_fun)();
        nTestsRun++;

        if(nTestResult) {
            nTestsFailed++;
        }
    }

    printf("\n%d of %d EXAMPLES FAILED\n", nTestsFailed, nTestsRun);
}
