/*
 *  t_cose_crypto_test.h
 *
 * Copyright 2022-2023, Laurence Lundblade
 * Created by Laurence Lundblade on 12/28/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef t_cose_crypto_test_h
#define t_cose_crypto_test_h

#include <stdint.h>


int_fast32_t aead_test(void);

int_fast32_t kw_test(void);

int_fast32_t hkdf_test(void);


#endif /* t_cose_crypto_test_h */