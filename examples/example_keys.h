/*
 * example_keys.h
 *
 * Copyright 2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 6/13/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef example_keys_h
#define example_keys_h

extern const unsigned char ec_P_256_key_pair_der[121];
extern const unsigned char ec_P_256_priv_key_raw[32];


extern const unsigned char ec_P_384_key_pair_der[167];
extern const unsigned char ec_P_384_priv_key_raw[48];


extern const unsigned char ec_P_521_key_pair_der[223];
extern const unsigned char ec_P_521_priv_key_raw[66];

extern const unsigned char RSA_2048_key_pair_der[1191];

extern const unsigned char ed25519_key_pair_der[48];


#endif /* example_keys_h */
