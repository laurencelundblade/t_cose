/*
 * t_cose_psa_crypto.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

/**
 * \file t_cose_psa_crypto.h
 *
 * \brief Public interface of the PSA Crypto adapter
 *
 */

#ifndef __T_COSE_PSA_CRYPTO_H__
#define __T_COSE_PSA_CRYPTO_H__

#include "psa/crypto.h"

#include "t_cose/t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct t_cose_psa_crypto_context {
    /* psa_hash_operation_t actually varied by the implementation of
     * the crypto library. Sometimes the implementation is inline and
     * thus the context is a few hundred bytes, sometimes it is not.
     * This varies by what is in crypto_struct.h (which is not quite
     * a public interface).
     *
     * This can be made smaller for PSA implementations that work inline
     * by disabling the larger algorithms using PSA / MBed configuration.
     */
    psa_hash_operation_t ctx;
    psa_status_t         status;
};

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_PSA_CRYPTO_H__ */