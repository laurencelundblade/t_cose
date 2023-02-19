/*
 * t_cose_key.h
 *
 * Copyright 2019-2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Created by Laurence Lundblade on 2/6/23.
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_key_h
#define t_cose_key_h

#include <stdbool.h>
#include <stdint.h>
#include <t_cose/q_useful_buf.h>

/*
 * This file has two purposes: 1) define struct t_cose_key,
 * the abstraction for passing a key through t_cose to the
 * crypto library (e.g.  OpenSSL or Mbed TLS), and 2)
 * methods for encoding and decoding a COSE_Key as defined
 * in RFC 9052.

 * This supports some of the standard serialized key formats
 * for various key types and algorithms. Lots of work to do
 * here, but probably this will support the translation of standard
 * key formats to/from a t_cose_key and then a t_cose_key
 * to a COSE_Key. Some are easy, for example the serialize
 * format for all symmetric keys is a byte string. It's a little
 * less straight forward for EC keys.
 */



/* Serialized key representations vary a lot from algorithm to algorithm and
 * API to API and standard to standard. The intent here is to support
 * some of the most common ones that are not tied to a particular crypto
 * library. That is to say, the functions here, like the rest of
 * t_cose work with any and *all* crypto libraries.
 *
 * That means not all key formats and such will be supported here and
 * use of t_cose will require callers to write code specific to
 * crypto libraries to inialize keys.
 *
 * There should be some caution here when adding new serialized key
 * formats because any one that is added will need to be implemented
 * for all the crypto libraries t_cose is integrated with.
 *
 */


/* This sets the maximum key size for symmetric ciphers like AES and ChaCha20 (not supported yet).
* It is set to 32 to accommodate AES 256 and anything with a smaller
* key size. This is used to size stack buffers that hold keys.
* Attempts to use a symmetric key size larger than this will result in an error.
* Smaller keys sizes are no problem.
* This applies to keys for HMAC and key wrap as well.
* This could be more dynamically sized based on which algorithms
* are turned on or off, but probably isn't necessary because
* it isn't very large and dynamic setting wouldn't save much stack.
*/
#define T_COSE_MAX_SYMMETRIC_KEY_LENGTH 32


/**
 * This structure passes a key through  t_cose
 * to the underlying cryptography libraries. While initialization methods
 * are provided for some key types, you often must know the
 * cryptographic library that is integrated with t_cose to know how to
 * fill in this data structure.
 *
 * This same data structure is used for many different key types such
 * as symmetric keys and public keys, private keys and even key pairs.
 *
 * (The crypto_lib member used in t_cose 1.x is dropped in 2.x because
 * it seems unnecessary and was not supported uniformly. It is unneccessary
 * because individual t_cose libraries are for a particular crypto library and
 * only one is supported at a time by t_cose. Removal of the he crypto_lib member
 * also saves object code).
 */
struct t_cose_key {
    union {
        /** For libraries that use a pointer to the key or key
         * handle. \c NULL indicates empty. */
        void *ptr;
        /** For libraries that use an integer handle to the key */
        uint64_t handle;
        /** For pointer and length of actual key bytes. Length is a uint16_t to keep the
         * size of this struct down because it occurs on the stack. */
        struct q_useful_buf_c buffer;
    } key;
};




/* This takes the bytes that make up a symmetric key and
 * makes a t_cose_key out of it in the form for use with the
 * current crypto library. This works for keys for AES (e.g.,   )
 * key wrap and HMAC  (e.g., ). For example, this can be used to
 * make a t_cose_key for t_cose_mac_set_computing_key(),
 * t_cose_encrypt_set_key(), t_cose_recipient_enc_keywrap_set_key()
 * and others APIs needing a symmetric
 * key.
 *
 * For some crypto libraries, the key will only be usable for
 * the algorithm specfied. For other crypto libraries
 * there no is policy enforcement.
 *
 * The number of bits in \c symmetric_key should be the correct number
 * for the algorithm specified. An error will usually
 * be returned if it is not.
 *
 * See \ref T_COSE_MAX_SYMMETRIC_KEY_LENGTH.
 *
 *
 */
enum t_cose_err_t
t_cose_key_init_symmetric(int32_t               cose_algorithm_id,
                          struct q_useful_buf_c symmetric_key,
                          struct t_cose_key     *key);


void
t_cose_key_free_symmetric(struct t_cose_key key);



/* -------------- inline ---------------- */

#endif /* t_cose_key_h */
