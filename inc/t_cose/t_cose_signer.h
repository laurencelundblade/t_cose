//
//  t_cose_signer.h
//  t_cose
//
//  Created by Laurence Lundblade on 5/23/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_signer_h
#define t_cose_signer_h

#include "qcbor/qcbor_encode.h"

/* This is an "abstract base class" for all signers
 * of all types for all algorithms. This is the interface
 * and data structure that t_cose_sign knows about to be able
 * to invoke each signer regardles of its type or algorithm.
 *
 * Each concrete signer (e.g., ECDSA signer, RSA signer,... must implement this. Each signer
 * also implements a few methods of its own beyond this
 * that it needs to work.
 *
 * t_cose_signer_callback is the type of a function that every
 * signer must implement. It takes as input the context
 * for the particular signer, the hash to sign and
 * the encoder instance. The work it does is to produce
 * the signature and output the COSE_Signature to the
 * encoder instance.
 *
 * This design allows new signers for new algorithms to be
 * added without modifying or even recompiling t_cose.
 * It is a clean and simple design that allows outputting a COSE_Sign
 * that has multiple signings by multiple aglorithms, for example
 * an ECDSA signature and an HSS/LMS signature.
 *
 * What's really going on here is a bit of doing object orientation
 * with C. This is an abstract base class, an object that
 * has no implementation of it's own. Each signer type, e.g.,
 * the ECDSA signer, inherits from this and provides and
 * implementation. The structure defined here holds
 * the vtable for the methods for the object. There is
 * only one. It's called a "callback" here, but it could
 * also be called the abstract sign method.
 *
 * Since C doesn't support object orientation there's a few
 * tricks to make this fly. The concrete instantiation
 * (e.g., an ECDSA signer) must make t_cose_signer the first
 * part of it's context and there will be casts back and
 * forth between this abstraction and the real instantion
 * of the signer. The other trick is that struct here
 * contains a pointer to a function and that makes up
 * the vtable, something that C++ would do for you.
 */

/* A declaration (not definition) of the generic structure for a signer.
 * See https://stackoverflow.com/questions/888386/resolve-circular-typedef-dependency
 */
typedef struct t_cose_signer t_cose_signer_d;


/* The main method / callback used to perform the signing and output
 * the COSE format signature.
 */
// TODO: this needs to have a few more parameters added to be able
// to produce correct signatures that cover the protected parameters
// and AAD, but that is not a change in the general design.
typedef enum t_cose_err_t
(* t_cose_signer_callback)(t_cose_signer_d             *me,
                           const struct q_useful_buf_c  hash,
                           QCBOREncodeContext          *qcbor_encoder);


/* The definition (not declaration) of the context that every
 * signiner implemtnation has.
 */
struct t_cose_signer {
    t_cose_signer_callback  callback; /* some will call this a vtable with one entry */
    struct t_cose_signer   *next_in_list; /* Linked list of signers */
};


#endif /* t_cose_signer_h */
