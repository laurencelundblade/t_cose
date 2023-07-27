/*
 * t_cose_recipient_enc_esdh.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_ENC_ESDH_H__
#define __T_COSE_RECIPIENT_ENC_ESDH_H__

#include <stdint.h>
#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif


/* The default size of the COSE_KDF_Context. See
 * t_cose_recipient_dec_esdh_kdf_buf() and
 * T_COSE_ERR_KDF_BUFFER_TOO_SMALL. */
#define T_COSE_ENC_COSE_KDF_CONTEXT_SIZE 50

struct t_cose_recipient_enc_esdh {
    /* Private data structure */

    /* t_cose_recipient_enc must be the first item for the polymorphism to
      * work.  This structure, t_cose_recipient_enc_esdh, will sometimes be
      * uses as a t_cose_recipient_enc.
      */
    struct t_cose_recipient_enc e;

    struct t_cose_key           recipient_pub_key;
    struct q_useful_buf_c       kid;
    int32_t                     cose_ec_curve_id;
    int32_t                     cose_algorithm_id;
    struct t_cose_parameter    *added_params;

    /* stuff for KDF context info struct */
    struct q_useful_buf_c       party_u_ident;
    struct q_useful_buf_c       party_v_ident;
    bool                        do_not_send;
    struct q_useful_buf_c       supp_pub_other;
    struct q_useful_buf_c       supp_priv_info;
    struct q_useful_buf         kdf_context_buf;
};



/**
 * @brief Initialize the creator COSE_Recipient for ESDH content key distribution.

 * @param[in]  cose_algorithm_id    The content key distribution algorithm ID.
 * @param[in]  cose_ec_curve_id  The curve ID.
 *
 * This must be called not only to set the keywrap id, the content key
 * distribution (ckd) id, and the curve id, but also because this sets
 * up the recipient callbacks. That is when all the real work of
 * content key distribution gets done.
 *
 * If unknown algorithm IDs are passed, an error will occur when
 * t_cose_encrypt_enc() is called and the error code will be returned
 * there.
 */
static void
t_cose_recipient_enc_esdh_init(struct t_cose_recipient_enc_esdh *context,
                               int32_t                      cose_algorithm_id,
                               int32_t                      cose_ec_curve_id);


/**
 * @brief Sets the recipient key, pkR
 *
 * The kid is optional and can be NULL
 */
static void
t_cose_recipient_enc_esdh_set_key(struct t_cose_recipient_enc_esdh *context,
                                  struct t_cose_key                 recipient,
                                  struct q_useful_buf_c             kid);


/*
 * This COSE_Recipient always uses and sends a random salt as
 * described section 5.1 of RFC 9053. The length of the salt
 * is set based on the algorithm ID.
 *
 * t_cose is assumed to be integrated with a high quality
 * random number generated as such are common. The salt
 * is thusly generated.
 *
 * Because the salt is always present and of high quality,
 * all the nonce parameters in the PartyInfo are considered
 * unnecessary and there is no interface to provide them.
 *
 * Also, the algorithm and key length that go into PartyInfo
 * are derived from the algorithm IDs set elsewhere.
 */

/**
 * \brief Set PartyU and PartyV for KDF context info struct.
 *
 * \param[in] context   ESDH Signer context.
 * \param[in] party_u_ident  String for PartyU or NULL_Q_USEFUL_BUF_C.
 * \param[in] party_v_ident  String for PartyV or NULL_Q_USEFUL_BUF_C.
 * \param[in] do_not_send  True indicates these should be left out of
 * the COSE header parameters, that they should not be sent to the recipient.
 *
 * Speaking with opinion, you probably don't need to set this. If you don't set this
 * and don't do anything on the receiving side, COSE will work. It is expected
 * that most use cases will not set these. The point
 * of it is to bind the content encryption key to sender and receiver context.
 * This is in COSE because it is in NIST SP800-56A and JOSE. It is justifed
 * by academic papers on attacks on key agreement protocols found in
 * Appendix B of NIST SP800-56A. Probably these attacks don't apply
 * because you probably are using a good RNG and because the ephemeral
 * key is generated anew for every encryption. Good RNGs are much more
 * common now (2023) than when these papers were written.
 *
 * These data items are described in RFC 9053 section 5.2. This API
 * doesn't allow setting Party*.nonce or Party*.other. It always sets them
 * to NULL. Speaking with opinion, this data items seem very unnecessary
 * and complex. Hopefully no implementation ever uses them. You can do
 * everything you need to do with the other data items in the KDF context.
 *
 * See t_cose_recipient_enc_esdh_supp_info() where it is recommended to
 * set one of the KDF context inputs.
 *
 * The opinions here were formed from discussions with long-time workers
 * on COSE, CMS, LAMPS, reading of NIST SP800-56A and trying to formulate
 * attacks that these data items defend against. No one really had any
 * good attacks in a world were RNGs are good and the ephemeral key
 * is generated anew for each encryption.
 *
 * Now on to non-opinion facts of this API.
 *
 * If these data items are not set, then PartyInfo.identity will be NULL when
 * the KDF Context Information Structure is created.Otherwise they will
 * be the values set here. If they are set to NULL_Q_USEFUL_C here, they will also
 * be NULL in created. PartyInfo.nonce and
 * PartyInfo.other are always NULL.
 *
 * If these are set to non-NULL values, they will be sent in non-protected headers,
 * unless do_not_send is true.
 *
 * If these are set to long strings, then t_cose_recipient_enc_esdh_kdf_buf() may have
 * to be called to supply a larger buffer for the internal KDF Context construction.
 */
static inline void
t_cose_recipient_enc_esdh_party_info(struct t_cose_recipient_enc_esdh *context,
                                     const struct q_useful_buf_c party_u_ident,
                                     const struct q_useful_buf_c party_v_ident,
                                     bool                        do_not_send);


/**
 * \brief Set supplimentary data items in the KDF context info struct.
 *
 * \param[in] context   ESDH Signer context.
 * \param[in] supp_pub_other  Supplemental public info other or NULL_Q_USEFUL_BUF_C
 * \param[in] supp_priv_info  Supplemental private info other or NULL_Q_USEFUL_BUF_C
 *
 * To save you time, this will start out with the opinion and recommendation
 * that you set supp_pub_other to a fixed string naming your COSE
 * use case, for example "Firmware Encryption". This is not
 * the name of the application implementing the use case, but the
 * broad name of the use case. All applications must hard code the same string.
 * This recommendation is made based on discussion with long-time
 * experts in COSE, CMS, LAMPS and other. supp_priv_info can
 * remain NULL.
 *
 * If in doubt about this and you just want to get started, you
 * can just not call this at all in which cases these values will
 * be omiited from the KDF Context.
 *
 * Note that the for decryption to work the receiver must
 * set the same values that are set here using t_cose_recipient_dec_esdh_party_info(). If not the AEAD
 * integrity check will error out because from the CEK
 * being different. TODO: document error code
 *
 * See t_cose_recipient_enc_esdh_party_info() for further discussion.
 *
 * Set the "SuppPubInfo.other" field of PartyInfo as described in RFC
 * 9053.  This is optional and will be nil if not set. If this is set
 * it will be sent to the recipient in a header parameter.  Don't call
 * this or pass NULL_USEFUL_BUF_C to not set this.
 *
 * Also sets "SuppPrivInfo" from PartyInfo. This is optional. It is
 * never sent since it is pivate info. Somehow the recipient must also
 * know and set this during decryption. Don't call this or pass
 * NULL_USEFUL_BUF_C to not set this.
 *
 * The reasons for setting these and background on what to set it to
 * are in Section 5.2 of RFC 9053 and in NIST SP800-56A.
 */
static inline void
t_cose_recipient_enc_esdh_supp_info(struct t_cose_recipient_enc_esdh *context,
                                    const struct q_useful_buf_c supp_pub_other,
                                    const struct q_useful_buf_c supp_priv_info);


/**
 * \brief Configure a larger buffer used to serialize the COSE_KDF_Context.
 *
 * \param[in] context           The t_cose signing context.
 * \param[in] kdf_buffer  The buffer used to serialize the COSE_KDF_Context.
 *
 * For most use the internal buffer for the COSE_KDF_Context is usually
 * large enough. The internal buffer size is  \ref T_COSE_ENC_COSE_KDF_CONTEXT_SIZE.
 *
 * The COSE_KDF_Context described RFC 9053 section 5.3 must fit  in
 * this buffer. With no additional context items provided it is about 20 bytes
 * including the protected headers for the algorithm ID. If additional protected
 * headers are added with xxx, PartyU or PartyV is added with t_cose_recipient_enc_esdh_party_info()
 * or suppplemental info is added with t_cose_recipient_enc_esdh_supp_info(),
 * it may be necessary to call this with a larger buffer.
 *
 * \ref T_COSE_ERR_KDF_BUFFER_TOO_SMALL will be returned from t_cose_encrypt_enc()
 * or t_cose_encrypt_enc_detached() if the buffer is too small.
 */
static void
t_cose_recipient_enc_esdh_kdf_buf(struct t_cose_recipient_enc_esdh *context,
                                  struct q_useful_buf               kdf_buffer);

/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */

enum t_cose_err_t
t_cose_recipient_create_esdh_cb_private(struct t_cose_recipient_enc  *me_x,
                                        struct q_useful_buf_c         cek,
                                        const struct t_cose_alg_and_bits ce_alg,
                                        QCBOREncodeContext           *cbor_encoder);


static inline void
t_cose_recipient_enc_esdh_init(struct t_cose_recipient_enc_esdh *me,
                               int32_t                      cose_algorithm_id,
                               int32_t                      cose_ec_curve_id)
{
    memset(me, 0, sizeof(*me));
    me->e.creat_cb        = t_cose_recipient_create_esdh_cb_private;
    me->cose_algorithm_id = cose_algorithm_id;
    me->cose_ec_curve_id  = cose_ec_curve_id;
}


static inline void
t_cose_recipient_enc_esdh_set_key(struct t_cose_recipient_enc_esdh *me,
                                  struct t_cose_key           recipient_pub_key,
                                  struct q_useful_buf_c       kid)
{
    me->recipient_pub_key = recipient_pub_key;
    me->kid               = kid;
}


static inline void
t_cose_recipient_enc_esdh_party_info(struct t_cose_recipient_enc_esdh *me,
                                     const struct q_useful_buf_c  party_u_ident,
                                     const struct q_useful_buf_c  party_v_ident,
                                     const bool                   do_not_send)
{
    me->party_u_ident = party_u_ident;
    me->party_v_ident = party_v_ident;
    me->do_not_send      = do_not_send;
}


static inline void
t_cose_recipient_enc_esdh_supp_info(struct t_cose_recipient_enc_esdh *me,
                                    const struct q_useful_buf_c  supp_pub_other,
                                    const struct q_useful_buf_c  supp_priv_info)
{
    me->supp_pub_other = supp_pub_other;
    me->supp_priv_info = supp_priv_info;
}

static inline void
t_cose_recipient_enc_esdh_kdf_buf(struct t_cose_recipient_enc_esdh *me,
                                  struct q_useful_buf               kdf_context_buf)
{
    me->kdf_context_buf = kdf_context_buf;
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_ESDH_H__ */
