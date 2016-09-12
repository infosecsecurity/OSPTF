/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_GOST_LOCL_H
#define HEADER_GOST_LOCL_H

#include <openssl/opensslconf.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>

/* Internal representation of GOST substitution blocks */
typedef struct {
    uint8_t k8[16];
    uint8_t k7[16];
    uint8_t k6[16];
    uint8_t k5[16];
    uint8_t k4[16];
    uint8_t k3[16];
    uint8_t k2[16];
    uint8_t k1[16];
} gost_subst_block;

#if defined(VIGORTLS_X86) || defined(VIGORTLS_X86_64)
#define c2l(c, l) ((l) = *((const unsigned int *)(c)), (c) += 4)
#define l2c(l, c) (*((unsigned int *)(c)) = (l), (c) += 4)
#else
#define c2l(c, l)                                                                  \
    (l = (((unsigned long)(*((c)++)))), l |= (((unsigned long)(*((c)++))) << 8),   \
     l |= (((unsigned long)(*((c)++))) << 16),                                     \
     l |= (((unsigned long)(*((c)++))) << 24))
#define l2c(l, c)                                                                  \
    (*((c)++) = (uint8_t)(((l)) & 0xff),                                     \
     *((c)++) = (uint8_t)(((l) >> 8) & 0xff),                                \
     *((c)++) = (uint8_t)(((l) >> 16) & 0xff),                               \
     *((c)++) = (uint8_t)(((l) >> 24) & 0xff))
#endif

extern void Gost2814789_encrypt(const uint8_t *in, uint8_t *out,
                                const GOST2814789_KEY *key);
extern void Gost2814789_decrypt(const uint8_t *in, uint8_t *out,
                                const GOST2814789_KEY *key);
extern void Gost2814789_cryptopro_key_mesh(GOST2814789_KEY *key);

/* GOST 28147-89 key wrapping */
extern int gost_key_unwrap_crypto_pro(int nid, const uint8_t *keyExchangeKey,
                                      const uint8_t *wrappedKey,
                                      uint8_t *sessionKey);
extern int gost_key_wrap_crypto_pro(int nid, const uint8_t *keyExchangeKey,
                                    const uint8_t *ukm,
                                    const uint8_t *sessionKey,
                                    uint8_t *wrappedKey);
/* Pkey part */
extern int gost2001_compute_public(GOST_KEY *ec);
extern ECDSA_SIG *gost2001_do_sign(BIGNUM *md, GOST_KEY *eckey);
extern int gost2001_do_verify(BIGNUM *md, ECDSA_SIG *sig, GOST_KEY *ec);
extern int gost2001_keygen(GOST_KEY *ec);
extern int VKO_compute_key(BIGNUM *X, BIGNUM *Y, const GOST_KEY *pkey,
                           GOST_KEY *priv_key, const BIGNUM *ukm);
extern BIGNUM *GOST_le2bn(const uint8_t *buf, size_t len, BIGNUM *bn);
extern int GOST_bn2le(BIGNUM *bn, uint8_t *buf, int len);

/* GOST R 34.10 parameters */
extern int GostR3410_get_md_digest(int nid);
extern int GostR3410_get_pk_digest(int nid);
extern int GostR3410_256_param_id(const char *value);
extern int GostR3410_512_param_id(const char *value);

#endif
