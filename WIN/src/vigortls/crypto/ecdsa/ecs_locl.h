/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ECS_LOCL_H
#define HEADER_ECS_LOCL_H

#include <openssl/ecdsa.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ecdsa_method {
    const char *name;
    ECDSA_SIG *(*ecdsa_do_sign)(const uint8_t *dgst, int dgst_len,
                                const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
    int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                            BIGNUM **r);
    int (*ecdsa_do_verify)(const uint8_t *dgst, int dgst_len,
                           const ECDSA_SIG *sig, EC_KEY *eckey);
#if 0
    int (*init)(EC_KEY *eckey);
    int (*finish)(EC_KEY *eckey);
#endif
    int flags;
    void *app_data;
};

/* The ECDSA_METHOD was allocated and can be freed */

#define ECDSA_METHOD_FLAG_ALLOCATED 0x2

typedef struct ecdsa_data_st {
    /* EC_KEY_METH_DATA part */
    int (*init)(EC_KEY *);
    /* method (ECDSA) specific part */
    ENGINE *engine;
    int flags;
    const ECDSA_METHOD *meth;
    CRYPTO_EX_DATA ex_data;
} ECDSA_DATA;

/** ecdsa_check
 * checks whether ECKEY->meth_data is a pointer to a ECDSA_DATA structure
 * and if not it removes the old meth_data and creates a ECDSA_DATA structure.
 * \param  eckey pointer to a EC_KEY object
 * \return pointer to a ECDSA_DATA structure
 */
ECDSA_DATA *ecdsa_check(EC_KEY *eckey);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_ECS_LOCL_H */
