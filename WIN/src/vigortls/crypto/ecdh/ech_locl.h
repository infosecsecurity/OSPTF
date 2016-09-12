/*
 * Copyright 2005 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ECH_LOCL_H
#define HEADER_ECH_LOCL_H

#include <openssl/ecdh.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ecdh_method {
    const char *name;
    int (*compute_key)(void *key, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
                       void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
    int flags;
    char *app_data;
};

typedef struct ecdh_data_st {
    /* EC_KEY_METH_DATA part */
    int (*init)(EC_KEY *);
    /* method specific part */
    ENGINE *engine;
    int flags;
    const ECDH_METHOD *meth;
    CRYPTO_EX_DATA ex_data;
} ECDH_DATA;

ECDH_DATA *ecdh_check(EC_KEY *);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_ECH_LOCL_H */
