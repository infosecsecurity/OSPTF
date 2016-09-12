/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdcompat.h>

int PEM_SealInit(PEM_ENCODE_SEAL_CTX *ctx, EVP_CIPHER *type, EVP_MD *md_type,
                 uint8_t **ek, int *ekl, uint8_t *iv, EVP_PKEY **pubk,
                 int npubk)
{
    uint8_t key[EVP_MAX_KEY_LENGTH];
    int ret = -1;
    int i, j, max = 0;
    char *s = NULL;

    for (i = 0; i < npubk; i++) {
        if (pubk[i]->type != EVP_PKEY_RSA) {
            PEMerr(PEM_F_PEM_SEALINIT, PEM_R_PUBLIC_KEY_NO_RSA);
            goto err;
        }
        j = RSA_size(pubk[i]->pkey.rsa);
        if (j > max)
            max = j;
    }
    s = (char *)reallocarray(NULL, max, 2);
    if (s == NULL) {
        PEMerr(PEM_F_PEM_SEALINIT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    EVP_EncodeInit(&ctx->encode);

    EVP_MD_CTX_init(&ctx->md);
    if (!EVP_SignInit(&ctx->md, md_type))
        goto err;

    EVP_CIPHER_CTX_init(&ctx->cipher);
    ret = EVP_SealInit(&ctx->cipher, type, ek, ekl, iv, pubk, npubk);
    if (ret <= 0)
        goto err;

    /* base64 encode the keys */
    for (i = 0; i < npubk; i++) {
        j = EVP_EncodeBlock((uint8_t *)s, ek[i],
                            RSA_size(pubk[i]->pkey.rsa));
        ekl[i] = j;
        memcpy(ek[i], s, j + 1);
    }

    ret = npubk;
err:
    free(s);
    vigortls_zeroize(key, EVP_MAX_KEY_LENGTH);
    return (ret);
}

void PEM_SealUpdate(PEM_ENCODE_SEAL_CTX *ctx, uint8_t *out, int *outl,
                    uint8_t *in, int inl)
{
    uint8_t buffer[1600];
    int i, j;

    *outl = 0;
    EVP_SignUpdate(&ctx->md, in, inl);
    for (;;) {
        if (inl <= 0)
            break;
        if (inl > 1200)
            i = 1200;
        else
            i = inl;
        EVP_EncryptUpdate(&ctx->cipher, buffer, &j, in, i);
        EVP_EncodeUpdate(&ctx->encode, out, &j, buffer, j);
        *outl += j;
        out += j;
        in += i;
        inl -= i;
    }
}

int PEM_SealFinal(PEM_ENCODE_SEAL_CTX *ctx, uint8_t *sig, int *sigl,
                  uint8_t *out, int *outl, EVP_PKEY *priv)
{
    uint8_t *s = NULL;
    int ret = 0, j;
    unsigned int i;

    if (priv->type != EVP_PKEY_RSA) {
        PEMerr(PEM_F_PEM_SEALFINAL, PEM_R_PUBLIC_KEY_NO_RSA);
        goto err;
    }
    i = RSA_size(priv->pkey.rsa);
    if (i < 100)
        i = 100;
    s = (uint8_t *)reallocarray(NULL, i, 2);
    if (s == NULL) {
        PEMerr(PEM_F_PEM_SEALFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_EncryptFinal_ex(&ctx->cipher, s, (int *)&i))
        goto err;
    EVP_EncodeUpdate(&ctx->encode, out, &j, s, i);
    *outl = j;
    out += j;
    EVP_EncodeFinal(&ctx->encode, out, &j);
    *outl += j;

    if (!EVP_SignFinal(&ctx->md, s, &i, priv))
        goto err;
    *sigl = EVP_EncodeBlock(sig, s, i);

    ret = 1;
err:
    EVP_MD_CTX_cleanup(&ctx->md);
    EVP_CIPHER_CTX_cleanup(&ctx->cipher);
    free(s);
    return (ret);
}
