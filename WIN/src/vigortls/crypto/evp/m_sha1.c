/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>


#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

static int init(EVP_MD_CTX *ctx)
{
    return SHA1_Init(ctx->md_data);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA1_Update(ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, uint8_t *md)
{
    return SHA1_Final(md, ctx->md_data);
}

static const EVP_MD sha1_md = {
    .type = NID_sha1,
    .pkey_type = NID_sha1WithRSAEncryption,
    .md_size = SHA_DIGEST_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    .init = init,
    .update = update,
    .final = final,
    .copy = NULL,
    .cleanup = NULL,
#ifndef OPENSSL_NO_RSA
    .sign = (evp_sign_method *)RSA_sign,
    .verify = (evp_verify_method *)RSA_verify,
    .required_pkey_type = {
        EVP_PKEY_RSA, EVP_PKEY_RSA2, 0, 0,
    },
#endif
    .block_size = SHA_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

const EVP_MD *EVP_sha1(void)
{
    return (&sha1_md);
}

static int init224(EVP_MD_CTX *ctx)
{
    return SHA224_Init(ctx->md_data);
}
static int init256(EVP_MD_CTX *ctx)
{
    return SHA256_Init(ctx->md_data);
}
/*
 * Even though there're separate SHA224_[Update|Final], we call
 * SHA256 functions even in SHA224 context. This is what happens
 * there anyway, so we can spare few CPU cycles:-)
 */
static int update256(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA256_Update(ctx->md_data, data, count);
}
static int final256(EVP_MD_CTX *ctx, uint8_t *md)
{
    return SHA256_Final(md, ctx->md_data);
}

static const EVP_MD sha224_md = {
    .type = NID_sha224,
    .pkey_type = NID_sha224WithRSAEncryption,
    .md_size = SHA224_DIGEST_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    .init = init224,
    .update = update256,
    .final = final256,
    .copy = NULL,
    .cleanup = NULL,
#ifndef OPENSSL_NO_RSA
    .sign = (evp_sign_method *)RSA_sign,
    .verify = (evp_verify_method *)RSA_verify,
    .required_pkey_type = {
        EVP_PKEY_RSA, EVP_PKEY_RSA2, 0, 0,
    },
#endif
    .block_size = SHA256_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA256_CTX),
};

const EVP_MD *EVP_sha224(void)
{
    return (&sha224_md);
}

static const EVP_MD sha256_md = {
    .type = NID_sha256,
    .pkey_type = NID_sha256WithRSAEncryption,
    .md_size = SHA256_DIGEST_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    .init = init256,
    .update = update256,
    .final = final256,
    .copy = NULL,
    .cleanup = NULL,
#ifndef OPENSSL_NO_RSA
    .sign = (evp_sign_method *)RSA_sign,
    .verify = (evp_verify_method *)RSA_verify,
    .required_pkey_type = {
        EVP_PKEY_RSA, EVP_PKEY_RSA2, 0, 0,
    },
#endif
    .block_size = SHA256_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA256_CTX),
};

const EVP_MD *EVP_sha256(void)
{
    return (&sha256_md);
}

static int init384(EVP_MD_CTX *ctx)
{
    return SHA384_Init(ctx->md_data);
}
static int init512(EVP_MD_CTX *ctx)
{
    return SHA512_Init(ctx->md_data);
}
/* See comment in SHA224/256 section */
static int update512(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA512_Update(ctx->md_data, data, count);
}
static int final512(EVP_MD_CTX *ctx, uint8_t *md)
{
    return SHA512_Final(md, ctx->md_data);
}

static const EVP_MD sha384_md = {
    .type = NID_sha384,
    .pkey_type = NID_sha384WithRSAEncryption,
    .md_size = SHA384_DIGEST_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    .init = init384,
    .update = update512,
    .final = final512,
#ifndef OPENSSL_NO_RSA
    .sign = (evp_sign_method *)RSA_sign,
    .verify = (evp_verify_method *)RSA_verify,
    .required_pkey_type = {
        EVP_PKEY_RSA, EVP_PKEY_RSA2, 0, 0,
    },
#endif
    .block_size = SHA512_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

const EVP_MD *EVP_sha384(void)
{
    return (&sha384_md);
}

static const EVP_MD sha512_md = {
    .type = NID_sha512,
    .pkey_type = NID_sha512WithRSAEncryption,
    .md_size = SHA512_DIGEST_LENGTH,
    .flags = EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    .init = init512,
    .update = update512,
    .final = final512,
#ifndef OPENSSL_NO_RSA
    .sign = (evp_sign_method *)RSA_sign,
    .verify = (evp_verify_method *)RSA_verify,
    .required_pkey_type = {
        EVP_PKEY_RSA, EVP_PKEY_RSA2, 0, 0,
    },
#endif
    .block_size = SHA512_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

const EVP_MD *EVP_sha512(void)
{
    return (&sha512_md);
}
