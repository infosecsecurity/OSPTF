/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif

/* This testing gunk is implemented (and explained) lower down. It also assumes
 * the application explicitly calls "ENGINE_load_openssl()" because this is no
 * longer automatic in ENGINE_load_builtin_engines(). */
#define TEST_ENG_OPENSSL_RC4
#define TEST_ENG_OPENSSL_PKEY
/* #define TEST_ENG_OPENSSL_RC4_OTHERS */
#define TEST_ENG_OPENSSL_RC4_P_INIT
/* #define TEST_ENG_OPENSSL_RC4_P_CIPHER */
#define TEST_ENG_OPENSSL_SHA
/* #define TEST_ENG_OPENSSL_SHA_OTHERS */
/* #define TEST_ENG_OPENSSL_SHA_P_INIT */
/* #define TEST_ENG_OPENSSL_SHA_P_UPDATE */
/* #define TEST_ENG_OPENSSL_SHA_P_FINAL */

/* Now check what of those algorithms are actually enabled */

#ifdef TEST_ENG_OPENSSL_RC4
static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid);
#endif
#ifdef TEST_ENG_OPENSSL_SHA
static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid);
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method, void *callback_data);
#endif

/* The constants used when creating the ENGINE */
static const char *engine_openssl_id = "openssl";
static const char *engine_openssl_name = "Software engine support";

/* This internal function is used by ENGINE_openssl() and possibly by the
 * "dynamic" ENGINE support too */
static int
bind_helper(ENGINE *e)
{
    if (!ENGINE_set_id(e, engine_openssl_id) || !ENGINE_set_name(e, engine_openssl_name)
#ifndef TEST_ENG_OPENSSL_NO_ALGORITHMS
#ifndef OPENSSL_NO_RSA
        || !ENGINE_set_RSA(e, RSA_get_default_method())
#endif
#ifndef OPENSSL_NO_DSA
        || !ENGINE_set_DSA(e, DSA_get_default_method())
#endif
        || !ENGINE_set_ECDH(e, ECDH_OpenSSL())
        || !ENGINE_set_ECDSA(e, ECDSA_OpenSSL())
#ifndef OPENSSL_NO_DH
        || !ENGINE_set_DH(e, DH_get_default_method())
#endif
        || !ENGINE_set_RAND(e, RAND_SSLeay())
#ifdef TEST_ENG_OPENSSL_RC4
        || !ENGINE_set_ciphers(e, openssl_ciphers)
#endif
#ifdef TEST_ENG_OPENSSL_SHA
        || !ENGINE_set_digests(e, openssl_digests)
#endif
#endif
#ifdef TEST_ENG_OPENSSL_PKEY
        || !ENGINE_set_load_privkey_function(e, openssl_load_privkey)
#endif
            )
        return 0;
    /* If we add errors to this ENGINE, ensure the error handling is setup here */
    /* openssl_load_error_strings(); */
    return 1;
}

static ENGINE *
engine_openssl(void)
{
    ENGINE *ret = ENGINE_new();

    if (!ret)
        return NULL;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void
ENGINE_load_openssl(void)
{
    ENGINE *toadd = engine_openssl();

    if (!toadd)
        return;
    ENGINE_add(toadd);
    /* If the "add" worked, it gets a structural reference. So either way,
     * we release our just-created reference. */
    ENGINE_free(toadd);
    ERR_clear_error();
}

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
#ifdef ENGINE_DYNAMIC_SUPPORT
static int
bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_openssl_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* ENGINE_DYNAMIC_SUPPORT */

#ifdef TEST_ENG_OPENSSL_RC4
/* This section of code compiles an "alternative implementation" of two modes of
 * RC4 into this ENGINE. The result is that EVP_CIPHER operation for "rc4"
 * should under normal circumstances go via this support rather than the default
 * EVP support. There are other symbols to tweak the testing;
 *    TEST_ENC_OPENSSL_RC4_OTHERS - print a one line message to stderr each time
 *        we're asked for a cipher we don't support (should not happen).
 *    TEST_ENG_OPENSSL_RC4_P_INIT - print a one line message to stderr each time
 *        the "init_key" handler is called.
 *    TEST_ENG_OPENSSL_RC4_P_CIPHER - ditto for the "cipher" handler.
 */
#include <openssl/rc4.h>
#define TEST_RC4_KEY_SIZE 16
static int test_cipher_nids[] = { NID_rc4, NID_rc4_40 };
static int test_cipher_nids_number = 2;

typedef struct {
    uint8_t key[TEST_RC4_KEY_SIZE];
    RC4_KEY ks;
} TEST_RC4_KEY;

#define test(ctx) ((TEST_RC4_KEY *)(ctx)->cipher_data)
static int
test_rc4_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                  const uint8_t *iv, int enc)
{
#ifdef TEST_ENG_OPENSSL_RC4_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_init_key() called\n");
#endif
    memcpy(&test(ctx)->key[0], key, EVP_CIPHER_CTX_key_length(ctx));
    RC4_set_key(&test(ctx)->ks, EVP_CIPHER_CTX_key_length(ctx),
                test(ctx)->key);
    return 1;
}

static int
test_rc4_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                const uint8_t *in, size_t inl)
{
#ifdef TEST_ENG_OPENSSL_RC4_P_CIPHER
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_cipher() called\n");
#endif
    RC4(&test(ctx)->ks, inl, in, out);
    return 1;
}

static const EVP_CIPHER test_r4_cipher = {
    NID_rc4,
    1, TEST_RC4_KEY_SIZE, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    test_rc4_init_key,
    test_rc4_cipher,
    NULL,
    sizeof(TEST_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

static const EVP_CIPHER test_r4_40_cipher = {
    NID_rc4_40,
    1, 5 /* 40 bit */, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    test_rc4_init_key,
    test_rc4_cipher,
    NULL,
    sizeof(TEST_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

static int
openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = test_cipher_nids;
        return test_cipher_nids_number;
    }
    /* We are being asked for a specific cipher */
    if (nid == NID_rc4)
        *cipher = &test_r4_cipher;
    else if (nid == NID_rc4_40)
        *cipher = &test_r4_40_cipher;
    else {
#ifdef TEST_ENG_OPENSSL_RC4_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) returning NULL for "
                        "nid %d\n",
                nid);
#endif
        *cipher = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_SHA
/* Much the same sort of comment as for TEST_ENG_OPENSSL_RC4 */
#include <openssl/sha.h>
static int test_digest_nids[] = { NID_sha1 };
static int test_digest_nids_number = 1;

static int
test_sha1_init(EVP_MD_CTX *ctx)
{
#ifdef TEST_ENG_OPENSSL_SHA_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_init() called\n");
#endif
    return SHA1_Init(ctx->md_data);
}

static int
test_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
#ifdef TEST_ENG_OPENSSL_SHA_P_UPDATE
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_update() called\n");
#endif
    return SHA1_Update(ctx->md_data, data, count);
}

static int
test_sha1_final(EVP_MD_CTX *ctx, uint8_t *md)
{
#ifdef TEST_ENG_OPENSSL_SHA_P_FINAL
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_final() called\n");
#endif
    return SHA1_Final(md, ctx->md_data);
}

static const EVP_MD test_sha_md = {
    .type = NID_sha1,
    .pkey_type = NID_sha1WithRSAEncryption,
    .md_size = SHA_DIGEST_LENGTH,
    .init = test_sha1_init,
    .update = test_sha1_update,
    .final = test_sha1_final,
    .sign = EVP_PKEY_RSA_method,
    .block_size = SHA_CBLOCK,
    .ctx_size = sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

static int
openssl_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = test_digest_nids;
        return test_digest_nids_number;
    }
    /* We are being asked for a specific digest */
    if (nid == NID_sha1)
        *digest = &test_sha_md;
    else {
#ifdef TEST_ENG_OPENSSL_SHA_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) returning NULL for "
                        "nid %d\n",
                nid);
#endif
        *digest = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *
openssl_load_privkey(ENGINE *eng, const char *key_id, UI_METHOD *ui_method,
                     void *callback_data)
{
    BIO *in;
    EVP_PKEY *key;

    fprintf(stderr, "(TEST_ENG_OPENSSL_PKEY)Loading Private key %s\n",
            key_id);
    in = BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    BIO_free(in);
    return key;
}
#endif
