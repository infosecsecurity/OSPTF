/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <sys/types.h>

#include <stdcompat.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>

#include <openssl/opensslconf.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#include "internal/threads.h"
#include "ssl_locl.h"

static CRYPTO_ONCE ssl_x509_store_ctx_once = CRYPTO_ONCE_STATIC_INIT;
static volatile int ssl_x509_store_ctx_idx = -1;

static void ssl_x509_store_ctx_init(void)
{
    ssl_x509_store_ctx_idx = X509_STORE_CTX_get_ex_new_index(0,
        (char *)"SSL for verify callback", NULL, NULL, NULL);
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    CRYPTO_thread_run_once(&ssl_x509_store_ctx_once, ssl_x509_store_ctx_init);
    return ssl_x509_store_ctx_idx;
}

void ssl_cert_set_default_md(CERT *cert)
{
    /* Set digest values to defaults */
    cert->pkeys[SSL_PKEY_DSA_SIGN].digest = EVP_sha1();
    cert->pkeys[SSL_PKEY_RSA_SIGN].digest = EVP_sha1();
    cert->pkeys[SSL_PKEY_RSA_ENC].digest = EVP_sha1();
    cert->pkeys[SSL_PKEY_ECC].digest = EVP_sha1();
}

CERT *ssl_cert_new(void)
{
    CERT *ret;

    ret = calloc(1, sizeof(CERT));
    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->key = &(ret->pkeys[SSL_PKEY_RSA_ENC]);
    ret->references = 1;
    ssl_cert_set_default_md(ret);
    ret->lock = CRYPTO_thread_new();
    if (ret->lock == NULL) {
        SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
        free(ret);
        return NULL;
    }
    return ret;
}

CERT *ssl_cert_dup(CERT *cert)
{
    CERT *ret;
    int i;

    ret = calloc(1, sizeof(CERT));
    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    /*
     * same as ret->key = ret->pkeys + (cert->key - cert->pkeys),
     * if you find that more readable
     */
    ret->references = 1;
    ret->key = &ret->pkeys[cert->key - &cert->pkeys[0]];

    ret->lock = CRYPTO_thread_new();
    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
        free(ret);
        return NULL;
    }

    ret->valid = cert->valid;
    ret->mask_k = cert->mask_k;
    ret->mask_a = cert->mask_a;

    if (cert->dh_tmp != NULL) {
        ret->dh_tmp = DHparams_dup(cert->dh_tmp);
        if (ret->dh_tmp == NULL) {
            SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_DH_LIB);
            goto err;
        }
        if (cert->dh_tmp->priv_key) {
            BIGNUM *b = BN_dup(cert->dh_tmp->priv_key);
            if (!b) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
                goto err;
            }
            ret->dh_tmp->priv_key = b;
        }
        if (cert->dh_tmp->pub_key) {
            BIGNUM *b = BN_dup(cert->dh_tmp->pub_key);
            if (!b) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_BN_LIB);
                goto err;
            }
            ret->dh_tmp->pub_key = b;
        }
    }
    ret->dh_tmp_cb = cert->dh_tmp_cb;
    ret->dh_tmp_auto = cert->dh_tmp_auto;

    if (cert->ecdh_tmp) {
        ret->ecdh_tmp = EC_KEY_dup(cert->ecdh_tmp);
        if (ret->ecdh_tmp == NULL) {
            SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_EC_LIB);
            goto err;
        }
    }
    ret->ecdh_tmp_cb = cert->ecdh_tmp_cb;
    ret->ecdh_tmp_auto = cert->ecdh_tmp_auto;

    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = cert->pkeys + i;
        CERT_PKEY *rpk = ret->pkeys + i;
        if (cpk->x509 != NULL) {
            rpk->x509 = cpk->x509;
            X509_up_ref(ret->pkeys[i].x509);
        }

        if (cpk->privatekey != NULL) {
            rpk->privatekey = cpk->privatekey;
            EVP_PKEY_up_ref(ret->pkeys[i].privatekey);
        }

        if (cpk->chain) {
            rpk->chain = X509_chain_up_ref(cpk->chain);
            if (rpk->chain == NULL) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        /* Clear all flags apart from explicit sign */
        cpk->valid_flags &= CERT_PKEY_EXPLICIT_SIGN;
        if (cert->pkeys[i].serverinfo != NULL) {
            /* Just copy everything. */
            ret->pkeys[i].serverinfo_length =
                cert->pkeys[i].serverinfo_length;
                ret->pkeys[i].serverinfo =
                    malloc(ret->pkeys[i].serverinfo_length);
                if (ret->pkeys[i].serverinfo == NULL) {
                    SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                    return NULL;
                }
                memcpy(ret->pkeys[i].serverinfo, cert->pkeys[i].serverinfo,
                       cert->pkeys[i].serverinfo_length);
        }
    }

    /*
     * ret->extra_certs *should* exist, but currently the own certificate
     * chain is held inside SSL_CTX
     */

    /*
     * Set digests to defaults. NB: we don't copy existing values
     * as they will be set during handshake.
     */
    ssl_cert_set_default_md(ret);

    /* Configure sigalgs however we copy across */
    if (cert->conf_sigalgs) {
        ret->conf_sigalgs = malloc(cert->conf_sigalgslen);
        if (ret->conf_sigalgs == NULL)
            goto err;
        memcpy(ret->conf_sigalgs, cert->conf_sigalgs, cert->conf_sigalgslen);
        ret->conf_sigalgslen = cert->conf_sigalgslen;
    }

    if (cert->client_sigalgs != NULL) {
        ret->client_sigalgs = malloc(cert->client_sigalgslen);
        if (ret->client_sigalgs == NULL)
            goto err;
        memcpy(ret->client_sigalgs, cert->client_sigalgs,
               cert->client_sigalgslen);
        ret->client_sigalgslen = cert->client_sigalgslen;
    }
    /* Copy any custom client certificate types */
    if (cert->ctypes != NULL) {
        ret->ctypes = malloc(cert->ctype_num);
        if (ret->ctypes == NULL)
            goto err;
        memcpy(ret->ctypes, cert->ctypes, cert->ctype_num);
        ret->ctype_num = cert->ctype_num;
    }

    ret->cert_flags = cert->cert_flags;
 
    ret->cert_cb = cert->cert_cb;
    ret->cert_cb_arg = cert->cert_cb_arg;

    if (cert->verify_store) {
        X509_STORE_up_ref(cert->verify_store);
        ret->verify_store = cert->verify_store;
    }

    if (cert->chain_store) {
        X509_STORE_up_ref(cert->chain_store);
        ret->chain_store = cert->chain_store;
    }

    if (!custom_exts_copy(&ret->cli_ext, &cert->cli_ext))
        goto err;
    if (!custom_exts_copy(&ret->srv_ext, &cert->srv_ext))
        goto err;

    return ret;

err:
    DH_free(ret->dh_tmp);
    EC_KEY_free(ret->ecdh_tmp);

    custom_exts_free(&ret->cli_ext);
    custom_exts_free(&ret->srv_ext);

    ssl_cert_clear_certs(ret);
    free(ret);
    return NULL;
}

/* Free up and clear all certificates and chains */

void ssl_cert_clear_certs(CERT *c)
{
    int i;

    if (c == NULL)
        return;

    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        X509_free(cpk->x509);
        cpk->x509 = NULL;
        EVP_PKEY_free(cpk->privatekey);
        cpk->privatekey = NULL;
        sk_X509_pop_free(cpk->chain, X509_free);
        cpk->chain = NULL;
        free(cpk->serverinfo);
        cpk->serverinfo = NULL;

        /* Clear all flags apart from explicit sign */
        cpk->valid_flags &= CERT_PKEY_EXPLICIT_SIGN;
    }
}

void ssl_cert_free(CERT *c)
{
    int i;

    if (c == NULL)
        return;

    CRYPTO_atomic_add(&c->references, -1, &i, c->lock);
    if (i > 0)
        return;

    DH_free(c->dh_tmp);
    EC_KEY_free(c->ecdh_tmp);

    ssl_cert_clear_certs(c);
    free(c->peer_sigalgs);
    free(c->conf_sigalgs);
    free(c->client_sigalgs);
    free(c->shared_sigalgs);
    free(c->ctypes);
    X509_STORE_free(c->verify_store);
    X509_STORE_free(c->chain_store);
    free(c->ciphers_raw);
    custom_exts_free(&c->cli_ext);
    custom_exts_free(&c->srv_ext);
    free(c->alpn_proposed);
    CRYPTO_thread_cleanup(c->lock);
    free(c);
}

int ssl_cert_inst(CERT **o)
{
    /*
     * Create a CERT if there isn't already one
     * (which cannot really happen, as it is initially created in
     * SSL_CTX_new; but the earlier code usually allows for that one
     * being non-existent, so we follow that behaviour, as it might
     * turn out that there actually is a reason for it -- but I'm
     * not sure that *all* of the existing code could cope with
     * s->cert being NULL, otherwise we could do without the
     * initialization in SSL_CTX_new).
     */

    if (o == NULL) {
        SSLerr(SSL_F_SSL_CERT_INST, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (*o == NULL) {
        if ((*o = ssl_cert_new()) == NULL) {
            SSLerr(SSL_F_SSL_CERT_INST, ERR_R_MALLOC_FAILURE);
            return (0);
        }
    }
    return (1);
}

int ssl_cert_set0_chain(CERT *c, STACK_OF(X509) *chain)
{
    CERT_PKEY *cpk = c->key;
    if (cpk == NULL)
        return 0;
    sk_X509_pop_free(cpk->chain, X509_free);
    cpk->chain = chain;
    return 1;
}

int ssl_cert_set1_chain(CERT *c, STACK_OF(X509) *chain)
{
    STACK_OF(X509) *dchain;
    if (chain == NULL)
        return ssl_cert_set0_chain(c, NULL);
    dchain = X509_chain_up_ref(chain);
    if (dchain == NULL)
        return 0;
    if (!ssl_cert_set0_chain(c, dchain)) {
        sk_X509_pop_free(dchain, X509_free);
        return 0;
    }
    return 1;
}

int ssl_cert_add0_chain_cert(CERT *c, X509 *x)
{
    CERT_PKEY *cpk = c->key;
    if (cpk == NULL)
        return 0;
    if (!cpk->chain)
        cpk->chain = sk_X509_new_null();
    if (!cpk->chain || !sk_X509_push(cpk->chain, x))
        return 0;
    return 1;
}

int ssl_cert_add1_chain_cert(CERT *c, X509 *x)
{
    if (!ssl_cert_add0_chain_cert(c, x))
        return 0;
    X509_up_ref(x);
    return 1;
}

int ssl_cert_select_current(CERT *c, X509 *x)
{
    int i;
    if (x == NULL)
        return 0;
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->x509 == x && cpk->privatekey != NULL) {
            c->key = cpk;
            return 1;
        }
    }

    for (i = 0; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->privatekey && cpk->x509 && !X509_cmp(cpk->x509, x)) {
            c->key = cpk;
            return 1;
        }
    }
    return 0;
}

int ssl_cert_set_current(CERT *c, long op)
{
    int i, idx;
    if (c == NULL)
        return 0;
    if (op == SSL_CERT_SET_FIRST)
        idx = 0;
    else if (op == SSL_CERT_SET_NEXT) {
        idx = (int)(c->key - c->pkeys + 1);
        if (idx >= SSL_PKEY_NUM)
            return 0;
    } else
        return 0;
    for (i = idx; i < SSL_PKEY_NUM; i++) {
        CERT_PKEY *cpk = c->pkeys + i;
        if (cpk->x509 && cpk->privatekey != NULL) {
            c->key = cpk;
            return 1;
        }
    }
    return 0;
}

void ssl_cert_set_cert_cb(CERT *c, int (*cb)(SSL *ssl, void *arg), void *arg)
{
    c->cert_cb = cb;
    c->cert_cb_arg = arg;
}

SESS_CERT *ssl_sess_cert_new(void)
{
    SESS_CERT *ret;

    ret = calloc(1, sizeof *ret);
    if (ret == NULL) {
        SSLerr(SSL_F_SSL_SESS_CERT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->peer_key = &(ret->peer_pkeys[SSL_PKEY_RSA_ENC]);
    ret->references = 1;
    ret->lock = CRYPTO_thread_new();
    if (ret->lock == NULL) {
        SSLerr(SSL_F_SSL_SESS_CERT_NEW, ERR_R_MALLOC_FAILURE);
        free(ret);
        return NULL;
    }

    return ret;
}

void ssl_sess_cert_free(SESS_CERT *sc)
{
    int i;

    if (sc == NULL)
        return;

    CRYPTO_atomic_add(&sc->references, -1, &i, sc->lock);
    if (i > 0)
        return;

    /* i == 0 */
    sk_X509_pop_free(sc->cert_chain, X509_free);
    for (i = 0; i < SSL_PKEY_NUM; i++)
        X509_free(sc->peer_pkeys[i].x509);

    RSA_free(sc->peer_rsa_tmp);
    DH_free(sc->peer_dh_tmp);
    EC_KEY_free(sc->peer_ecdh_tmp);

    free(sc);
}

void SSL_CERT_up_ref(SESS_CERT *sc)
{
    int i;
    CRYPTO_atomic_add(&sc->references, 1, &i, sc->lock);
}

int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk)
{
    X509_STORE_CTX ctx;
    X509_STORE *verify_store;
    X509 *x;
    int ret;

    if (s->cert->verify_store)
        verify_store = s->cert->verify_store;
    else
        verify_store = s->ctx->cert_store;

    if ((sk == NULL) || (sk_X509_num(sk) == 0))
        return (0);

    x = sk_X509_value(sk, 0);
    if (!X509_STORE_CTX_init(&ctx, verify_store, x, sk)) {
        SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, ERR_R_X509_LIB);
        return (0);
    }
    /* Set suite B flags if needed */
    X509_STORE_CTX_set_flags(&ctx, tls1_suiteb(s));

    X509_STORE_CTX_set_ex_data(&ctx, SSL_get_ex_data_X509_STORE_CTX_idx(), s);

    /*
     * We need to inherit the verify parameters. These can be
     * determined by the context: if its a server it will verify
     * SSL client certificates or vice versa.
     */
    X509_STORE_CTX_set_default(&ctx, s->server ? "ssl_client" : "ssl_server");

    /*
     * Anything non-default in "param" should overwrite anything
     * in the ctx.
     */
    X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(&ctx), s->param);

    if (s->verify_callback)
        X509_STORE_CTX_set_verify_cb(&ctx, s->verify_callback);

    if (s->ctx->app_verify_callback != NULL)
        ret = s->ctx->app_verify_callback(&ctx, s->ctx->app_verify_arg);
    else
        ret = X509_verify_cert(&ctx);

    s->verify_result = ctx.error;
    X509_STORE_CTX_cleanup(&ctx);

    return (ret);
}

static void set_client_CA_list(STACK_OF(X509_NAME) **ca_list,
                               STACK_OF(X509_NAME) *name_list)
{
    sk_X509_NAME_pop_free(*ca_list, X509_NAME_free);

    *ca_list = name_list;
}

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk)
{
    int i;
    STACK_OF(X509_NAME) *ret;
    X509_NAME *name;

    ret = sk_X509_NAME_new_null();
    for (i = 0; i < sk_X509_NAME_num(sk); i++) {
        name = X509_NAME_dup(sk_X509_NAME_value(sk, i));
        if ((name == NULL) || !sk_X509_NAME_push(ret, name)) {
            sk_X509_NAME_pop_free(ret, X509_NAME_free);
            return (NULL);
        }
    }
    return (ret);
}

void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)
{
    set_client_CA_list(&(s->client_CA), name_list);
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)
{
    set_client_CA_list(&(ctx->client_CA), name_list);
}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
{
    return (ctx->client_CA);
}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s)
{
    if (s->type == SSL_ST_CONNECT) {
        /* We are in the client. */
        if (((s->version >> 8) == SSL3_VERSION_MAJOR) && (s->s3 != NULL))
            return (s->s3->tmp.ca_names);
        else
            return (NULL);
    } else {
        if (s->client_CA != NULL)
            return (s->client_CA);
        else
            return (s->ctx->client_CA);
    }
}

static int add_client_CA(STACK_OF(X509_NAME) **sk, X509 * x)
{
    X509_NAME *name;

    if (x == NULL)
        return (0);
    if ((*sk == NULL) && ((*sk = sk_X509_NAME_new_null()) == NULL))
        return (0);

    if ((name = X509_NAME_dup(X509_get_subject_name(x))) == NULL)
        return (0);

    if (!sk_X509_NAME_push(*sk, name)) {
        X509_NAME_free(name);
        return (0);
    }
    return (1);
}

int SSL_add_client_CA(SSL *ssl, X509 *x)
{
    return (add_client_CA(&(ssl->client_CA), x));
}

int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
{
    return (add_client_CA(&(ctx->client_CA), x));
}

static int xname_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

/*!
 * Load CA certs from a file into a ::STACK. Note that it is somewhat misnamed;
 * it doesn't really have anything to do with clients (except that a common use
 * for a stack of CAs is to send it to the client). Actually, it doesn't have
 * much to do with CAs, either, since it will load any old cert.
 * \param file the file containing one or more certs.
 * \return a ::STACK containing the certs.
 */
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    STACK_OF(X509_NAME) *ret = NULL, *sk;

    sk = sk_X509_NAME_new(xname_cmp);

    in = BIO_new(BIO_s_file_internal());

    if ((sk == NULL) || (in == NULL)) {
        SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BIO_read_filename(in, file))
        goto err;

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        if (ret == NULL) {
            ret = sk_X509_NAME_new_null();
            if (ret == NULL) {
                SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if ((xn = X509_get_subject_name(x)) == NULL)
            goto err;
        /* check for duplicates */
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
            goto err;
        if (sk_X509_NAME_find(sk, xn) >= 0)
            X509_NAME_free(xn);
        else {
            sk_X509_NAME_push(sk, xn);
            sk_X509_NAME_push(ret, xn);
        }
    }

    if (0) {
    err:
        sk_X509_NAME_pop_free(ret, X509_NAME_free);
        ret = NULL;
    }
    sk_X509_NAME_free(sk);
    BIO_free(in);
    X509_free(x);
    if (ret != NULL)
        ERR_clear_error();
    return (ret);
}

/*!
 * Add a file of certs to a stack.
 * \param stack the stack to add to.
 * \param file the file to add from. All certs in this file that are not
 * already in the stack will be added.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                        const char *file)
{
    BIO *in;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    int ret = 1;
    int (*oldcmp)(const X509_NAME *const *a, const X509_NAME *const *b);

    oldcmp = sk_X509_NAME_set_cmp_func(stack, xname_cmp);

    in = BIO_new(BIO_s_file_internal());

    if (in == NULL) {
        SSLerr(SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!BIO_read_filename(in, file))
        goto err;

    for (;;) {
        if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL)
            break;
        if ((xn = X509_get_subject_name(x)) == NULL)
            goto err;
        xn = X509_NAME_dup(xn);
        if (xn == NULL)
            goto err;
        if (sk_X509_NAME_find(stack, xn) >= 0)
            X509_NAME_free(xn);
        else
            sk_X509_NAME_push(stack, xn);
    }

    ERR_clear_error();

    if (0) {
    err:
        ret = 0;
    }
    BIO_free(in);
    X509_free(x);

    (void)sk_X509_NAME_set_cmp_func(stack, oldcmp);

    return ret;
}

/*!
 * Add a directory of certs to a stack.
 * \param stack the stack to append to.
 * \param dir the directory to append from. All files in this directory will be
 * examined as potential certs. Any that are acceptable to
 * SSL_add_dir_cert_subjects_to_stack() that are not already in the stack will
 * be included.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                       const char *dir)
{
    DIR *dirp = NULL;
    char *path = NULL;
    int ret = 0;

    dirp = opendir(dir);
    if (dirp) {
        struct dirent *dp;
        while ((dp = readdir(dirp)) != NULL) {
            if (asprintf(&path, "%s/%s", dir, dp->d_name) != -1) {
                ret = SSL_add_file_cert_subjects_to_stack(stack, path);
                free(path);
            }
            if (!ret)
                break;
        }
        (void)closedir(dirp);
    }
    if (!ret) {
        SYSerr(SYS_F_OPENDIR, errno);
        ERR_asprintf_error_data("opendir ('%s')", dir);
        SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK, ERR_R_SYS_LIB);
    }

    return ret;
}

/* Add a certificate to a BUF_MEM structure */

static int ssl_add_cert_to_buf(BUF_MEM *buf, unsigned long *l, X509 *x)
{
    int n;
    uint8_t *p;

    n = i2d_X509(x, NULL);
    if (n < 0 || !BUF_MEM_grow_clean(buf, (int)(n + (*l) + 3))) {
        SSLerr(SSL_F_SSL_ADD_CERT_TO_BUF, ERR_R_BUF_LIB);
        return 0;
    }
    p = (uint8_t *)&(buf->data[*l]);
    l2n3(n, p);
    n = i2d_X509(x, &p);
    if (n < 0) {
        /* Shouldn't happen */
        SSLerr(SSL_F_SSL_ADD_CERT_TO_BUF, ERR_R_BUF_LIB);
        return 0;
    }
    *l += n + 3;

    return 1;
}

/* Add certificate chain to internal SSL BUF_MEM strcuture */
int ssl_add_cert_chain(SSL *s, CERT_PKEY *cpk, unsigned long *l)
{
    BUF_MEM *buf = s->init_buf;
    int no_chain;
    int i;
    X509 *x = NULL;
    STACK_OF(X509) *extra_certs;
    X509_STORE *chain_store;

    if (cpk != NULL)
        x = cpk->x509;

    if (s->cert->chain_store)
        chain_store = s->cert->chain_store;
    else
        chain_store = s->ctx->cert_store;

    /*
     * If we have a certificate specific chain use it, else use
     * parent ctx.
     */
    if (cpk && cpk->chain)
        extra_certs = cpk->chain;
    else
        extra_certs = s->ctx->extra_certs;

    if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || s->ctx->extra_certs)
        no_chain = 1;
    else
        no_chain = 0;

    /* TLSv1 sends a chain with nothing in it, instead of an alert */
    if (!BUF_MEM_grow_clean(buf, 10)) {
        SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, ERR_R_BUF_LIB);
        return 0;
    }
    if (x != NULL) {
        if (no_chain) {
            if (!ssl_add_cert_to_buf(buf, l, x))
                return 0;
        } else {
            X509_STORE_CTX xs_ctx;

            if (!X509_STORE_CTX_init(&xs_ctx, chain_store, x, NULL)) {
                SSLerr(SSL_F_SSL_ADD_CERT_CHAIN, ERR_R_X509_LIB);
                return 0;
            }
            X509_verify_cert(&xs_ctx);
            /* Don't leave errors in the queue */
            ERR_clear_error();
            for (i = 0; i < sk_X509_num(xs_ctx.chain); i++) {
                x = sk_X509_value(xs_ctx.chain, i);

                if (!ssl_add_cert_to_buf(buf, l, x)) {
                    X509_STORE_CTX_cleanup(&xs_ctx);
                    return 0;
                }
            }
            X509_STORE_CTX_cleanup(&xs_ctx);
        }
    }
    for (i = 0; i < sk_X509_num(extra_certs); i++) {
        x = sk_X509_value(extra_certs, i);
        if (!ssl_add_cert_to_buf(buf, l, x))
            return 0;
    }

    return 1;
}

/* Build a certificate chain for current certificate */
int ssl_build_cert_chain(CERT *c, X509_STORE *chain_store, int flags)
{
    CERT_PKEY *cpk = c->key;
    X509_STORE_CTX xs_ctx;
    STACK_OF(X509) *chain = NULL, *untrusted = NULL;
    X509 *x;
    int i, rv = 0;
    unsigned long error;

    if (cpk->x509 == NULL) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, SSL_R_NO_CERTIFICATE_SET);
        goto err;
    }
    
    /* Rearranging and check the chain: add everything to a store */
    if (flags & SSL_BUILD_CHAIN_FLAG_CHECK) {
        chain_store = X509_STORE_new();
        if (chain_store == NULL)
            goto err;
        for (i = 0; i < sk_X509_num(cpk->chain); i++) {
            x = sk_X509_value(cpk->chain, i);
            if (!X509_STORE_add_cert(chain_store, x)) {
                error = ERR_peek_last_error();
                if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
                    ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
                {
                        goto err;
                }
                ERR_clear_error();
            }
        }
        /* Add EE cert too: it might be self signed */
        if (!X509_STORE_add_cert(chain_store, cpk->x509)) {
            error = ERR_peek_last_error();
            if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
                ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
            {
                goto err;
            }
            ERR_clear_error();
        }
        } else {
            if (c->chain_store != NULL)
                chain_store = c->chain_store;

            if (flags & SSL_BUILD_CHAIN_FLAG_UNTRUSTED)
                untrusted = cpk->chain;
        }

    if (!X509_STORE_CTX_init(&xs_ctx, chain_store, cpk->x509, untrusted)) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, ERR_R_X509_LIB);
        goto err;
    }
    /* Set suite B flags if needed */
    X509_STORE_CTX_set_flags(&xs_ctx, c->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS);

    i = X509_verify_cert(&xs_ctx);
    if (i <= 0 && flags & SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR) {
        if (flags & SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR)
            ERR_clear_error();
        i = 1;
        rv = 2;
    }
    if (i > 0)
        chain = X509_STORE_CTX_get1_chain(&xs_ctx);
    if (i <= 0) {
        SSLerr(SSL_F_SSL_BUILD_CERT_CHAIN, SSL_R_CERTIFICATE_VERIFY_FAILED);
        ERR_asprintf_error_data("Verify error:%s",
                                X509_verify_cert_error_string(i));
        X509_STORE_CTX_cleanup(&xs_ctx);
        goto err;
    }
    X509_STORE_CTX_cleanup(&xs_ctx);
    sk_X509_pop_free(cpk->chain, X509_free);
    /* Remove EE certificate from chain */
    x = sk_X509_shift(chain);
    X509_free(x);
    if (flags & SSL_BUILD_CHAIN_FLAG_NO_ROOT) {
        if (sk_X509_num(chain) > 0) {
            /* See if last cert is self signed */
            x = sk_X509_value(chain, sk_X509_num(chain) - 1);
            X509_check_purpose(x, -1, 0);
            if (x->ex_flags & EXFLAG_SS) {
                x = sk_X509_pop(chain);
                X509_free(x);
            }
        }
    }
    cpk->chain = chain;
    if (rv == 0)
        rv = 1;
err:
    if (flags & SSL_BUILD_CHAIN_FLAG_CHECK)
        X509_STORE_free(chain_store);

    return rv;
}

int ssl_cert_set_cert_store(CERT *c, X509_STORE *store, int chain, int ref)
{
    X509_STORE **pstore;
    if (chain)
        pstore = &c->chain_store;
    else
        pstore = &c->verify_store;
    X509_STORE_free(*pstore);
    *pstore = store;
    if (ref && store)
        X509_STORE_up_ref(store);
    return 1;
}
