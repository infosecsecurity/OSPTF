/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/opensslconf.h>
#include <sys/types.h>

#define PORT 4433
#define PORT_STR "4433"
#define PROTOCOL "tcp"

int do_server(int port, int type, int *ret,
              int (*cb)(char *hostname, int s, int stype, uint8_t *context),
              uint8_t *context, int naccept);
#ifdef HEADER_X509_H
int verify_callback(int ok, X509_STORE_CTX *ctx);
#endif
#ifdef HEADER_SSL_H
int set_cert_stuff(SSL_CTX *ctx, char *cert_file, char *key_file);
int set_cert_key_stuff(SSL_CTX *ctx, X509 *cert, EVP_PKEY *key,
                       STACK_OF(X509) *chain, int build_chain);
int ssl_print_sigalgs(BIO *out, SSL *s);
int ssl_print_point_formats(BIO *out, SSL *s);
int ssl_print_curves(BIO *out, SSL *s, int noshared);
#endif
int ssl_print_tmp_key(BIO *out, SSL *s);
int init_client(int *sock, char *server, char *port, int type, int af);
int should_retry(int i);
int extract_port(char *str, short *port_ptr);
int extract_host_port(char *str, char **host_ptr, uint8_t *ip, char **p);

long bio_dump_callback(BIO *bio, int cmd, const char *argp, int argi, long argl,
                       long ret);

#ifdef HEADER_SSL_H
void apps_ssl_info_callback(const SSL *s, int where, int ret);
void msg_cb(int write_p, int version, int content_type, const void *buf,
            size_t len, SSL *ssl, void *arg);
void tlsext_cb(SSL *s, int client_server, int type, uint8_t *data, int len,
               void *arg);
#endif

int generate_cookie_callback(SSL *ssl, uint8_t *cookie,
                             unsigned int *cookie_len);
int verify_cookie_callback(SSL *ssl, uint8_t *cookie, unsigned int cookie_len);

typedef struct ssl_excert_st SSL_EXCERT;

void ssl_ctx_set_excert(SSL_CTX *ctx, SSL_EXCERT *exc);
void ssl_excert_free(SSL_EXCERT *exc);
int args_excert(char ***pargs, int *pargc, int *badarg, BIO *err,
                SSL_EXCERT **pexc);
int load_excert(SSL_EXCERT **pexc, BIO *err);
void print_ssl_summary(BIO *bio, SSL *s);
#ifdef HEADER_SSL_H
int args_ssl(char ***pargs, int *pargc, SSL_CONF_CTX *cctx, int *badarg,
             BIO *err, STACK_OF(OPENSSL_STRING) **pstr);
int args_ssl_call(SSL_CTX *ctx, BIO *err, SSL_CONF_CTX *cctx,
                  STACK_OF(OPENSSL_STRING) *str, int no_ecdhe);
int ssl_ctx_add_crls(SSL_CTX *ctx, STACK_OF(X509_CRL) *crls, int crl_download);
int ssl_load_stores(SSL_CTX *sctx, const char *vfyCApath, const char *vfyCAfile,
                    const char *chCApath, const char *chCAfile,
                    STACK_OF(X509_CRL) *crls, int crl_download);
#endif