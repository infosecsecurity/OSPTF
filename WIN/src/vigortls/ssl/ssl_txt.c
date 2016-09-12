/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/buffer.h>
#include "ssl_locl.h"

int SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *x)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file_internal())) == NULL) {
        SSLerr(SSL_F_SSL_SESSION_PRINT_FP, ERR_R_BUF_LIB);
        return (0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = SSL_SESSION_print(b, x);
    BIO_free(b);
    return (ret);
}

int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x)
{
    unsigned int i;
    const char *s;

    if (x == NULL)
        goto err;
    if (BIO_puts(bp, "SSL-Session:\n") <= 0)
        goto err;

    s = ssl_version_string(x->ssl_version);
    if (BIO_printf(bp, "    Protocol  : %s\n", s) <= 0)
        goto err;

    if (x->cipher == NULL) {
        if (((x->cipher_id) & 0xff000000) == 0x02000000) {
            if (BIO_printf(bp, "    Cipher    : %06lX\n", x->cipher_id & 0xffffff) <= 0)
                goto err;
        } else {
            if (BIO_printf(bp, "    Cipher    : %04lX\n", x->cipher_id & 0xffff) <= 0)
                goto err;
        }
    } else {
        if (BIO_printf(bp, "    Cipher    : %s\n",
                       ((x->cipher == NULL) ? "unknown" : x->cipher->name)) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "    Session-ID: ") <= 0)
        goto err;
    for (i = 0; i < x->session_id_length; i++) {
        if (BIO_printf(bp, "%02X", x->session_id[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\n    Session-ID-ctx: ") <= 0)
        goto err;
    for (i = 0; i < x->sid_ctx_length; i++) {
        if (BIO_printf(bp, "%02X", x->sid_ctx[i]) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\n    Master-Key: ") <= 0)
        goto err;
    for (i = 0; i < (unsigned int)x->master_key_length; i++) {
        if (BIO_printf(bp, "%02X", x->master_key[i]) <= 0)
            goto err;
    }
    if (x->tlsext_tick_lifetime_hint) {
        if (BIO_printf(bp, "\n    TLS session ticket lifetime hint: %ld (seconds)",
                       x->tlsext_tick_lifetime_hint) <= 0)
            goto err;
    }
    if (x->tlsext_tick) {
        if (BIO_puts(bp, "\n    TLS session ticket:\n") <= 0)
            goto err;
        if (BIO_dump_indent(bp, (char *)x->tlsext_tick, x->tlsext_ticklen, 4) <= 0)
            goto err;
    }

    if (x->time != 0) {
        if (BIO_printf(bp, "\n    Start Time: %lld", (long long)x->time) <= 0)
            goto err;
    }
    if (x->timeout != 0L) {
        if (BIO_printf(bp, "\n    Timeout   : %ld (sec)", x->timeout) <= 0)
            goto err;
    }
    if (BIO_puts(bp, "\n") <= 0)
        goto err;

    if (BIO_puts(bp, "    Verify return code: ") <= 0)
        goto err;

    if (BIO_printf(bp, "%ld (%s)\n", x->verify_result,
                   X509_verify_cert_error_string(x->verify_result)) <= 0)
        goto err;

    return (1);
err:
    return (0);
}
