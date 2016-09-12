/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

long ssl23_default_timeout(void)
{
    return (300);
}

int ssl23_read(SSL *s, void *buf, int len)
{
    int n;

    errno = 0;
    if (SSL_in_init(s) && (!s->in_handshake)) {
        n = s->handshake_func(s);
        if (n < 0)
            return (n);
        if (n == 0) {
            SSLerr(SSL_F_SSL23_READ, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }
        return (SSL_read(s, buf, len));
    } else {
        ssl_undefined_function(s);
        return (-1);
    }
}

int ssl23_peek(SSL *s, void *buf, int len)
{
    int n;

    errno = 0;
    if (SSL_in_init(s) && (!s->in_handshake)) {
        n = s->handshake_func(s);
        if (n < 0)
            return (n);
        if (n == 0) {
            SSLerr(SSL_F_SSL23_PEEK, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }
        return (SSL_peek(s, buf, len));
    } else {
        ssl_undefined_function(s);
        return (-1);
    }
}

int ssl23_write(SSL *s, const void *buf, int len)
{
    int n;

    errno = 0;
    if (SSL_in_init(s) && (!s->in_handshake)) {
        n = s->handshake_func(s);
        if (n < 0)
            return (n);
        if (n == 0) {
            SSLerr(SSL_F_SSL23_WRITE, SSL_R_SSL_HANDSHAKE_FAILURE);
            return (-1);
        }
        return (SSL_write(s, buf, len));
    } else {
        ssl_undefined_function(s);
        return (-1);
    }
}
