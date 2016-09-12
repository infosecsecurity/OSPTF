/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdcompat.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/lhash.h>

#include "internal/threads.h"

void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
                         void *u)
{
    unsigned long l;
    char buf[256];
    char buf2[4096];
    const char *file, *data;
    int line, flags;
    /*
     * We don't know what kind of thing CRYPTO_THREAD_ID is. Here is our best
     * attempt to convert it into something we can print.
     */
    union {
        CRYPTO_THREAD_ID tid;
        unsigned long ltid;
    } tid;

    tid.ltid = 0;
    tid.tid = CRYPTO_thread_get_current_id();

    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(l, buf, sizeof buf);
        snprintf(buf2, sizeof(buf2), "%lu:%s:%s:%d:%s\n", tid.ltid, buf,
                 file, line, (flags & ERR_TXT_STRING) ? data : "");
        if (cb(buf2, strlen(buf2), u) <= 0)
            break; /* abort outputting the error report */
    }
}

static int print_fp(const char *str, size_t len, void *fp)
{
    BIO bio;

    BIO_set(&bio, BIO_s_file());
    BIO_set_fp(&bio, fp, BIO_NOCLOSE);

    return BIO_printf(&bio, "%s", str);
}
void ERR_print_errors_fp(FILE *fp)
{
    ERR_print_errors_cb(print_fp, fp);
}

static int print_bio(const char *str, size_t len, void *bp)
{
    return BIO_write((BIO *)bp, str, len);
}
void ERR_print_errors(BIO *bp)
{
    ERR_print_errors_cb(print_bio, bp);
}
