/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

void SSL_load_error_strings(void)
{
#ifndef OPENSSL_NO_ERR
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
#endif
}
