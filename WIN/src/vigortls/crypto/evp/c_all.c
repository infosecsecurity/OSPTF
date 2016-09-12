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
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "cryptlib.h"

#if 0
#undef OpenSSL_add_all_algorithms

void OpenSSL_add_all_algorithms(void)
    {
    OPENSSL_add_all_algorithms_noconf();
    }
#endif

void OPENSSL_add_all_algorithms_noconf(void)
{
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
}
