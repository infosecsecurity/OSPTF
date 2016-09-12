/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/conf.h>

/* Load all algorithms and configure OpenSSL.
 * This function is called automatically when
 * OPENSSL_LOAD_CONF is set.
 */

void OPENSSL_add_all_algorithms_conf(void)
{
    OPENSSL_add_all_algorithms_noconf();
    OPENSSL_config(NULL);
}
