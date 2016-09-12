/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cryptlib.h"
#include "eng_int.h"

void ENGINE_load_builtin_engines(void)
{
    /* Some ENGINEs need this */
    ENGINE_register_all_complete();
}
