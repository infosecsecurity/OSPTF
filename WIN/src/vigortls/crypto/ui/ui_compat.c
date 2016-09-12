/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/ui_compat.h>

int _ossl_old_des_read_pw_string(char *buf, int length, const char *prompt, int verify)
{
    return UI_UTIL_read_pw_string(buf, length, prompt, verify);
}

int _ossl_old_des_read_pw(char *buf, char *buff, int size, const char *prompt, int verify)
{
    return UI_UTIL_read_pw(buf, buff, size, prompt, verify);
}
