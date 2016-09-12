/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_UI_COMPAT_H
#define HEADER_UI_COMPAT_H

#include <openssl/base.h>
#include <openssl/ui.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The following functions were previously part of the DES section,
   and are provided here for backward compatibility reasons. */

#define des_read_pw_string(b, l, p, v) \
    _ossl_old_des_read_pw_string((b), (l), (p), (v))
#define des_read_pw(b, bf, s, p, v) \
    _ossl_old_des_read_pw((b), (bf), (s), (p), (v))

VIGORTLS_EXPORT int _ossl_old_des_read_pw_string(char *buf, int length,
                                                 const char *prompt,
                                                 int verify);
VIGORTLS_EXPORT int _ossl_old_des_read_pw(char *buf, char *buff, int size,
                                          const char *prompt, int verify);

#ifdef __cplusplus
}
#endif
#endif
