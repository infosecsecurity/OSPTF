/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CONF_API_H
#define HEADER_CONF_API_H

#include <openssl/base.h>
#include <openssl/conf.h>
#include <openssl/lhash.h>

#ifdef __cplusplus
extern "C" {
#endif

VIGORTLS_EXPORT CONF_VALUE *_CONF_new_section(CONF *conf, const char *section);
VIGORTLS_EXPORT CONF_VALUE *_CONF_get_section(const CONF *conf,
                                              const char *section);
VIGORTLS_EXPORT STACK_OF(CONF_VALUE) *
    _CONF_get_section_values(const CONF *conf, const char *section);

VIGORTLS_EXPORT int _CONF_add_string(CONF *conf, CONF_VALUE *section,
                                     CONF_VALUE *value);
VIGORTLS_EXPORT char *_CONF_get_string(const CONF *conf, const char *section,
                                       const char *name);
VIGORTLS_EXPORT long _CONF_get_number(const CONF *conf, const char *section,
                                      const char *name);

VIGORTLS_EXPORT int _CONF_new_data(CONF *conf);
VIGORTLS_EXPORT void _CONF_free_data(CONF *conf);

#ifdef __cplusplus
}
#endif
#endif
