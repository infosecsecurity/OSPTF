/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_TXT_DB_H
#define HEADER_TXT_DB_H

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/lhash.h>
#include <openssl/stack.h>

#define DB_ERROR_OK                 0
#define DB_ERROR_MALLOC             1
#define DB_ERROR_INDEX_CLASH        2
#define DB_ERROR_INDEX_OUT_OF_RANGE 3
#define DB_ERROR_NO_INDEX           4
#define DB_ERROR_INSERT_INDEX_CLASH 5

#ifdef __cplusplus
extern "C" {
#endif

typedef OPENSSL_STRING *OPENSSL_PSTRING;
DECLARE_SPECIAL_STACK_OF(OPENSSL_PSTRING, OPENSSL_STRING)

typedef struct txt_db_st {
    int num_fields;
    STACK_OF(OPENSSL_PSTRING) *data;
    LHASH_OF(OPENSSL_STRING) **index;
    int (**qual)(OPENSSL_STRING *);
    long error;
    long arg1;
    long arg2;
    OPENSSL_STRING *arg_row;
} TXT_DB;

VIGORTLS_EXPORT TXT_DB *TXT_DB_read(BIO *in, int num);
VIGORTLS_EXPORT long TXT_DB_write(BIO *out, TXT_DB *db);
VIGORTLS_EXPORT int TXT_DB_create_index(TXT_DB *db, int field,
                                        int (*qual)(OPENSSL_STRING *),
                                        LHASH_HASH_FN_TYPE hash,
                                        LHASH_COMP_FN_TYPE cmp);
VIGORTLS_EXPORT void TXT_DB_free(TXT_DB *db);
VIGORTLS_EXPORT OPENSSL_STRING *TXT_DB_get_by_index(TXT_DB *db, int idx,
                                                    OPENSSL_STRING *value);
VIGORTLS_EXPORT int TXT_DB_insert(TXT_DB *db, OPENSSL_STRING *value);

#ifdef __cplusplus
}
#endif

#endif
