/*
 * Copyright 2003-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "eng_int.h"

/* If this symbol is defined then ENGINE_get_default_STORE(), the function that is
 * used by STORE to hook in implementation code and cache defaults (etc), will
 * display brief debugging summaries to stderr with the 'nid'. */
/* #define ENGINE_STORE_DEBUG */

static ENGINE_TABLE *store_table = NULL;
static const int dummy_nid = 1;

void ENGINE_unregister_STORE(ENGINE *e)
{
    engine_table_unregister(&store_table, e);
}

static void engine_unregister_all_STORE(void)
{
    engine_table_cleanup(&store_table);
}

int ENGINE_register_STORE(ENGINE *e)
{
    if (e->store_meth)
        return engine_table_register(&store_table,
                                     engine_unregister_all_STORE, e, &dummy_nid, 1, 0);
    return 1;
}

void ENGINE_register_all_STORE(void)
{
    ENGINE *e;

    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e))
        ENGINE_register_STORE(e);
}

/* Obtains an STORE implementation from an ENGINE functional reference */
const STORE_METHOD *ENGINE_get_STORE(const ENGINE *e)
{
    return e->store_meth;
}

/* Sets an STORE implementation in an ENGINE structure */
int ENGINE_set_STORE(ENGINE *e, const STORE_METHOD *store_meth)
{
    e->store_meth = store_meth;
    return 1;
}
