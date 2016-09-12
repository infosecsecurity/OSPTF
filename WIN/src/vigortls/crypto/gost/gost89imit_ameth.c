/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/evp.h>

#include <openssl/ossl_typ.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"

static void mackey_free_gost(EVP_PKEY *pk)
{
    free(pk->pkey.ptr);
}

static int mac_ctrl_gost(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
        case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
            *(int *)arg2 = NID_id_Gost28147_89_MAC;
            return 2;
    }
    return -2;
}

const EVP_PKEY_ASN1_METHOD gostimit_asn1_meth = {
    .pkey_id = EVP_PKEY_GOSTIMIT,
    .pkey_base_id = EVP_PKEY_GOSTIMIT,
    .pkey_flags = ASN1_PKEY_SIGPARAM_NULL,

    .pem_str = "GOST-MAC",
    .info = "GOST 28147-89 MAC",

    .pkey_free = mackey_free_gost,
    .pkey_ctrl = mac_ctrl_gost,
};

#endif
