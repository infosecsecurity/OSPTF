/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <strings.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/objects.h>
#include <openssl/gost.h>

#include "gost_locl.h"

int GostR3410_get_md_digest(int nid)
{
    if (nid == NID_id_GostR3411_94_CryptoProParamSet)
        return NID_id_GostR3411_94;
    return nid;
}

int GostR3410_get_pk_digest(int nid)
{
    switch (nid) {
        case NID_id_GostR3411_94_CryptoProParamSet:
            return NID_id_GostR3410_2001;
        case NID_id_tc26_gost3411_2012_256:
            return NID_id_tc26_gost3410_2012_256;
        case NID_id_tc26_gost3411_2012_512:
            return NID_id_tc26_gost3410_2012_512;
        default:
            return NID_undef;
    }
}

typedef struct GostR3410_params {
    const char *name;
    int nid;
} GostR3410_params;

static const GostR3410_params GostR3410_256_params[] = {
    { "A", NID_id_GostR3410_2001_CryptoPro_A_ParamSet },
    { "B", NID_id_GostR3410_2001_CryptoPro_B_ParamSet },
    { "C", NID_id_GostR3410_2001_CryptoPro_C_ParamSet },
    { "0", NID_id_GostR3410_2001_TestParamSet },
    { "XA", NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet },
    { "XB", NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet },
    { NULL, NID_undef },
};

static const GostR3410_params GostR3410_512_params[] = {
    { "A", NID_id_tc26_gost_3410_2012_512_paramSetA },
    { "B", NID_id_tc26_gost_3410_2012_512_paramSetB },
    { NULL, NID_undef },
};

int GostR3410_256_param_id(const char *value)
{
    int i;
    for (i = 0; GostR3410_256_params[i].nid != NID_undef; i++) {
        if (!strcasecmp(GostR3410_256_params[i].name, value))
            return GostR3410_256_params[i].nid;
    }

    return NID_undef;
}

int GostR3410_512_param_id(const char *value)
{
    int i;
    for (i = 0; GostR3410_512_params[i].nid != NID_undef; i++) {
        if (!strcasecmp(GostR3410_512_params[i].name, value))
            return GostR3410_512_params[i].nid;
    }

    return NID_undef;
}

#endif
