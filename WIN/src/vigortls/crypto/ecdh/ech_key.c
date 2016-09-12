/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions of this software developed by SUN MICROSYSTEMS, INC.,
 * and contributed to the OpenSSL project.
 */

#include "ech_locl.h"

int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                     EC_KEY *eckey,
                     void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
{
    ECDH_DATA *ecdh = ecdh_check(eckey);
    if (ecdh == NULL)
        return 0;
    return ecdh->meth->compute_key(out, outlen, pub_key, eckey, KDF);
}
