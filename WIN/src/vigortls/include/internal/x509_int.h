/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal X509 structures and functions: not for application use */

/* we always keep X509_NAMEs in 2 forms. */
struct X509_name_st {
    STACK_OF(X509_NAME_ENTRY) *entries;
    int modified;               /* true if 'bytes' needs to be built */
    BUF_MEM *bytes;
/*      unsigned long hash; Keep the hash around for lookups */
    uint8_t *canon_enc;
    int canon_enclen;
} /* X509_NAME */ ;

