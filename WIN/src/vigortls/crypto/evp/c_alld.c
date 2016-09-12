/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

void OpenSSL_add_all_digests(void)
{
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
    EVP_add_digest(EVP_sha1());
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
#ifndef OPENSSL_NO_DSA
    EVP_add_digest(EVP_dss1());
    EVP_add_digest_alias(SN_dsaWithSHA1, SN_dsaWithSHA1_2);
    EVP_add_digest_alias(SN_dsaWithSHA1, "DSS1");
    EVP_add_digest_alias(SN_dsaWithSHA1, "dss1");
#endif
    EVP_add_digest(EVP_ecdsa());
#ifndef OPENSSL_NO_GOST
    EVP_add_digest(EVP_gostr341194());
    EVP_add_digest(EVP_gost2814789imit());
    EVP_add_digest(EVP_streebog256());
    EVP_add_digest(EVP_streebog512());
#endif
#ifndef OPENSSL_NO_RIPEMD
    EVP_add_digest(EVP_ripemd160());
    EVP_add_digest_alias(SN_ripemd160, "ripemd");
    EVP_add_digest_alias(SN_ripemd160, "rmd160");
#endif
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_digest(EVP_whirlpool());
}
