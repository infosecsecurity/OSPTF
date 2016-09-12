/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/objects.h>
#include <openssl/lhash.h>
#include "ssl_locl.h"

int SSL_library_init(void)
{

#ifndef OPENSSL_NO_DES
    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
#endif
#ifndef OPENSSL_NO_IDEA
    EVP_add_cipher(EVP_idea_cbc());
#endif
    EVP_add_cipher(EVP_rc4());
#if !defined(OPENSSL_NO_MD5) && defined(VIGORTLS_X86_64)
    EVP_add_cipher(EVP_rc4_hmac_md5());
#endif
#ifndef OPENSSL_NO_RC2
    EVP_add_cipher(EVP_rc2_cbc());
    /* Not actually used for SSL/TLS but this makes PKCS#12 work
   * if an application only calls SSL_library_init().
   */
    EVP_add_cipher(EVP_rc2_40_cbc());
#endif
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_256_cbc());

    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "ssl2-md5");
    EVP_add_digest_alias(SN_md5, "ssl3-md5");
    EVP_add_digest(EVP_sha1()); /* RSA with sha1 */
    EVP_add_digest_alias(SN_sha1, "ssl3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_digest(EVP_dss1()); /* DSA with sha1 */
    EVP_add_digest_alias(SN_dsaWithSHA1, SN_dsaWithSHA1_2);
    EVP_add_digest_alias(SN_dsaWithSHA1, "DSS1");
    EVP_add_digest_alias(SN_dsaWithSHA1, "dss1");
    EVP_add_digest(EVP_ecdsa());
    /* initialize cipher/digest methods table */
    ssl_load_ciphers();
    return (1);
}
