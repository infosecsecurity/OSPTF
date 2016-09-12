/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

void OpenSSL_add_all_ciphers(void)
{

#ifndef OPENSSL_NO_DES
    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher_alias(SN_des_cbc, "DES");
    EVP_add_cipher_alias(SN_des_cbc, "des");
    EVP_add_cipher(EVP_des_ede3_cbc());
    EVP_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    EVP_add_cipher_alias(SN_des_ede3_cbc, "des3");
    EVP_add_cipher(EVP_des_ede3_wrap());
#endif

    EVP_add_cipher(EVP_rc4());
    EVP_add_cipher(EVP_rc4_40());
    EVP_add_cipher(EVP_rc4_hmac_md5());

#ifndef OPENSSL_NO_IDEA
    EVP_add_cipher(EVP_idea_ecb());
    EVP_add_cipher(EVP_idea_cfb());
    EVP_add_cipher(EVP_idea_ofb());
    EVP_add_cipher(EVP_idea_cbc());
    EVP_add_cipher_alias(SN_idea_cbc, "IDEA");
    EVP_add_cipher_alias(SN_idea_cbc, "idea");
#endif

#ifndef OPENSSL_NO_RC2
    EVP_add_cipher(EVP_rc2_ecb());
    EVP_add_cipher(EVP_rc2_cfb());
    EVP_add_cipher(EVP_rc2_ofb());
    EVP_add_cipher(EVP_rc2_cbc());
    EVP_add_cipher(EVP_rc2_40_cbc());
    EVP_add_cipher(EVP_rc2_64_cbc());
    EVP_add_cipher_alias(SN_rc2_cbc, "RC2");
    EVP_add_cipher_alias(SN_rc2_cbc, "rc2");
#endif

#ifndef OPENSSL_NO_RC5
    EVP_add_cipher(EVP_rc5_32_12_16_ecb());
    EVP_add_cipher(EVP_rc5_32_12_16_cfb());
    EVP_add_cipher(EVP_rc5_32_12_16_ofb());
    EVP_add_cipher(EVP_rc5_32_12_16_cbc());
    EVP_add_cipher_alias(SN_rc5_cbc, "rc5");
    EVP_add_cipher_alias(SN_rc5_cbc, "RC5");
#endif

    EVP_add_cipher(EVP_aes_128_ecb());
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_128_cfb());
    EVP_add_cipher(EVP_aes_128_cfb1());
    EVP_add_cipher(EVP_aes_128_cfb8());
    EVP_add_cipher(EVP_aes_128_ofb());
    EVP_add_cipher(EVP_aes_128_ctr());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_128_xts());
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_128_wrap());
    EVP_add_cipher_alias(SN_aes_128_cbc, "AES128");
    EVP_add_cipher_alias(SN_aes_128_cbc, "aes128");
    EVP_add_cipher(EVP_aes_192_ecb());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_192_cfb());
    EVP_add_cipher(EVP_aes_192_cfb1());
    EVP_add_cipher(EVP_aes_192_cfb8());
    EVP_add_cipher(EVP_aes_192_ofb());
    EVP_add_cipher(EVP_aes_192_ctr());
    EVP_add_cipher(EVP_aes_192_gcm());
    EVP_add_cipher(EVP_aes_192_ccm());
    EVP_add_cipher(EVP_aes_192_wrap());
    EVP_add_cipher_alias(SN_aes_192_cbc, "AES192");
    EVP_add_cipher_alias(SN_aes_192_cbc, "aes192");
    EVP_add_cipher(EVP_aes_256_ecb());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_256_cfb());
    EVP_add_cipher(EVP_aes_256_cfb1());
    EVP_add_cipher(EVP_aes_256_cfb8());
    EVP_add_cipher(EVP_aes_256_ofb());
    EVP_add_cipher(EVP_aes_256_ctr());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_256_xts());
    EVP_add_cipher(EVP_aes_256_ccm());
    EVP_add_cipher(EVP_aes_256_wrap());
    EVP_add_cipher_alias(SN_aes_256_cbc, "AES256");
    EVP_add_cipher_alias(SN_aes_256_cbc, "aes256");
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());

    EVP_add_cipher(EVP_camellia_128_ecb());
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_128_cfb());
    EVP_add_cipher(EVP_camellia_128_cfb1());
    EVP_add_cipher(EVP_camellia_128_cfb8());
    EVP_add_cipher(EVP_camellia_128_ofb());
    EVP_add_cipher_alias(SN_camellia_128_cbc, "CAMELLIA128");
    EVP_add_cipher_alias(SN_camellia_128_cbc, "camellia128");
    EVP_add_cipher(EVP_camellia_192_ecb());
    EVP_add_cipher(EVP_camellia_192_cbc());
    EVP_add_cipher(EVP_camellia_192_cfb());
    EVP_add_cipher(EVP_camellia_192_cfb1());
    EVP_add_cipher(EVP_camellia_192_cfb8());
    EVP_add_cipher(EVP_camellia_192_ofb());
    EVP_add_cipher_alias(SN_camellia_192_cbc, "CAMELLIA192");
    EVP_add_cipher_alias(SN_camellia_192_cbc, "camellia192");
    EVP_add_cipher(EVP_camellia_256_ecb());
    EVP_add_cipher(EVP_camellia_256_cbc());
    EVP_add_cipher(EVP_camellia_256_cfb());
    EVP_add_cipher(EVP_camellia_256_cfb1());
    EVP_add_cipher(EVP_camellia_256_cfb8());
    EVP_add_cipher(EVP_camellia_256_ofb());
    EVP_add_cipher_alias(SN_camellia_256_cbc, "CAMELLIA256");
    EVP_add_cipher_alias(SN_camellia_256_cbc, "camellia256");

#ifndef OPENSSL_NO_CHACHA
    EVP_add_cipher(EVP_chacha20());
#endif

#ifndef OPENSSL_NO_GOST
    EVP_add_cipher(EVP_gost2814789_ecb());
    EVP_add_cipher(EVP_gost2814789_cfb64());
    EVP_add_cipher(EVP_gost2814789_cnt());
#endif
}
