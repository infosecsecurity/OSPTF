/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */

#include <stdio.h>

#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/objects.h>

#include "bytestring.h"
#include "ssl_locl.h"

#define SSL3_NUM_CIPHERS (sizeof(ssl3_ciphers) / sizeof(SSL_CIPHER))

/*
 * FIXED_NONCE_LEN is a macro that provides in the correct value to set the
 * fixed nonce length in algorithms2. It is the inverse of the
 * SSL_CIPHER_AEAD_FIXED_NONCE_LEN macro.
 */
#define FIXED_NONCE_LEN(x) (((x / 2) & 0xf) << 24)

/* list of available SSLv3 ciphers (sorted by id) */
SSL_CIPHER ssl3_ciphers[] = {

    /* The RSA ciphers */
    /* Cipher 01 */
    {
      .valid = 1,
      .name = SSL3_TXT_RSA_NULL_MD5,
      .id = SSL3_CK_RSA_NULL_MD5,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_MD5,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 0,
      .alg_bits = 0,
    },

    /* Cipher 02 */
    {
      .valid = 1,
      .name = SSL3_TXT_RSA_NULL_SHA,
      .id = SSL3_CK_RSA_NULL_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 0,
      .alg_bits = 0,
    },

    /* Cipher 04 */
    {
      .valid = 1,
      .name = SSL3_TXT_RSA_RC4_128_MD5,
      .id = SSL3_CK_RSA_RC4_128_MD5,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_RC4,
      .algorithm_mac = SSL_MD5,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_MEDIUM,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 05 */
    {
      .valid = 1,
      .name = SSL3_TXT_RSA_RC4_128_SHA,
      .id = SSL3_CK_RSA_RC4_128_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_RC4,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_MEDIUM,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

/* Cipher 07 */
#ifndef OPENSSL_NO_IDEA
    {
      .valid = 1,
      .name = SSL3_TXT_RSA_IDEA_128_SHA,
      .id = SSL3_CK_RSA_IDEA_128_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_IDEA,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_MEDIUM,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },
#endif

    /* Cipher 09 */
    {
      .valid = 1,
      .name = SSL3_TXT_RSA_DES_64_CBC_SHA,
      .id = SSL3_CK_RSA_DES_64_CBC_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_LOW,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 56,
      .alg_bits = 56,
    },

    /* Cipher 0A */
    {
      .valid = 1,
      .name = SSL3_TXT_RSA_DES_192_CBC3_SHA,
      .id = SSL3_CK_RSA_DES_192_CBC3_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_3DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 112,
      .alg_bits = 168,
    },

    /*
     * Ephemeral DH (DHE) ciphers.
     */

    /* Cipher 12 */
    {
      .valid = 1,
      .name = SSL3_TXT_EDH_DSS_DES_64_CBC_SHA,
      .id = SSL3_CK_EDH_DSS_DES_64_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_LOW,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 56,
      .alg_bits = 56,
    },

    /* Cipher 13 */
    {
      .valid = 1,
      .name = SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA,
      .id = SSL3_CK_EDH_DSS_DES_192_CBC3_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_3DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 112,
      .alg_bits = 168,
    },

    /* Cipher 15 */
    {
      .valid = 1,
      .name = SSL3_TXT_EDH_RSA_DES_64_CBC_SHA,
      .id = SSL3_CK_EDH_RSA_DES_64_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_LOW,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 56,
      .alg_bits = 56,
    },

    /* Cipher 16 */
    {
      .valid = 1,
      .name = SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA,
      .id = SSL3_CK_EDH_RSA_DES_192_CBC3_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_3DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 112,
      .alg_bits = 168,
    },

    /* Cipher 18 */
    {
      .valid = 1,
      .name = SSL3_TXT_ADH_RC4_128_MD5,
      .id = SSL3_CK_ADH_RC4_128_MD5,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_RC4,
      .algorithm_mac = SSL_MD5,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_MEDIUM,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 1A */
    {
      .valid = 1,
      .name = SSL3_TXT_ADH_DES_64_CBC_SHA,
      .id = SSL3_CK_ADH_DES_64_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_LOW,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 56,
      .alg_bits = 56,
    },

    /* Cipher 1B */
    {
      .valid = 1,
      .name = SSL3_TXT_ADH_DES_192_CBC_SHA,
      .id = SSL3_CK_ADH_DES_192_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_3DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_SSLV3,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 112,
      .alg_bits = 168,
    },

    /*
     * AES ciphersuites.
     */

    /* Cipher 2F */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_AES_128_SHA,
      .id = TLS1_CK_RSA_WITH_AES_128_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 32 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
      .id = TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 33 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
      .id = TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 34 */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_AES_128_SHA,
      .id = TLS1_CK_ADH_WITH_AES_128_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 35 */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_AES_256_SHA,
      .id = TLS1_CK_RSA_WITH_AES_256_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 38 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
      .id = TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 39 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
      .id = TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 3A */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_AES_256_SHA,
      .id = TLS1_CK_ADH_WITH_AES_256_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* TLS v1.2 ciphersuites */
    /* Cipher 3B */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_NULL_SHA256,
      .id = TLS1_CK_RSA_WITH_NULL_SHA256,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 0,
      .alg_bits = 0,
    },

    /* Cipher 3C */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_AES_128_SHA256,
      .id = TLS1_CK_RSA_WITH_AES_128_SHA256,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 3D */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_AES_256_SHA256,
      .id = TLS1_CK_RSA_WITH_AES_256_SHA256,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 40 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
      .id = TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Camellia ciphersuites from RFC4132 (128-bit portion) */

    /* Cipher 41 */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
      .id = TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CAMELLIA128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 44 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
      .id = TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_CAMELLIA128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 45 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
      .id = TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CAMELLIA128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 46 */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
      .id = TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_CAMELLIA128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* TLS v1.2 ciphersuites */
    /* Cipher 67 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
      .id = TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 6A */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
      .id = TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 6B */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
      .id = TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 6C */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_AES_128_SHA256,
      .id = TLS1_CK_ADH_WITH_AES_128_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 6D */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_AES_256_SHA256,
      .id = TLS1_CK_ADH_WITH_AES_256_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* GOST Ciphersuites */

    /* Cipher 80 */
    { .valid = 1,
      .name = "GOST94-GOST89-GOST89",
      .id = 0x3000080,
      .algorithm_mkey = SSL_kGOST,
      .algorithm_auth = SSL_aGOST94,
      .algorithm_enc = SSL_eGOST2814789CNT,
      .algorithm_mac = SSL_GOST89MAC,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
      .strength_bits = 256,
      .alg_bits = 256 },

    /* Cipher 81 */
    { .valid = 1,
      .name = "GOST2001-GOST89-GOST89",
      .id = 0x3000081,
      .algorithm_mkey = SSL_kGOST,
      .algorithm_auth = SSL_aGOST01,
      .algorithm_enc = SSL_eGOST2814789CNT,
      .algorithm_mac = SSL_GOST89MAC,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
      .strength_bits = 256,
      .alg_bits = 256 },

    /* Cipher 82 */
    { .valid = 1,
      .name = "GOST94-NULL-GOST94",
      .id = 0x3000082,
      .algorithm_mkey = SSL_kGOST,
      .algorithm_auth = SSL_aGOST94,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_GOST94,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
      .strength_bits = 0,
      .alg_bits = 0 },

    /* Cipher 83 */
    { .valid = 1,
      .name = "GOST2001-NULL-GOST94",
      .id = 0x3000083,
      .algorithm_mkey = SSL_kGOST,
      .algorithm_auth = SSL_aGOST01,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_GOST94,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
      .strength_bits = 0,
      .alg_bits = 0 },

    /* Camellia ciphersuites from RFC4132 (256-bit portion) */

    /* Cipher 84 */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
      .id = TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CAMELLIA256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 87 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
      .id = TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_CAMELLIA256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 88 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
      .id = TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CAMELLIA256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 89 */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
      .id = TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_CAMELLIA256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /*
     * GCM ciphersuites from RFC5288.
     */

    /* Cipher 9C */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
      .id = TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 9D */
    {
      .valid = 1,
      .name = TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
      .id = TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher 9E */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
      .id = TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher 9F */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
      .id = TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher A2 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
      .id = TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_AES128GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher A3 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
      .id = TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aDSS,
      .algorithm_enc = SSL_AES256GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher A6 */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
      .id = TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES128GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher A7 */
    {
      .valid = 1,
      .name = TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
      .id = TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES256GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher C006 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 0,
      .alg_bits = 0,
    },

    /* Cipher C007 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_RC4,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_MEDIUM,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C008 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_3DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 112,
      .alg_bits = 168,
    },

    /* Cipher C009 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C00A */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher C010 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
      .id = TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 0,
      .alg_bits = 0,
    },

    /* Cipher C011 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
      .id = TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_RC4,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_MEDIUM,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C012 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
      .id = TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_3DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 112,
      .alg_bits = 168,
    },

    /* Cipher C013 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      .id = TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C014 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      .id = TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher C015 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
      .id = TLS1_CK_ECDH_anon_WITH_NULL_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_eNULL,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_STRONG_NONE,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 0,
      .alg_bits = 0,
    },

    /* Cipher C016 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
      .id = TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_RC4,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_MEDIUM,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C017 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
      .id = TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_3DES,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 112,
      .alg_bits = 168,
    },

    /* Cipher C018 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
      .id = TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C019 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
      .id = TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aNULL,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA1,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* HMAC based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C023 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C024 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA384,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher C027 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
      .id = TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128,
      .algorithm_mac = SSL_SHA256,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C028 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
      .id = TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256,
      .algorithm_mac = SSL_SHA384,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* GCM based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C02B */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_AES128GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C02C */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      .id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_AES256GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher C02F */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      .id = TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES128GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 128,
      .alg_bits = 128,
    },

    /* Cipher C030 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      .id = TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_AES256GCM,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(4) | SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher C072 */    
    {
     .valid = 1,
     .name = TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     .id = TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     .algorithm_mkey = SSL_kECDHE,
     .algorithm_auth = SSL_aECDSA,
     .algorithm_enc = SSL_CAMELLIA128,
     .algorithm_mac = SSL_SHA256,
     .algorithm_ssl = SSL_TLSV1_2,
     .algo_strength = SSL_HIGH,
     .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     .strength_bits = 128,
     .alg_bits = 128,
    },

    /* Cipher C073 */
    {
     .valid = 1,
     .name = TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     .id = TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     .algorithm_mkey = SSL_kECDHE,
     .algorithm_auth = SSL_aECDSA,
     .algorithm_enc = SSL_CAMELLIA256,
     .algorithm_mac = SSL_SHA384,
     .algorithm_ssl = SSL_TLSV1_2,
     .algo_strength = SSL_HIGH,
     .algorithm2 = SSL_HANDSHAKE_MAC_SHA384|TLS1_PRF_SHA384,
     .strength_bits = 256,
     .alg_bits = 256,
    },

    /* Cipher C076 */
    {
     .valid = 1,
     .name = TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     .id = TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     .algorithm_mkey = SSL_kECDHE,
     .algorithm_auth = SSL_aRSA,
     .algorithm_enc = SSL_CAMELLIA128,
     .algorithm_mac = SSL_SHA256,
     .algorithm_ssl = SSL_TLSV1_2,
     .algo_strength = SSL_HIGH,
     .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     .strength_bits = 128,
     .alg_bits = 128,
    },

    /* Cipher C077 */
    {
     .valid = 1,
     .name = TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     .id = TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     .algorithm_mkey = SSL_kECDHE,
     .algorithm_auth = SSL_aRSA,
     .algorithm_enc = SSL_CAMELLIA256,
     .algorithm_mac = SSL_SHA384,
     .algorithm_ssl = SSL_TLSV1_2,
     .algo_strength = SSL_HIGH,
     .algorithm2 = SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     .strength_bits = 256,
     .alg_bits = 256,
    },

#ifdef TEMP_GOST_TLS
    /* Cipher FF00 */
    {
      .valid = 1,
      .name = "GOST-MD5",
      .id = 0x0300ff00,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eGOST2814789CNT,
      .algorithm_mac = SSL_MD5,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256,
    },

    /* Cipher FF01 */
    { .valid = 1,
      .name = "GOST-GOST94",
      .id = 0x0300ff01,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eGOST2814789CNT,
      .algorithm_mac = SSL_GOST94,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256 },

    /* Cipher FF02 */
    { .valid = 1,
      .name = "GOST-GOST89MAC",
      .id = 0x0300ff02,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eGOST2814789CNT,
      .algorithm_mac = SSL_GOST89MAC,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
      .strength_bits = 256,
      .alg_bits = 256 },

    /* Cipher FF03 */
    { .valid = 1,
      .name = "GOST-GOST89STREAM",
      .id = 0x0300ff03,
      .algorithm_mkey = SSL_kRSA,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_eGOST2814789CNT,
      .algorithm_mac = SSL_GOST89MAC,
      .algorithm_ssl = SSL_TLSV1,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF | TLS1_STREAM_MAC,
      .strength_bits = 256,
      .alg_bits = 256 },
#endif

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    /* Cipher CC13 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305_OLD,
      .id = TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305_OLD,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CHACHA20POLY1305_OLD,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(0),
      .strength_bits = 256,
      .alg_bits = 0,
    },

    /* Cipher CC14 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_OLD,
      .id = TLS1_CK_ECDHE_ECDSA_CHACHA20_POLY1305_OLD,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_CHACHA20POLY1305_OLD,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(0),
      .strength_bits = 256,
      .alg_bits = 0,
    },

    /* Cipher CC15 */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305_OLD,
      .id = TLS1_CK_DHE_RSA_CHACHA20_POLY1305_OLD,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CHACHA20POLY1305_OLD,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(0),
      .strength_bits = 256,
      .alg_bits = 0,
    },

    /* Cipher CCA8 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
      .id = TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CHACHA20POLY1305,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(12),
      .strength_bits = 256,
      .alg_bits = 0,
    },

    /* Cipher CCA9 */
    {
      .valid = 1,
      .name = TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
      .id = TLS1_CK_ECDHE_ECDSA_CHACHA20_POLY1305,
      .algorithm_mkey = SSL_kECDHE,
      .algorithm_auth = SSL_aECDSA,
      .algorithm_enc = SSL_CHACHA20POLY1305,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(12),
      .strength_bits = 256,
      .alg_bits = 0,
    },

    /* Cipher CCAA */
    {
      .valid = 1,
      .name = TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
      .id = TLS1_CK_DHE_RSA_CHACHA20_POLY1305,
      .algorithm_mkey = SSL_kDHE,
      .algorithm_auth = SSL_aRSA,
      .algorithm_enc = SSL_CHACHA20POLY1305,
      .algorithm_mac = SSL_AEAD,
      .algorithm_ssl = SSL_TLSV1_2,
      .algo_strength = SSL_HIGH,
      .algorithm2 = SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD | FIXED_NONCE_LEN(12),
      .strength_bits = 256,
      .alg_bits = 0,
    },
#endif

    /* end of list */
};

int ssl3_num_ciphers(void)
{
    return (SSL3_NUM_CIPHERS);
}

const SSL_CIPHER *ssl3_get_cipher(unsigned int u)
{
    if (u < SSL3_NUM_CIPHERS)
        return (&(ssl3_ciphers[SSL3_NUM_CIPHERS - 1 - u]));
    else
        return (NULL);
}

const SSL_CIPHER *ssl3_get_cipher_by_id(unsigned int id)
{
    const SSL_CIPHER *cp;
    SSL_CIPHER c;

    c.id = id;
    cp = OBJ_bsearch_ssl_cipher_id(&c, ssl3_ciphers, SSL3_NUM_CIPHERS);
    if (cp != NULL && cp->valid == 1)
        return (cp);
    return (NULL);
}

const SSL_CIPHER *ssl3_get_cipher_by_value(uint16_t value)
{
    return ssl3_get_cipher_by_id(SSL3_CK_ID | value);
}

uint16_t ssl3_cipher_get_value(const SSL_CIPHER *cipher)
{
    return (cipher->id & SSL3_CK_VALUE_MASK);
}

int ssl3_pending(const SSL *s)
{
    if (s->rstate == SSL_ST_READ_BODY)
        return 0;

    return (s->s3->rrec.type == SSL3_RT_APPLICATION_DATA) ? s->s3->rrec.length : 0;
}

void ssl3_set_handshake_header(SSL *s, int htype, unsigned long len)
{
    uint8_t *p = (uint8_t *)s->init_buf->data;
    *(p++) = htype;
    l2n3(len, p);
    s->init_num = (int)len + SSL3_HM_HEADER_LENGTH;
    s->init_off = 0;
}

int ssl3_handshake_write(SSL *s)
{
    return ssl3_do_write(s, SSL3_RT_HANDSHAKE);
}

int ssl3_new(SSL *s)
{
    SSL3_STATE *s3;

    if ((s3 = calloc(1, sizeof *s3)) == NULL)
        goto err;
    memset(s3->rrec.seq_num, 0, sizeof(s3->rrec.seq_num));
    memset(s3->wrec.seq_num, 0, sizeof(s3->wrec.seq_num));

    s->s3 = s3;

    s->method->ssl_clear(s);
    return (1);
err:
    return (0);
}

void ssl3_free(SSL *s)
{
    if (s == NULL || s->s3 == NULL)
        return;

    ssl3_cleanup_key_block(s);
    ssl3_release_read_buffer(s);
    ssl3_release_write_buffer(s);

    DH_free(s->s3->tmp.dh);
    EC_KEY_free(s->s3->tmp.ecdh);

    sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
    BIO_free(s->s3->handshake_buffer);
    tls1_free_digest_list(s);
    free(s->s3->alpn_selected);

    vigortls_zeroize(s->s3, sizeof *s->s3);
    free(s->s3);
    s->s3 = NULL;
}

void ssl3_clear(SSL *s)
{
    uint8_t *rp, *wp;
    size_t rlen, wlen;
    int init_extra;

    ssl3_cleanup_key_block(s);
    sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
    DH_free(s->s3->tmp.dh);
    s->s3->tmp.dh = NULL;
    EC_KEY_free(s->s3->tmp.ecdh);
    s->s3->tmp.ecdh = NULL;

    rp = s->s3->rbuf.buf;
    wp = s->s3->wbuf.buf;
    rlen = s->s3->rbuf.len;
    wlen = s->s3->wbuf.len;
    init_extra = s->s3->init_extra;

    BIO_free(s->s3->handshake_buffer);
    s->s3->handshake_buffer = NULL;

    tls1_free_digest_list(s);

    free(s->s3->alpn_selected);
    s->s3->alpn_selected = NULL;

    memset(s->s3, 0, sizeof *s->s3);
    s->s3->rbuf.buf = rp;
    s->s3->wbuf.buf = wp;
    s->s3->rbuf.len = rlen;
    s->s3->wbuf.len = wlen;
    s->s3->init_extra = init_extra;

    ssl_free_wbio_buffer(s);

    s->packet_length = 0;
    s->s3->renegotiate = 0;
    s->s3->total_renegotiations = 0;
    s->s3->num_renegotiations = 0;
    s->s3->in_read_app_data = 0;
    s->version = TLS1_VERSION;

    free(s->next_proto_negotiated);
    s->next_proto_negotiated = NULL;
    s->next_proto_negotiated_len = 0;
}

static int ssl3_set_req_cert_type(CERT *c, const uint8_t *p, size_t len);

long ssl3_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    int ret = 0;

    if (cmd == SSL_CTRL_SET_TMP_DH || cmd == SSL_CTRL_SET_TMP_DH_CB) {
        if (!ssl_cert_inst(&s->cert)) {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_MALLOC_FAILURE);
            return (0);
        }
    }

    switch (cmd) {
        case SSL_CTRL_GET_SESSION_REUSED:
            ret = s->hit;
            break;
        case SSL_CTRL_GET_CLIENT_CERT_REQUEST:
            break;
        case SSL_CTRL_GET_NUM_RENEGOTIATIONS:
            ret = s->s3->num_renegotiations;
            break;
        case SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS:
            ret = s->s3->num_renegotiations;
            s->s3->num_renegotiations = 0;
            break;
        case SSL_CTRL_GET_TOTAL_RENEGOTIATIONS:
            ret = s->s3->total_renegotiations;
            break;
        case SSL_CTRL_GET_FLAGS:
            ret = (int)(s->s3->flags);
            break;
        case SSL_CTRL_NEED_TMP_RSA:
                ret = 0;
            break;
        case SSL_CTRL_SET_TMP_RSA:
        case SSL_CTRL_SET_TMP_RSA_CB:
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            break;
        case SSL_CTRL_SET_TMP_DH: {
            DH *dh = (DH *)parg;
            if (dh == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return (ret);
            }
            if ((dh = DHparams_dup(dh)) == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_DH_LIB);
                return (ret);
            }
            DH_free(s->cert->dh_tmp);
            s->cert->dh_tmp = dh;
            ret = 1;
        } break;
        case SSL_CTRL_SET_TMP_DH_CB:
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (ret);

        case SSL_CTRL_SET_DH_AUTO:
            s->cert->dh_tmp_auto = larg;
            return 1;

        case SSL_CTRL_SET_TMP_ECDH: {
            EC_KEY *ecdh = NULL;

            if (parg == NULL) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
                return (ret);
            }
            if (!EC_KEY_up_ref((EC_KEY *)parg)) {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_ECDH_LIB);
                return (ret);
            }
            ecdh = (EC_KEY *)parg;
            if (!(s->options & SSL_OP_SINGLE_ECDH_USE)) {
                if (!EC_KEY_generate_key(ecdh)) {
                    EC_KEY_free(ecdh);
                    SSLerr(SSL_F_SSL3_CTRL, ERR_R_ECDH_LIB);
                    return (ret);
                }
            }
            EC_KEY_free(s->cert->ecdh_tmp);
            s->cert->ecdh_tmp = ecdh;
            ret = 1;
        } break;
        case SSL_CTRL_SET_TMP_ECDH_CB: {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (ret);
        } break;
        case SSL_CTRL_SET_TLSEXT_HOSTNAME:
            if (larg == TLSEXT_NAMETYPE_host_name) {
                size_t len;

                free(s->tlsext_hostname);
                s->tlsext_hostname = NULL;

                ret = 1;
                if (parg == NULL)
                    break;
                len = strlen((char *)parg);
                if (len == 0 || len > TLSEXT_MAXLEN_host_name) {
                    SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME);
                    return 0;
                }
                if ((s->tlsext_hostname = strdup((char *)parg)) == NULL) {
                    SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            } else {
                SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE);
                return 0;
            }
            break;
        case SSL_CTRL_SET_TLSEXT_DEBUG_ARG:
            s->tlsext_debug_arg = parg;
            ret = 1;
            break;

        case SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE:
            s->tlsext_status_type = larg;
            ret = 1;
            break;

        case SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS:
            *(STACK_OF(X509_EXTENSION) **)parg = s->tlsext_ocsp_exts;
            ret = 1;
            break;

        case SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS:
            s->tlsext_ocsp_exts = parg;
            ret = 1;
            break;

        case SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS:
            *(STACK_OF(OCSP_RESPID) **)parg = s->tlsext_ocsp_ids;
            ret = 1;
            break;

        case SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS:
            s->tlsext_ocsp_ids = parg;
            ret = 1;
            break;

        case SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP:
            *(uint8_t **)parg = s->tlsext_ocsp_resp;
            return s->tlsext_ocsp_resplen;

        case SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP:
            free(s->tlsext_ocsp_resp);
            s->tlsext_ocsp_resp = parg;
            s->tlsext_ocsp_resplen = larg;
            ret = 1;
            break;

        case SSL_CTRL_CHAIN:
            if (larg)
                return ssl_cert_set1_chain(s->cert, (STACK_OF (X509) *)parg);
            else
                return ssl_cert_set0_chain(s->cert, (STACK_OF (X509) *)parg);

        case SSL_CTRL_CHAIN_CERT:
            if (larg)
                return ssl_cert_add1_chain_cert(s->cert, (X509 *)parg);
            else
                return ssl_cert_add0_chain_cert(s->cert, (X509 *)parg);

        case SSL_CTRL_GET_CHAIN_CERTS:
            *(STACK_OF(X509) **)parg = s->cert->key->chain;
            break;

        case SSL_CTRL_SELECT_CURRENT_CERT:
            return ssl_cert_select_current(s->cert, (X509 *)parg);
            
        case SSL_CTRL_SET_CURRENT_CERT:
            if (larg == SSL_CERT_SET_SERVER) {
                CERT_PKEY *cpk;
                const SSL_CIPHER *cipher;
                if (!s->server)
                    return 0;
                cipher = s->s3->tmp.new_cipher;
                if (cipher == NULL)
                    return 0;
                /* No certificate for unauthenticated ciphersuites */
                if (cipher->algorithm_auth & SSL_aNULL)
                    return 2;
                cpk = ssl_get_server_send_pkey(s);
                if (cpk == NULL)
                    return 0;
                s->cert->key = cpk;
                return 1;
            }
            return ssl_cert_set_current(s->cert, larg);

        case SSL_CTRL_GET_CURVES: {
            uint16_t *clist;
            size_t clistlen;
            if (!s->session)
                return 0;
            clist = s->session->tlsext_ellipticcurvelist;
            clistlen = s->session->tlsext_ellipticcurvelist_length;
            if (parg) {
                size_t i;
                int *cptr = parg;
                unsigned int nid;
                for (i = 0; i < clistlen; i++) {
                    nid = tls1_ec_curve_id2nid(clist[i]);
                    if (nid != 0)
                        cptr[i] = nid;
                    else
                        cptr[i] = TLSEXT_nid_unknown | clist[i];
                }
            }
            return (int)clistlen;
        }

        case SSL_CTRL_SET_CURVES:
            return tls1_set_curves(&s->tlsext_ellipticcurvelist,
                                   &s->tlsext_ellipticcurvelist_length,
                                   parg, larg);

        case SSL_CTRL_SET_CURVES_LIST:
            return tls1_set_curves_list(&s->tlsext_ellipticcurvelist,
                                        &s->tlsext_ellipticcurvelist_length,
                                        parg);

        case SSL_CTRL_GET_SHARED_CURVE:
            return tls1_shared_curve(s, larg);

        case SSL_CTRL_CHECK_PROTO_VERSION:
            /* For library-internal use; checks that the current protocol
             * is the highest enabled version (according to s->ctx->method,
             * as version negotiation may have changed s->method). */
            if (s->version == s->ctx->method->version)
                return 1;
            /* Apparently we're using a version-flexible SSL_METHOD
             * (not at its highest protocol version). */
            if (s->ctx->method->version == SSLv23_method()->version) {
#if TLS_MAX_VERSION != TLS1_2_VERSION
# error Code needs to be updated for SSLv23_method() support beyond TLS1_2_VERSION.
#endif
                if (!(s->options & SSL_OP_NO_TLSv1_2))
                    return s->version == TLS1_2_VERSION;
                if (!(s->options & SSL_OP_NO_TLSv1_1))
                    return s->version == TLS1_1_VERSION;
                if (!(s->options & SSL_OP_NO_TLSv1))
                    return s->version == TLS1_VERSION;
            }
            return 0; /* Unexpected state; fail closed. */

        case SSL_CTRL_SET_ECDH_AUTO:
            s->cert->ecdh_tmp_auto = larg;
            ret = 1;
            break;

        case SSL_CTRL_SET_SIGALGS:
            return tls1_set_sigalgs(s->cert, parg, larg, 0);

        case SSL_CTRL_SET_SIGALGS_LIST:
            return tls1_set_sigalgs_list(s->cert, parg, 0 );

        case SSL_CTRL_SET_CLIENT_SIGALGS:
            return tls1_set_sigalgs(s->cert, parg, larg, 1);

        case SSL_CTRL_SET_CLIENT_SIGALGS_LIST:
            return tls1_set_sigalgs_list(s->cert, parg, 1);

        case SSL_CTRL_GET_CLIENT_CERT_TYPES: {
            const uint8_t **pctype = parg;
            if (s->server || !s->s3->tmp.cert_req)
                return 0;
            if (s->cert->ctypes != NULL) {
                if (pctype != NULL)
                    *pctype = s->cert->ctypes;
                return (int)s->cert->ctype_num;
            }
            if (pctype != NULL)
                *pctype = (uint8_t *)s->s3->tmp.ctype;
            return s->s3->tmp.ctype_num;
        }

        case SSL_CTRL_SET_CLIENT_CERT_TYPES:
            if (!s->server)
                return 0;
            return ssl3_set_req_cert_type(s->cert, parg, larg);

        case SSL_CTRL_BUILD_CERT_CHAIN:
            return ssl_build_cert_chain(s->cert, s->ctx->cert_store, larg);

        case SSL_CTRL_SET_VERIFY_CERT_STORE:
            return ssl_cert_set_cert_store(s->cert, parg, 0, larg);

        case SSL_CTRL_SET_CHAIN_CERT_STORE:
            return ssl_cert_set_cert_store(s->cert, parg, 1, larg);

        case SSL_CTRL_GET_PEER_SIGNATURE_NID:
            if (SSL_USE_SIGALGS(s)) {
                if (s->session && s->session->sess_cert) {
                    const EVP_MD *sig;
                    sig = s->session->sess_cert->peer_key->digest;
                    if (sig != NULL) {
                        *(int *)parg = EVP_MD_type(sig);
                        return 1;
                    }
                }
                return 0;
            } else /* Might want to do something here for other versions */
                return 0;

        case SSL_CTRL_GET_SERVER_TMP_KEY:
            if (s->server || !s->session || !s->session->sess_cert)
                return 0;
            else {
                SESS_CERT *sc;
                EVP_PKEY *ptmp;
                int rv = 0;
                sc = s->session->sess_cert;
                if (!sc->peer_rsa_tmp && !sc->peer_dh_tmp &&
                    !sc->peer_ecdh_tmp)
                    return 0;
                ptmp = EVP_PKEY_new();
                if (ptmp == NULL)
                    return 0;
                if (sc->peer_rsa_tmp)
                    rv = EVP_PKEY_set1_RSA(ptmp, sc->peer_rsa_tmp);
                else if (sc->peer_dh_tmp)
                    rv = EVP_PKEY_set1_DH(ptmp, sc->peer_dh_tmp);
                else if (sc->peer_ecdh_tmp)
                    rv = EVP_PKEY_set1_EC_KEY(ptmp, sc->peer_ecdh_tmp);
                if (rv) {
                    *(EVP_PKEY **)parg = ptmp;
                    return 1;
                }
                EVP_PKEY_free(ptmp);
                return 0;
            }

        case SSL_CTRL_GET_EC_POINT_FORMATS: {
            SSL_SESSION *sess = s->session;
            const uint8_t **pformat = parg;
            if (sess == NULL || sess->tlsext_ecpointformatlist == NULL)
                return 0;
            *pformat = sess->tlsext_ecpointformatlist;
            return (int)sess->tlsext_ecpointformatlist_length;
        }

        default:
            break;
    }
    return (ret);
}

long ssl3_callback_ctrl(SSL *s, int cmd, void (*fp)(void))
{
    int ret = 0;

    if (cmd == SSL_CTRL_SET_TMP_DH_CB) {
        if (!ssl_cert_inst(&s->cert)) {
            SSLerr(SSL_F_SSL3_CALLBACK_CTRL, ERR_R_MALLOC_FAILURE);
            return (0);
        }
    }

    switch (cmd) {
        case SSL_CTRL_SET_TMP_RSA_CB:
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            break;
        case SSL_CTRL_SET_TMP_DH_CB:
            s->cert->dh_tmp_cb = (DH * (*)(SSL *, int, int))fp;
            break;
        case SSL_CTRL_SET_TMP_ECDH_CB:
            s->cert->ecdh_tmp_cb = (EC_KEY * (*)(SSL *, int, int))fp;
            break;

        case SSL_CTRL_SET_TLSEXT_DEBUG_CB:
            s->tlsext_debug_cb = (void (*)(SSL *, int, int, uint8_t *, int, void *))fp;
            break;
        default:
            break;
    }
    return (ret);
}

long ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    CERT *cert;

    cert = ctx->cert;

    switch (cmd) {
        case SSL_CTRL_NEED_TMP_RSA:
            return 0;
        case SSL_CTRL_SET_TMP_RSA:
        case SSL_CTRL_SET_TMP_RSA_CB:
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return 0;
        case SSL_CTRL_SET_TMP_DH: {
            DH *new = NULL, *dh;

            dh = (DH *)parg;
            if ((new = DHparams_dup(dh)) == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_DH_LIB);
                return 0;
            }
            DH_free(cert->dh_tmp);
            cert->dh_tmp = new;
            return 1;
        }
        /*break; */
        case SSL_CTRL_SET_TMP_DH_CB:
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return 0;

        case SSL_CTRL_SET_DH_AUTO:
            ctx->cert->dh_tmp_auto = larg;
            return 1;

        case SSL_CTRL_SET_TMP_ECDH: {
            EC_KEY *ecdh = NULL;

            if (parg == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_ECDH_LIB);
                return 0;
            }
            ecdh = EC_KEY_dup((EC_KEY *)parg);
            if (ecdh == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_EC_LIB);
                return 0;
            }
            if (!(ctx->options & SSL_OP_SINGLE_ECDH_USE)) {
                if (!EC_KEY_generate_key(ecdh)) {
                    EC_KEY_free(ecdh);
                    SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_ECDH_LIB);
                    return 0;
                }
            }

            EC_KEY_free(cert->ecdh_tmp);
            cert->ecdh_tmp = ecdh;
            return 1;
        }
        /* break; */
        case SSL_CTRL_SET_TMP_ECDH_CB: {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return (0);
        } break;
        case SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG:
            ctx->tlsext_servername_arg = parg;
            break;
        case SSL_CTRL_SET_TLSEXT_TICKET_KEYS:
        case SSL_CTRL_GET_TLSEXT_TICKET_KEYS: {
            uint8_t *keys = parg;
            if (!keys)
                return 48;
            if (larg != 48) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_INVALID_TICKET_KEYS_LENGTH);
                return 0;
            }
            if (cmd == SSL_CTRL_SET_TLSEXT_TICKET_KEYS) {
                memcpy(ctx->tlsext_tick_key_name, keys, 16);
                memcpy(ctx->tlsext_tick_hmac_key, keys + 16, 16);
                memcpy(ctx->tlsext_tick_aes_key, keys + 32, 16);
            } else {
                memcpy(keys, ctx->tlsext_tick_key_name, 16);
                memcpy(keys + 16, ctx->tlsext_tick_hmac_key, 16);
                memcpy(keys + 32, ctx->tlsext_tick_aes_key, 16);
            }
            return 1;
        }

        case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG:
            ctx->tlsext_status_arg = parg;
            return 1;
            break;

        case SSL_CTRL_SET_ECDH_AUTO:
            ctx->cert->ecdh_tmp_auto = larg;
            return 1;

        case SSL_CTRL_SET_SIGALGS:
            return tls1_set_sigalgs(ctx->cert, parg, larg, 0);

        case SSL_CTRL_SET_SIGALGS_LIST:
            return tls1_set_sigalgs_list(ctx->cert, parg, 0);

        case SSL_CTRL_SET_CLIENT_SIGALGS:
            return tls1_set_sigalgs(ctx->cert, parg, larg, 1);

        case SSL_CTRL_SET_CLIENT_SIGALGS_LIST:
            return tls1_set_sigalgs_list(ctx->cert, parg, 1);

        case SSL_CTRL_SET_CLIENT_CERT_TYPES:
            return ssl3_set_req_cert_type(ctx->cert, parg, larg);

        case SSL_CTRL_BUILD_CERT_CHAIN:
            return ssl_build_cert_chain(ctx->cert, ctx->cert_store, larg);

        case SSL_CTRL_SET_VERIFY_CERT_STORE:
            return ssl_cert_set_cert_store(ctx->cert, parg, 0, larg);

        case SSL_CTRL_SET_CHAIN_CERT_STORE:
            return ssl_cert_set_cert_store(ctx->cert, parg, 1, larg);

        case SSL_CTRL_SET_CURVES:
            return tls1_set_curves(&ctx->tlsext_ellipticcurvelist,
                                   &ctx->tlsext_ellipticcurvelist_length,
                                   parg, larg);

        case SSL_CTRL_SET_CURVES_LIST:
            return tls1_set_curves_list(&ctx->tlsext_ellipticcurvelist,
                                        &ctx->tlsext_ellipticcurvelist_length,
                                        parg);

        /* A Thawte special :-) */
        case SSL_CTRL_EXTRA_CHAIN_CERT:
            if (ctx->extra_certs == NULL) {
                if ((ctx->extra_certs = sk_X509_new_null()) == NULL)
                    return (0);
            }
            sk_X509_push(ctx->extra_certs, (X509 *)parg);
            break;

        case SSL_CTRL_GET_EXTRA_CHAIN_CERTS:
            if (ctx->extra_certs == NULL && larg == 0)
                *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
            else
                *(STACK_OF(X509) **)parg = ctx->extra_certs;
            break;

        case SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS:
            if (ctx->extra_certs) {
                sk_X509_pop_free(ctx->extra_certs, X509_free);
                ctx->extra_certs = NULL;
            }
            break;

        case SSL_CTRL_CHAIN:
            if (larg)
                return ssl_cert_set1_chain(ctx->cert, (STACK_OF (X509) *)parg);
            else
                return ssl_cert_set0_chain(ctx->cert, (STACK_OF (X509) *)parg);

        case SSL_CTRL_CHAIN_CERT:
            if (larg)
                return ssl_cert_add1_chain_cert(ctx->cert, (X509 *)parg);
            else
                return ssl_cert_add0_chain_cert(ctx->cert, (X509 *)parg);

        case SSL_CTRL_GET_CHAIN_CERTS:
            *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
            break;

        case SSL_CTRL_SELECT_CURRENT_CERT:
            return ssl_cert_select_current(ctx->cert, (X509 *)parg);
            
        case SSL_CTRL_SET_CURRENT_CERT:
            return ssl_cert_set_current(ctx->cert, larg);

        default:
            return 0;
    }
    return 1;
}

long ssl3_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)(void))
{
    CERT *cert;

    cert = ctx->cert;

    switch (cmd) {
        case SSL_CTRL_SET_TMP_RSA_CB:
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return 0;
        case SSL_CTRL_SET_TMP_DH_CB:
            cert->dh_tmp_cb = (DH * (*)(SSL *, int, int))fp;
            break;
        case SSL_CTRL_SET_TMP_ECDH_CB:
            cert->ecdh_tmp_cb = (EC_KEY * (*)(SSL *, int, int))fp;
            break;
        case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
            ctx->tlsext_servername_callback = (int (*)(SSL *, int *, void *))fp;
            break;

        case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB:
            ctx->tlsext_status_cb = (int (*)(SSL *, void *))fp;
            break;

        case SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB:
            ctx->tlsext_ticket_key_cb = (int (*)(SSL *, uint8_t *, uint8_t *, EVP_CIPHER_CTX *,
                                                 HMAC_CTX *, int))fp;
            break;

        default:
            return (0);
    }
    return (1);
}

/*
 * This function needs to check if the ciphers required are actually available.
 */
const SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p)
{
    CBS cipher;
    uint16_t cipher_value;

    /* We have to assume it is at least 2 bytes due to existing API. */
    CBS_init(&cipher, p, 2);
    if (!CBS_get_u16(&cipher, &cipher_value))
        return NULL;

    return ssl3_get_cipher_by_value(cipher_value);
}

int ssl3_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p)
{
    if (p != NULL) {
        if ((c->id & ~SSL3_CK_VALUE_MASK) != SSL3_CK_ID)
            return 0;
        s2n(ssl3_cipher_get_value(c), p); 
    }
    return 2;
}

SSL_CIPHER *ssl3_choose_cipher(SSL *s, STACK_OF(SSL_CIPHER) *clnt,
                               STACK_OF(SSL_CIPHER) *srvr)
{
    unsigned long alg_k, alg_a, mask_k, mask_a;
    STACK_OF(SSL_CIPHER) *prio, *allow;
    SSL_CIPHER *c, *ret = NULL;
    int i, ii, ok, use_chacha = 0;
    CERT *cert;

    /* Let's see which ciphers we can support */
    cert = s->cert;

    /*
     * Do not set the compare functions, because this may lead to a
     * reordering by "id". We want to keep the original ordering.
     * We may pay a price in performance during sk_SSL_CIPHER_find(),
     * but would have to pay with the price of sk_SSL_CIPHER_dup().
     */

    if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE || tls1_suiteb(s)) {
        prio = srvr;
        allow = clnt;
        /* Use ChaCha20+Poly1305 if it's the client's most preferred cipher suite */
        if (sk_SSL_CIPHER_num(clnt) > 0) {
            c = sk_SSL_CIPHER_value(clnt, 0);
            if (c->algorithm_enc == SSL_CHACHA20POLY1305 ||
                c->algorithm_enc == SSL_CHACHA20POLY1305_OLD)
                use_chacha = 1;
        }
    } else {
        prio = clnt;
        allow = srvr;
        use_chacha = 1;
    }

    tls1_set_cert_validity(s);

    for (i = 0; i < sk_SSL_CIPHER_num(prio); i++) {
        c = sk_SSL_CIPHER_value(prio, i);

        /* Skip TLS v1.2 only ciphersuites if not supported. */
        if ((c->algorithm_ssl & SSL_TLSV1_2) && !SSL_USE_TLS1_2_CIPHERS(s))
            continue;

        if ((c->algorithm_enc == SSL_CHACHA20POLY1305) && !use_chacha)
            continue;

        ssl_set_cert_masks(cert, c);
        mask_k = cert->mask_k;
        mask_a = cert->mask_a;

        alg_k = c->algorithm_mkey;
        alg_a = c->algorithm_auth;

        ok = (alg_k & mask_k) && (alg_a & mask_a);

        /*
         * If we are considering an ECC cipher suite that uses
         * an ephemeral EC key check it.
         */
        if (alg_k & SSL_kECDHE)
            ok = ok && tls1_check_ec_tmp_key(s, c->id);

        if (!ok)
            continue;
        ii = sk_SSL_CIPHER_find(allow, c);
        if (ii >= 0) {
            ret = sk_SSL_CIPHER_value(allow, ii);
            break;
        }
    }
    return (ret);
}

int ssl3_get_req_cert_type(SSL *s, uint8_t *p)
{
    int ret = 0;
    const uint8_t *sig;
    size_t i, siglen;
    int have_rsa_sign = 0, have_dsa_sign = 0, have_ecdsa_sign = 0;
    int nostrict = 1;
    unsigned long alg_k;

    /* If we have custom certificate types set, use them */
    if (s->cert->ctypes != NULL) {
        memcpy(p, s->cert->ctypes, s->cert->ctype_num);
        return (int)s->cert->ctype_num;
    }
    /* get configured sigalgs */
    siglen = tls12_get_psigalgs(s, &sig);
    if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)
        nostrict = 0;
    for (i = 0; i < siglen; i += 2, sig += 2) {
        switch(sig[1]) {
            case TLSEXT_signature_rsa:
                have_rsa_sign = 1;
                break;

            case TLSEXT_signature_dsa:
                have_dsa_sign = 1;
                break;

            case TLSEXT_signature_ecdsa:
                have_ecdsa_sign = 1;
                break;
        }
    }

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

#ifndef OPENSSL_NO_GOST
    if (s->version >= TLS1_VERSION) {
        if (alg_k & SSL_kGOST) {
            p[ret++] = TLS_CT_GOST94_SIGN;
            p[ret++] = TLS_CT_GOST01_SIGN;
            return (ret);
        }
    }
#endif

    if (alg_k & SSL_kDHE) {
        if (nostrict || have_rsa_sign)
            p[ret++] = SSL3_CT_RSA_FIXED_DH;
        if (nostrict || have_dsa_sign)
            p[ret++] = SSL3_CT_DSS_FIXED_DH;
    }
    if (have_rsa_sign)
        p[ret++] = SSL3_CT_RSA_SIGN;
    if (have_dsa_sign)
        p[ret++] = SSL3_CT_DSS_SIGN;

    /*
     * ECDSA certs can be used with RSA cipher suites as well
     * so we don't need to check for SSL_kECDH or SSL_kECDHE
     */
    if (nostrict || have_ecdsa_sign)
        p[ret++] = TLS_CT_ECDSA_SIGN;

    return (ret);
}

static int ssl3_set_req_cert_type(CERT *c, const uint8_t *p, size_t len)
{
    free(c->ctypes);
    c->ctypes = NULL;

    if (p == NULL || !len)
        return 1;
    if (len > 0xff)
        return 0;
    c->ctypes = malloc(len);
    if (c->ctypes == NULL)
        return 0;
    memcpy(c->ctypes, p, len);
    c->ctype_num = len;

    return 1;
}

int ssl3_shutdown(SSL *s)
{
    int ret;

    /*
     * Don't do anything much if we have not done the handshake or
     * we don't want to send messages :-)
     */
    if ((s->quiet_shutdown) || (s->state == SSL_ST_BEFORE)) {
        s->shutdown = (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        return 1;
    }

    if (!(s->shutdown & SSL_SENT_SHUTDOWN)) {
        s->shutdown |= SSL_SENT_SHUTDOWN;
        ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY);
        /*
         * Our shutdown alert has been sent now, and if it still needs
         * to be written, s->s3->alert_dispatch will be true
         */
        if (s->s3->alert_dispatch)
            return -1; /* return WANT_WRITE */
    } else if (s->s3->alert_dispatch) {
        /* resend it if not sent */
        ret = s->method->ssl_dispatch_alert(s);
        if (ret == -1) {
            /*
             * We only get to return -1 here on the 2nd/Nth
             * invocation, we must have already signaled
             * return 0 upon a previous invocation,
             * return WANT_WRITE
             */
            return ret;
        }
    } else if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
        /* If we are waiting for a close from our peer, we are closed */
        s->method->ssl_read_bytes(s, 0, NULL, 0, 0);
        if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
            return -1; /* return WANT_READ */
        }
    }

    if ((s->shutdown == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) &&
        !s->s3->alert_dispatch)
        return 1;
    else
        return 0;
}

int ssl3_write(SSL *s, const void *buf, int len)
{
    int ret, n;

#if 0
    if (s->shutdown & SSL_SEND_SHUTDOWN) {
        s->rwstate = SSL_NOTHING;
        return (0);
    }
#endif
    errno = 0;
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s);

    /*
     * This is an experimental flag that sends the
     * last handshake message in the same packet as the first
     * use data - used to see if it helps the TCP protocol during
     * session-id reuse
     */
    /* The second test is because the buffer may have been removed */
    if ((s->s3->flags & SSL3_FLAGS_POP_BUFFER) && (s->wbio == s->bbio)) {
        /* First time through, we write into the buffer */
        if (s->s3->delay_buf_pop_ret == 0) {
            ret = ssl3_write_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len);
            if (ret <= 0)
                return (ret);

            s->s3->delay_buf_pop_ret = ret;
        }

        s->rwstate = SSL_WRITING;
        n = BIO_flush(s->wbio);
        if (n <= 0)
            return (n);
        s->rwstate = SSL_NOTHING;

        /* We have flushed the buffer, so remove it */
        ssl_free_wbio_buffer(s);
        s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;

        ret = s->s3->delay_buf_pop_ret;
        s->s3->delay_buf_pop_ret = 0;
    } else {
        ret = s->method->ssl_write_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len);
        if (ret <= 0)
            return (ret);
    }

    return (ret);
}

static int ssl3_read_internal(SSL *s, void *buf, int len, int peek)
{
    int ret;

    errno = 0;
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s);
    s->s3->in_read_app_data = 1;
    ret = s->method->ssl_read_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len, peek);
    if ((ret == -1) && (s->s3->in_read_app_data == 2)) {
        /*
         * ssl3_read_bytes decided to call s->handshake_func, which
         * called ssl3_read_bytes to read handshake data.
         * However, ssl3_read_bytes actually found application data
         * and thinks that application data makes sense here; so disable
         * handshake processing and try to read application data again.
         */
        s->in_handshake++;
        ret = s->method->ssl_read_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len, peek);
        s->in_handshake--;
    } else
        s->s3->in_read_app_data = 0;

    return (ret);
}

int ssl3_read(SSL *s, void *buf, int len)
{
    return ssl3_read_internal(s, buf, len, 0);
}

int ssl3_peek(SSL *s, void *buf, int len)
{
    return ssl3_read_internal(s, buf, len, 1);
}

int ssl3_renegotiate(SSL *s)
{
    if (s->handshake_func == NULL)
        return (1);

    if (s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
        return (0);

    s->s3->renegotiate = 1;
    return (1);
}

int ssl3_renegotiate_check(SSL *s)
{
    int ret = 0;

    if (s->s3->renegotiate) {
        if ((s->s3->rbuf.left == 0) && (s->s3->wbuf.left == 0) && !SSL_in_init(s)) {
            /*
             * If we are the server, and we have sent
             * a 'RENEGOTIATE' message, we need to go
             * to SSL_ST_ACCEPT.
             */
            /* SSL_ST_ACCEPT */
            s->state = SSL_ST_RENEGOTIATE;
            s->s3->renegotiate = 0;
            s->s3->num_renegotiations++;
            s->s3->total_renegotiations++;
            ret = 1;
        }
    }
    return (ret);
}
/*
 * If we are using TLS v1.2 or later and default SHA1+MD5 algorithms switch
 * to new SHA256 PRF and handshake macs
 */
long ssl_get_algorithm2(SSL *s)
{
    long alg2 = s->s3->tmp.new_cipher->algorithm2;

    if (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SHA256_PRF &&
        alg2 == (SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF))
        return SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256;
    return alg2;
}
