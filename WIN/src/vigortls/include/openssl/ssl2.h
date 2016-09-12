/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SSL2_H
#define HEADER_SSL2_H

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol Version Codes */
#define SSL2_VERSION        0x0002
#define SSL2_VERSION_MAJOR  0x00
#define SSL2_VERSION_MINOR  0x02
/* #define SSL2_CLIENT_VERSION    0x0002 */
/* #define SSL2_SERVER_VERSION    0x0002 */

/* Protocol Message Codes */
#define SSL2_MT_ERROR               0
#define SSL2_MT_CLIENT_HELLO        1
#define SSL2_MT_CLIENT_MASTER_KEY   2
#define SSL2_MT_CLIENT_FINISHED     3
#define SSL2_MT_SERVER_HELLO        4
#define SSL2_MT_SERVER_VERIFY       5
#define SSL2_MT_SERVER_FINISHED     6
#define SSL2_MT_REQUEST_CERTIFICATE 7
#define SSL2_MT_CLIENT_CERTIFICATE  8

/* Error Message Codes */
#define SSL2_PE_UNDEFINED_ERROR                 0x0000
#define SSL2_PE_NO_CIPHER                       0x0001
#define SSL2_PE_NO_CERTIFICATE                  0x0002
#define SSL2_PE_BAD_CERTIFICATE                 0x0004
#define SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE    0x0006

/* Cipher Kind Values */
#define SSL2_CK_NULL_WITH_MD5                   0x02000000 /* v3 */
#define SSL2_CK_RC4_128_WITH_MD5                0x02010080
#define SSL2_CK_RC4_128_EXPORT40_WITH_MD5       0x02020080
#define SSL2_CK_RC2_128_CBC_WITH_MD5            0x02030080
#define SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5   0x02040080
#define SSL2_CK_IDEA_128_CBC_WITH_MD5           0x02050080
#define SSL2_CK_DES_64_CBC_WITH_MD5             0x02060040
#define SSL2_CK_DES_64_CBC_WITH_SHA             0x02060140 /* v3 */
#define SSL2_CK_DES_192_EDE3_CBC_WITH_MD5       0x020700c0
#define SSL2_CK_DES_192_EDE3_CBC_WITH_SHA       0x020701c0 /* v3 */
#define SSL2_CK_RC4_64_WITH_MD5                 0x02080080 /* MS hack */

#define SSL2_CK_DES_64_CFB64_WITH_MD5_1         0x02ff0800 /* SSLeay */
#define SSL2_CK_NULL                            0x02ff0810 /* SSLeay */

#define SSL2_TXT_DES_64_CFB64_WITH_MD5_1        "DES-CFB-M1"
#define SSL2_TXT_NULL_WITH_MD5                  "NULL-MD5"
#define SSL2_TXT_RC4_128_WITH_MD5               "RC4-MD5"
#define SSL2_TXT_RC4_128_EXPORT40_WITH_MD5      "EXP-RC4-MD5"
#define SSL2_TXT_RC2_128_CBC_WITH_MD5           "RC2-CBC-MD5"
#define SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5  "EXP-RC2-CBC-MD5"
#define SSL2_TXT_IDEA_128_CBC_WITH_MD5          "IDEA-CBC-MD5"
#define SSL2_TXT_DES_64_CBC_WITH_MD5            "DES-CBC-MD5"
#define SSL2_TXT_DES_64_CBC_WITH_SHA            "DES-CBC-SHA"
#define SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5      "DES-CBC3-MD5"
#define SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA      "DES-CBC3-SHA"
#define SSL2_TXT_RC4_64_WITH_MD5                "RC4-64-MD5"

#define SSL2_TXT_NULL                           "NULL"

/* Flags for the SSL_CIPHER.algorithm2 field */
#define SSL2_CF_5_BYTE_ENC 0x01
#define SSL2_CF_8_BYTE_ENC 0x02

/* Certificate Type Codes */
#define SSL2_CT_X509_CERTIFICATE 0x01

/* Authentication Type Code */
#define SSL2_AT_MD5_WITH_RSA_ENCRYPTION 0x01

#define SSL2_MAX_SSL_SESSION_ID_LENGTH 32

/* Upper/Lower Bounds */
#define SSL2_MAX_MASTER_KEY_LENGTH_IN_BITS 256
#define SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER 32767u /* 2^15-1 */
#define SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER 16383  /* 2^14-1 */

#define SSL2_CHALLENGE_LENGTH 16
/*#define SSL2_CHALLENGE_LENGTH    32 */
#define SSL2_MIN_CHALLENGE_LENGTH 16
#define SSL2_MAX_CHALLENGE_LENGTH 32
#define SSL2_CONNECTION_ID_LENGTH 16
#define SSL2_MAX_CONNECTION_ID_LENGTH 16
#define SSL2_SSL_SESSION_ID_LENGTH 16
#define SSL2_MAX_CERT_CHALLENGE_LENGTH 32
#define SSL2_MIN_CERT_CHALLENGE_LENGTH 16
#define SSL2_MAX_KEY_MATERIAL_LENGTH 24

#ifdef __cplusplus
}
#endif
#endif
