/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SSL23_H
#define HEADER_SSL23_H

#ifdef __cplusplus
extern "C" {
#endif

/*client */
/* write to server */
#define SSL23_ST_CW_CLNT_HELLO_A (0x210 | SSL_ST_CONNECT)
#define SSL23_ST_CW_CLNT_HELLO_B (0x211 | SSL_ST_CONNECT)
/* read from server */
#define SSL23_ST_CR_SRVR_HELLO_A (0x220 | SSL_ST_CONNECT)
#define SSL23_ST_CR_SRVR_HELLO_B (0x221 | SSL_ST_CONNECT)

/* server */
/* read from client */
#define SSL23_ST_SR_CLNT_HELLO_A (0x210 | SSL_ST_ACCEPT)
#define SSL23_ST_SR_CLNT_HELLO_B (0x211 | SSL_ST_ACCEPT)

#ifdef __cplusplus
}
#endif
#endif
