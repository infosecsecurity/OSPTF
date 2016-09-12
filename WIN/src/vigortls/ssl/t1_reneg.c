/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/objects.h>

#include "bytestring.h"
#include "ssl_locl.h"

/* Add the client's renegotiation binding */
int ssl_add_clienthello_renegotiate_ext(SSL *s, uint8_t *p, int *len,
                                        int maxlen)
{
    if (p) {
        if ((s->s3->previous_client_finished_len + 1) > maxlen) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT,
                   SSL_R_RENEGOTIATE_EXT_TOO_LONG);
            return 0;
        }

        /* Length byte */
        *p = s->s3->previous_client_finished_len;
        p++;

        memcpy(p, s->s3->previous_client_finished,
               s->s3->previous_client_finished_len);
    }

    *len = s->s3->previous_client_finished_len + 1;

    return 1;
}

/* Parse the client's renegotiation binding and abort if it's not
   right */
int ssl_parse_clienthello_renegotiate_ext(SSL *s, const uint8_t *d, int len,
                                          int *al)
{
    CBS cbs, reneg;

    /* Parse the length byte */
    if (len < 0) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    CBS_init(&cbs, d, len);
    if (!CBS_get_u8_length_prefixed(&cbs, &reneg) ||
        /* Consistency check */
        CBS_len(&cbs) != 0) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Check that the extension matches */
    if (CBS_len(&reneg) != s->s3->previous_client_finished_len) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (!CBS_mem_equal(&reneg, s->s3->previous_client_finished,
               s->s3->previous_client_finished_len)) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    s->s3->send_connection_binding = 1;

    return 1;
}

/* Add the server's renegotiation binding */
int ssl_add_serverhello_renegotiate_ext(SSL *s, uint8_t *p, int *len,
                                        int maxlen)
{
    if (p) {
        if ((s->s3->previous_client_finished_len + s->s3->previous_server_finished_len + 1) > maxlen) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT,
                   SSL_R_RENEGOTIATE_EXT_TOO_LONG);
            return 0;
        }

        /* Length byte */
        *p = s->s3->previous_client_finished_len + s->s3->previous_server_finished_len;
        p++;

        memcpy(p, s->s3->previous_client_finished,
               s->s3->previous_client_finished_len);
        p += s->s3->previous_client_finished_len;

        memcpy(p, s->s3->previous_server_finished,
               s->s3->previous_server_finished_len);
    }

    *len = s->s3->previous_client_finished_len + s->s3->previous_server_finished_len + 1;

    return 1;
}

/* Parse the server's renegotiation binding and abort if it's not right */
int ssl_parse_serverhello_renegotiate_ext(SSL *s, const uint8_t *d, int len,
                                          int *al)
{
    CBS cbs, reneg, previous_client, previous_server;
    int expected_len = s->s3->previous_client_finished_len +
        s->s3->previous_server_finished_len;

    /* Check for logic errors */
    OPENSSL_assert(!expected_len || s->s3->previous_client_finished_len);
    OPENSSL_assert(!expected_len || s->s3->previous_server_finished_len);

    /* Parse the length byte */
    if (len < 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    CBS_init(&cbs, d, len);

    if (!CBS_get_u8_length_prefixed(&cbs, &reneg) ||
        /* Consistency check */
        CBS_len(&cbs) != 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Check that the extension matches */
    if (CBS_len(&reneg) != (size_t)expected_len ||
        !CBS_get_bytes(&reneg, &previous_client,
        s->s3->previous_client_finished_len) ||
        !CBS_get_bytes(&reneg, &previous_server,
        s->s3->previous_server_finished_len) ||
        CBS_len(&reneg) != 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (!CBS_mem_equal(&previous_client, s->s3->previous_client_finished,
        CBS_len(&previous_client))) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (!CBS_mem_equal(&previous_server, s->s3->previous_server_finished,
               CBS_len(&previous_server))) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    s->s3->send_connection_binding = 1;

    return 1;
}
