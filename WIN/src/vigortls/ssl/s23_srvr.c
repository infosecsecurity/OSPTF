/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

int ssl23_get_client_hello(SSL *s);

int ssl23_accept(SSL *s)
{
    void (*cb)(const SSL *ssl, int type, int val) = NULL;
    int ret = -1;
    int new_state, state;

    ERR_clear_error();
    errno = 0;

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

    for (;;) {
        state = s->state;

        switch (s->state) {
            case SSL_ST_BEFORE:
            case SSL_ST_ACCEPT:
            case SSL_ST_BEFORE | SSL_ST_ACCEPT:
            case SSL_ST_OK | SSL_ST_ACCEPT:

                s->server = 1;
                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_START, 1);

                /* s->version=SSL3_VERSION; */
                s->type = SSL_ST_ACCEPT;

                if (s->init_buf == NULL) {
                    BUF_MEM *buf;
                    if ((buf = BUF_MEM_new()) == NULL) {
                        ret = -1;
                        goto end;
                    }
                    if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                        BUF_MEM_free(buf);
                        ret = -1;
                        goto end;
                    }
                    s->init_buf = buf;
                }

                tls1_init_finished_mac(s);

                s->state = SSL23_ST_SR_CLNT_HELLO_A;
                s->ctx->stats.sess_accept++;
                s->init_num = 0;
                break;

            case SSL23_ST_SR_CLNT_HELLO_A:
            case SSL23_ST_SR_CLNT_HELLO_B:

                s->shutdown = 0;
                ret = ssl23_get_client_hello(s);
                if (ret >= 0)
                    cb = NULL;
                goto end;
            /* break; */

            default:
                SSLerr(SSL_F_SSL23_ACCEPT, SSL_R_UNKNOWN_STATE);
                ret = -1;
                goto end;
                /* break; */
        }

        if ((cb != NULL) && (s->state != state)) {
            new_state = s->state;
            s->state = state;
            cb(s, SSL_CB_ACCEPT_LOOP, 1);
            s->state = new_state;
        }
    }
end:
    s->in_handshake--;
    if (cb != NULL)
        cb(s, SSL_CB_ACCEPT_EXIT, ret);
    return (ret);
}

int ssl23_get_client_hello(SSL *s)
{
    char buf[11];
    /*
     * sizeof(buf) == 11, because we'll need to request this many bytes in
     * the initial read.
     * We can detect SSL 3.0/TLS 1.0 Client Hellos ('type == 3') correctly
     * only when the following is in a single record, which is not
     * guaranteed by the protocol specification:
     * Byte  Content
     *  0     type            \
     *  1/2   version         > record header
     *  3/4   length          /
     *  5     msg_type        \
     *  6-8   length          > Client Hello message
     *  9/10  client_version  /
     */
    uint8_t *p, *d, *d_len, *dd;
    unsigned int i;
    unsigned int csl, sil, cl;
    int n = 0, j;
    int type = 0;
    int v[2];

    if (s->state == SSL23_ST_SR_CLNT_HELLO_A) {
        /* read the initial header */
        v[0] = v[1] = 0;

        if (!ssl3_setup_buffers(s))
            return -1;

        n = ssl23_read_bytes(s, sizeof buf);
        if (n != sizeof buf)
            return (n);

        p = s->packet;

        memcpy(buf, p, n);

        if ((p[0] & 0x80) && (p[2] == SSL2_MT_CLIENT_HELLO)) {
            /*
             * SSLv2 header
             */
            if ((p[3] == 0x00) && (p[4] == 0x02)) {
                v[0] = p[3];
                v[1] = p[4];
                /* SSLv2 */
                if (!(s->options & SSL_OP_NO_SSLv2))
                    type = 1;
            } else if (p[3] == SSL3_VERSION_MAJOR) {
                v[0] = p[3];
                v[1] = p[4];
                /* SSLv3/TLSv1 */
                if (p[4] >= TLS1_VERSION_MINOR) {
                    if (p[4] >= TLS1_2_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_2)) {
                        s->version = TLS1_2_VERSION;
                        s->state = SSL23_ST_SR_CLNT_HELLO_B;
                    } else if (p[4] >= TLS1_1_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_1)) {
                        s->version = TLS1_1_VERSION;
                        /* type=2; */ /* done later to survive restarts */
                        s->state = SSL23_ST_SR_CLNT_HELLO_B;
                    } else if (!(s->options & SSL_OP_NO_TLSv1)) {
                        s->version = TLS1_VERSION;
                        /* type=2; */ /* done later to survive restarts */
                        s->state = SSL23_ST_SR_CLNT_HELLO_B;
                    }
                }
            }
        } else if ((p[0] == SSL3_RT_HANDSHAKE)
            && (p[1] == SSL3_VERSION_MAJOR)
            && (p[5] == SSL3_MT_CLIENT_HELLO)
            && ((p[3] == 0 && p[4] < 5 /* silly record length? */)
            || (p[9] >= p[1]))) {
            /*
             * SSLv3 or tls1 header
             */

            v[0] = p[1]; /* major version (= SSL3_VERSION_MAJOR) */
            /* We must look at client_version inside the Client Hello message
             * to get the correct minor version.
             * However if we have only a pathologically small fragment of the
             * Client Hello message, this would be difficult, and we'd have
             * to read more records to find out.
             * No known SSL 3.0 client fragments ClientHello like this,
             * so we simply reject such connections to avoid
             * protocol version downgrade attacks. */
            if (p[3] == 0 && p[4] < 6) {
                SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_RECORD_TOO_SMALL);
                return -1;
            }
            /* if major version number > 3 set minor to a value
             * which will use the highest version 3 we support.
             * If TLS 2.0 ever appears we will need to revise
             * this....
             */
            if (p[9] > SSL3_VERSION_MAJOR)
                v[1] = 0xff;
            else
                v[1] = p[10]; /* minor version according to client_version */
            if (v[1] >= TLS1_VERSION_MINOR) {
                if (v[1] >= TLS1_2_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_2)) {
                    s->version = TLS1_2_VERSION;
                    type = 3;
                } else if (v[1] >= TLS1_1_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_1)) {
                    s->version = TLS1_1_VERSION;
                    type = 3;
                } else if (!(s->options & SSL_OP_NO_TLSv1)) {
                    s->version = TLS1_VERSION;
                    type = 3;
                }
            } else {
                if (!(s->options & SSL_OP_NO_TLSv1)) {
                    /* we won't be able to use TLS of course,
                     * but this will send an appropriate alert */
                    s->version = TLS1_VERSION;
                    type = 3;
                }
            }
        } else if ((strncmp("GET ", (char *)p, 4) == 0)
            || (strncmp("POST ", (char *)p, 5) == 0)
            || (strncmp("HEAD ", (char *)p, 5) == 0)
            || (strncmp("PUT ", (char *)p, 4) == 0)) {
            SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_HTTP_REQUEST);
            return -1;
        } else if (strncmp("CONNECT", (char *)p, 7) == 0) {
            SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_HTTPS_PROXY_REQUEST);
            return -1;
        }
    }

    if (s->version < TLS1_2_VERSION && tls1_suiteb(s)) {
        SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE);
        return -1;
    }

    /* ensure that TLS_MAX_VERSION is up-to-date */
    OPENSSL_assert(s->version <= TLS_MAX_VERSION);

    if (s->state == SSL23_ST_SR_CLNT_HELLO_B) {
        /* we have SSLv3/TLSv1 in an SSLv2 header
         * (other cases skip this state) */

        type = 2;
        p = s->packet;
        v[0] = p[3]; /* == SSL3_VERSION_MAJOR */
        v[1] = p[4];

        /* An SSLv3/TLSv1 backwards-compatible CLIENT-HELLO in an SSLv2
         * header is sent directly on the wire, not wrapped as a TLS
         * record. It's format is:
         * Byte  Content
         * 0-1   msg_length
         * 2     msg_type
         * 3-4   version
         * 5-6   cipher_spec_length
         * 7-8   session_id_length
         * 9-10  challenge_length
         * ...   ...
         */
        n = ((p[0] & 0x7f) << 8) | p[1];
        if (n > (1024 * 4)) {
            SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_RECORD_TOO_LARGE);
            return -1;
        }
        if (n < 9) {
            SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_RECORD_LENGTH_MISMATCH);
            return -1;
        }

        j = ssl23_read_bytes(s, n + 2);
        if (j != n + 2)
            return -1;

        tls1_finish_mac(s, s->packet + 2, s->packet_length - 2);
        if (s->msg_callback)
            s->msg_callback(0, SSL2_VERSION, 0, s->packet + 2, s->packet_length - 2,
                            s, s->msg_callback_arg);

        p = s->packet;
        p += 5;
        n2s(p, csl);
        n2s(p, sil);
        n2s(p, cl);
        d = (uint8_t *)s->init_buf->data;
        if ((csl + sil + cl + 11) != s->packet_length) {
            /*
             * We can't have TLS extensions in SSL 2.0 format
             * Client Hello, can we ? Error condition should be
             * '>' otherwise
             */
            SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_RECORD_LENGTH_MISMATCH);
            return -1;
        }

        /* record header: msg_type ... */
        *(d++) = SSL3_MT_CLIENT_HELLO;
        /* ... and length (actual value will be written later) */
        d_len = d;
        d += 3;

        /* client_version */
        *(d++) = SSL3_VERSION_MAJOR; /* == v[0] */
        *(d++) = v[1];

        /* lets populate the random area */
        /* get the challenge_length */
        i = (cl > SSL3_RANDOM_SIZE) ? SSL3_RANDOM_SIZE : cl;
        memset(d, 0, SSL3_RANDOM_SIZE);
        memcpy(&(d[SSL3_RANDOM_SIZE - i]), &(p[csl + sil]), i);
        d += SSL3_RANDOM_SIZE;

        /* no session-id reuse */
        *(d++) = 0;

        /* ciphers */
        j = 0;
        dd = d;
        d += 2;
        for (i = 0; i < csl; i += 3) {
            if (p[i] != 0)
                continue;
            *(d++) = p[i + 1];
            *(d++) = p[i + 2];
            j += 2;
        }
        s2n(j, dd);

        /* add in (no) COMPRESSION */
        *(d++) = 1;
        *(d++) = 0;

        i = (d - (uint8_t *)s->init_buf->data) - 4;
        l2n3((long)i, d_len);

        /* get the data reused from the init_buf */
        s->s3->tmp.reuse_message = 1;
        s->s3->tmp.message_type = SSL3_MT_CLIENT_HELLO;
        s->s3->tmp.message_size = i;
    }

    /* imaginary new state (for program structure): */
    /* s->state = SSL23_SR_CLNT_HELLO_C */

    if (type == 1) {
        SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_UNSUPPORTED_PROTOCOL);
        return -1;
    }

    if ((type == 2) || (type == 3)) {
        /* we have SSLv3/TLSv1 (type 2: SSL2 style, type 3: SSL3/TLS style) */

        if (!ssl_init_wbio_buffer(s, 1))
            return -1;

        /* we are in this state */
        s->state = SSL3_ST_SR_CLNT_HELLO_A;

        if (type == 3) {
            /* put the 'n' bytes we have read into the input buffer
             * for SSLv3 */
            s->rstate = SSL_ST_READ_HEADER;
            s->packet_length = n;
            if (s->s3->rbuf.buf == NULL)
                if (!ssl3_setup_read_buffer(s))
                    return -1;

            s->packet = &(s->s3->rbuf.buf[0]);
            memcpy(s->packet, buf, n);
            s->s3->rbuf.left = n;
            s->s3->rbuf.offset = 0;
        } else {
            s->packet_length = 0;
            s->s3->rbuf.left = 0;
            s->s3->rbuf.offset = 0;
        }
        if (s->version == TLS1_2_VERSION)
            s->method = TLSv1_2_server_method();
        else if (s->version == TLS1_1_VERSION)
            s->method = TLSv1_1_server_method();
        else
            s->method = TLSv1_server_method();

        s->handshake_func = s->method->ssl_accept;
    }

    if ((type < 1) || (type > 3)) {
        /* bad, very bad */
        SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_UNKNOWN_PROTOCOL);
        return -1;
    }
    s->init_num = 0;

    return (SSL_accept(s));
}
