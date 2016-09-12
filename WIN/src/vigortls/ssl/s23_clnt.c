/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

static int ssl23_client_hello(SSL *s);
static int ssl23_get_server_hello(SSL *s);

int ssl23_connect(SSL *s)
{
    BUF_MEM *buf = NULL;
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
            case SSL_ST_CONNECT:
            case SSL_ST_BEFORE | SSL_ST_CONNECT:
            case SSL_ST_OK | SSL_ST_CONNECT:

                if (s->session != NULL) {
                    SSLerr(SSL_F_SSL23_CONNECT, SSL_R_SSL23_DOING_SESSION_ID_REUSE);
                    ret = -1;
                    goto end;
                }
                s->server = 0;
                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_START, 1);

                /* s->version=TLS1_VERSION; */
                s->type = SSL_ST_CONNECT;

                if (s->init_buf == NULL) {
                    if ((buf = BUF_MEM_new()) == NULL) {
                        ret = -1;
                        goto end;
                    }
                    if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                        ret = -1;
                        goto end;
                    }
                    s->init_buf = buf;
                    buf = NULL;
                }

                if (!ssl3_setup_buffers(s)) {
                    ret = -1;
                    goto end;
                }

                tls1_init_finished_mac(s);

                s->state = SSL23_ST_CW_CLNT_HELLO_A;
                s->ctx->stats.sess_connect++;
                s->init_num = 0;
                break;

            case SSL23_ST_CW_CLNT_HELLO_A:
            case SSL23_ST_CW_CLNT_HELLO_B:

                s->shutdown = 0;
                ret = ssl23_client_hello(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL23_ST_CR_SRVR_HELLO_A;
                s->init_num = 0;

                break;

            case SSL23_ST_CR_SRVR_HELLO_A:
            case SSL23_ST_CR_SRVR_HELLO_B:
                ret = ssl23_get_server_hello(s);
                if (ret >= 0)
                    cb = NULL;
                goto end;
            /* break; */

            default:
                SSLerr(SSL_F_SSL23_CONNECT, SSL_R_UNKNOWN_STATE);
                ret = -1;
                goto end;
                /* break; */
        }

        if (s->debug) {
            (void)BIO_flush(s->wbio);
        }

        if ((cb != NULL) && (s->state != state)) {
            new_state = s->state;
            s->state = state;
            cb(s, SSL_CB_CONNECT_LOOP, 1);
            s->state = new_state;
        }
    }
end:
    s->in_handshake--;
    BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s, SSL_CB_CONNECT_EXIT, ret);
    return (ret);
}

/*
 * Fill a ClientRandom or ServerRandom field of length len.
 * Returns <= 0 on failure, 1 on success.
 */
int ssl_fill_hello_random(SSL *s, uint8_t *result, int len)
{
    int send_time = 0;
    if (len < 4)
        return 0;
    if (s->server)
        send_time = (s->mode & SSL_MODE_SEND_SERVERHELLO_TIME) != 0;
    else
        send_time = (s->mode & SSL_MODE_SEND_CLIENTHELLO_TIME) != 0;
    if (send_time) {
        unsigned long Time = time(NULL);
        uint8_t *p = result;
        l2n(Time, p);
        return RAND_bytes(p, len - 4);
    } else
        return RAND_bytes(result, len);
}

static int ssl23_client_hello(SSL *s)
{
    uint8_t *buf;
    uint8_t *p, *d;
    int i;
    unsigned long l;
    int version = 0, version_major, version_minor;
    int ret, al;
    unsigned long mask, options = s->options;

    /*
     * SSL_OP_NO_X disables all protocols above X *if* there are
     * some protocols below X enabled. This is required in order
     * to maintain "version capability" vector contiguous. So
     * that if application wants to disable TLS1.0 in favour of
     * TLS1>=1, it would be insufficient to pass SSL_NO_TLSv1, the
     * answer is SSL_OP_NO_TLSv1|SSL_OP_NO_SSLv3|SSL_OP_NO_SSLv2.
     */
    mask = SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv3;
    version = TLS1_2_VERSION;

    if ((options & SSL_OP_NO_TLSv1_2) && (options & mask) != mask)
        version = TLS1_1_VERSION;
    mask &= ~SSL_OP_NO_TLSv1_1;
    if ((options & SSL_OP_NO_TLSv1_1) && (options & mask) != mask)
        version = TLS1_VERSION;
    mask &= ~SSL_OP_NO_TLSv1;

    buf = (uint8_t *)s->init_buf->data;
    if (s->state == SSL23_ST_CW_CLNT_HELLO_A) {
        /*
         * Since we're sending s23 client hello, we're not reusing a session, as
         * we'd be using the method from the saved session instead
         */
        if (!ssl_get_new_session(s, 0)) {
            return -1;
        }

        p = s->s3->client_random;
        if (ssl_fill_hello_random(s, p, SSL3_RANDOM_SIZE) <= 0) {
            SSLerr(SSL_F_SSL23_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            return -1;
        }

        if (version == TLS1_2_VERSION) {
            version_major = TLS1_2_VERSION_MAJOR;
            version_minor = TLS1_2_VERSION_MINOR;
        } else if (tls1_suiteb(s)) {
            SSLerr(SSL_F_SSL23_CLIENT_HELLO,
                   SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE);
            return -1;
        } else if (version == TLS1_1_VERSION) {
            version_major = TLS1_1_VERSION_MAJOR;
            version_minor = TLS1_1_VERSION_MINOR;
        } else if (version == TLS1_VERSION) {
            version_major = TLS1_VERSION_MAJOR;
            version_minor = TLS1_VERSION_MINOR;
        } else {
            SSLerr(SSL_F_SSL23_CLIENT_HELLO, SSL_R_NO_PROTOCOLS_AVAILABLE);
            return (-1);
        }

        s->client_version = version;

        /* create Client Hello in SSL 3.0/TLS 1.0 format */

        /*
         * Do the record header (5 bytes) and handshake
         * message header (4 bytes) last
         */
        d = p = &(buf[SSL3_RT_HEADER_LENGTH + SSL3_HM_HEADER_LENGTH]);

        *(p++) = version_major;
        *(p++) = version_minor;

        /* Random stuff */
        memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
        p += SSL3_RANDOM_SIZE;

        /* Session ID (zero since there is no reuse) */
        *(p++) = 0;

        /* Ciphers supported (using SSL 3.0/TLS 1.0 format) */
        i = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &p[2]);
        if (i == 0) {
            SSLerr(SSL_F_SSL23_CLIENT_HELLO, SSL_R_NO_CIPHERS_AVAILABLE);
            return -1;
        }
#ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
        /*
         * Some servers hang if client hello > 256 bytes
         * as hack workaround chop number of supported ciphers
         * to keep it well below this if we use TLS v1.2
         */
        if (TLS1_get_version(s) >= TLS1_2_VERSION && i > OPENSSL_MAX_TLS1_2_CIPHER_LENGTH)
            i = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
        s2n(i, p);
        p += i;

        /* add in (no) COMPRESSION */
        *(p++) = 1;
        /* Add the NULL method */
        *(p++) = 0;

        /* TLS extensions*/
        if (ssl_prepare_clienthello_tlsext(s) <= 0) {
            SSLerr(SSL_F_SSL23_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
            return -1;
        }
        p = ssl_add_clienthello_tlsext(s, p, buf + SSL3_RT_MAX_PLAIN_LENGTH,
                                       &al);
        if (p == NULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, al);
            SSLerr(SSL_F_SSL23_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            return -1;
        }

        l = p - d;

        /* fill in 4-byte handshake header */
        d = &(buf[SSL3_RT_HEADER_LENGTH]);
        *(d++) = SSL3_MT_CLIENT_HELLO;
        l2n3(l, d);

        l += 4;

        if (l > SSL3_RT_MAX_PLAIN_LENGTH) {
            SSLerr(SSL_F_SSL23_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            return -1;
        }

        /* fill in 5-byte record header */
        d = buf;
        *(d++) = SSL3_RT_HANDSHAKE;
        *(d++) = version_major;

        /*
         * Some servers hang if we use long client hellos
         * and a record number > TLS 1.0.
         */
        if (TLS1_get_client_version(s) > TLS1_VERSION)
            *(d++) = 1;
        else
            *(d++) = version_minor;
        s2n((int)l, d);

        /* number of bytes to write */
        s->init_num = p - buf;
        s->init_off = 0;

        tls1_finish_mac(s, &(buf[SSL3_RT_HEADER_LENGTH]),
            s->init_num - SSL3_RT_HEADER_LENGTH);

        s->state = SSL23_ST_CW_CLNT_HELLO_B;
        s->init_off = 0;
    }

    /* SSL3_ST_CW_CLNT_HELLO_B */
    ret = ssl23_write_bytes(s);

    if ((ret >= 2) && s->msg_callback) {
        /* Client Hello has been sent; tell msg_callback */
        s->msg_callback(1, version, SSL3_RT_HEADER, s->init_buf->data, 5, s,
                        s->msg_callback_arg);
        s->msg_callback(1, version, SSL3_RT_HANDSHAKE, s->init_buf->data + 5,
                        ret - 5, s, s->msg_callback_arg);
    }

    return ret;
}

static int ssl23_get_server_hello(SSL *s)
{
    char buf[8];
    uint8_t *p;
    int i;
    int n;

    n = ssl23_read_bytes(s, 7);

    if (n != 7)
        return (n);
    p = s->packet;

    memcpy(buf, p, n);

    /* Old unsupported sslv2 handshake */
    if ((p[0] & 0x80) && (p[2] == SSL2_MT_SERVER_HELLO) && (p[5] == 0x00) && (p[6] == 0x02)) {
        SSLerr(SSL_F_SSL23_GET_SERVER_HELLO, SSL_R_UNSUPPORTED_PROTOCOL);
        goto err;
    }

    if (p[1] == SSL3_VERSION_MAJOR && p[2] <= TLS1_2_VERSION_MINOR
        && ((p[0] == SSL3_RT_HANDSHAKE && p[5] == SSL3_MT_SERVER_HELLO)
        || (p[0] == SSL3_RT_ALERT && p[3] == 0 && p[4] == 2))) {
        /* we have sslv3 or tls1 (server hello or alert) */

        if ((p[2] == TLS1_VERSION_MINOR) && !(s->options & SSL_OP_NO_TLSv1)) {
            s->version = TLS1_VERSION;
            s->method = TLSv1_client_method();
        } else if ((p[2] == TLS1_1_VERSION_MINOR) && !(s->options & SSL_OP_NO_TLSv1_1)) {
            s->version = TLS1_1_VERSION;
            s->method = TLSv1_1_client_method();
        } else if ((p[2] == TLS1_2_VERSION_MINOR) && !(s->options & SSL_OP_NO_TLSv1_2)) {
            s->version = TLS1_2_VERSION;
            s->method = TLSv1_2_client_method();
        } else {
            SSLerr(SSL_F_SSL23_GET_SERVER_HELLO, SSL_R_UNSUPPORTED_PROTOCOL);
            goto err;
        }

        s->session->ssl_version = s->version;

        /* ensure that TLS_MAX_VERSION is up-to-date */
        OPENSSL_assert(s->version <= TLS_MAX_VERSION);

        if (p[0] == SSL3_RT_ALERT && p[5] != SSL3_AL_WARNING) {
            /* fatal alert */
            void (*cb)(const SSL *ssl, int type, int val) = NULL;
            int j;

            if (s->info_callback != NULL)
                cb = s->info_callback;
            else if (s->ctx->info_callback != NULL)
                cb = s->ctx->info_callback;

            i = p[5];
            if (cb != NULL) {
                j = (i << 8) | p[6];
                cb(s, SSL_CB_READ_ALERT, j);
            }

            if (s->msg_callback) {
                s->msg_callback(0, s->version, SSL3_RT_HEADER, p, 5, s,
                                s->msg_callback_arg);
                s->msg_callback(0, s->version, SSL3_RT_ALERT, p + 5, 2, s,
                                s->msg_callback_arg);
            }

            s->rwstate = SSL_NOTHING;
            SSLerr(SSL_F_SSL23_GET_SERVER_HELLO, SSL_AD_REASON_OFFSET + p[6]);
            goto err;
        }

        if (!ssl_init_wbio_buffer(s, 1))
            goto err;

        /* we are in this state */
        s->state = SSL3_ST_CR_SRVR_HELLO_A;

        /* put the 7 bytes we have read into the input buffer
         * for SSLv3 */
        s->rstate = SSL_ST_READ_HEADER;
        s->packet_length = n;
        if (s->s3->rbuf.buf == NULL)
            if (!ssl3_setup_read_buffer(s))
                goto err;
        s->packet = &(s->s3->rbuf.buf[0]);
        memcpy(s->packet, buf, n);
        s->s3->rbuf.left = n;
        s->s3->rbuf.offset = 0;

        s->handshake_func = s->method->ssl_connect;
    } else {
        SSLerr(SSL_F_SSL23_GET_SERVER_HELLO, SSL_R_UNKNOWN_PROTOCOL);
        goto err;
    }
    s->init_num = 0;

    return (SSL_connect(s));
err:
    return (-1);
}
