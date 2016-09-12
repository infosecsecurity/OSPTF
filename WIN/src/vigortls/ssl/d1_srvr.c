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
#include <openssl/x509.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

static const SSL_METHOD *dtls1_get_server_method(int ver);
static int dtls1_send_hello_verify_request(SSL *s);

const SSL_METHOD DTLSv1_server_method_data = {
    .version = DTLS1_VERSION,
    .ssl_new = dtls1_new,
    .ssl_clear = dtls1_clear,
    .ssl_free = dtls1_free,
    .ssl_accept = dtls1_accept,
    .ssl_connect = ssl_undefined_function,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = dtls1_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = dtls1_get_message,
    .ssl_read_bytes = dtls1_read_bytes,
    .ssl_write_bytes = dtls1_write_app_data_bytes,
    .ssl_dispatch_alert = dtls1_dispatch_alert,
    .ssl_ctrl = dtls1_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = dtls1_get_cipher,
    .get_ssl_method = dtls1_get_server_method,
    .get_timeout = dtls1_default_timeout,
    .ssl3_enc = &DTLSv1_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *DTLSv1_server_method(void)
{
    return &DTLSv1_server_method_data;
}

const SSL_METHOD DTLSv1_2_server_method_data = {
    .version = DTLS1_2_VERSION,
    .ssl_new = dtls1_new,
    .ssl_clear = dtls1_clear,
    .ssl_free = dtls1_free,
    .ssl_accept = dtls1_accept,
    .ssl_connect = ssl_undefined_function,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = dtls1_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = dtls1_get_message,
    .ssl_read_bytes = dtls1_read_bytes,
    .ssl_write_bytes = dtls1_write_app_data_bytes,
    .ssl_dispatch_alert = dtls1_dispatch_alert,
    .ssl_ctrl = dtls1_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = dtls1_get_cipher,
    .get_ssl_method = dtls1_get_server_method,
    .get_timeout = dtls1_default_timeout,
    .ssl3_enc = &DTLSv1_2_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *DTLSv1_2_server_method(void)
{
    return &DTLSv1_2_server_method_data;
}

const SSL_METHOD DTLS_server_method_data = {
    .version = DTLS_ANY_VERSION,
    .ssl_new = dtls1_new,
    .ssl_clear = dtls1_clear,
    .ssl_free = dtls1_free,
    .ssl_accept = dtls1_accept,
    .ssl_connect = ssl_undefined_function,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = dtls1_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = dtls1_get_message,
    .ssl_read_bytes = dtls1_read_bytes,
    .ssl_write_bytes = dtls1_write_app_data_bytes,
    .ssl_dispatch_alert = dtls1_dispatch_alert,
    .ssl_ctrl = dtls1_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .get_cipher_by_char = ssl3_get_cipher_by_char,
    .put_cipher_by_char = ssl3_put_cipher_by_char,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = dtls1_get_cipher,
    .get_ssl_method = dtls1_get_server_method,
    .get_timeout = dtls1_default_timeout,
    .ssl3_enc = &DTLSv1_2_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *DTLS_server_method(void)
{
    return &DTLS_server_method_data;
}

static const SSL_METHOD *dtls1_get_server_method(int ver)
{
    switch (ver) {
        case DTLS_ANY_VERSION:
            return DTLS_server_method();
        case DTLS1_VERSION:
            return DTLSv1_server_method();
        case DTLS1_2_VERSION:
            return DTLSv1_2_server_method();
        default:
            return NULL;
    }
}

int dtls1_accept(SSL *s)
{
    void (*cb)(const SSL *ssl, int type, int val) = NULL;
    unsigned long alg_k;
    int ret = -1;
    int new_state, state, skip = 0;
    int listen;

    ERR_clear_error();
    errno = 0;

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    listen = s->d1->listen;

    /* init things to blank */
    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

    s->d1->listen = listen;

    if (s->cert == NULL) {
        SSLerr(SSL_F_DTLS1_ACCEPT, SSL_R_NO_CERTIFICATE_SET);
        return (-1);
    }

    for (;;) {
        state = s->state;

        switch (s->state) {
            case SSL_ST_RENEGOTIATE:
                s->renegotiate = 1;
            /* s->state=SSL_ST_ACCEPT; */

            case SSL_ST_BEFORE:
            case SSL_ST_ACCEPT:
            case SSL_ST_BEFORE | SSL_ST_ACCEPT:
            case SSL_ST_OK | SSL_ST_ACCEPT:

                s->server = 1;
                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_START, 1);

                if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00)) {
                    SSLerr(SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                    return -1;
                }
                s->type = SSL_ST_ACCEPT;

                if (s->init_buf == NULL) {
                    BUF_MEM *buf;
                    if ((buf = BUF_MEM_new()) == NULL) {
                        ret = -1;
                        s->state = SSL_ST_ERR;
                        goto end;
                    }
                    if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                        BUF_MEM_free(buf);
                        ret = -1;
                        s->state = SSL_ST_ERR;
                        goto end;
                    }
                    s->init_buf = buf;
                }

                if (!ssl3_setup_buffers(s)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                s->init_num = 0;
                s->d1->change_cipher_spec_ok = 0;
                /* Should have been reset by ssl3_get_finished, too. */
                s->s3->change_cipher_spec = 0;

                if (s->state != SSL_ST_RENEGOTIATE) {
                    /*
                     * Ok, we now need to push on a buffering BIO so that
                     * the output is sent in a way that TCP likes :-)
                     * ...but not with SCTP :-)
                     */
                    if (!ssl_init_wbio_buffer(s, 1)) {
                        ret = -1;
                        s->state = SSL_ST_ERR;
                        goto end;
                    }

                    tls1_init_finished_mac(s);
                    s->state = SSL3_ST_SR_CLNT_HELLO_A;
                    s->ctx->stats.sess_accept++;
                } else if (!s->s3->send_connection_binding) {
                    /*
                     * Server attempting to renegotiate with client that doesn't
                     * support secure renegotiation.
                     */
                    SSLerr(SSL_F_DTLS1_ACCEPT,
                           SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
                    ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                } else {
                    /* s->state == SSL_ST_RENEGOTIATE,
                     * we will just send a HelloRequest */
                    s->ctx->stats.sess_accept_renegotiate++;
                    s->state = SSL3_ST_SW_HELLO_REQ_A;
                }

                break;

            case SSL3_ST_SW_HELLO_REQ_A:
            case SSL3_ST_SW_HELLO_REQ_B:

                s->shutdown = 0;
                dtls1_clear_record_buffer(s);
                dtls1_start_timer(s);
                ret = ssl3_send_hello_request(s);
                if (ret <= 0)
                    goto end;
                s->s3->tmp.next_state = SSL3_ST_SR_CLNT_HELLO_A;
                s->state = SSL3_ST_SW_FLUSH;
                s->init_num = 0;

                tls1_init_finished_mac(s);
                break;

            case SSL3_ST_SW_HELLO_REQ_C:
                s->state = SSL_ST_OK;
                break;

            case SSL3_ST_SR_CLNT_HELLO_A:
            case SSL3_ST_SR_CLNT_HELLO_B:
            case SSL3_ST_SR_CLNT_HELLO_C:

                s->shutdown = 0;
                ret = ssl3_get_client_hello(s);
                if (ret <= 0)
                    goto end;
                dtls1_stop_timer(s);

                if (ret == 1 && (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE))
                    s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A;
                else
                    s->state = SSL3_ST_SW_SRVR_HELLO_A;

                s->init_num = 0;

                /* Reflect ClientHello sequence to remain stateless while listening */
                if (listen) {
                    memcpy(s->s3->write_sequence, s->s3->read_sequence,
                           sizeof(s->s3->write_sequence));
                }

                /* If we're just listening, stop here */
                if (listen && s->state == SSL3_ST_SW_SRVR_HELLO_A) {
                    ret = 2;
                    s->d1->listen = 0;
                    /*
                     * Set expected sequence numbers
                     * to continue the handshake.
                     */
                    s->d1->handshake_read_seq = 2;
                    s->d1->handshake_write_seq = 1;
                    s->d1->next_handshake_write_seq = 1;
                    goto end;
                }

                break;

            case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A:
            case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B:

                ret = dtls1_send_hello_verify_request(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_SW_FLUSH;
                s->s3->tmp.next_state = SSL3_ST_SR_CLNT_HELLO_A;

                /* HelloVerifyRequest resets Finished MAC */
                tls1_init_finished_mac(s);
                break;


            case SSL3_ST_SW_SRVR_HELLO_A:
            case SSL3_ST_SW_SRVR_HELLO_B:
                s->renegotiate = 2;
                dtls1_start_timer(s);
                ret = ssl3_send_server_hello(s);
                if (ret <= 0)
                    goto end;

                if (s->hit) {
                    if (s->tlsext_ticket_expected)
                        s->state = SSL3_ST_SW_SESSION_TICKET_A;
                    else
                        s->state = SSL3_ST_SW_CHANGE_A;
                } else
                    s->state = SSL3_ST_SW_CERT_A;
                s->init_num = 0;
                break;

            case SSL3_ST_SW_CERT_A:
            case SSL3_ST_SW_CERT_B:
                /* Check if it is anon DH. */
                if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)) {
                    dtls1_start_timer(s);
                    ret = ssl3_send_server_certificate(s);
                    if (ret <= 0)
                        goto end;
                    if (s->tlsext_status_expected)
                        s->state = SSL3_ST_SW_CERT_STATUS_A;
                    else
                        s->state = SSL3_ST_SW_KEY_EXCH_A;
                } else {
                    skip = 1;
                    s->state = SSL3_ST_SW_KEY_EXCH_A;
                }
                s->init_num = 0;
                break;

            case SSL3_ST_SW_KEY_EXCH_A:
            case SSL3_ST_SW_KEY_EXCH_B:
                alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

                /* only send if a DH key exchange */
                if (alg_k & (SSL_kDHE | SSL_kECDHE)) {
                    dtls1_start_timer(s);
                    ret = ssl3_send_server_key_exchange(s);
                    if (ret <= 0)
                        goto end;
                } else
                    skip = 1;

                s->state = SSL3_ST_SW_CERT_REQ_A;
                s->init_num = 0;
                break;

            case SSL3_ST_SW_CERT_REQ_A:
            case SSL3_ST_SW_CERT_REQ_B:
                /*
                 * Determine whether or not we need to request a
                 * certificate.
                 *
                 * Do not request a certificate if:
                 *
                 * - We did not ask for it (SSL_VERIFY_PEER is unset).
                 *
                 * - SSL_VERIFY_CLIENT_ONCE is set and we are
                 *   renegotiating.
                 *
                 * - We are using an anonymous ciphersuites
                 *   (see section "Certificate request" in SSL 3 drafts
                 *   and in RFC 2246) ... except when the application
                 *   insists on verification (against the specs, but
                 *   s3_clnt.c accepts this for SSL 3).
                 */
                if (!(s->verify_mode & SSL_VERIFY_PEER) ||
                    ((s->session->peer != NULL) &&
                    (s->verify_mode & SSL_VERIFY_CLIENT_ONCE)) ||
                    ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) &&
                    !(s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)))
                {
                    /* no cert request */
                    skip = 1;
                    s->s3->tmp.cert_request = 0;
                    s->state = SSL3_ST_SW_SRVR_DONE_A;
                } else {
                    s->s3->tmp.cert_request = 1;
                    dtls1_start_timer(s);
                    ret = ssl3_send_certificate_request(s);
                    if (ret <= 0)
                        goto end;
                    s->state = SSL3_ST_SW_SRVR_DONE_A;
                    s->init_num = 0;
                }
                break;

            case SSL3_ST_SW_SRVR_DONE_A:
            case SSL3_ST_SW_SRVR_DONE_B:
                dtls1_start_timer(s);
                ret = ssl3_send_server_done(s);
                if (ret <= 0)
                    goto end;
                s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
                s->state = SSL3_ST_SW_FLUSH;
                s->init_num = 0;
                break;

            case SSL3_ST_SW_FLUSH:
                s->rwstate = SSL_WRITING;
                if (BIO_flush(s->wbio) <= 0) {
                    /* If the write error was fatal, stop trying */
                    if (!BIO_should_retry(s->wbio)) {
                        s->rwstate = SSL_NOTHING;
                        s->state = s->s3->tmp.next_state;
                    }

                    ret = -1;
                    goto end;
                }
                s->rwstate = SSL_NOTHING;
                s->state = s->s3->tmp.next_state;
                break;

            case SSL3_ST_SR_CERT_A:
            case SSL3_ST_SR_CERT_B:
                if (s->s3->tmp.cert_request) {
                    ret = ssl3_get_client_certificate(s);
                    if (ret <= 0)
                        goto end;
                }
                s->init_num = 0;
                s->state = SSL3_ST_SR_KEY_EXCH_A;
                break;

            case SSL3_ST_SR_KEY_EXCH_A:
            case SSL3_ST_SR_KEY_EXCH_B:
                ret = ssl3_get_client_key_exchange(s);
                if (ret <= 0)
                    goto end;

                s->state = SSL3_ST_SR_CERT_VRFY_A;
                s->init_num = 0;

                if (ret == 2) {
                    /* For the ECDH ciphersuites when
                     * the client sends its ECDH pub key in
                     * a certificate, the CertificateVerify
                     * message is not sent.
                     */
                    s->state = SSL3_ST_SR_FINISHED_A;
                    s->init_num = 0;
                } else if (SSL_USE_SIGALGS(s)) {
                    s->state = SSL3_ST_SR_CERT_VRFY_A;
                    s->init_num = 0;
                    if (!s->session->peer)
                        break;
                    /*
                     * For sigalgs freeze the handshake buffer
                     * at this point and digest cached records.
                     */
                    if (!s->s3->handshake_buffer) {
                        SSLerr(SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                        s->state = SSL_ST_ERR;
                        return -1;
                    }
                    s->s3->flags |= TLS1_FLAGS_KEEP_HANDSHAKE;
                    if (!tls1_digest_cached_records(s)) {
                        s->state = SSL_ST_ERR;
                        return -1;
                    }
                } else {
                    s->state = SSL3_ST_SR_CERT_VRFY_A;
                    s->init_num = 0;

                    /* We need to get hashes here so if there is
                     * a client cert, it can be verified */
                    s->method->ssl3_enc->cert_verify_mac(s, NID_md5,
                                                         &(s->s3->tmp.cert_verify_md[0]));
                    s->method->ssl3_enc->cert_verify_mac(
                        s, NID_sha1, &(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]));
                }
                break;

            case SSL3_ST_SR_CERT_VRFY_A:
            case SSL3_ST_SR_CERT_VRFY_B:
                ret = ssl3_get_cert_verify(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_SR_FINISHED_A;
                s->init_num = 0;
                break;

            case SSL3_ST_SR_FINISHED_A:
            case SSL3_ST_SR_FINISHED_B:
                /*
                 * Enable CCS. Receiving a CCS clears the flag, so make
                 * sure not to re-enable it to ban duplicates. This *should* be the
                 * first time we have received one - but we check anyway to be
                 * cautious.
                 * s->s3->change_cipher_spec is set when a CCS is
                 * processed in d1_pkt.c, and remains set until
                 * the client's Finished message is read.
                 */
                if (!s->s3->change_cipher_spec)
                    s->d1->change_cipher_spec_ok = 1;
                ret = ssl3_get_finished(s, SSL3_ST_SR_FINISHED_A, SSL3_ST_SR_FINISHED_B);
                if (ret <= 0)
                    goto end;
                dtls1_stop_timer(s);
                if (s->hit)
                    s->state = SSL_ST_OK;
                else if (s->tlsext_ticket_expected)
                    s->state = SSL3_ST_SW_SESSION_TICKET_A;
                else
                    s->state = SSL3_ST_SW_CHANGE_A;
                s->init_num = 0;
                break;

            case SSL3_ST_SW_SESSION_TICKET_A:
            case SSL3_ST_SW_SESSION_TICKET_B:
                ret = ssl3_send_newsession_ticket(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_SW_CHANGE_A;
                s->init_num = 0;
                break;

            case SSL3_ST_SW_CERT_STATUS_A:
            case SSL3_ST_SW_CERT_STATUS_B:
                ret = ssl3_send_cert_status(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_SW_KEY_EXCH_A;
                s->init_num = 0;
                break;

            case SSL3_ST_SW_CHANGE_A:
            case SSL3_ST_SW_CHANGE_B:

                s->session->cipher = s->s3->tmp.new_cipher;
                if (!s->method->ssl3_enc->setup_key_block(s)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                ret = dtls1_send_change_cipher_spec(s, SSL3_ST_SW_CHANGE_A,
                                                    SSL3_ST_SW_CHANGE_B);

                if (ret <= 0)
                    goto end;


                s->state = SSL3_ST_SW_FINISHED_A;
                s->init_num = 0;

                if (!s->method->ssl3_enc->change_cipher_state(s,
                        SSL3_CHANGE_CIPHER_SERVER_WRITE))
                {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
                break;

            case SSL3_ST_SW_FINISHED_A:
            case SSL3_ST_SW_FINISHED_B:
                ret = ssl3_send_finished(s, SSL3_ST_SW_FINISHED_A, SSL3_ST_SW_FINISHED_B,
                                         s->method->ssl3_enc->server_finished_label,
                                         s->method->ssl3_enc->server_finished_label_len);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_SW_FLUSH;
                if (s->hit) {
                    s->s3->tmp.next_state = SSL3_ST_SR_FINISHED_A;

                } else {
                    s->s3->tmp.next_state = SSL_ST_OK;
                }
                s->init_num = 0;
                break;

            case SSL_ST_OK:
                /* clean a few things up */
                ssl3_cleanup_key_block(s);

                /* remove buffering on output */
                ssl_free_wbio_buffer(s);

                s->init_num = 0;

                if (s->renegotiate == 2) /* skipped if we just sent a HelloRequest */
                {
                    s->renegotiate = 0;
                    s->new_session = 0;

                    ssl_update_cache(s, SSL_SESS_CACHE_SERVER);

                    s->ctx->stats.sess_accept_good++;
                    /* s->server=1; */
                    s->handshake_func = dtls1_accept;

                    if (cb != NULL)
                        cb(s, SSL_CB_HANDSHAKE_DONE, 1);
                }

                ret = 1;

                /* done handshaking, next message is client hello */
                s->d1->handshake_read_seq = 0;
                /* next message is server hello */
                s->d1->handshake_write_seq = 0;
                s->d1->next_handshake_write_seq = 0;
                goto end;
            /* break; */

            case SSL_ST_ERR:
            default:
                SSLerr(SSL_F_DTLS1_ACCEPT, SSL_R_UNKNOWN_STATE);
                ret = -1;
                goto end;
                /* break; */
        }

        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret = BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state = s->state;
                s->state = state;
                cb(s, SSL_CB_ACCEPT_LOOP, 1);
                s->state = new_state;
            }
        }
        skip = 0;
    }
end:
    /* BIO_flush(s->wbio); */

    s->in_handshake--;

    if (cb != NULL)
        cb(s, SSL_CB_ACCEPT_EXIT, ret);
    return ret;
}

int dtls1_send_hello_verify_request(SSL *s)
{
    unsigned int msg_len;
    uint8_t *msg, *buf, *p;

    if (s->state == DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A) {
        buf = (uint8_t *)s->init_buf->data;

        msg = p = &(buf[DTLS1_HM_HEADER_LENGTH]);
        /* Always use DTLS 1.0 version: see RFC 6347 */
        *(p++) = DTLS1_VERSION >> 8;
        *(p++) = DTLS1_VERSION & 0xFF;

        if (s->ctx->app_gen_cookie_cb == NULL ||
            s->ctx->app_gen_cookie_cb(s, s->d1->cookie, &(s->d1->cookie_len)) == 0)
        {
            SSLerr(SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST, ERR_R_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return 0;
        }

        *(p++) = (uint8_t)s->d1->cookie_len;
        memcpy(p, s->d1->cookie, s->d1->cookie_len);
        p += s->d1->cookie_len;
        msg_len = p - msg;

        dtls1_set_message_header(s, buf, DTLS1_MT_HELLO_VERIFY_REQUEST, msg_len, 0,
                                 msg_len);

        s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B;
        /* number of bytes to write */
        s->init_num = p - buf;
        s->init_off = 0;
    }

    /* s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B */
    return dtls1_do_write(s, SSL3_RT_HANDSHAKE);
}
