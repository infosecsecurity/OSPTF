/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <openssl/objects.h>

#include "pqueue.h"
#include "ssl_locl.h"

static void dtls1_set_handshake_header(SSL *s, int type, unsigned long len);
static int dtls1_handshake_write(SSL *s);
int dtls1_listen(SSL *s, struct sockaddr *client);

SSL3_ENC_METHOD DTLSv1_enc_data = {
    .enc = tls1_enc,
    .mac = tls1_mac,
    .setup_key_block = tls1_setup_key_block,
    .generate_master_secret = tls1_generate_master_secret,
    .change_cipher_state = tls1_change_cipher_state,
    .final_finish_mac = tls1_final_finish_mac,
    .finish_mac_length = TLS1_FINISH_MAC_LENGTH,
    .cert_verify_mac = tls1_cert_verify_mac,
    .client_finished_label = TLS_MD_CLIENT_FINISH_CONST,
    .client_finished_label_len = TLS_MD_CLIENT_FINISH_CONST_SIZE,
    .server_finished_label = TLS_MD_SERVER_FINISH_CONST,
    .server_finished_label_len = TLS_MD_SERVER_FINISH_CONST_SIZE,
    .alert_value = tls1_alert_code,
    .export_keying_material = tls1_export_keying_material,
    .enc_flags = SSL_ENC_FLAG_DTLS | SSL_ENC_FLAG_EXPLICIT_IV,
    .hhlen = DTLS1_HM_HEADER_LENGTH,
    .set_handshake_header = dtls1_set_handshake_header,
    .do_write = dtls1_handshake_write,
};

SSL3_ENC_METHOD DTLSv1_2_enc_data = {
    .enc = tls1_enc,
    .mac = tls1_mac,
    .setup_key_block = tls1_setup_key_block,
    .generate_master_secret = tls1_generate_master_secret,
    .change_cipher_state = tls1_change_cipher_state,
    .final_finish_mac = tls1_final_finish_mac,
    .finish_mac_length = TLS1_FINISH_MAC_LENGTH,
    .cert_verify_mac = tls1_cert_verify_mac,
    .client_finished_label = TLS_MD_CLIENT_FINISH_CONST,
    .client_finished_label_len = TLS_MD_CLIENT_FINISH_CONST_SIZE,
    .server_finished_label = TLS_MD_SERVER_FINISH_CONST,
    .server_finished_label_len = TLS_MD_SERVER_FINISH_CONST_SIZE,
    .alert_value = tls1_alert_code,
    .export_keying_material = tls1_export_keying_material,
    .enc_flags = SSL_ENC_FLAG_DTLS | SSL_ENC_FLAG_EXPLICIT_IV |
                 SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_SHA256_PRF |
                 SSL_ENC_FLAG_TLS1_2_CIPHERS,
    .hhlen = DTLS1_HM_HEADER_LENGTH,
    .set_handshake_header = dtls1_set_handshake_header,
    .do_write = dtls1_handshake_write,
};

long dtls1_default_timeout(void)
{
    /* 2 hours, the 24 hours mentioned in the DTLSv1 spec
     * is way too long for http, the cache would over fill */
    return (60 * 60 * 2);
}

int dtls1_new(SSL *s)
{
    DTLS1_STATE *d1;

    if (!ssl3_new(s))
        return (0);
    if ((d1 = calloc(1, sizeof *d1)) == NULL) {
        ssl3_free(s);
        return (0);
    }

    /* d1->handshake_epoch=0; */

    d1->unprocessed_rcds.q = pqueue_new();
    d1->processed_rcds.q = pqueue_new();
    d1->buffered_messages = pqueue_new();
    d1->sent_messages = pqueue_new();
    d1->buffered_app_data.q = pqueue_new();

    if (s->server) {
        d1->cookie_len = sizeof(s->d1->cookie);
    }

    d1->link_mtu = 0;
    d1->mtu = 0;

    if (!d1->unprocessed_rcds.q || !d1->processed_rcds.q || !d1->buffered_messages || !d1->sent_messages || !d1->buffered_app_data.q) {
        if (d1->unprocessed_rcds.q)
            pqueue_free(d1->unprocessed_rcds.q);
        if (d1->processed_rcds.q)
            pqueue_free(d1->processed_rcds.q);
        if (d1->buffered_messages)
            pqueue_free(d1->buffered_messages);
        if (d1->sent_messages)
            pqueue_free(d1->sent_messages);
        if (d1->buffered_app_data.q)
            pqueue_free(d1->buffered_app_data.q);
        free(d1);
        ssl3_free(s);
        return (0);
    }

    s->d1 = d1;
    s->method->ssl_clear(s);
    return (1);
}

static void dtls1_clear_queues(SSL *s)
{
    pitem *item = NULL;
    hm_fragment *frag = NULL;
    DTLS1_RECORD_DATA *rdata;

    while ((item = pqueue_pop(s->d1->unprocessed_rcds.q)) != NULL) {
        rdata = (DTLS1_RECORD_DATA *)item->data;
        free(rdata->rbuf.buf);
        free(item->data);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->processed_rcds.q)) != NULL) {
        rdata = (DTLS1_RECORD_DATA *)item->data;
        free(rdata->rbuf.buf);
        free(item->data);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->buffered_messages)) != NULL) {
        frag = (hm_fragment *)item->data;
        dtls1_hm_fragment_free(frag);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->sent_messages)) != NULL) {
        frag = (hm_fragment *)item->data;
        dtls1_hm_fragment_free(frag);
        pitem_free(item);
    }

    while ((item = pqueue_pop(s->d1->buffered_app_data.q)) != NULL) {
        rdata = (DTLS1_RECORD_DATA *)item->data;
        free(rdata->rbuf.buf);
        free(item->data);
        pitem_free(item);
    }
}

void dtls1_free(SSL *s)
{
    ssl3_free(s);

    dtls1_clear_queues(s);

    pqueue_free(s->d1->unprocessed_rcds.q);
    pqueue_free(s->d1->processed_rcds.q);
    pqueue_free(s->d1->buffered_messages);
    pqueue_free(s->d1->sent_messages);
    pqueue_free(s->d1->buffered_app_data.q);

    vigortls_zeroize(s->d1, sizeof *s->d1);
    free(s->d1);
    s->d1 = NULL;
}

void dtls1_clear(SSL *s)
{
    pqueue unprocessed_rcds;
    pqueue processed_rcds;
    pqueue buffered_messages;
    pqueue sent_messages;
    pqueue buffered_app_data;
    unsigned int mtu;
    unsigned int link_mtu;

    if (s->d1) {
        unprocessed_rcds = s->d1->unprocessed_rcds.q;
        processed_rcds = s->d1->processed_rcds.q;
        buffered_messages = s->d1->buffered_messages;
        sent_messages = s->d1->sent_messages;
        buffered_app_data = s->d1->buffered_app_data.q;
        mtu = s->d1->mtu;
        link_mtu = s->d1->link_mtu;

        dtls1_clear_queues(s);

        memset(s->d1, 0, sizeof(*(s->d1)));

        if (s->server) {
            s->d1->cookie_len = sizeof(s->d1->cookie);
        }

        if (SSL_get_options(s) & SSL_OP_NO_QUERY_MTU) {
            s->d1->mtu = mtu;
            s->d1->link_mtu = link_mtu;
        }

        s->d1->unprocessed_rcds.q = unprocessed_rcds;
        s->d1->processed_rcds.q = processed_rcds;
        s->d1->buffered_messages = buffered_messages;
        s->d1->sent_messages = sent_messages;
        s->d1->buffered_app_data.q = buffered_app_data;
    }

    ssl3_clear(s);
    if (s->method->version == DTLS_ANY_VERSION)
        s->version = DTLS1_2_VERSION;
    else
        s->version = s->method->version;
}

long dtls1_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    int ret = 0;

    switch (cmd) {
        case DTLS_CTRL_GET_TIMEOUT:
            if (dtls1_get_timeout(s, (struct timeval *)parg) != NULL) {
                ret = 1;
            }
            break;
        case DTLS_CTRL_HANDLE_TIMEOUT:
            ret = dtls1_handle_timeout(s);
            break;
        case DTLS_CTRL_LISTEN:
            ret = dtls1_listen(s, parg);
            break;
        case SSL_CTRL_CHECK_PROTO_VERSION:
            /*
             * For library-internal use; checks that the current protocol
             * is the highest enabled version (according to s->ctx->method,
             * as version negotiation may have changed s->method).
             */
            if (s->version == s->ctx->method->version)
                return 1;
            /*
             * Apparently we're using a version-flexible SSL_METHOD
             * (not at its highest protocol version).
             */
            if (s->ctx->method->version == DTLS_method()->version) {
#if DTLS_MAX_VERSION != DTLS1_2_VERSION
#error Code needs update for DTLS_method() support beyond DTLS1_2_VERSION.
#endif
                if (!(s->options & SSL_OP_NO_DTLSv1_2))
                    return s->version == DTLS1_2_VERSION;
                if (!(s->options & SSL_OP_NO_DTLSv1))
                    return s->version == DTLS1_VERSION;
            }
            return 0; /* Unexpected state; fail closed. */
        case DTLS_CTRL_SET_LINK_MTU:
            if (larg < (long)dtls1_link_min_mtu())
                return 0;
            s->d1->link_mtu = larg;
            return 1;
        case DTLS_CTRL_GET_LINK_MIN_MTU:
            return (long)dtls1_link_min_mtu();
        case SSL_CTRL_SET_MTU:
            /*
             *  We may not have a BIO set yet so can't call dtls1_min_mtu()
             *  We'll have to make do with dtls1_link_min_mtu() and max overhead
             */
            if (larg < (long)dtls1_link_min_mtu() - DTLS1_MAX_MTU_OVERHEAD)
                return 0;
            s->d1->mtu = larg;
            return larg;
        default:
            ret = ssl3_ctrl(s, cmd, larg, parg);
            break;
    }
    return (ret);
}

/*
 * As it's impossible to use stream ciphers in "datagram" mode, this
 * simple filter is designed to disengage them in DTLS. Unfortunately
 * there is no universal way to identify stream SSL_CIPHER, so we have
 * to explicitly list their SSL_* codes. Currently RC4 is the only one
 * available, but if new ones emerge, they will have to be added...
 */
const SSL_CIPHER *dtls1_get_cipher(unsigned int u)
{
    const SSL_CIPHER *ciph = ssl3_get_cipher(u);

    if (ciph != NULL) {
        if (ciph->algorithm_enc == SSL_RC4)
            return NULL;
    }

    return ciph;
}

void dtls1_start_timer(SSL *s)
{

    /* If timer is not set, initialize duration with 1 second */
    if (s->d1->next_timeout.tv_sec == 0 && s->d1->next_timeout.tv_usec == 0) {
        s->d1->timeout_duration = 1;
    }

    /* Set timeout to current time */
    gettimeofday(&(s->d1->next_timeout), NULL);

    /* Add duration to current time */
    s->d1->next_timeout.tv_sec += s->d1->timeout_duration;
    BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
             &(s->d1->next_timeout));
}

struct timeval *dtls1_get_timeout(SSL *s, struct timeval *timeleft)
{
    struct timeval timenow;

    /* If no timeout is set, just return NULL */
    if (s->d1->next_timeout.tv_sec == 0 && s->d1->next_timeout.tv_usec == 0) {
        return NULL;
    }

    /* Get current time */
    gettimeofday(&timenow, NULL);

    /* If timer already expired, set remaining time to 0 */
    if (s->d1->next_timeout.tv_sec < timenow.tv_sec
        || (s->d1->next_timeout.tv_sec == timenow.tv_sec && s->d1->next_timeout.tv_usec <= timenow.tv_usec))
    {
        memset(timeleft, 0, sizeof(struct timeval));
        return timeleft;
    }

    /* Calculate time left until timer expires */
    memcpy(timeleft, &(s->d1->next_timeout), sizeof(struct timeval));
    timeleft->tv_sec -= timenow.tv_sec;
    timeleft->tv_usec -= timenow.tv_usec;
    if (timeleft->tv_usec < 0) {
        timeleft->tv_sec--;
        timeleft->tv_usec += 1000000;
    }

    /* If remaining time is less than 15 ms, set it to 0
     * to prevent issues because of small devergences with
     * socket timeouts.
     */
    if (timeleft->tv_sec == 0 && timeleft->tv_usec < 15000) {
        memset(timeleft, 0, sizeof(struct timeval));
    }

    return timeleft;
}

int dtls1_is_timer_expired(SSL *s)
{
    struct timeval timeleft;

    /* Get time left until timeout, return false if no timer running */
    if (dtls1_get_timeout(s, &timeleft) == NULL) {
        return 0;
    }

    /* Return false if timer is not expired yet */
    if (timeleft.tv_sec > 0 || timeleft.tv_usec > 0) {
        return 0;
    }

    /* Timer expired, so return true */
    return 1;
}

void dtls1_double_timeout(SSL *s)
{
    s->d1->timeout_duration *= 2;
    if (s->d1->timeout_duration > 60)
        s->d1->timeout_duration = 60;
    dtls1_start_timer(s);
}

void dtls1_stop_timer(SSL *s)
{
    /* Reset everything */
    memset(&(s->d1->timeout), 0, sizeof(struct dtls1_timeout_st));
    memset(&(s->d1->next_timeout), 0, sizeof(struct timeval));
    s->d1->timeout_duration = 1;
    BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
             &(s->d1->next_timeout));
    /* Clear retransmission buffer */
    dtls1_clear_record_buffer(s);
}

int dtls1_check_timeout_num(SSL *s)
{
    unsigned int mtu;

    s->d1->timeout.num_alerts++;

    /* Reduce MTU after 2 unsuccessful retransmissions */
    if (s->d1->timeout.num_alerts > 2 &&
        !(SSL_get_options(s) & SSL_OP_NO_QUERY_MTU))
    {
        mtu = BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0,
                       NULL);
        if (mtu < s->d1->mtu)
            s->d1->mtu = mtu;
    }

    if (s->d1->timeout.num_alerts > DTLS1_TMO_ALERT_COUNT) {
        /* fail the connection, enough alerts have been sent */
        SSLerr(SSL_F_DTLS1_CHECK_TIMEOUT_NUM, SSL_R_READ_TIMEOUT_EXPIRED);
        return -1;
    }

    return 0;
}

int dtls1_handle_timeout(SSL *s)
{
    /* if no timer is expired, don't do anything */
    if (!dtls1_is_timer_expired(s)) {
        return 0;
    }

    dtls1_double_timeout(s);

    if (dtls1_check_timeout_num(s) < 0)
        return -1;

    s->d1->timeout.read_timeouts++;
    if (s->d1->timeout.read_timeouts > DTLS1_TMO_READ_COUNT) {
        s->d1->timeout.read_timeouts = 1;
    }

    dtls1_start_timer(s);
    return dtls1_retransmit_buffered_messages(s);
}

int dtls1_listen(SSL *s, struct sockaddr *client)
{
    int ret;
    
    /* Ensure there is no state left over from a previous invocation */
    SSL_clear(s);

    SSL_set_options(s, SSL_OP_COOKIE_EXCHANGE);
    s->d1->listen = 1;

    ret = SSL_accept(s);
    if (ret <= 0)
        return ret;

    (void)BIO_dgram_get_peer(SSL_get_rbio(s), client);
    return 1;
}

void dtls1_build_sequence_number(uint8_t *dst, uint8_t *seq,
                                 unsigned short epoch)
{
    uint8_t dtlsseq[SSL3_SEQUENCE_SIZE];
    uint8_t *p;

    p = dtlsseq;
    s2n(epoch, p);
    memcpy(p, &seq[2], SSL3_SEQUENCE_SIZE - 2);
    memcpy(dst, dtlsseq, SSL3_SEQUENCE_SIZE);
}

static void dtls1_set_handshake_header(SSL *s, int htype, unsigned long len)
{
    uint8_t *p = (uint8_t *)s->init_buf->data;
    dtls1_set_message_header(s, p, htype, len, 0, len);
    s->init_num = (int)len + DTLS1_HM_HEADER_LENGTH;
    s->init_off = 0;
    /* Buffer the message to handle re-xmits */
    dtls1_buffer_message(s, 0);

}

static int dtls1_handshake_write(SSL *s)
{
    return dtls1_do_write(s, SSL3_RT_HANDSHAKE);
}
