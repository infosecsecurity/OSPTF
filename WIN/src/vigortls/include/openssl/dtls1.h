/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DTLS1_H
#define HEADER_DTLS1_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

#include <openssl/base.h>
#include <openssl/buffer.h>

/* Fixes conflicts with wincrypt.h */
#if defined(_WIN32) && defined(__WINCRYPT_H__)
#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#undef PKCS7_ISSUER_AND_SERIAL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DTLS1_VERSION       0xFEFF
#define DTLS1_VERSION_MAJOR 0xFE
#define DTLS1_2_VERSION     0xFEFD
#define DTLS_MAX_VERSION    DTLS1_2_VERSION
/* Special value for method supporting multiple versions */
#define DTLS_ANY_VERSION    0x1FFFF

/* lengths of messages */
#define DTLS1_COOKIE_LENGTH     256

#define DTLS1_RT_HEADER_LENGTH  13

#define DTLS1_HM_HEADER_LENGTH  12

#define DTLS1_HM_BAD_FRAGMENT   -2
#define DTLS1_HM_FRAGMENT_RETRY -3

#define DTLS1_CCS_HEADER_LENGTH 1

#ifdef DTLS1_AD_MISSING_HANDSHAKE_MESSAGE
#define DTLS1_AL_HEADER_LENGTH  7
#else
#define DTLS1_AL_HEADER_LENGTH  2
#endif

#ifndef OPENSSL_NO_SSL_INTERN

/* Max MTU overhead we know about so far is 40 for IPv6 + 8 for UDP */
#define DTLS1_MAX_MTU_OVERHEAD  48

typedef struct dtls1_bitmap_st {
    unsigned long map;      /* track 32 packets on 32-bit systems
                             * and 64 - on 64-bit systems */
    uint8_t max_seq_num[8]; /* max record number seen so far,
                             * 64-bit value in big-endian
                             * encoding */
} DTLS1_BITMAP;

struct dtls1_retransmit_state {
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    EVP_MD_CTX *write_hash;        /* used for mac generation */
    SSL_SESSION *session;
    unsigned short epoch;
};

struct hm_header_st {
    uint8_t type;
    unsigned long msg_len;
    unsigned short seq;
    unsigned long frag_off;
    unsigned long frag_len;
    unsigned int is_ccs;
    struct dtls1_retransmit_state saved_retransmit_state;
};

struct ccs_header_st {
    uint8_t type;
    unsigned short seq;
};

struct dtls1_timeout_st {
    /* Number of read timeouts so far */
    unsigned int read_timeouts;

    /* Number of write timeouts so far */
    unsigned int write_timeouts;

    /* Number of alerts received so far */
    unsigned int num_alerts;
};

struct _pqueue;

typedef struct record_pqueue_st {
    unsigned short epoch;
    struct _pqueue *q;
} record_pqueue;

typedef struct hm_fragment_st {
    struct hm_header_st msg_header;
    uint8_t *fragment;
    uint8_t *reassembly;
} hm_fragment;

typedef struct dtls1_state_st {
    unsigned int send_cookie;
    uint8_t cookie[DTLS1_COOKIE_LENGTH];
    uint8_t rcvd_cookie[DTLS1_COOKIE_LENGTH];
    unsigned int cookie_len;

    /*
     * The current data and handshake epoch.  This is initially
     * undefined, and starts at zero once the initial handshake is
     * completed
     */
    unsigned short r_epoch;
    unsigned short w_epoch;

    /* records being received in the current epoch */
    DTLS1_BITMAP bitmap;

    /* renegotiation starts a new set of sequence numbers */
    DTLS1_BITMAP next_bitmap;

    /* handshake message numbers */
    unsigned short handshake_write_seq;
    unsigned short next_handshake_write_seq;

    unsigned short handshake_read_seq;

    /* save last sequence number for retransmissions */
    uint8_t last_write_sequence[8];

    /* Received handshake records (processed and unprocessed) */
    record_pqueue unprocessed_rcds;
    record_pqueue processed_rcds;

    /* Buffered handshake messages */
    struct _pqueue *buffered_messages;

    /* Buffered (sent) handshake records */
    struct _pqueue *sent_messages;

    /* Buffered application records.
     * Only for records between CCS and Finished
     * to prevent either protocol violation or
     * unnecessary message loss.
     */
    record_pqueue buffered_app_data;

    /* Is set when listening for new connections with dtls1_listen() */
    unsigned int listen;

    unsigned int link_mtu; /* max on-the-wire DTLS packet size */
    unsigned int mtu; /* max DTLS packet size */

    struct hm_header_st w_msg_hdr;
    struct hm_header_st r_msg_hdr;

    struct dtls1_timeout_st timeout;

    /* Indicates when the last handshake msg or heartbeat sent will timeout */
    struct timeval next_timeout;

    /* Timeout duration */
    unsigned short timeout_duration;

    /* storage for Alert/Handshake protocol data received but not
     * yet processed by ssl3_read_bytes: */
    uint8_t alert_fragment[DTLS1_AL_HEADER_LENGTH];
    unsigned int alert_fragment_len;
    uint8_t handshake_fragment[DTLS1_HM_HEADER_LENGTH];
    unsigned int handshake_fragment_len;

    unsigned int retransmitting;
    /*
     * Set when the handshake is ready to process peer's ChangeCipherSpec
     * message.
     * Cleared after the message has been processed.
     */
    unsigned int change_cipher_spec_ok;

} DTLS1_STATE;

typedef struct dtls1_record_data_st {
    uint8_t *packet;
    unsigned int packet_length;
    SSL3_BUFFER rbuf;
    SSL3_RECORD rrec;
} DTLS1_RECORD_DATA;

#endif

/* Timeout multipliers (timeout slice is defined in apps/timeouts.h */
#define DTLS1_TMO_READ_COUNT    2
#define DTLS1_TMO_WRITE_COUNT   2

#define DTLS1_TMO_ALERT_COUNT   12

#ifdef __cplusplus
}
#endif
#endif
