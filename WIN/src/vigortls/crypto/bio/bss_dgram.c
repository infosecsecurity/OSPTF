/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/opensslconf.h>

#include <openssl/bio.h>

#ifndef OPENSSL_NO_DGRAM

static int BIO_dgram_should_retry(int s);

typedef struct bio_dgram_data_st {
    union {
        struct sockaddr sa;
        struct sockaddr_in sa_in;
        struct sockaddr_in6 sa_in6;
    } peer;
    unsigned int connected;
    unsigned int _errno;
    unsigned int mtu;
    struct timeval next_timeout;
    struct timeval socket_timeout;
} bio_dgram_data;

BIO *BIO_new_dgram(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_datagram());
    if (ret == NULL)
        return (NULL);
    BIO_set_fd(ret, fd, close_flag);
    return (ret);
}

static int dgram_new(BIO *bi)
{
    bio_dgram_data *data = NULL;

    bi->init = 0;
    bi->num = 0;
    data = calloc(1, sizeof(bio_dgram_data));
    if (data == NULL)
        return 0;
    bi->ptr = data;

    bi->flags = 0;
    return (1);
}

static int dgram_clear(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if (a->init) {
            shutdown((a->num), SHUT_RDWR);
            close((a->num));
        }
        a->init = 0;
        a->flags = 0;
    }
    return (1);
}

static int dgram_free(BIO *a)
{
    bio_dgram_data *data;

    if (a == NULL)
        return (0);
    if (!dgram_clear(a))
        return 0;

    data = (bio_dgram_data *)a->ptr;
    free(data);

    return (1);
}

static void dgram_adjust_rcv_timeout(BIO *b)
{
#if defined(SO_RCVTIMEO)
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;
    union {
        size_t s;
        int i;
    } sz = { 0 };

    /* Is a timer active? */
    if (data->next_timeout.tv_sec > 0 || data->next_timeout.tv_usec > 0) {
        struct timeval timenow, timeleft;

        /* Read current socket timeout */
        sz.i = sizeof(data->socket_timeout);
        if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                       &(data->socket_timeout), (void *)&sz) < 0) {
            perror("getsockopt");
        } else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0)
            OPENSSL_assert(sz.s <= sizeof(data->socket_timeout));

        /* Get current time */
        gettimeofday(&timenow, NULL);

        /* Calculate time left until timer expires */
        memcpy(&timeleft, &(data->next_timeout), sizeof(struct timeval));
        if (timeleft.tv_usec < timenow.tv_usec) {
            timeleft.tv_usec = 1000000 - timenow.tv_usec + timeleft.tv_usec;
            timeleft.tv_sec--;
        } else {
            timeleft.tv_usec -= timenow.tv_usec;
        }

        if (timeleft.tv_sec < timenow.tv_sec) {
            timeleft.tv_sec = 0;
            timeleft.tv_usec = 1;
        } else {
            timeleft.tv_sec -= timenow.tv_sec;
        }

        /* Adjust socket timeout if next handhake message timer
         * will expire earlier.
         */
        if ((data->socket_timeout.tv_sec == 0 && data->socket_timeout.tv_usec == 0)
            || (data->socket_timeout.tv_sec > timeleft.tv_sec)
            || (data->socket_timeout.tv_sec == timeleft.tv_sec
                && data->socket_timeout.tv_usec >= timeleft.tv_usec)) {
            if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO, &timeleft,
                           sizeof(struct timeval)) < 0) {
                perror("setsockopt");
            }
        }
    }
#endif
}

static void dgram_reset_rcv_timeout(BIO *b)
{
#if defined(SO_RCVTIMEO)
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;

    /* Is a timer active? */
    if (data->next_timeout.tv_sec > 0 || data->next_timeout.tv_usec > 0) {
        if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO, &(data->socket_timeout),
                       sizeof(struct timeval)) < 0) {
            perror("setsockopt");
        }
    }
#endif
}

static int dgram_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;

    struct {
        socklen_t len;
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
            struct sockaddr_in6 sa_in6;
        } peer;
    } sa;

    sa.len = sizeof(sa.peer);

    if (out != NULL) {
        errno = 0;
        memset(&sa.peer, 0x00, sizeof(sa.peer));
        dgram_adjust_rcv_timeout(b);
        ret = recvfrom(b->num, out, outl, 0, &sa.peer.sa, &sa.len);

        if (!data->connected && ret >= 0)
            BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, &sa.peer);

        BIO_clear_retry_flags(b);
        if (ret < 0) {
            if (BIO_dgram_should_retry(ret)) {
                BIO_set_retry_read(b);
                data->_errno = errno;
            }
        }

        dgram_reset_rcv_timeout(b);
    }
    return (ret);
}

static int dgram_write(BIO *b, const char *in, int inl)
{
    int ret;
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;
    errno = 0;

    if (data->connected)
        ret = write(b->num, in, inl);
    else {
        int peerlen = sizeof(data->peer);

        if (data->peer.sa.sa_family == AF_INET)
            peerlen = sizeof(data->peer.sa_in);
        else if (data->peer.sa.sa_family == AF_INET6)
            peerlen = sizeof(data->peer.sa_in6);
        ret = sendto(b->num, in, inl, 0, &data->peer.sa, peerlen);
    }

    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_dgram_should_retry(ret)) {
            BIO_set_retry_write(b);
            data->_errno = errno;
        }
    }
    return (ret);
}

static long dgram_get_mtu_overhead(bio_dgram_data *data)
{
    long ret;

    switch (data->peer.sa.sa_family) {
        case AF_INET:
            /* Assume this is UDP - 20 bytes for IP, 8 bytes for UDP */
            ret = 28;
            break;
        case AF_INET6:
#ifdef IN6_IS_ADDR_V4MAPPED
            if (IN6_IS_ADDR_V4MAPPED(&data->peer.sa_in6.sin6_addr))
                /* Assume this is UDP - 20 bytes for IP, 8 bytes for UDP */
                ret = 28;
            else
#endif
                /* Assume this is UDP - 40 bytes for IP, 8 bytes for UDP */
                ret = 48;
            break;
        default:
            /* We don't know. Go with the historical default */
            ret = 28;
            break;
    }
    return ret;
}

static long dgram_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
    struct sockaddr *to = NULL;
    bio_dgram_data *data = NULL;
#ifdef IP_MTU
    socklen_t sockopt_len; /* assume that system supporting IP_MTU is
                            * modern enough to define socklen_t */
#endif
#if (defined(IP_MTU_DISCOVER) || defined(IP_MTU))
    int sockopt_val = 0;

    socklen_t addr_len;
    union {
        struct sockaddr sa;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } addr;
#endif

    data = (bio_dgram_data *)b->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            num = 0;
            ret = 0;
            break;
        case BIO_CTRL_INFO:
            ret = 0;
            break;
        case BIO_C_SET_FD:
            dgram_clear(b);
            b->num = *((int *)ptr);
            b->shutdown = (int)num;
            b->init = 1;
            break;
        case BIO_C_GET_FD:
            if (b->init) {
                ip = (int *)ptr;
                if (ip != NULL)
                    *ip = b->num;
                ret = b->num;
            } else
                ret = -1;
            break;
        case BIO_CTRL_GET_CLOSE:
            ret = b->shutdown;
            break;
        case BIO_CTRL_SET_CLOSE:
            b->shutdown = (int)num;
            break;
        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
            ret = 0;
            break;
        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
        case BIO_CTRL_DGRAM_CONNECT:
            to = (struct sockaddr *)ptr;
            switch (to->sa_family) {
                case AF_INET:
                    memcpy(&data->peer, to, sizeof(data->peer.sa_in));
                    break;
                case AF_INET6:
                    memcpy(&data->peer, to, sizeof(data->peer.sa_in6));
                    break;
                default:
                    memcpy(&data->peer, to, sizeof(data->peer.sa));
                    break;
            }
            break;
        /* (Linux)kernel sets DF bit on outgoing IP packets */
        case BIO_CTRL_DGRAM_MTU_DISCOVER:
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
            addr_len = (socklen_t)sizeof(addr);
            memset((void *)&addr, 0, sizeof(addr));
            if (getsockname(b->num, &addr.sa, &addr_len) < 0) {
                ret = 0;
                break;
            }
            switch (addr.sa.sa_family) {
                case AF_INET:
                    sockopt_val = IP_PMTUDISC_DO;
                    if ((ret = setsockopt(b->num, IPPROTO_IP, IP_MTU_DISCOVER,
                                          &sockopt_val, sizeof(sockopt_val))) < 0)
                        perror("setsockopt");
                    break;
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
                case AF_INET6:
                    sockopt_val = IPV6_PMTUDISC_DO;
                    if ((ret = setsockopt(b->num, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                                          &sockopt_val, sizeof(sockopt_val))) < 0)
                        perror("setsockopt");
                    break;
#endif
                default:
                    ret = -1;
                    break;
            }
            ret = -1;
#else
            break;
#endif
        case BIO_CTRL_DGRAM_QUERY_MTU:
#ifdef IP_MTU
            addr_len = (socklen_t)sizeof(addr);
            memset((void *)&addr, 0, sizeof(addr));
            if (getsockname(b->num, &addr.sa, &addr_len) < 0) {
                ret = 0;
                break;
            }
            sockopt_len = sizeof(sockopt_val);
            switch (addr.sa.sa_family) {
                case AF_INET:
                    if ((ret = getsockopt(b->num, IPPROTO_IP, IP_MTU, (void *)&sockopt_val,
                                          &sockopt_len)) < 0 || sockopt_val < 0) {
                        ret = 0;
                    } else {
                        /* we assume that the transport protocol is UDP and no
                         * IP options are used.
                         */
                        data->mtu = sockopt_val - 8 - 20;
                        ret = data->mtu;
                    }
                    break;
#ifdef IPV6_MTU
                case AF_INET6:
                    if ((ret = getsockopt(b->num, IPPROTO_IPV6, IPV6_MTU, (void *)&sockopt_val,
                                          &sockopt_len)) < 0 || sockopt_val < 0) {
                        ret = 0;
                    } else {
                        /* we assume that the transport protocol is UDP and no
                         * IPV6 options are used.
                         */
                        data->mtu = sockopt_val - 8 - 40;
                        ret = data->mtu;
                    }
                    break;
#endif
                default:
                    ret = 0;
                    break;
            }
#else
            ret = 0;
#endif
            break;
        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
            ret = -dgram_get_mtu_overhead(data);
            switch (data->peer.sa.sa_family) {
                case AF_INET:
                    ret += 576;
                    break;
                case AF_INET6:
#ifdef IN6_IS_ADDR_V4MAPPED
                    if (IN6_IS_ADDR_V4MAPPED(&data->peer.sa_in6.sin6_addr))
                        ret += 576;
                    else
#endif
                        ret += 1280;
                    break;
                default:
                    ret += 576;
                    break;
            }
            break;
        case BIO_CTRL_DGRAM_GET_MTU:
            return data->mtu;
            break;
        case BIO_CTRL_DGRAM_SET_MTU:
            data->mtu = num;
            ret = num;
            break;
        case BIO_CTRL_DGRAM_SET_CONNECTED:
            to = (struct sockaddr *)ptr;

            if (to != NULL) {
                data->connected = 1;
                switch (to->sa_family) {
                    case AF_INET:
                        memcpy(&data->peer, to, sizeof(data->peer.sa_in));
                        break;
                    case AF_INET6:
                        memcpy(&data->peer, to, sizeof(data->peer.sa_in6));
                        break;
                    default:
                        memcpy(&data->peer, to, sizeof(data->peer.sa));
                        break;
                }
            } else {
                data->connected = 0;
                memset(&(data->peer), 0x00, sizeof(data->peer));
            }
            break;
        case BIO_CTRL_DGRAM_GET_PEER:
            switch (data->peer.sa.sa_family) {
                case AF_INET:
                    ret = sizeof(data->peer.sa_in);
                    break;
                case AF_INET6:
                    ret = sizeof(data->peer.sa_in6);
                    break;
                default:
                    ret = sizeof(data->peer.sa);
                    break;
            }
            if (num == 0 || num > ret)
                num = ret;
            memcpy(ptr, &data->peer, (ret = num));
            break;
        case BIO_CTRL_DGRAM_SET_PEER:
            to = (struct sockaddr *)ptr;
            switch (to->sa_family) {
                case AF_INET:
                    memcpy(&data->peer, to, sizeof(data->peer.sa_in));
                    break;
                case AF_INET6:
                    memcpy(&data->peer, to, sizeof(data->peer.sa_in6));
                    break;
                default:
                    memcpy(&data->peer, to, sizeof(data->peer.sa));
                    break;
            }
            break;
        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
            memcpy(&(data->next_timeout), ptr, sizeof(struct timeval));
            break;
#if defined(SO_RCVTIMEO)
        case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
            if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO, ptr,
                           sizeof(struct timeval)) < 0) {
                perror("setsockopt");
                ret = -1;
            }
            break;
        case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT: {
            union {
                size_t s;
                int i;
            } sz = { 0 };
            sz.i = sizeof(struct timeval);
            if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                           ptr, (void *)&sz) < 0) {
                perror("getsockopt");
                ret = -1;
            } else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                OPENSSL_assert(sz.s <= sizeof(struct timeval));
                ret = (int)sz.s;
            } else
                ret = sz.i;
        } break;
#endif
#if defined(SO_SNDTIMEO)
        case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
            if (setsockopt(b->num, SOL_SOCKET, SO_SNDTIMEO, ptr,
                           sizeof(struct timeval)) < 0) {
                perror("setsockopt");
                ret = -1;
            }
            break;
        case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT: {
            union {
                size_t s;
                int i;
            } sz = { 0 };
            sz.i = sizeof(struct timeval);
            if (getsockopt(b->num, SOL_SOCKET, SO_SNDTIMEO,
                           ptr, (void *)&sz) < 0) {
                perror("getsockopt");
                ret = -1;
            } else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                OPENSSL_assert(sz.s <= sizeof(struct timeval));
                ret = (int)sz.s;
            } else
                ret = sz.i;
        } break;
#endif
        case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
        /* fall-through */
        case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
            if (data->_errno == EAGAIN) {
                ret = 1;
                data->_errno = 0;
            } else
                ret = 0;
            break;
#ifdef EMSGSIZE
        case BIO_CTRL_DGRAM_MTU_EXCEEDED:
            if (data->_errno == EMSGSIZE) {
                ret = 1;
                data->_errno = 0;
            } else
                ret = 0;
            break;
#endif
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
            ret = dgram_get_mtu_overhead(data);
            break;
        default:
            ret = 0;
            break;
    }
    return (ret);
}

static int dgram_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = dgram_write(bp, str, n);
    return (ret);
}

static int BIO_dgram_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = errno;

        return (BIO_dgram_non_fatal_error(err));
    }
    return (0);
}

int BIO_dgram_non_fatal_error(int err)
{
    switch (err) {

#ifdef EWOULDBLOCK
#ifdef WSAEWOULDBLOCK
#if WSAEWOULDBLOCK != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
#else
        case EWOULDBLOCK:
#endif
#endif

#ifdef EINTR
        case EINTR:
#endif

#ifdef EAGAIN
#if EWOULDBLOCK != EAGAIN
        case EAGAIN:
#endif
#endif

#ifdef EPROTO
        case EPROTO:
#endif

#ifdef EINPROGRESS
        case EINPROGRESS:
#endif

#ifdef EALREADY
        case EALREADY:
#endif

            return (1);
        /* break; */
        default:
            break;
    }
    return (0);
}

static BIO_METHOD methods_dgramp = {
    .type = BIO_TYPE_DGRAM,
    .name = "datagram socket",
    .bwrite  = dgram_write,
    .bread   = dgram_read,
    .bputs   = dgram_puts,
    .ctrl    = dgram_ctrl,
    .create  = dgram_new,
    .destroy = dgram_free,
};

BIO_METHOD *BIO_s_datagram(void)
{
    return (&methods_dgramp);
}

#endif
