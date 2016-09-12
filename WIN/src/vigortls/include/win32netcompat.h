/*
 * Copyright (c) 2015, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Based off of previous work by Brent Cook <bcook@openbsd.org>
 */

#ifndef VIGORTLS_WIN32NETCOMPAT_H
#define VIGORTLS_WIN32NETCOMPAT_H

#if defined(_WIN32)

#ifdef _MSC_VER
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif
#include <ws2tcpip.h>

#define SHUT_RDWR SD_BOTH
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND

#include <errno.h>
#include <unistd.h>

static int wsa_errno(int err)
{
    switch (err) {
        case WSAENOBUFS:
            errno = ENOMEM;
            break;
        case WSAEACCES:
            errno = EACCES;
            break;
        case WSANOTINITIALISED:
            errno = EPERM;
            break;
        case WSAEHOSTUNREACH:
        case WSAENETDOWN:
            errno = EIO;
            break;
        case WSAEFAULT:
            errno = EFAULT;
            break;
        case WSAEINTR:
            errno = EINTR;
            break;
        case WSAEINVAL:
            errno = EINVAL;
            break;
        case WSAEINPROGRESS:
            errno = EINPROGRESS;
            break;
        case WSAEWOULDBLOCK:
            errno = EAGAIN;
            break;
        case WSAEOPNOTSUPP:
            errno = ENOTSUP;
            break;
        case WSAEMSGSIZE:
            errno = EFBIG;
            break;
        case WSAENOTSOCK:
            errno = ENOTSOCK;
            break;
        case WSAENOPROTOOPT:
            errno = ENOPROTOOPT;
            break;
        case WSAECONNREFUSED:
            errno = ECONNREFUSED;
            break;
        case WSAEAFNOSUPPORT:
            errno = EAFNOSUPPORT;
            break;
        case WSAENETRESET:
        case WSAENOTCONN:
        case WSAECONNABORTED:
        case WSAECONNRESET:
        case WSAESHUTDOWN:
        case WSAETIMEDOUT:
            errno = EPIPE;
            break;
    }
    return -1;
}

static inline int posix_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int rc = connect(sockfd, addr, addrlen);
    if (rc == SOCKET_ERROR)
        return wsa_errno(WSAGetLastError());
    return rc;
}

#define connect(sockfd, addr, addrlen) posix_connect(sockfd, addr, addrlen)
#define close(fd) posix_close(fd)
#define read(fd, buf, count) posix_read(fd, buf, count)
#define write(fd, buf, count) posix_write(fd, buf, count)

static inline int posix_close(int fd)
{
    if (closesocket(fd) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        return err == WSAENOTSOCK ?
                   close(fd) :
                   wsa_errno(err);
    }
    return 0;
}

static inline ssize_t posix_read(int fd, void *buf, size_t count)
{
    ssize_t rc = recv(fd, buf, count, 0);
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        return err == WSAENOTSOCK ?
                   read(fd, buf, count) :
                   wsa_errno(err);
    }
    return rc;
}

static inline ssize_t posix_write(int fd, const void *buf, size_t count)
{
    ssize_t rc = send(fd, buf, count, 0);
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        return err == WSAENOTSOCK ?
                   write(fd, buf, count) :
                   wsa_errno(err);
    }
    return rc;
}

static inline int posix_getsockopt(int sockfd, int level, int optname,
                                   void *optval, socklen_t *optlen)
{
    int rc = getsockopt(sockfd, level, optname, (char *)optval, optlen);
    return rc == 0 ? 0 : wsa_errno(WSAGetLastError());
}

#define getsockopt(sockfd, level, optname, optval, optlen) \
    posix_getsockopt(sockfd, level, optname, optval, optlen)

static inline int posix_setsockopt(int sockfd, int level, int optname,
                                   const void *optval, socklen_t optlen)
{
    int rc = setsockopt(sockfd, level, optname, (char *)optval, optlen);
    return rc == 0 ? 0 : wsa_errno(WSAGetLastError());
}

#define setsockopt(sockfd, level, optname, optval, optlen) \
    posix_setsockopt(sockfd, level, optname, optval, optlen)

#endif

#endif
