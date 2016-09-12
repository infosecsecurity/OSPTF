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
 * Based off of previous work by:
 * Dongsheng Song <dongsheng.song@gmail.com> and Brent Cook <bcook@openbsd.org>
 */

#if defined(_WIN32)

#include <ws2tcpip.h>

#include <openssl/bio.h>
#include <openssl/err.h>

static int wsa_init_done = 0;

int BIO_sock_init(void)
{
    /*
    * WSAStartup loads the winsock .dll and initializes the networking
    * stack on Windows, or simply increases the reference count.
    */
    static struct WSAData wsa_state = { 0 };
    WORD version_requested = MAKEWORD(2, 2);
    if (!wsa_init_done) {
        if (WSAStartup(version_requested, &wsa_state) != 0) {
            int err = WSAGetLastError();
            SYSerr(SYS_F_WSASTARTUP, err);
            BIOerr(BIO_F_BIO_SOCK_INIT, BIO_R_WSASTARTUP);
            return (-1);
        }
        wsa_init_done = 1;
    }
    return (1);
}

void BIO_sock_cleanup(void)
{
    if (wsa_init_done) {
        wsa_init_done = 0;
        WSACleanup();
    }
}

int BIO_socket_nbio(int s, int mode)
{
    u_long value = mode;
    return ioctlsocket(s, FIONBIO, &value) != SOCKET_ERROR;
}

#endif
