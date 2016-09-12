/*
 * Copyright (C) 2016, Kurt Cancemi
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

#include <fcntl.h>
#include <unistd.h>

#include <openssl/bio.h>

int BIO_sock_init(void)
{
    return 1;
}

void BIO_sock_cleanup(void)
{
    return;
}

int BIO_socket_nbio(int s, int mode)
{
    int flags = fcntl(s, F_GETFD);
    if (mode && !(flags & O_NONBLOCK))
        return (fcntl(s, F_SETFL, flags | O_NONBLOCK) != -1);
    else if (!mode && (flags & O_NONBLOCK))
        return (fcntl(s, F_SETFL, flags & ~O_NONBLOCK) != -1);
    return 1;
}
