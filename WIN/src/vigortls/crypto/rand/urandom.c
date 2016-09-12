/*
 * Copyright (c) 2016, Kurt Cancemi (kurt@x64architecture.com)
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#if defined(__linux)
#include <linux/random.h>
#include <sys/syscall.h>
#endif

#ifdef SYS_getrandom
static int rand_getrandom(uint8_t *out, size_t requested)
{
    int rv;
    unsigned int flags = 0;

    do {
        rv = syscall(SYS_getrandom, (void *)out, requested, flags);
    } while (rv == -1 && (errno == EAGAIN || errno == EINTR));

    if ((size_t)rv != requested)
        return 0;

    return 1;
}
#endif

static int rand_urandom(uint8_t *out, size_t requested)
{
    int fd;
    int flags;
    ssize_t r;

start:
    flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif

    fd = open("/dev/urandom", flags);
    if (fd == -1) {
        if (errno == EINTR)
            goto start;
        return 0;
    }
#if !defined(O_CLOEXEC) && defined(__linux)
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

    while (requested > 0) {
        do {
            r = read(fd, out, requested);
        } while (r == -1 && (errno == EAGAIN || errno == EINTR));

        if (r <= 0) {
            close(fd);
            return 0;
        }

        out += r;
        requested -= r;
    }

    close(fd);
    return 1;
}

int CRYPTO_genrandom(uint8_t *out, size_t requested)
{
    int rv;

#ifdef SYS_getrandom
    rv = rand_getrandom(out, requested);
    if (rv != 0)
        return 1;
    if (errno != ENOSYS) {
        abort();
        return 0;
    }
#endif

    rv = rand_urandom(out, requested);
    if (!rv) {
        abort();
        return 0;
    }

    return 1;
}

void RAND_cleanup(void)
{
    return;
}
