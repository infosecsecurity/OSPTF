/*
 * Copyright (c) 2014 - 2015, Kurt Cancemi (kurt@x64architecture.com)
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
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <errno.h>
#include <limits.h>
#include <stdcompat.h>
#include <stdlib.h>

#define INVALID 1
#define OVERFLOW 2
#define UNDERFLOW 3

long long strtonum(const char *nptr, long long minval, long long maxval, const char **stnerr)
{
    long long sl = 0;
    int error = 0;
    char *ex;
    struct errval {
        const char *errstr;
        int err;
    } ev[4] = {
          { NULL, 0 },
          { "invalid", EINVAL },
          { "too large", ERANGE },
          { "too small", ERANGE },
    };

    errno = 0;
    ev[0].err = errno;
    if (minval > maxval) {
        error = INVALID;
    } else {
        sl = strtoll(nptr, &ex, 10);
        if (*ex != '\0') {
            error = INVALID;
        } else if ((sl == LLONG_MAX && errno == ERANGE) || sl > maxval) {
            error = OVERFLOW;
        } else if ((sl == LLONG_MIN && errno == ERANGE) || sl < minval) {
            error = UNDERFLOW;
        }
    }
    if (stnerr != NULL)
        *stnerr = ev[error].errstr;
    errno = ev[error].err;
    if (error)
        return (0);

    return (sl);
}
