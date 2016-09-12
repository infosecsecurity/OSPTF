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

#ifndef HEADER_BASE_H
#define HEADER_BASE_H

#include <openssl/opensslconf.h>
#include <openssl/ossl_typ.h>
#include <openssl/threads.h>

#if defined(_WIN32)
#define VIGORTLS_WINDOWS
#endif

#if defined(VIGORTLS_SHARED_LIBRARY)
 #if defined(VIGORTLS_WINDOWS)
  #if defined(VIGORTLS_IMPLEMENTATION)
   #define VIGORTLS_EXPORT __declspec(dllexport)
  #else
   #define VIGORTLS_EXPORT __declspec(dllimport)
  #endif
 #else  /* defined(VIGORTLS_WINDOWS) */
  #if defined(VIGORTLS_IMPLEMENTATION)
   #define VIGORTLS_EXPORT __attribute__((visibility("default")))
  #else
   #define VIGORTLS_EXPORT
  #endif
 #endif  /* defined(VIGORTLS_WINDOWS) */
#else  /* defined(VIGORTLS_SHARED_LIBRARY) */
 #define VIGORTLS_EXPORT
#endif  /* defined(VIGORTLS_SHARED_LIBRARY) */

#endif /* !HEADER_BASE_H */
