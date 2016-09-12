/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#ifndef HEADER_CRYPTO_H
#define HEADER_CRYPTO_H

#include <stdlib.h>
#include <stdio.h>

#include <openssl/base.h>
#include <openssl/opensslv.h>
#include <openssl/safestack.h>
#include <openssl/stack.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backward compatibility to SSLeay */
/* This is more to be used to check the correct DLL is being used
 * in the MS world. */
#define SSLEAY_VERSION_NUMBER   OPENSSL_VERSION_NUMBER
#define SSLEAY_VERSION          0
#define SSLEAY_CFLAGS           2
#define SSLEAY_BUILT_ON         3
#define SSLEAY_PLATFORM         4
#define SSLEAY_DIR              5

/* A generic structure to pass assorted data in a expandable way */
typedef struct openssl_item_st {
    int code;
    void *value;          /* Not used for flag attributes */
    size_t value_size;    /* Max size of value for output, length for input */
    size_t *value_length; /* Returned length of value for output */
} OPENSSL_ITEM;

/*
 * Old type for allocating dynamic locks. No longer used. Use the new thread
 * API instead.
 */
typedef struct {
    int dummy;
} CRYPTO_dynlock;

/* The following can be used to detect memory leaks in the SSLeay library.
 * It used, it turns on malloc checking */

#define CRYPTO_MEM_CHECK_OFF        0x0 /* an enume */
#define CRYPTO_MEM_CHECK_ON         0x1 /* a bit */
#define CRYPTO_MEM_CHECK_ENABLE     0x2 /* a bit */
#define CRYPTO_MEM_CHECK_DISABLE    0x3 /* an enum */

/* The following are bit values to turn on or off options connected to the
 * malloc checking functionality */

/* Adds time to the memory checking information */
#define V_CRYPTO_MDEBUG_TIME    0x1 /* a bit */
/* Adds thread number to the memory checking information */
#define V_CRYPTO_MDEBUG_THREAD  0x2 /* a bit */

#define V_CRYPTO_MDEBUG_ALL     (V_CRYPTO_MDEBUG_TIME | V_CRYPTO_MDEBUG_THREAD)

/* predec of the BIO type */
typedef struct bio_st BIO_dummy;

struct crypto_ex_data_st {
    STACK_OF(void) *sk;
};
DECLARE_STACK_OF(void)

/* Per class, we have a STACK of CRYPTO_EX_DATA_FUNCS for each CRYPTO_EX_DATA
 * entry.
 */

#define CRYPTO_EX_INDEX_BIO             0
#define CRYPTO_EX_INDEX_SSL             1
#define CRYPTO_EX_INDEX_SSL_CTX         2
#define CRYPTO_EX_INDEX_SSL_SESSION     3
#define CRYPTO_EX_INDEX_X509_STORE      4
#define CRYPTO_EX_INDEX_X509_STORE_CTX  5
#define CRYPTO_EX_INDEX_RSA             6
#define CRYPTO_EX_INDEX_DSA             7
#define CRYPTO_EX_INDEX_DH              8
#define CRYPTO_EX_INDEX_ENGINE          9
#define CRYPTO_EX_INDEX_X509            10
#define CRYPTO_EX_INDEX_UI              11
#define CRYPTO_EX_INDEX_ECDSA           12
#define CRYPTO_EX_INDEX_ECDH            13
#define CRYPTO_EX_INDEX_COMP            14
#define CRYPTO_EX_INDEX_STORE           15
#define CRYPTO_EX_INDEX_APP             16
#define CRYPTO_EX_INDEX__COUNT          17

/* This is the default callbacks, but we can have others as well:
 * this is needed in Win32 where the application malloc and the
 * library malloc may not be the same.
 */
#define CRYPTO_malloc_init() CRYPTO_set_mem_functions(malloc, realloc, free)

#if defined CRYPTO_MDEBUG_ALL || defined CRYPTO_MDEBUG_TIME || \
    defined CRYPTO_MDEBUG_THREAD
#ifndef CRYPTO_MDEBUG /* avoid duplicate #define */
#define CRYPTO_MDEBUG
#endif
#endif

/* Set standard debugging functions (not done by default
 * unless CRYPTO_MDEBUG is defined) */
#define CRYPTO_malloc_debug_init()                                  \
    do {                                                            \
        CRYPTO_set_mem_debug_functions(                             \
            CRYPTO_dbg_malloc, CRYPTO_dbg_realloc, CRYPTO_dbg_free, \
            CRYPTO_dbg_set_options, CRYPTO_dbg_get_options);        \
    } while (0)

VIGORTLS_EXPORT int CRYPTO_mem_ctrl(int mode);
VIGORTLS_EXPORT int CRYPTO_is_mem_check_on(void);

/* for applications */
#define MemCheck_start() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON)
#define MemCheck_stop() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF)

/* for library-internal use */
#define MemCheck_on() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
#define MemCheck_off() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
#define is_MemCheck_on() CRYPTO_is_mem_check_on()

#define OPENSSL_malloc(num) CRYPTO_malloc((int)num, __FILE__, __LINE__)
#define OPENSSL_strdup(str) CRYPTO_strdup((str), __FILE__, __LINE__)
#define OPENSSL_realloc(addr, num) \
    CRYPTO_realloc((char *)addr, (int)num, __FILE__, __LINE__)
#define OPENSSL_realloc_clean(addr, old_num, num) \
    CRYPTO_realloc_clean(addr, old_num, num, __FILE__, __LINE__)
#define OPENSSL_remalloc(addr, num) \
    CRYPTO_remalloc((char **)addr, (int)num, __FILE__, __LINE__)
#define OPENSSL_freeFunc CRYPTO_free
#define OPENSSL_free(addr) CRYPTO_free(addr)

#define OPENSSL_malloc_locked(num) \
    CRYPTO_malloc_locked((int)num, __FILE__, __LINE__)
#define OPENSSL_free_locked(addr) CRYPTO_free_locked(addr)

VIGORTLS_EXPORT const char *SSLeay_version(int type);
VIGORTLS_EXPORT unsigned long SSLeay(void);

VIGORTLS_EXPORT int OPENSSL_issetugid(void);

/* Within a given class, get/register a new index */
VIGORTLS_EXPORT int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func);
/* Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a given
 * class (invokes whatever per-class callbacks are applicable) */
VIGORTLS_EXPORT int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
VIGORTLS_EXPORT int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
                       CRYPTO_EX_DATA *from);
VIGORTLS_EXPORT void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
/* Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular index
 * (relative to the class type involved) */
VIGORTLS_EXPORT int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
VIGORTLS_EXPORT void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx);
/* This function cleans up all "ex_data" state. It mustn't be called under
 * potential race-conditions. */
VIGORTLS_EXPORT void CRYPTO_cleanup_all_ex_data(void);

/*
 * These are the functions for the old threading API. These are all now no-ops
 * and should not be used.
 */
#define CRYPTO_get_new_lockid(name) (0)
#define CRYPTO_num_locks() (0)
/*
 * The old CRYPTO_lock() function has been removed completely without a
 * compatibility macro. This is because previously it could not return an error
 * response, but if any applications are using this they will not work and could
 * fail in strange ways. Better for them to fail at compile time.
 *
 * void CRYPTO_lock(int mode, int type, const char *file, int line);
 */
#define CRYPTO_set_locking_callback(func)
#define CRYPTO_get_locking_callback() (NULL)
#define CRYPTO_set_add_lock_callback(func)
#define CRYPTO_get_add_lock_callback() (NULL)

/* This structure is no longer used */
typedef struct crypto_threadid_st {
    int dummy;
} CRYPTO_THREADID;
#define CRYPTO_THREADID_set_numeric(id, val)
#define CRYPTO_THREADID_set_pointer(id, ptr)
#define CRYPTO_THREADID_set_callback(threadid_func) (0)
#define CRYPTO_THREADID_get_callback() (NULL)
#define CRYPTO_THREADID_current(id)
#define CRYPTO_THREADID_cmp(a, b) (-1)
#define CRYPTO_THREADID_cpy(dest, src)
#define CRYPTO_THREADID_hash(id) (0UL)

#define CRYPTO_set_id_callback(func)
#define CRYPTO_get_id_callback() (NULL)
#define CRYPTO_thread_id() (0UL)

#define CRYPTO_get_lock_name(type) (NULL)
#define CRYPTO_add_lock(pointer, amount, type, file, line) (0)

#define CRYPTO_get_new_dynlockid() (0)
#define CRYPTO_destroy_dynlockid(i)
#define CRYPTO_get_dynlock_value(i) (NULL)
#define CRYPTO_set_dynlock_create_callback(dyn_create_function)
#define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
#define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
#define CRYPTO_get_dynlock_create_callback() (NULL)
#define CRYPTO_get_dynlock_lock_callback() (NULL)
#define CRYPTO_get_dynlock_destroy_callback() (NULL)

/* CRYPTO_set_mem_functions includes CRYPTO_set_locked_mem_functions --
 * call the latter last if you need different functions */
VIGORTLS_EXPORT int CRYPTO_set_mem_functions(void *(*m)(size_t),
                                             void *(*r)(void *, size_t),
                                             void (*f)(void *));
VIGORTLS_EXPORT int CRYPTO_set_locked_mem_functions(void *(*m)(size_t),
                                                    void (*free_func)(void *));
VIGORTLS_EXPORT int
CRYPTO_set_mem_ex_functions(void *(*m)(size_t, const char *, int),
                            void *(*r)(void *, size_t, const char *, int),
                            void (*f)(void *));
VIGORTLS_EXPORT int
CRYPTO_set_locked_mem_ex_functions(void *(*m)(size_t, const char *, int),
                                   void (*free_func)(void *));
VIGORTLS_EXPORT int CRYPTO_set_mem_debug_functions(
    void (*m)(void *, int, const char *, int, int),
    void (*r)(void *, void *, int, const char *, int, int),
    void (*f)(void *, int), void (*so)(long), long (*go)(void));
VIGORTLS_EXPORT void CRYPTO_get_mem_functions(void *(**m)(size_t),
                                              void *(**r)(void *, size_t),
                                              void (**f)(void *));
VIGORTLS_EXPORT void CRYPTO_get_locked_mem_functions(void *(**m)(size_t),
                                                     void (**f)(void *));
VIGORTLS_EXPORT void
CRYPTO_get_mem_ex_functions(void *(**m)(size_t, const char *, int),
                            void *(**r)(void *, size_t, const char *, int),
                            void (**f)(void *));
VIGORTLS_EXPORT void
CRYPTO_get_locked_mem_ex_functions(void *(**m)(size_t, const char *, int),
                                   void (**f)(void *));
VIGORTLS_EXPORT void CRYPTO_get_mem_debug_functions(
    void (**m)(void *, int, const char *, int, int),
    void (**r)(void *, void *, int, const char *, int, int),
    void (**f)(void *, int), void (**so)(long), long (**go)(void));

#ifndef VIGORTLS_IMPLEMENTATION
VIGORTLS_EXPORT void *CRYPTO_malloc_locked(int num, const char *file, int line);
VIGORTLS_EXPORT void CRYPTO_free_locked(void *ptr);
VIGORTLS_EXPORT void *CRYPTO_malloc(int num, const char *file, int line);
VIGORTLS_EXPORT char *CRYPTO_strdup(const char *str, const char *file,
                                    int line);
VIGORTLS_EXPORT void CRYPTO_free(void *ptr);
VIGORTLS_EXPORT void *CRYPTO_realloc(void *addr, int num, const char *file,
                                     int line);
#endif
VIGORTLS_EXPORT void *CRYPTO_realloc_clean(void *addr, int old_num, int num,
                                           const char *file, int line);
VIGORTLS_EXPORT void *CRYPTO_remalloc(void *addr, int num, const char *file,
                                      int line);

VIGORTLS_EXPORT void vigortls_zeroize(void *ptr, size_t len);
VIGORTLS_EXPORT void OPENSSL_cleanse(void *ptr, size_t len);

VIGORTLS_EXPORT void CRYPTO_set_mem_debug_options(long bits);
VIGORTLS_EXPORT long CRYPTO_get_mem_debug_options(void);

#define CRYPTO_push_info(info) CRYPTO_push_info_(info, __FILE__, __LINE__);
VIGORTLS_EXPORT int CRYPTO_push_info_(const char *info, const char *file,
                                      int line);
VIGORTLS_EXPORT int CRYPTO_pop_info(void);
VIGORTLS_EXPORT int CRYPTO_remove_all_info(void);

/* Default debugging functions (enabled by CRYPTO_malloc_debug_init() macro;
 * used as default in CRYPTO_MDEBUG compilations): */
/* The last argument has the following significance:
 *
 * 0:    called before the actual memory allocation has taken place
 * 1:    called after the actual memory allocation has taken place
 */
VIGORTLS_EXPORT void CRYPTO_dbg_malloc(void *addr, int num, const char *file,
                                       int line, int before_p);
VIGORTLS_EXPORT void CRYPTO_dbg_realloc(void *addr1, void *addr2, int num,
                                        const char *file, int line,
                                        int before_p);
VIGORTLS_EXPORT void CRYPTO_dbg_free(void *addr, int before_p);
/* Tell the debugging code about options.  By default, the following values
 * apply:
 *
 * 0:                           Clear all options.
 * V_CRYPTO_MDEBUG_TIME (1):    Set the "Show Time" option.
 * V_CRYPTO_MDEBUG_THREAD (2):  Set the "Show Thread Number" option.
 * V_CRYPTO_MDEBUG_ALL (3):     1 + 2
 */
VIGORTLS_EXPORT void CRYPTO_dbg_set_options(long bits);
VIGORTLS_EXPORT long CRYPTO_dbg_get_options(void);

VIGORTLS_EXPORT void CRYPTO_mem_leaks_fp(FILE *);
VIGORTLS_EXPORT void CRYPTO_mem_leaks(struct bio_st *bio);
/* unsigned long order, char *file, int line, int num_bytes, char *addr */
typedef void *CRYPTO_MEM_LEAK_CB(unsigned long, const char *, int, int, void *);
VIGORTLS_EXPORT void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb);

/* die if we have to */
VIGORTLS_EXPORT void OpenSSLDie(const char *file, int line,
                                const char *assertion);
#define OPENSSL_assert(e) \
    (void)((e) ? 0 : (OpenSSLDie(__FILE__, __LINE__, #e), 1))

/*
 * CRYPTO_memcmp returns zero if the |len| bytes at |in_a| and |in_b| are equal.
 * It takes an amount of time dependent on |len|, but independent of the
 * contents
 * of |in_a| and |in_b|. Unlike memcmp, it cannot be used to put elements into a
 * defined order as the return value when in_a != in_b is undefined, other than
 * to be non-zero.
 */
VIGORTLS_EXPORT int CRYPTO_memcmp(const volatile void *volatile in_a,
                                  const volatile void *volatile in_b,
                                  size_t len);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
VIGORTLS_EXPORT void ERR_load_CRYPTO_strings(void);

/* Error codes for the CRYPTO functions. */

/* Function codes. */
# define CRYPTO_F_CRYPTO_DUP_EX_DATA                      110
# define CRYPTO_F_CRYPTO_FREE_EX_DATA                     111
# define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX                 100
# define CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID                103
# define CRYPTO_F_CRYPTO_GET_NEW_LOCKID                   101
# define CRYPTO_F_CRYPTO_NEW_EX_DATA                      112
# define CRYPTO_F_CRYPTO_SET_EX_DATA                      102
# define CRYPTO_F_DEF_ADD_INDEX                           104
# define CRYPTO_F_DEF_GET_CLASS                           105
# define CRYPTO_F_INT_DUP_EX_DATA                         106
# define CRYPTO_F_INT_FREE_EX_DATA                        107
# define CRYPTO_F_INT_NEW_EX_DATA                         108

/* Reason codes. */
# define CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK              100

#ifdef  __cplusplus
}
#endif
#endif
