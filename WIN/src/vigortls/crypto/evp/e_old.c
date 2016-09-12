/*
 * Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_DEPRECATED

#include <openssl/evp.h>

/* Define some deprecated functions, so older programs
   don't crash and burn too quickly.  On Windows and VMS,
   these will never be used, since functions and variables
   in shared libraries are selected by entry point location,
   not by name.  */

#ifndef OPENSSL_NO_IDEA
#undef EVP_idea_cfb
const EVP_CIPHER *EVP_idea_cfb(void);
const EVP_CIPHER *EVP_idea_cfb(void)
{
    return EVP_idea_cfb64();
}
#endif

#ifndef OPENSSL_NO_RC2
#undef EVP_rc2_cfb
const EVP_CIPHER *EVP_rc2_cfb(void);
const EVP_CIPHER *EVP_rc2_cfb(void)
{
    return EVP_rc2_cfb64();
}
#endif

#ifndef OPENSSL_NO_RC5
#undef EVP_rc5_32_12_16_cfb
const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void);
const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void)
{
    return EVP_rc5_32_12_16_cfb64();
}
#endif

#undef EVP_aes_128_cfb
const EVP_CIPHER *EVP_aes_128_cfb(void);
const EVP_CIPHER *EVP_aes_128_cfb(void)
{
    return EVP_aes_128_cfb128();
}
#undef EVP_aes_192_cfb
const EVP_CIPHER *EVP_aes_192_cfb(void);
const EVP_CIPHER *EVP_aes_192_cfb(void)
{
    return EVP_aes_192_cfb128();
}
#undef EVP_aes_256_cfb
const EVP_CIPHER *EVP_aes_256_cfb(void);
const EVP_CIPHER *EVP_aes_256_cfb(void)
{
    return EVP_aes_256_cfb128();
}

#endif
