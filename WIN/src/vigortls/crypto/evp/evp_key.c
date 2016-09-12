/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/ui.h>
#include <stdcompat.h>

/* should be init to zeros. */
static char prompt_string[80];

void EVP_set_pw_prompt(const char *prompt)
{
    if (prompt == NULL)
        prompt_string[0] = '\0';
    else
        strlcpy(prompt_string, prompt, sizeof(prompt_string));
}

char *EVP_get_pw_prompt(void)
{
    if (prompt_string[0] == '\0')
        return (NULL);
    else
        return (prompt_string);
}

/* For historical reasons, the standard function for reading passwords is
 * in the DES library -- if someone ever wants to disable DES,
 * this function will fail */
int EVP_read_pw_string(char *buf, int len, const char *prompt, int verify)
{
    return EVP_read_pw_string_min(buf, 0, len, prompt, verify);
}

int EVP_read_pw_string_min(char *buf, int min, int len, const char *prompt, int verify)
{
    int ret;
    char buff[BUFSIZ];
    UI *ui;

    if ((prompt == NULL) && (prompt_string[0] != '\0'))
        prompt = prompt_string;
    ui = UI_new();
    if (ui == NULL)
        return -1;
    UI_add_input_string(ui, prompt, 0, buf, min, (len >= BUFSIZ) ? BUFSIZ - 1 : len);
    if (verify)
        UI_add_verify_string(ui, prompt, 0,
                             buff, min, (len >= BUFSIZ) ? BUFSIZ - 1 : len, buf);
    ret = UI_process(ui);
    UI_free(ui);
    vigortls_zeroize(buff, BUFSIZ);
    return ret;
}

int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                   const uint8_t *salt, const uint8_t *data, int datal,
                   int count, uint8_t *key, uint8_t *iv)
{
    EVP_MD_CTX c;
    uint8_t md_buf[EVP_MAX_MD_SIZE];
    int niv, nkey, addmd = 0;
    unsigned int mds = 0, i;
    int rv = 0;
    nkey = type->key_len;
    niv = type->iv_len;
    OPENSSL_assert(nkey <= EVP_MAX_KEY_LENGTH);
    OPENSSL_assert(niv <= EVP_MAX_IV_LENGTH);

    if (data == NULL)
        return (nkey);

    EVP_MD_CTX_init(&c);
    for (;;) {
        if (!EVP_DigestInit_ex(&c, md, NULL))
            goto err;
        if (addmd++)
            if (!EVP_DigestUpdate(&c, &(md_buf[0]), mds))
                goto err;
        if (!EVP_DigestUpdate(&c, data, datal))
            goto err;
        if (salt != NULL)
            if (!EVP_DigestUpdate(&c, salt, PKCS5_SALT_LEN))
                goto err;
        if (!EVP_DigestFinal_ex(&c, &(md_buf[0]), &mds))
            goto err;

        for (i = 1; i < (unsigned int)count; i++) {
            if (!EVP_DigestInit_ex(&c, md, NULL))
                goto err;
            if (!EVP_DigestUpdate(&c, &(md_buf[0]), mds))
                goto err;
            if (!EVP_DigestFinal_ex(&c, &(md_buf[0]), &mds))
                goto err;
        }
        i = 0;
        if (nkey) {
            for (;;) {
                if (nkey == 0)
                    break;
                if (i == mds)
                    break;
                if (key != NULL)
                    *(key++) = md_buf[i];
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds)) {
            for (;;) {
                if (niv == 0)
                    break;
                if (i == mds)
                    break;
                if (iv != NULL)
                    *(iv++) = md_buf[i];
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0))
            break;
    }
    rv = type->key_len;
err:
    EVP_MD_CTX_cleanup(&c);
    vigortls_zeroize(md_buf, sizeof md_buf);
    return rv;
}
