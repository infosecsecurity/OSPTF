/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#define CLIENT_VERSION_LEN 2
#define SESSION_ID_LEN_LEN 1
#define CIPHERS_LEN_LEN 2
#define COMPRESSION_LEN_LEN 1
#define EXTENSIONS_LEN_LEN 2
#define EXTENSION_TYPE_LEN 2
#define EXTENSION_SIZE_LEN 2

#define TOTAL_NUM_TESTS 2

/*
 * Test that explicitly setting ticket data results in it appearing in the
 * ClientHello for TLS1.2
 */
#define TEST_SET_SESSION_TICK_DATA_TLS_1_2 0

/*
 * Test that explicitly setting ticket data results in it appearing in the
 * ClientHello for a negotiated SSL/TLS version
 */
#define TEST_SET_SESSION_TICK_DATA_VER_NEG 1

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    SSL *con;
    BIO *rbio;
    BIO *wbio;
    long len;
    uint8_t *data;
    uint8_t *dataend;
    char *dummytick = "Hello World!";
    unsigned int tmplen;
    unsigned int type;
    unsigned int size;
    int testresult = 0;
    int currtest = 0;

    SSL_library_init();
    SSL_load_error_strings();

    /*
     * For each test set up an SSL_CTX and SSL and see what ClientHello gets
     * produced when we try to connect
     */
    for (; currtest < TOTAL_NUM_TESTS; currtest++) {
        testresult = 0;
        if (currtest == TEST_SET_SESSION_TICK_DATA_TLS_1_2) {
            ctx = SSL_CTX_new(TLSv1_2_method());
        }
        else {
            ctx = SSL_CTX_new(SSLv23_method());
        }
        con = SSL_new(ctx);

        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        SSL_set_bio(con, rbio, wbio);
        SSL_set_connect_state(con);

        if (currtest == TEST_SET_SESSION_TICK_DATA_TLS_1_2 ||
            currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
            if (!SSL_set_session_ticket_ext(con, dummytick, strlen(dummytick)))
                goto end;
        }

        if (SSL_connect(con) > 0) {
            /* This shouldn't succeed because we don't have a server! */
            goto end;
        }

        len = BIO_get_mem_data(wbio, (char **)&data);
        dataend = data + len;

        /* Skip the record header */
        data += SSL3_RT_HEADER_LENGTH;
        /* Skip the handshake message header */
        data += SSL3_HM_HEADER_LENGTH;
        /* Skip client version and random */
        data += CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE;
        if (data + SESSION_ID_LEN_LEN > dataend)
            goto end;
        /* Skip session id */
        tmplen = *data;
        data += SESSION_ID_LEN_LEN + tmplen;
        if (data + CIPHERS_LEN_LEN > dataend)
            goto end;
        /* Skip ciphers */
        tmplen = ((*data) << 8) | *(data + 1);
        data += CIPHERS_LEN_LEN + tmplen;
        if (data + COMPRESSION_LEN_LEN > dataend)
            goto end;
        /* Skip compression */
        tmplen = *data;
        data += COMPRESSION_LEN_LEN + tmplen;
        if (data + EXTENSIONS_LEN_LEN > dataend)
            goto end;
        /* Extensions len */
        tmplen = ((*data) << 8) | *(data + 1);
        data += EXTENSIONS_LEN_LEN;
        if (data + tmplen > dataend)
            goto end;

        /* Loop through all extensions */
        while (tmplen > EXTENSION_TYPE_LEN + EXTENSION_SIZE_LEN) {
            type = ((*data) << 8) | *(data + 1);
            data += EXTENSION_TYPE_LEN;
            size = ((*data) << 8) | *(data + 1);
            data += EXTENSION_SIZE_LEN;
            if (data + size > dataend)
                goto end;

            if (type == TLSEXT_TYPE_session_ticket) {
                if (currtest == TEST_SET_SESSION_TICK_DATA_TLS_1_2 ||
                    currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
                    if (size == strlen(dummytick) &&
                        memcmp(data, dummytick, size) == 0) {
                        /* Ticket data is as we expected */
                        testresult = 1;
                    } else {
                        printf("Received session ticket is not as expected\n");
                    }
                    break;
                }
            }

            tmplen -= EXTENSION_TYPE_LEN + EXTENSION_SIZE_LEN + size;
            data += size;
        }

    end:
        SSL_free(con);
        SSL_CTX_free(ctx);
        if (!testresult) {
            printf("ClientHello test: FAILED (Test %d)\n", currtest);
            break;
        }
    }

    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    return testresult ? 0 : 1;
}
