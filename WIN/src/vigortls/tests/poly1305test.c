#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/poly1305.h>

struct poly1305_test {
    const char *inputhex;
    const char *keyhex;
    const char *outhex;
};

static const struct poly1305_test poly1305_tests[] = {
    /*
     * RFC7539
     */
    {
      "43727970746f6772617068696320466f72756d2052657365617263682047726f"
      "7570",
      "85d6be7857556d337f4452fe42d506a8"
      "0103808afb0db2fd4abff6af4149f51b",
      "a8061dc1305136c6c22b8baf0c0127a9"
    },
    /*
     * test vectors from "The Poly1305-AES message-authentication code"
     */
    {
      "f3f6",
      "851fc40c3467ac0be05cc20404f3f700"
      "580b3b0f9447bb1e69d095b5928b6dbc",
      "f4c633c3044fc145f84f335cb81953de" },
    {
      "",
      "a0f3080000f46400d0c7e9076c834403"
      "dd3fab2251f11ac759f0887129cc2ee7",
      "dd3fab2251f11ac759f0887129cc2ee7"
    },
    {
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
      "48443d0bb0d21109c89a100b5ce2c208"
      "83149c69b561dd88298a1798b10716ef",
      "0ee1c16bb73f0f4fd19881753c01cdbe"
    },
    { "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "5154ad0d2cb26e01274fc51148491f1b"
    },
    /*
     * self-generated
     */
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "812059a5da198637cac7c4a631bee466"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "5b88d7f6228b11e2e28579a5c0c1f761"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "bbb613b2b6d753ba07395b916aaece15"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "c794d7057d1778c4bbee0a39b3d97342"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "ffbcb9b371423152d7fca5ad042fbaa9"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
      "812059a5da198637cac7c4a631bee466",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "069ed6b8ef0f207b3e243bb1019fe632"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
      "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "cca339d9a45fa2368c2c68b3a4179133"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
      "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761"
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "53f6e828a2f0fe0ee815bf0bd5841a34"
    },
    {
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
      "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761"
      "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
      "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
      "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
      "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
      "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761",
      "12976a08c4426d0ce8a82407c4f48207"
      "80f8c20aa71202d1e29179cbcb555a57",
      "b846d44e9bbd53cedffbfbb6b7fa4933"
    },
    { /*
       * poly1305_ieee754.c failed this in final stage
       */
      "842364e156336c0998b933a6237726180d9e3fdcbde4cd5d17080fc3beb49614"
      "d7122c037463ff104d73f19c12704628d417c4c54a3fe30d3c3d7714382d43b0"
      "382a50a5dee54be844b076e8df88201a1cd43b90eb21643fa96f39b518aa8340"
      "c942ff3c31baf7c9bdbf0f31ae3fa096bf8c63030609829fe72e179824890bc8"
      "e08c315c1cce2a83144dbbff09f74e3efc770b54d0984a8f19b14719e6363564"
      "1d6b1eedf63efbf080e1783d32445412114c20de0b837a0dfa33d6b82825fff4"
      "4c9a70ea54ce47f07df698e6b03323b53079364a5fc3e9dd034392bdde86dccd"
      "da94321c5e44060489336cb65bf3989c36f7282c2f5d2b882c171e74",
      "95d5c005503e510d8cd0aa072c4a4d06"
      "6eabc52d11653df47fbf63ab198bcc26",
      "f248312e578d9d58f8b7bb4d19105431"
    },
    /*
     * AVX2 in poly1305-x86.pl failed this with 176+32 split
     */
    {
      "248ac31085b6c2adaaa38259a0d7192c5c35d1bb4ef39ad94c38d1c82479e2dd"
      "2159a077024b0589bc8a20101b506f0a1ad0bbab76e83a83f1b94be6beae74e8"
      "74cab692c5963a75436b776121ec9f62399a3e66b2d22707dae81933b6277f3c"
      "8516bcbe26dbbd86f373103d7cf4cad1888c952118fbfbd0d7b4bedc4ae4936a"
      "ff91157e7aa47c54442ea78d6ac251d324a0fbe49d89cc3521b66d16e9c66a37"
      "09894e4eb0a4eedc4ae19468e66b81f2"
      "71351b1d921ea551047abcc6b87a901fde7db79fa1818c11336dbc07244a40eb",
      "000102030405060708090a0b0c0d0e0f""00000000000000000000000000000000",
      "bc939bc5281480fa99c6d68c258ec42f"
    },
    /*
     * test vectors from Google
     */
    {
        "",
        "c8afaac331ee372cd6082de134943b17"
        "4710130e9f6fea8d72293850a667d86c",
        "4710130e9f6fea8d72293850a667d86c",
    },
    {
      "48656c6c6f20776f726c6421",
      "746869732069732033322d6279746520"
      "6b657920666f7220506f6c7931333035",
      "a6f745008f81c916a20dcc74eef2b2f0"
    },
    { "0000000000000000000000000000000000000000000000000000000000000000",
      "746869732069732033322d6279746520"
      "6b657920666f7220506f6c7931333035",
      "49ec78090e481ec6c26b33b91ccc0307"
    },
    {
     "89dab80b7717c1db5db437860a3f70218e93e1b8f461fb677f16f35f6f87e2a9"
     "1c99bc3a47ace47640cc95c345be5ecca5a3523c35cc01893af0b64a62033427"
     "0372ec12482d1b1e363561698a578b359803495bb4e2ef1930b17a5190b580f1"
     "41300df30adbeca28f6427a8bc1a999fd51c554a017d095d8c3e3127daf9f595",
     "2d773be37adb1e4d683bf0075e79c4ee""037918535a7f99ccb7040fb5f5f43aea",
     "c85d15ed44c378d6b00e23064c7bcd51"
    },
    {
     "000000000000000b1703030200000000"
     "06db1f1f368d696a810a349c0c714c9a5e7850c2407d721acded95e018d7a852"
     "66a6e1289cdb4aeb18da5ac8a2b0026d24a59ad485227f3eaedbb2e7e35e1c66"
     "cd60f9abf716dcc9ac42682dd7dab287a7024c4eefc321cc0574e16793e37cec"
     "03c5bda42b54c114a80b57af26416c7be742005e20855c73e21dc8e2edc9d435"
     "cb6f6059280011c270b71570051c1c9b3052126620bc1e2730fa066c7a509d53"
     "c60e5ae1b40aa6e39e49669228c90eecb4a50db32a50bc49e90b4f4b359a1dfd"
     "11749cd3867fcf2fb7bb6cd4738f6a4ad6f7ca5058f7618845af9f020f6c3b96"
     "7b8f4cd4a91e2813b507ae66f2d35c18284f7292186062e10fd5510d18775351"
     "ef334e7634ab4743f5b68f49adcab384d3fd75f7390f4006ef2a295c8c7a076a"
     "d54546cd25d2107fbe1436c840924aaebe5b370893cd63d1325b8616fc481088"
     "6bc152c53221b6df373119393255ee72bcaa880174f1717f9184fa91646f17a2"
     "4ac55d16bfddca9581a92eda479201f0edbf633600d6066d1ab36d5d2415d713"
     "51bbcd608a25108d25641992c1f26c531cf9f90203bc4cc19f5927d834b0a471"
     "16d3884bbb164b8ec883d1ac832e56b3918a98601a08d171881541d594db399c"
     "6ae6151221745aec814c45b0b05b565436fd6f137aa10a0c0b643761dbd6f9a9"
     "dcb99b1a6e690854ce0769cde39761d82fcdec15f0d92d7d8e94ade8eb83fbe0",
     "99e5822dd4173c995e3dae0ddefb9774""3fde3b080134b39f76e9bf8d0e88d546",
     "2637408fe13086ea73f971e3425e2820"
    },
    /*
     * test vectors from Andrew Moon
     */
    { /* nacl */
      "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
      "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
      "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
      "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
      "e355a5",
      "eea6a7251c1e72916d11c2cb214d3c25"
      "2539121d8e234e652d651fa4c8cff880",
      "f3ffc7703f9400e52a7dfb4b3d3305d9"
    },
    { /* wrap 2^130-5 */
      "ffffffffffffffffffffffffffffffff",
      "02000000000000000000000000000000"
      "00000000000000000000000000000000",
      "03000000000000000000000000000000"
    },
    { /* wrap 2^128 */
      "02000000000000000000000000000000",
      "02000000000000000000000000000000"
      "ffffffffffffffffffffffffffffffff",
      "03000000000000000000000000000000"
    },
    { /* limb carry */
      "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff"
      "11000000000000000000000000000000",
      "01000000000000000000000000000000"
      "00000000000000000000000000000000",
      "05000000000000000000000000000000"
    },
    { /* 2^130-5 */
      "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe"
      "01010101010101010101010101010101",
      "01000000000000000000000000000000"
      "00000000000000000000000000000000",
      "00000000000000000000000000000000"
    },
    { /* 2^130-6 */
      "fdffffffffffffffffffffffffffffff",
      "02000000000000000000000000000000"
      "00000000000000000000000000000000",
      "faffffffffffffffffffffffffffffff"
    },
    { /* 5*H+L reduction intermediate */
      "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
      "0000000000000000000000000000000001000000000000000000000000000000",
      "01000000000000000400000000000000"
      "00000000000000000000000000000000",
      "14000000000000005500000000000000"
    },
    { /* 5*H+L reduction final */
      "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
      "00000000000000000000000000000000",
      "01000000000000000400000000000000"
      "00000000000000000000000000000000",
      "13000000000000000000000000000000"
    },
};

static uint8_t hex_digit(char h)
{
    if (h >= '0' && h <= '9')
        return h - '0';
    else if (h >= 'a' && h <= 'f')
        return h - 'a' + 10;
    else if (h >= 'A' && h <= 'F')
        return h - 'A' + 10;
    else
        abort();
}

static void hex_decode(uint8_t *out, const char *hex)
{
    size_t j = 0;

    while (*hex != 0) {
        uint8_t v = hex_digit(*hex++);
        v <<= 4;
        v |= hex_digit(*hex++);
        out[j++] = v;
    }
}

static void hexdump(uint8_t *a, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", a[i]);
}

int main(void)
{
    static const unsigned num_tests =
        sizeof(poly1305_tests) / sizeof(struct poly1305_test);
    unsigned i;
    uint8_t key[32], out[16], expected[16];
    poly1305_state poly1305;

    for (i = 0; i < num_tests; i++) {
        const struct poly1305_test *test = &poly1305_tests[i];
        uint8_t *in;
        size_t inlen = strlen(test->inputhex);

        if (strlen(test->keyhex) != sizeof(key) * 2 ||
            strlen(test->outhex) != sizeof(out) * 2 || (inlen & 1) == 1)
            return 1;

        inlen /= 2;

        hex_decode(key, test->keyhex);
        hex_decode(expected, test->outhex);

        in = malloc(inlen);

        hex_decode(in, test->inputhex);

        CRYPTO_poly1305_init(&poly1305, key);
        CRYPTO_poly1305_update(&poly1305, in, inlen);
        CRYPTO_poly1305_finish(&poly1305, out);

        if (memcmp(out, expected, sizeof(expected)) != 0) {
            printf("Poly1305 test #%d failed.\n", i);
            printf("got:      ");
            hexdump(out, sizeof(out));
            printf("\nexpected: ");
            hexdump(expected, sizeof(expected));
            printf("\n");
            return 1;
        }

        if (inlen > 16) {
            CRYPTO_poly1305_init(&poly1305, key);
            CRYPTO_poly1305_update(&poly1305, in, 1);
            CRYPTO_poly1305_update(&poly1305, in + 1, inlen - 1);
            CRYPTO_poly1305_finish(&poly1305, out);

            if (memcmp(out, expected, sizeof(expected)) != 0) {
                printf("Poly1305 test #%d/1+(N-1) failed.\n", i);
                printf("got:      ");
                hexdump(out, sizeof(out));
                printf("\nexpected: ");
                hexdump(expected, sizeof(expected));
                printf("\n");
                return 1;
            }
        }

        if (inlen > 32) {
            size_t half = inlen / 2;

            CRYPTO_poly1305_init(&poly1305, key);
            CRYPTO_poly1305_update(&poly1305, in, half);
            CRYPTO_poly1305_update(&poly1305, in + half, inlen - half);
            CRYPTO_poly1305_finish(&poly1305, out);

            if (memcmp(out, expected, sizeof(expected)) != 0) {
                printf("Poly1305 test #%d/2 failed.\n", i);
                printf("got:      ");
                hexdump(out, sizeof(out));
                printf("\nexpected: ");
                hexdump(expected, sizeof(expected));
                printf("\n");
                return 1;
            }

            for (half = 16; half < inlen; half += 16) {
                CRYPTO_poly1305_init(&poly1305, key);
                CRYPTO_poly1305_update(&poly1305, in, half);
                CRYPTO_poly1305_update(&poly1305, in+half, inlen-half);
                CRYPTO_poly1305_finish(&poly1305, out);

                if (memcmp(out, expected, sizeof(expected)) != 0) {
                    printf("Poly1305 test #%d/%zu+%zu failed.\n", i, half,
                        inlen - half);
                    printf("got:      ");
                    hexdump(out, sizeof(out));
                    printf("\nexpected: ");
                    hexdump(expected, sizeof(expected));
                    printf("\n");
                    return 1;
                }
            }
        }

        free(in);
    }

    printf("PASS\n");
    return 0;
}
