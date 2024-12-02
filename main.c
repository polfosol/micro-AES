/*
 ==============================================================================
 Name        : main.c
 Author      : polfosol
 Version     : 10
 Copyright   : copyright © 2022 - polfosol
 Description : test vectors for µAES ™ library, mostly generated by Crypto++ ®
 ==============================================================================
 */

#define  HEXSTR_LENGTH  114               /* plaintext hex characters */
#include "micro_aes.h"
#include <stdio.h>

static const char
    *plainText = "c9f775baafa36c25 cd610d3c75a482ea dda97ca4864cdfe0 6eaf70a0ec0d7191"
                 "d55027cf8f900214 e634412583ff0b47 8EA2B7CA516745BF EA",
    *iVec      = "8EA2B7CA516745BF EAfc49904b496089",
    *cipherKey = "279fb74a7572135e 8f9b8ef6d1eee003 69c4e0d86a7b0430 d8cdb78070b4c55a",
    *secretKey = "0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F",
    *secondKey = "0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F",
#if  AES___   == 256                      /* ↑↓ see p.34 of RFC-3394: */
    *k_wrapped = "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B"
                 "FB988B9B7A02DD21",      /* ↓ with GCM_NONCE_LEN=12  */
    *gcmcipher = "eb0f39c8cc86af34 3545fec3abc4d1fd 26241218546289ec 5ce5208e01873e90"
                 "e86772931b80d749 22565b38d35fe11a 387b347949dda087 9ca5f20fc9357760"
                 "4b2f659e3b1d1b0f 33",
    *xtscipher = "40bfcc14845b1bb4 15dd13abf1e6f89d 3bfd794cf6655ffd 14c0d7e4177eeaf4"
                 "5dd95f05663fcfb4 47671154a91b9d00 d1bd7a35c14c7410 9a";
#elif AES___  != 192                      /* ↓ AES-128 ↓ KeySize=16 ↓ */
    *ecbcipher = "5d00c273f8b2607d a834632dcbb521f4 697dd4ab20bb0645 32a6545e24e33ae9"
                 "f545176111f93773 dbecd262841cf83b 10d145e71b772cf7 a12889cda84be795",
    *xtscipher = "10f9301a157bfceb 3eb9e7bd38500b7e 959e21ba3cc1179a d7f7d7d99460e695"
                 "5e8bcb177571c719 6de58ff28c381913 e7c82d0adfd90c45 ca",
    *cbccipher = "65c48fdf9fbd6261 28f2d8bac3f71251 75e7f4821fda0263 70011632779d7403"
#if CTS
                 "c119ef461ac4e1bc 8a7e36bf92b3b3d1 7E9E2D298E154BC4 2D",
#else                                     /* ↓ zero-padded plaintext  */
                 "7E9E2D298E154BC4 2Dc7a9bc419b915d c119ef461ac4e1bc 8a7e36bf92b3b3d1",
#endif
    *cfbcipher = "edab3105e673bc9e b9102539a9f457bc 245c14e1bff81b5b 4a4a147c988cb0a6"
                 "3f9c56525efbe64a 876ad1d761d3fc93 59fb4f5b2354acd4 90",
    *ofbcipher = "edab3105e673bc9e b9102539a9f457bc d28c8e4c92995f5c d9426926be1e775d"
                 "e22b8ce4d0278b18 181b8bec93b9726f 959aa5d701d46102 f0",
#if CTR_IV_LENGTH == 16
    *ctrcipher = "edab3105e673bc9e b9102539a9f457bc f2e2606dfa3f93c5 c51b910a89cddb67"
                 "191a118531ea0427 97626c9bfd370426 fdf3f59158bf7d4d 43",
#else
    *ctrcipher = "6c6bae886c235d8c 7997d45c1bf0bca2 48b4bca9eb396d1b f6945e5b7a4fc10f"
                 "488cfe76fd5eaeff 2b8fb469f78fa61e 285e4cf9b9aee3d0 a8",
#endif                                    /* ↓ 16 bytes i.v PREPENDED */
    *sivcipher = "ff2537a371fba0bb ed11acf2a3631300 97964f088881bdbd f163e261afd158e6"
                 "09272e759213c76a edc83a451d094c9e 06e2600e50a27cbb c0d9fad10eb6d369"
                 "4614362e5cd68b90 a9",   /* ↓ all tag-sizes are 16 ↓ */
    *ccmcipher = "d2575123438338d7 0b2955537fdfcf41 729870884e85af15 f0a74975a72b337d"
                 "04d426de87594b9a be3e6dcf07f21c99 db3999f81299d302 ad1e5ba683e9039a"
                 "5483685f1bd2c3fa 3b",
    *gcmcipher = "5ceab5b7c2d6dede 555a23c7e3e63274 4075a51df482730b a31485ec987ddcc8"
                 "73acdcfc6759a47b a424d838e7c0cb71 b9a4d8f4572e2141 18c8ab284ca845c1"
                 "4394618703cddf3a fb",
    *gsvcipher = "2f1488496ada3f70 9760420ac72e5acf a977f6add4c55ac6 85f1b9dff8f381e0"
                 "2a64bbdd64cdd778 525462949bb0b141 db908c5cfa365750 3666f879ac879fcb"
                 "f25c15d496a1e6f7 f8",
    *ocbcipher = "fc254896eb785b05 dd87f240722dd935 61f5a0ef6aff2eb6 5953da0b26257ed0"
                 "d69cb496e9a0cb1b f646151aa07e629a 28d99f0ffd7ea753 5c39f440df33c988"
                 "c55cbcc8ac086ffa 23",
#if !EAXP
    *eaxcipher = "4e2fa1bef9ffc23f 6965ee7135981c91 af9bfe97a6b13c01 b8b99e114dda2391"
                 "50661c618335a005 47cca55a8f22fbd5 ed5ab4b4a17d0aa3 29febd14ef271bae"
                 "986810a504f01ec6 02",
#else                                     /* ↓ with 4 bytes mac added */
    *eaxcipher = "f516e9c20069292c c51ba8b6403ddedf 5a34798f62187f58 d723fa33573fd80b"
                 "f08ffbb09dadbd0b 6fa4812ca4bb5e6d db9a384943b36690 e81738a7a1",
#endif                                    /* ↓ a large Prime Number ↓ */
    *fpe_plain = "122333444455555666666777777788888888999999999012345682747",
#if  FF_X == 3                            /* ↓ if RADIX=10: MAXLEN=56 */
    *fpecipher = "0053317760589559020399280014720716878020198371161819152",
#else
    *fpecipher = "000260964766881620856103152534002821752468680082944565411",
#endif
    *ptxt_cmac = "b887df1fd8c239c3 e8a64d9822e21128",
    *poly_1305 = "3175bed9bd01821a 62d4c7bef26722be",
    *k_wrapped = "1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5";
#else                                     /* ↓ AES-192: enable PKCS#7 */
    *ecbcipher = "af1893f0fbb09a43 7f6b0fd4f4977890 7bb85cccf1e9d2e3 ebe5bae935107868"
                 "c6d72cb2ca375c12 ce6b6b1141141fd0 d268d14db351d680 5aabb99427341da9",
    *k_wrapped = "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2";
#endif

enum buffer_sizes
{
    PTSIZE = HEXSTR_LENGTH / 2,
    PADDED = PTSIZE + 15 & ~15,
    TAGGED = PTSIZE + 16
};

static void hex2bytes(const char* hex, uint8_t* bytes)
{
    unsigned shl = 0;
    for (--bytes; *hex; ++hex)
    {
        if (*hex < '0' || 'f' < *hex)  continue;
        if ((shl ^= 4) != 0)  *++bytes = 0;
        *bytes |= (*hex % 16 + (*hex > '9') * 9) << shl;
    }
}

static void check(const char* method, void* result, const void* expected, size_t size)
{
    int c = memcmp(expected, result, size);
    printf("AES-%d %s: %s\n", AES_KEY_SIZE * 8, method, c ? "FAILED :`(" : "PASSED!");
    memset(result, 0xcc, TAGGED);
}

int main(void)
{
    uint8_t iv[16], key[64], authKey[32], input[PADDED], test[TAGGED], output[TAGGED],
           *a = authKey + 1, sa = sizeof authKey - 1, sp = PTSIZE;
    hex2bytes(cipherKey, key);
    hex2bytes(secondKey, key + 32);
    hex2bytes(secretKey, authKey);
    hex2bytes(iVec, iv);
    hex2bytes(plainText, input);
#if MICRO_RJNDL
    hex2bytes(iVec, input + 48);
    hex2bytes(secondKey, test);
    a = AES_KEY_SIZE == 16 ? key : input + (AES___ - 192) / 2;

    AES_Cipher(test, 'E', authKey, output);
    AES_Cipher(authKey, 'E', test, output + 16);
    check("Encryption test", output, a, 32);
    AES_Cipher(test, 'D', a, output + 16);
    AES_Cipher(authKey, 'D', a + 16, output);
    check("Decryption test", output, test, 32);
    return 0;
#endif
    printf("%s %s Test results\n", __DATE__, __TIME__);

#if ECB && AES_KEY_SIZE - 8 * AES_PADDING == 16
    hex2bytes(ecbcipher, test);
    AES_ECB_encrypt(key, input, sp, output);
    check("ECB encryption", output, test, sizeof input);
    AES_ECB_decrypt(key, test, sizeof input, output);
    check("ECB decryption", output, input, sp);
#endif
#if CBC && AES_KEY_SIZE == 16
    hex2bytes(cbccipher, test);
    AES_CBC_encrypt(key, iv, input, sp, output);
    check("CBC encryption", output, test, CTS ? sp : sizeof input);
    AES_CBC_decrypt(key, iv, test, CTS ? sp : sizeof input, output);
    check("CBC decryption", output, input, sp);
#endif
#if CFB && AES_KEY_SIZE == 16
    hex2bytes(cfbcipher, test);
    AES_CFB_encrypt(key, iv, input, sp, output);
    check("CFB encryption", output, test, sp);
    AES_CFB_decrypt(key, iv, test, sp, output);
    check("CFB decryption", output, input, sp);
#endif
#if OFB && AES_KEY_SIZE == 16
    hex2bytes(ofbcipher, test);
    AES_OFB_encrypt(key, iv, input, sp, output);
    check("OFB encryption", output, test, sp);
    AES_OFB_decrypt(key, iv, test, sp, output);
    check("OFB decryption", output, input, sp);
#endif
#if CTR_NA && AES_KEY_SIZE == 16
    hex2bytes(ctrcipher, test);
    AES_CTR_encrypt(key, iv, input, sp, output);
    check("CTR encryption", output, test, sp);
    AES_CTR_decrypt(key, iv, test, sp, output);
    check("CTR decryption", output, input, sp);
#endif
#if XTS && AES_KEY_SIZE != 24
    hex2bytes(xtscipher, test);
    AES_XTS_encrypt(key, iv, input, sp, output);
    check("XTS encryption", output, test, sp);
    AES_XTS_decrypt(key, iv, test, sp, output);
    check("XTS decryption", output, input, sp);
#endif
#if CMAC && AES_KEY_SIZE == 16
    hex2bytes(ptxt_cmac, test);
    AES_CMAC(key, input, sp, output);
    check("plaintext CMAC", output, test, 16);
#endif
#if POLY1305 && AES_KEY_SIZE == 16
    hex2bytes(poly_1305, test);
    AES_Poly1305(key, iv, input, sp, output);
    check("Poly-1305 *mac", output, test, 16);
#endif
#if GCM && AES_KEY_SIZE != 24
    hex2bytes(gcmcipher, test);
    AES_GCM_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("GCM encryption", output, test, sp + 16);
    AES_GCM_decrypt(key, iv, test, sp, a, sa, 16, output);
    check("GCM decryption", output, input, sp);
#endif
#if CCM && AES_KEY_SIZE == 16
    hex2bytes(ccmcipher, test);
    AES_CCM_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("CCM encryption", output, test, sp + CCM_TAG_LEN);
    *output ^= AES_CCM_decrypt(key, iv, test, sp, a, sa, CCM_TAG_LEN, output);
    check("CCM decryption", output, input, sp);
#endif
#if OCB && AES_KEY_SIZE == 16
    hex2bytes(ocbcipher, test);
    AES_OCB_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("OCB encryption", output, test, sp + OCB_TAG_LEN);
    *output ^= AES_OCB_decrypt(key, iv, test, sp, a, sa, OCB_TAG_LEN, output);
    check("OCB decryption", output, input, sp);
#endif
#if SIV && AES_KEY_SIZE == 16
    hex2bytes(sivcipher, test);
    AES_SIV_encrypt(key, input, sp, a, sa, output, output + 16);
    check("SIV encryption", output, test, sp + 16);
    *output ^= AES_SIV_decrypt(key, test, test + 16, sp, a, sa, output);
    check("SIV decryption", output, input, sp);
#endif
#if GCM_SIV && AES_KEY_SIZE == 16
    hex2bytes(gsvcipher, test);
    GCM_SIV_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("GCMSIV encrypt", output, test, sp + 16);
    *output ^= GCM_SIV_decrypt(key, iv, test, sp, a, sa, 16, output);
    check("GCMSIV decrypt", output, input, sp);
#endif
#if EAX && AES_KEY_SIZE == 16
    hex2bytes(eaxcipher, test);
#if EAXP
    AES_EAX_encrypt(key, a, input, sp, sa, output);
    check("EAX encryption", output, test, sp + 4);
    AES_EAX_decrypt(key, a, test, sp, sa, output);
#else
    AES_EAX_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("EAX encryption", output, test, sp + 16);
    AES_EAX_decrypt(key, iv, test, sp, a, sa, 16, output);
#endif
    check("EAX decryption", output, input, sp);
#endif
#if AES_KEY_SIZE + !FPE + CUSTOM_ALPHABET == 16
    memcpy(test, fpecipher, FF_X == 3 ? (sp = 55) : sp);
#if FF_X == 3
    AES_FPE_encrypt(key, a, fpe_plain, sp, output);
    check("FF3 encryption", output, test, sp);
    AES_FPE_decrypt(key, a, test, sp, output);
#else
    AES_FPE_encrypt(key, a, sa, fpe_plain, sp, output);
    check("FF1 encryption", output, test, sp);
    AES_FPE_decrypt(key, a, sa, test, sp, output);
#endif
    check("FPE decryption", output, fpe_plain, sp);
#endif
#if KWA
    hex2bytes(k_wrapped, test);
    AES_KEY_wrap(authKey, key + 32, AES_KEY_SIZE, output);
    check("key wrapping  ", output, test, AES_KEY_SIZE + 8);
    AES_KEY_unwrap(authKey, test, AES_KEY_SIZE + 8, output);
    check("key unwrapping", output, key + 32, AES_KEY_SIZE);
#endif
    /** a template for "OFFICIAL TEST VECTORS":  */
#if OCB * EAX * SIV * GCM_SIV * POLY1305 * FPE * (16 / AES_KEY_SIZE)
    printf("+-> Let's do some extra tests\n");

    sp = sa = 24;       /* taken from RFC-7253:  */
    hex2bytes("000102030405060708090A0B0C0D0E0F", key);
    hex2bytes("BBAA99887766554433221107", iv);
    hex2bytes("000102030405060708090A0B0C0D0E0F1011121314151617", a);
    hex2bytes("000102030405060708090A0B0C0D0E0F1011121314151617", input);
    hex2bytes("1CA2207308C87C010756104D8840CE1952F09673A448A122\
               C92C62241051F57356D7F3C90BB0E07F", test);
    AES_OCB_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("OCB encryption", output, test, sp + OCB_TAG_LEN);
    *output ^= AES_OCB_decrypt(key, iv, test, sp, a, sa, OCB_TAG_LEN, output);
    check("OCB decryption", output, input, sp);

    sp = 11, sa = 7;    /* taken from RFC-8452:  */
    hex2bytes("ee8e1ed9ff2540ae8f2ba9f50bc2f27c", key);
    hex2bytes("752abad3e0afb5f434dc4310", iv);
    hex2bytes("6578616d706c65", a);
    hex2bytes("48656c6c6f20776f726c64", input);
    hex2bytes("5d349ead175ef6b1def6fd4fbcdeb7e4793f4a1d7e4faa70100af1", test);
    GCM_SIV_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("GCMSIV encrypt", output, test, sp + 16);
    *output ^= GCM_SIV_decrypt(key, iv, test, sp, a, sa, 16, output);
    check("GCMSIV decrypt", output, input, sp);
    sp = 12, sa = 1;    /* taken from RFC-8452:  */
    hex2bytes("01000000000000000000000000000000", key);
    hex2bytes("030000000000000000000000", iv);
    hex2bytes("01", a);
    hex2bytes("020000000000000000000000", input);
    hex2bytes("296c7889fd99f41917f4462008299c51\
               02745aaa3a0c469fad9e075a", test);
    GCM_SIV_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("GCMSIV encrypt", output, test, sp + 16);
    *output ^= GCM_SIV_decrypt(key, iv, test, sp, a, sa, 16, output);
    check("GCMSIV decrypt", output, input, sp);

    sp = 14, sa = 24;   /* taken from RFC-5297:  */
    hex2bytes("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0\
               f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff", key);
    hex2bytes("10111213 14151617 18191a1b 1c1d1e1f\
               20212223 24252627", a);
    hex2bytes("11223344 55667788 99aabbcc ddee", input);
    hex2bytes("85632d07 c6e8f37f 950acd32 0a2ecc93\
               40c02b96 90c4dc04 daef7f6a fe5c", test);
    AES_SIV_encrypt(key, input, sp, a, sa, output, output + 16);
    check("SIV encryption", output, test, sp + 16);
    *output ^= AES_SIV_decrypt(key, test, test + 16, sp, a, sa, output);
    check("SIV decryption", output, input, sp);
    sp = 16, sa = 0;    /* from miscreant on github: bit.ly/3ycgGB */
    hex2bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", key);
    hex2bytes("00112233445566778899aabbccddeeff", input);
    hex2bytes("f304f912863e303d5b540e5057c7010c942ffaf45b0e5ca5fb9a56a5263bb065", test);
    AES_SIV_encrypt(key, input, sp, a, sa, output, output + 16);
    check("SIV encryption", output, test, sp + 16);
    *output ^= AES_SIV_decrypt(key, test, test + 16, sp, a, sa, output);
    check("SIV decryption", output, input, sp);
#if EAXP
    sp = 0, sa = 50;    /* from Annex G of the IEEE Std. 1703-2012 */
    hex2bytes("01020304050607080102030405060708", key);
    hex2bytes("A20D060B607C86F7540116007BC175A8\
               03020100BE0D280B810984A60C060A60\
               7C86F7540116007B040248F3C2040330\
               0005", input);
    hex2bytes("515AE775", test);
    AES_EAX_encrypt(key, input, NULL, sp, sa, output);
    check("EAX encryption", output, test, sp + 4);
    sp += AES_EAX_decrypt(key, input, test, sp, sa, output);
    check("EAX decryption", output, input, sp);
    sp = 28, sa = 65;   /* from Moise-Beroset-Phinney-Burns paper: */
    hex2bytes("10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0 00", authKey);
    hex2bytes("a2 0e 06 0c 60 86 48 01 86 fc 2f 81 1c aa 4e 01\
               a8 06 02 04 39 a0 0e bb ac 0f a2 0d a0 0b a1 09\
               80 01 00 81 04 4b ce e2 c3 be 25 28 23 81 21 88\
               a6 0a 06 08 2b 06 01 04 01 82 85 63 00 4b ce e2\
               c3", test);
    hex2bytes("17 51 30 30 30 30 30 30 30 30 30 30 30 30 30 30\
               30 30 30 30 30 30 00 00 03 30 00 01", input);
    hex2bytes("9c f3 2c 7e c2 4c 25 0b e7 b0 74 9f ee e7 1a 22\
               0d 0e ee 97 6e c2 3d bf 0c aa 08 ea 00 54 3e 66", key);
    AES_EAX_encrypt(authKey, test, input, sp, sa, output);
    check("EAX encryption", output, key, sp + 4);
    AES_EAX_decrypt(authKey, test, key, sp, sa, output);
#else
    sp = 12, sa = 8;    /* from Bellare-Rogaway-Wagner 2004 paper: */
    hex2bytes("BD8E6E11475E60B268784C38C62FEB22", key);
    hex2bytes("6EAC5C93072D8E8513F750935E46DA1B", iv);
    hex2bytes("D4482D1CA78DCE0F", a);
    hex2bytes("4DE3B35C3FC039245BD1FB7D", input);
    hex2bytes("835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F", test);
    AES_EAX_encrypt(key, iv, input, sp, a, sa, output, output + sp);
    check("EAX encryption", output, test, sp + 16);
    AES_EAX_decrypt(key, iv, test, sp, a, sa, 16, output);
#endif
    check("EAX decryption", output, input, sp);

#if (FF_X != 3) * CUSTOM_ALPHABET == 3
    sp = 19, sa = 11;
    hex2bytes("2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C", key);
    hex2bytes("37 37 37 37 70 71 72 73 37 37 37", a);
    memcpy(input, "0123456789abcdefghi", sp);
    memcpy(output, "a9tv40mll9kdu509eum", sp);
    AES_FPE_encrypt(key, a, sa, input, sp, test);
    check("FF1 encryption", test, output, sp);
    AES_FPE_decrypt(key, a, sa, output, sp, test);
    check("FF1 decryption", test, input, sp);
#elif FF_X * !CUSTOM_ALPHABET == 3
    sp = 29;            /* zero tweak works for both FF3 and FF3-1 */
    hex2bytes("EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94", key);
    hex2bytes("00 00 00 00 00 00 00 00", a);
    memcpy(input, "89012123456789000000789000000", sp);
    memcpy(output, "34695224821734535122613701434", sp);
    AES_FPE_encrypt(key, a, input, sp, test);
    check("FF3 encryption", test, output, sp);
    AES_FPE_decrypt(key, a, output, sp, test);
    check("FF3 decryption", test, input, sp);
#endif
    sp = 32;            /* ↓ from Daniel J. Bernstein's 2005 paper */
    hex2bytes("66 3c ea 19 0f fb 83 d8 95 93 f3 f4 76 b6 bc 24\
               d7 e6 79 10 7e a2 6a db 8c af 66 52 d0 65 61 36", input);
    hex2bytes("6a cb 5f 61 a7 17 6d d3 20 c5 c1 eb 2e dc dc 74\
               48 44 3d 0b b0 d2 11 09 c8 9a 10 0b 5c e2 c2 08", key);
    hex2bytes("ae 21 2a 55 39 97 29 59 5d ea 45 8b c6 21 ff 0e", iv);
    hex2bytes("0e e1 c1 6b b7 3f 0f 4f d1 98 81 75 3c 01 cd be", test);
    AES_Poly1305(key, iv, input, sp, output);
    check("Poly-1305 *mac", output, test, 16);
    sp = 63;
    hex2bytes("ab 08 12 72 4a 7f 1e 34 27 42 cb ed 37 4d 94 d1\
               36 c6 b8 79 5d 45 b3 81 98 30 f2 c0 44 91 fa f0\
               99 0c 62 e4 8b 80 18 b2 c3 e4 a0 fa 31 34 cb 67\
               fa 83 e1 58 c9 94 d9 61 c4 cb 21 09 5c 1b f9", input);
    hex2bytes("e1 a5 66 8a 4d 5b 66 a5 f6 8c c5 42 4e d5 98 2d\
               12 97 6a 08 c4 42 6d 0c e8 a8 24 07 c4 f4 82 07", key);
    hex2bytes("9a e8 31 e7 43 97 8d 3a 23 52 7c 71 28 14 9e 3a", iv);
    hex2bytes("51 54 ad 0d 2c b2 6e 01 27 4f c5 11 48 49 1f 1b", test);
    AES_Poly1305(key, iv, input, sp, output);
    check("Poly-1305 *mac", output, test, 16);
#endif
    return 0;
}
