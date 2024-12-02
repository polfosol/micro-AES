/*
 ==============================================================================
 Name        : aes_testvectors.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : methods and definitions for the test-functions of AES modes
 ==============================================================================
 */

#ifndef _TEST_AES_MODES_H_
#define _TEST_AES_MODES_H_

#include <stdio.h>
#include "../micro_aes.h"

#ifdef _CRT_SECURE_NO_WARNINGS
#define _LOOKUP_ "testvectors/"
#else
#define _LOOKUP_
#endif

#if CMAC
#if     AES___ == 256
#define CMAC_TEST_FILE _LOOKUP_ "CMACGenAES256.rsp"
#elif   AES___ == 192
#define CMAC_TEST_FILE _LOOKUP_ "CMACGenAES192.rsp"
#else
#define CMAC_TEST_FILE _LOOKUP_ "CMACGenAES128.rsp"
#endif
#define CMAC_HEADLINES { "Key = ", "Msg = ", "Mac = " }
#endif

#if CCM
#if     AES___ == 256
#define CCM_TEST_FILE _LOOKUP_ "ccmVNT256.rsp"
#elif   AES___ == 192
#define CCM_TEST_FILE _LOOKUP_ "ccmVNT192.rsp"
#else
#define CCM_TEST_FILE _LOOKUP_ "ccmVNT128.rsp"
#endif
#define CCM_HEADLINES { "Key = ", "Nonce = ", "Adata = ", "Payload = ", "CT = " }
#endif

#if GCM
#if     AES___ == 256
#define GCM_TEST_FILE _LOOKUP_ "gcmEncryptExtIV256.rsp"
#elif   AES___ == 192
#define GCM_TEST_FILE _LOOKUP_ "gcmEncryptExtIV192.rsp"
#else
#define GCM_TEST_FILE _LOOKUP_ "gcmEncryptExtIV128.rsp"
#endif
#define GCM_HEADLINES { "Key = ", "IV = ", "AAD = ", "PT = ", "CT = ", "Tag = " }
#endif

#if XTS
#if AES___ == 256
#define XTS_TEST_FILE _LOOKUP_ "XTSGenAES256.rsp"
#else
#define XTS_TEST_FILE _LOOKUP_ "XTSGenAES128.rsp"
#endif
#define XTS_HEADLINES { "Key = ", "i = ", "PT = ", "CT = ", "DataUnitLen = " }
#endif

#if FPE
#define FPE_TEST_FILE _LOOKUP_ "FPE_FF1&FF3&FF3-1.tv"
#define FPE_HEADLINES { "Method = ", "Alphabet = ", "Key = ", "Tweak = ", \
                        "PT = ", "CT = " }
#define FPE_ALPHABETS { "0123456789", "01", "abcdefghijklmnopqrstuvwxyz", \
                        "0123456789abcdefghijklmnopqrstuvwxyz", "******", \
                        "*******", "*****", "0123456789abcdefghijklmnop", \
       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/" }
#endif

#if OCB
#define OCB_TEST_FILE _LOOKUP_ "OCB_AES128.tv"
#define OCB_HEADLINES { "Key = ", "IV = ", "AAD = ", "Plaintext = ", \
                        "Ciphertext = ",   "Tag = ", "Result = "     }
#endif

#if GCM_SIV
#define GCMSIV_TEST_FILE _LOOKUP_ "SIV_GCM_ACVP.tv"
#define GCMSIV_HEADLINES { "key = ", "iv = ", "aad = ", "pt = ", "ct = " }
#endif

#if POLY1305
#define POLY_TEST_FILE _LOOKUP_ "Poly1305AES128.tv"
#define POLY_HEADLINES { "Keys = ", "Nonce = ", "Msg = ", "PolyMac = " }
#endif

/** convert hex-string to byte array; e.g. "7142075A340d" results in qB\aZ4\r */
static void str2bytes(const char* hex, uint8_t* bytes)
{
    unsigned shl = 0;
    for (--bytes; *hex; ++hex)
    {
        if (*hex < '0' || 'f' < *hex)  continue;
        if ((shl ^= 4) != 0)  *++bytes = 0;
        *bytes |= (*hex % 16 + (*hex > '9') * 9) << shl;
    }
}

/** convert byte array to hex-string; e.g. +\n50\tK results in "2b0a3530094b" */
static void bytes2str(const uint8_t* bytes, char* str, const size_t len)
{
    const char offset = 0x27;       /* offset must be 7 for UPPERCASE */
    size_t i = len + len, shr = 0;
    for (str[i] = 0; i--; shr ^= 4)
    {
        str[i] = bytes[i / 2] >> shr & 0xF | '0';
        if (str[i] > '9')  str[i] += offset;
    }
}

/** function pointer as a template for all the test functions. its arguments are
 * an array of pre-determined files and the number of test cases/failed ones. */
typedef void (*ftest_t)(FILE**, unsigned*);

static int check_testvectors(const char* mode, const char* path, ftest_t test)
{
    int error = 0, i;
    char p_log[20], e_log[20];
    FILE* files[3];     /* test vectors file, errors log, success log */
    unsigned count[3];  /* total tests, encrypt fails, decrypt fails. */

    printf("\nVerifying vectors: AES%d-%s\n", AES_KEY_SIZE * 8, mode);
    strcpy(p_log, mode);
    strcpy(e_log, mode);
    files[0] = fopen(path, "r");
    files[1] = fopen(strcat(p_log, "passed.log"), "w");
    files[2] = fopen(strcat(e_log, "failed.log"), "w");

    if (!files[0])
    {
        printf("Error: file not found: %s\n", path);
        error |= 1;
    }
    if (!files[1] || !files[2])
    {
        printf("Error: cannot save log files...\n");
        error |= 1;
    }
    if (error)
    {
        for (i = 0; i < 3; ++i)
        {
            if (files[i])
            {
                fclose(files[i]);
                if (i)  remove(i == 1 ? p_log : e_log);
            }
        }
        printf("Test has failed.\n");
        return error;
    }
    memset(count, 0, sizeof count);
    test(files, count);

    for (i = 0; i < 3; i++)
    {
        fclose(files[i]);
    }
    error = count[1] + (~count[2] ? count[2] : 0);
    if (error)
    {
        printf("Nmber of tests: %d, there were some errors:\n", count[0]);
        if (count[2] == ~0U)    /* MAC test, no encryption/decryption */
        {
            printf("Failed cases: %d, see the log files.\n", count[1]);
        }
        else
        {
            printf("Encryption failures: %d, decryption failures: %d\n"
                "See the log files for more info.\n", count[1], count[2]);
        }
        return error;
    }
    else
    {
        if (count[0] == 0)  printf("There was no test cases.\n");
        else
        {
            printf("Nmber of tests: %4d, All Passed!\n", count[0]);
        }
        remove(p_log);
        remove(e_log);
    }
    return 0;
}

#endif /* header guard */
