/*
 ==============================================================================
 Name        : aes_testvectors.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : methods and definitions for the test-functions of AES modes
 ==============================================================================
 */

#ifndef _TEST_AES_MODES_H_
#define _TEST_AES_MODES_H_

#include <stdio.h>
#include <stdlib.h>
#include "../micro_aes.h"

#ifdef _CRT_SECURE_NO_WARNINGS
#define VEC_PATH "testvectors/"
#else
#define VEC_PATH
#endif

#if CMAC
#if     AES___ == 256
#define CMAC_TEST_FILE VEC_PATH "CMACGenAES256.rsp"
#elif   AES___ == 192
#define CMAC_TEST_FILE VEC_PATH "CMACGenAES192.rsp"
#else
#define CMAC_TEST_FILE VEC_PATH "CMACGenAES128.rsp"
#endif
#define CMAC_HEADLINES { "Key = ", "Msg = ", "Mac = " }
#endif

#if CCM
#if     AES___ == 256
#define CCM_TEST_FILE VEC_PATH "VNT256.rsp"
#elif   AES___ == 192
#define CCM_TEST_FILE VEC_PATH "VNT192.rsp"
#else
#define CCM_TEST_FILE VEC_PATH "VNT128.rsp"
#endif
#define CCM_HEADLINES { "Key = ", "Nonce = ", "Adata = ", "Payload = ", "CT = " }
#endif

#if GCM
#if     AES___ == 256
#define GCM_TEST_FILE VEC_PATH "GcmEncryptExtIV256.rsp"
#elif   AES___ == 192
#define GCM_TEST_FILE VEC_PATH "GcmEncryptExtIV192.rsp"
#else
#define GCM_TEST_FILE VEC_PATH "GcmEncryptExtIV128.rsp"
#endif
#define GCM_HEADLINES { "Key = ", "IV = ", "AAD = ", "PT = ", "CT = ", "Tag = " }
#endif

#if XTS
#if     AES___ == 256
#define XTS_TEST_FILE VEC_PATH "XTSGenAES256.rsp"
#elif   AES___ != 192
#define XTS_TEST_FILE VEC_PATH "XTSGenAES128.rsp"
#endif
#define XTS_HEADLINES { "Key = ", "i = ", "PT = ", "CT = ", "DataUnitLen = " }
#endif

#if POLY1305
#define POLY_TEST_FILE VEC_PATH "Poly1305AES128.tv"
#define POLY_HEADLINES { "Keys = ", "Nonce = ", "Msg = ", "PolyMac = " }
#endif

#if EAX
#define EAX_TEST_FILE VEC_PATH "EAX_AES128.tv"
#define EAX_HEADLINES { "MSG: ", "KEY: ", "NONCE: ", "HEADER: ", "CIPHER: " }
#endif

#if GCM_SIV
#define GCMSIV_TEST_FILE VEC_PATH "SIV_GCM_ACVP.tv"
#define GCMSIV_HEADLINES { "key = ", "iv = ", "aad = ", "pt = ", "ct = " }
#endif

#if FPE
#define FPE_TEST_FILE VEC_PATH "FPE_FF1&FF3&FF3-1.tv"
#define FPE_HEADLINES { "Method = ", "Alphabet = ", "Key = ", "Tweak = ", \
                        "PT = ", "CT = " }
#define FPE_ALPHABETS { DECIMALS, LLETTERS, "PLACEHOLDER: your alphabet", \
        DIGITS01, DECIMALS  LLETTERS,  ULETTERS  LLETTERS  DECIMALS "+/", \
        DECIMALS  ULETTERS  LLETTERS "!#$%&()*+-;<=>?@^_`{|}~", DECIMALS  \
        ULETTERS  LLETTERS "+/", DECIMALS "abcdefghijklmnop", " !\"#$%&"  \
        "\'()*+,-./" DECIMALS ":;<=>?@" ULETTERS"[\\]^_`" LLETTERS"{|}~"  }
#endif

#if OCB
#define OCB_TEST_FILE VEC_PATH "OCB_AES128.tv"
#define OCB_HEADLINES { "Key = ", "IV = ", "AAD = ", "Plaintext = ", \
                        "Ciphertext = ",   "Tag = ", "Result = "     }
#endif

#define LINES_MAX_LEN 0x20040L  /*  maximum length of a line among all files. */

/** function pointer as a template for all the test functions. its arguments are
 * an array of pre-determined files and the number of test cases/failed ones. */
typedef void (*ftest_t)(FILE**, unsigned*);

static int check_testvectors(const char* mode, const char* path, ftest_t test)
{
    char i, log[2][22], error = -1;
    FILE* files[3];             /* test vectors file, success log, errors log */
    unsigned count[3] = { 0 };  /* total tests, encrypt fails, decrypt fails. */

    printf("\nVerifying vectors: AES%d-%s\n", AES_KEYLENGTH * 8, mode);
    files[0] = fopen(path, "r");
    files[1] = fopen(strcat(strcpy(log[0], mode), "success.log"), "w");
    files[2] = fopen(strcat(strcpy(log[1], mode), "failure.log"), "w");

    if (files[0] && files[1] && files[2])
    {
        test(files, count);
        error = count[1] || (count[2] && ~count[2]);
    }
    for (i = 0; i < 3; i++)     /* close and delete unnecessary logs. */
    {
        if (files[i] && -fclose(files[i]) >= error)
        {
            error += i ? remove(log[i - 1]) : error;
        }
    }
    switch (2 * !error + !*count)
    {
    case 0:
        printf("Nmber of tests: %d, there were some errors.\n", count[0]);
        if (count[2] == ~0U)    /* MAC test, no encryption/decryption */
        {
            printf("Failed cases: %d, see the log files.\n", count[1]);
        }
        else
        {
            printf("Encryption failures: %d, decryption failures: %d\n"
                "See the log files for more info.\n", count[1], count[2]);
        }
        break;
    case 1:
        printf("Error: Test has failed.\n");
        if (error == -1)
        {
            printf("File not found: %s\n", path);
        }
        else
        {
            printf("Cannot save log files...\n");
        }
        break;
    case 2:
        printf("Nmber of tests: %3d, All Passed!\n", count[0]);
        break;
    case 3:
        printf("No valid cases found in %s\n", path);
        break;
    }
    return error;
}

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
#define UPPERCASE_HEXSTRING 0
{
    size_t i = len + len, shr = 0;
    for (str[i] = 0; i--; shr ^= 4)
    {
        str[i] = bytes[i / 2] >> shr & 0xF;
        str[i] += str[i] < 10 ? '0' : (UPPERCASE_HEXSTRING ? '7' : 'W');
    }
}

#endif /* header guard */
