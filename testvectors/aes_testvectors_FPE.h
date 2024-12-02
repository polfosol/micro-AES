/*
 ==============================================================================
 Name        : aes_testvectors_FPE.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-FPE
 ==============================================================================
 */

#ifndef _TESTING_FPE_H_
#define _TESTING_FPE_H_

#include "aes_testvectors.h"
#ifdef FPE_TEST_FILE

static int verifyfpe(uint8_t* key, uint8_t* twk, char* a, char* p, char* c,
                     size_t np, size_t nt, char* r)
{
    char sk[2 * AES_KEY_SIZE + 1], st[65], msg[30], tmp[0x800], v = 0;
    strcpy(msg, "passed the test");
#if FF_X == 3
    AES_FPE_encrypt(key, twk, p, np, tmp);
#else
    AES_FPE_encrypt(key, twk, nt, p, np, tmp);
#endif
    if (memcmp(c, tmp, np))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
#if FF_X == 3
    *sk = AES_FPE_decrypt(key, twk, c, np, tmp);
#else
    *sk = AES_FPE_decrypt(key, twk, nt, c, np, tmp);
#endif
    if (*sk || memcmp(p, tmp, np))
    {
        sprintf(msg, "%sdecrypt failure", v ? "encrypt & " : "");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEY_SIZE);
    bytes2str(twk, st, nt);
    sprintf(r, "%s\nA: %s\nK: %s\nT: %s\nP: %s\nC: %s", msg, a, sk, st, p, c);
    return v;
}

static void aes_fpe_test(FILE** files, unsigned* count)
{
    const char *linehdr[] = FPE_HEADLINES, *alphabets[] = FPE_ALPHABETS;
    char buffer[0x1000], alpha[90], p[0x800], c[0x800], m[6], a = 0, *value = NULL;
    size_t s[3] = { 0 };
    uint8_t j, key[2 * AES_KEY_SIZE], twk[32], n = 0;

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) < 4)  continue;
        for (j = 0; j < 6; j++)
        {
            if (strncmp(buffer, linehdr[j], strlen(linehdr[j])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                n += j > 2;
                break;
            }
        }
        switch (j)
        {
        case 0:
            strcpy(m, value);
            break;
        case 1:
            for (j = 0; j < 9; j++)
            {
                if ((a = strlen(alphabets[j])) != strlen(value)) continue;
                if (strncmp(value, alphabets[j], a) == 0) break;
            }
            strcpy(alpha, value), a = j;
            break;
        case 2:
            s[0] = strlen(value) / 2;
            str2bytes(value, key);
            break;
        case 3:
            s[1] = strlen(value) / 2;
            str2bytes(value, twk);
            break;
        case 4:
            s[2] = strlen(value);
            strcpy(p, value);
            break;
        case 5:
            strcpy(c, value);
            break;
        }
        if (n == 3)
        {
            n = (FF_X == 3) ^ (m[2] != '3');
#if FF3_TWEAK_LEN == 8
            n &= s[1] == 8;      /* old FF3 with 8-byte tweak */
#else
            n &= FF_X != 3 || s[1] != 8 || !twk[7];  /* FF3-1 */
#endif
            if (n && a == CUSTOM_ALPHABET && s[0] == AES_KEY_SIZE)
            {
                n = verifyfpe(key, twk, alpha, p, c, s[2], s[1], buffer);
                fprintf(files[2 - !n], "%s\n\n", buffer); /* save the log */
                ++count[0];
                if (n & 1) ++count[1];
                if (n & 2) ++count[2];
            }
            n = 0;
        }
    }
}

#endif
#endif /* header guard */
