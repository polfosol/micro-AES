/*
 ==============================================================================
 Name        : FPEtest.c
 Author      : polfosol
 Version     : 1.4.1.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how to validate NIST's vectors for AES-FPE mode
 ==============================================================================
 */

#include <stdio.h>
#include "../micro_aes.h"

#define TESTFILEPATH "FPE_FF1&FF3&FF3-1.tv"

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

static void bytes2str(const uint8_t* bytes, char* str, const size_t len)
{
    const char offset = 0x27;       /* offset must be 7 for uppercase */
    size_t i = len + len, shr = 0;
    for (str[i] = 0; i--; shr ^= 4)
    {
        str[i] = bytes[i / 2] >> shr & 0xF | '0';
        if (str[i] > '9')  str[i] += offset;
    }
}

static int ciphertest(uint8_t* key, uint8_t* tk, char* a, char* p, char* c,
                      size_t n, size_t nt, char* r)
{
    char sk[2*AES_KEY_SIZE + 1], st[65], msg[30], tmp[0x800], t = 0;
    sprintf(msg, "%s", "passed the test");
#if FF_X == 3
    AES_FPE_encrypt(key, tk, p, n, tmp);
#else
    AES_FPE_encrypt(key, tk, nt, p, n, tmp);
#endif
    if (memcmp(c, tmp, n))
    {
        sprintf(msg, "%s", "encrypt failure");
        t = 1;
    }
    memset(tmp, 0xcc , sizeof tmp);
#if FF_X == 3
    AES_FPE_decrypt(key, tk, c, n, tmp);
#else
    AES_FPE_decrypt(key, tk, nt, c, n, tmp);
#endif
    if (memcmp(p, tmp, n))
    {
        sprintf(msg, "%sdecrypt failure", t ? "encrypt & " : "");
        t |= 2;
    }
    bytes2str(key, sk, AES_KEY_SIZE);
    bytes2str(tk, st, nt);
    sprintf(r, "%s\nA: %s\nK: %s\nT: %s\nP: %s\nC: %s", msg, a, sk, st, p, c);
    return t;
}

int main()
{
    const char *linehdr[] =
    {
        "Method = ", "Alphabet = ", "Key = ", "Tweak = ", "PT = ", "CT = "
    }, *alphabets[] =
    {
        "0123456789", "01", "abcdefghijklmnopqrstuvwxyz",
        "0123456789abcdefghijklmnopqrstuvwxyz", "*", "*", "*", "0123456789abcdefghijklmnop",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    };
    char buffer[0x1000], alpha[90], p[0x800], c[0x800], m[6], a = 0, *value = "";
    size_t pass = 0, df = 0, ef = 0, sp = 0, st = 0;
    uint8_t i, key[2*AES_KEY_SIZE], twk[32], sk = 0, n = 0;
    FILE *fp, *fs, *ferr;

    fp = fopen(TESTFILEPATH, "r");
    fs = fopen("passed.log", "w");
    ferr = fopen("failed.log", "w");

    if (fp == NULL)
    {
        printf("File not found: %s\n", TESTFILEPATH);
        return 1;
    }
    if (!fs || !ferr) return 1;

    while (fgets(buffer, sizeof buffer, fp) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) < 4) continue;
        for (i = 0; i < 6; i++)
        {
            if (strncmp(buffer, linehdr[i], strlen(linehdr[i])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                break;
            }
        }
        switch (i)
        {
        case 0:
            strcpy(m, value);
            break;
        case 1:
            for (i = 0; i < 9; i++)
            {
                if ((a = strlen(alphabets[i])) != strlen(value)) continue;
                if (strncmp(value, alphabets[i], a) == 0) break;
            }
            strcpy(alpha, value); a = i;
            break;
        case 2:
            sk = strlen(value) / 2;
            str2bytes(value, key);
            break;
        case 3:
            st = strlen(value) / 2; ++n;
            str2bytes(value, twk);
            break;
        case 4:
            sp = strlen(value);
            strcpy(p, value);
            break;
        case 5:
            ++n;
            strcpy(c, value);
            break;
        }
        if (n == 2)
        {
            n = (FF_X == 3) ^ (m[2] != '3');
#if FF3_TWEAK_LEN == 8
            n &= (st == 8);      /* old FF3 with 8-byte tweak */
#else
            n &= FF_X != 3 || !(st == 8 && twk[7]);  /* FF3-1 */
#endif
            if (n && a == CUSTOM_ALPHABET && sk == AES_KEY_SIZE)
            {
                n = ciphertest(key, twk, alpha, p, c, sp, st, buffer);
                fprintf(n ? ferr : fs, "%s\n\n", buffer); /* save the log */
                if (n == 0) ++pass;
                if (n & 1) ++ef;
                if (n & 2) ++df;
            }
            n = 0;
        }
    }
    printf ("test cases: %d\nsuccessful: %d\nfailed encrypt: %d, failed decrypt: %d\n",
        pass + (ef > df ? ef : df), pass, ef, df);

    fclose(fp); fclose(fs); fclose(ferr);
    if (ef + df == 0)
    {
        remove("passed.log"); remove("failed.log");
    }
    return 0;
}
