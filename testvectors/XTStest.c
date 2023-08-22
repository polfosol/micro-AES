/*
 ==============================================================================
 Name        : XTStest.c
 Author      : polfosol
 Version     : 2.3.1.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how to validate NIST's vectors for AES-XTS mode
 ==============================================================================
 */

#include <stdio.h>
#include "../micro_aes.h"

#define TESTFILEPATH "XTSGenAES128.rsp"

static void str2bytes(const char* str, uint8_t* bytes)
#define char2num(c)  (c > '9' ? (c & 7) + 9 : c & 0xF)
{
    size_t i, j;
    for (i = 0, j = ~0; str[i]; ++i)
    {
        if (str[i] < '0' || str[i] > 'f') continue;
        if (j++ & 1) bytes[j / 2] = char2num(str[i]) << 4;
        else bytes[j / 2] |= char2num(str[i]);
    }
}

static void bytes2str(const uint8_t* bytes, char* str, size_t len)
#define num2char(x)  ((x) > 9 ? 'a' - 10 + (x) : '0' + (x))
{
    size_t i, j;
    for (i = 0, j = 0; i < len; ++i)
    {
        str[j++] = num2char(bytes[i] >> 4);
        str[j++] = num2char(bytes[i] & 15);
    }
    str[j] = 0;
}

static int ciphertest(uint8_t* key, uint8_t* iv, uint8_t* p, uint8_t* c, size_t n, char* r)
{
    char sk[4*AES_KEY_SIZE + 1], si[33], sp[0x80], sc[0x80], msg[30];
    uint8_t tmp[0x80], t = 0;
    sprintf(msg, "%s", "passed the test");

    AES_XTS_encrypt(key, iv, p, n, tmp);
    if (memcmp(c, tmp, n))
    {
        sprintf(msg, "%s", "encrypt failure");
        t = 1;
    }
    memset(tmp, 0xcc , sizeof tmp);
    AES_XTS_decrypt(key, iv, c, n, tmp);
    if (memcmp(p, tmp, n))
    {
        sprintf(msg, "%sdecrypt failure", t ? "encrypt & " : "");
        t |= 2;
    }
    bytes2str(key, sk, 2*AES_KEY_SIZE);
    bytes2str(iv, si, 16);
    bytes2str(p, sp, n);
    bytes2str(c, sc, n);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nC: %s", msg, sk, si, sp, sc);
    return t;
}

int main()
{
    const char *linehdr[] = { "Key = ", "i = ", "PT = ", "CT = ", "DataUnitLen = " };
    char buffer[0x800], *value = "";
    size_t i, n = 0, pass = 0, df = 0, ef = 0, s = 0, sk = 0;
    uint8_t key[2*AES_KEY_SIZE], iv[16], p[0x80], c[0x80], ul[2];
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
        for (i = 0; i < 5; i++)
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
            sk = strlen(value) / 2;
            if (sk == 2 * AES_KEY_SIZE) str2bytes(value, key);
            break;
        case 1:
            str2bytes(value, iv);
            break;
        case 2:
            str2bytes(value, p);
            ++n;
            break;
        case 3:
            str2bytes(value, c);
            ++n;
            break;
        case 4:
            str2bytes(value, ul);
            break;
        }
        if (n == 2)
        {
            s = (ul[0] >> 4) *100 + (ul[0] & 15) *10 + (ul[1] >> 4);
            if (sk == 2 * AES_KEY_SIZE && s % 8 == 0)
            {
                n = ciphertest(key, iv, p, c, s / 8, buffer);
                fprintf(n ? ferr : fs, "%s\n", buffer); /* save the log */
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
