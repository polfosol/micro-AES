/*
 ==============================================================================
 Name        : CMACtest.c
 Author      : polfosol
 Version     : 1.5.1.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how to validate NIST's vectors for AES-CMAC
 ==============================================================================
 */

#include <stdio.h>
#include "../micro_aes.h"

#define TESTFILEPATH "CMACGenAES128.rsp"

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

static int ciphertest(uint8_t* key, uint8_t* d, uint8_t* m, size_t ds, size_t ms, char* r)
{
    char sk[2*AES_KEY_LENGTH + 1], smac[33], msg[30];
    uint8_t tmp[32], t = 0;
    sprintf(msg, "%s", "passed the test");

    AES_CMAC(key, d, ds, tmp);
    t = memcmp(m, tmp, ms);
    if (t)  sprintf(msg, "%s", "failed");

    bytes2str(key, sk, AES_KEY_LENGTH);
    bytes2str(m, smac, ms);
    sprintf(r, "%s\nK: %s\nmac: %s\n", msg, sk, smac);
    return t;
}

int main()
{
    const char *linehdr[] = { "Key = ", "Msg = ", "Mac = " };
    char buffer[0x20100], *value = "";
    size_t pass = 0, nf = 0, sk = 0, sd = 0, sm = 0;
    uint8_t i, n = 0, key[32], d[0x10100], m[32];
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
        for (i = 0; i < 3; i++)
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
            if (sk == AES_KEY_LENGTH) str2bytes(value, key);
            break;
        case 1:
            sd = strlen(value) / 2;
            str2bytes(value, d);
            sd -= (sd == 1 && d[0] == 0);
            ++n;
            break;
        case 2:
            sm = strlen(value) / 2;
            str2bytes(value, m);
            ++n;
            break;
        }
        if (n == 2)
        {
            if (sk == AES_KEY_LENGTH)
            {
                n = ciphertest(key, d, m, sd, sm, buffer);
                fprintf(n ? ferr : fs, "%s\n", buffer); /* save the log */
                i = n == 0 ? ++pass : ++nf;
            }
            n = 0;
        }
    }
    printf ("CMAC test cases: %d\nsuccessful: %d\nfailed: %d\n", pass + nf, pass, nf);

    fclose(fp); fclose(fs); fclose(ferr);
    if (nf == 0)
    {
        remove("passed.log"); remove("failed.log");
    }
    return 0;
}
