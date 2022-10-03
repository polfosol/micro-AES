/*
 ==============================================================================
 Name        : CMACtest.c
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how the NIST's vectors for AES-CMAC are used
 ==============================================================================
 */

#include <stdio.h>
#include <string.h>
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
    char sk[40], smac[40], msg[30];
    uint8_t tmp[32], t = 0;
    sprintf(msg, "%s", "success");

    AES_CMAC(key, d, ds, tmp);
    t = memcmp(m, tmp, ms);
    if (t)  sprintf(msg, "%s", "failed");

    bytes2str(key, sk, 16);
    bytes2str(m, smac, ms);
    sprintf(r, "%s\nK: %s\nmac: %s\n", msg, sk, smac);
    return t;
}

int main()
{
    const char *linehdr[] = { "Key = ", "Msg = ", "Mac = " };
    char buffer[0x20100], *value = "";
    size_t i, n = 0, pass = 0, nf = 0, sd = 0, sm = 0;
    uint8_t key[32], d[0x10100], m[32];
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
        if (strlen(buffer) < 4 || !strcspn(buffer, "=")) continue;
        for (i = 0; i < 3; i++)
        {
            if (strncmp(buffer, linehdr[i], strlen(linehdr[i])) == 0)
            {
                value = strrchr(buffer, ' ');
                break;
            }
        }
        switch (i)
        {
        case 0:
            str2bytes(value + 1, key);
            break;
        case 1:
            sd = strlen(value + 1) / 2;
            str2bytes(value + 1, d);
            if (sd == 1 && d[0] == 0) --sd;
            ++n;
            break;
        case 2:
            sm = strlen(value + 1) / 2;
            str2bytes(value + 1, m);
            ++n;
            break;
        default:
            continue;
        }
        if (n == 2)
        {
            n = ciphertest(key, d, m, sd, sm, buffer);

            fprintf(n ? ferr : fs, "%s\n", buffer); /* save the log */
            if (n == 0) ++pass;
            else
            {
                ++nf;
                n = 0;
            }
        }
    }
    printf ("test cases: %d\nsuccessful: %d\nfailed: %d\n", pass + nf, pass, nf);

    fclose(fp); fclose(fs); fclose(ferr);
    if (nf == 0)
    {
        remove("passed.log"); remove("failed.log");
    }
    return 0;
}
