/*
 ==============================================================================
 Name        : Poly1305test.c
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how the test vectors of Poly1305-AES are processed
 ==============================================================================
 */

#include <stdio.h>
#include "../micro_aes.h"

#define TESTFILEPATH "Poly1305AES128.tv"

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

static int ciphertest(uint8_t* key, uint8_t* nnc, uint8_t* d, uint8_t* m, size_t ds, char* r)
{
    char sk[2*AES_KEY_LENGTH + 40], smac[40], msg[30];
    uint8_t tmp[32], t = 0;
    sprintf(msg, "%s", "success");

    AES_Poly1305(key, nnc, d, ds, tmp);
    t = memcmp(m, tmp, 16);
    if (t)  sprintf(msg, "%s", "failed");

    bytes2str(key, sk, AES_KEY_LENGTH + 16);
    bytes2str(m, smac, 16);
    sprintf(r, "%s\nK: %s\npoly: %s\n", msg, sk, smac);
    return t;
}

int main()
{
    const char *linehdr[] = { "Keys = ", "Nonce = ", "Msg = ", "PolyMac = " };
    char buffer[0x20100], *value = "";
    size_t pass = 0, nf = 0, sk = 0, sd = 0;
    uint8_t i, n = 0, key[AES_KEY_LENGTH + 16], nc[16], d[0x10100], m[16];
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
        for (i = 0; i < 4; i++)
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
            str2bytes(value, key);
            break;
        case 1:
            str2bytes(value, nc);
            break;
        case 2:
            sd = strlen(value) / 2;
            str2bytes(value, d);
            ++n;
            break;
        case 3:
            str2bytes(value, m);
            ++n;
            break;
        default:
            continue;
        }
        if (n == 2)
        {
            if (sk == AES_KEY_LENGTH + 16)
            {
                n = ciphertest(key, nc, d, m, sd, buffer);
                fprintf(n ? ferr : fs, "%s\n", buffer); /* save the log */
                i = n == 0 ? ++pass : ++nf;
            }
            n = 0;
        }
    }
    printf ("Poly1305 test cases: %d\nsuccessful: %d\nfailed: %d\n", pass + nf, pass, nf);

    fclose(fp); fclose(fs); fclose(ferr);
    if (nf == 0)
    {
        remove("passed.log"); remove("failed.log");
    }
    return 0;
}
