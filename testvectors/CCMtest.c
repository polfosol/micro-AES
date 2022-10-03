/*
 ==============================================================================
 Name        : CCMtest.c
 Author      : polfosol
 Version     : 1.5.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how the NIST's vectors for AES-CCM mode are used
 ==============================================================================
 */

#include <stdio.h>
#include <string.h>
#include "../micro_aes.h"

#define TESTFILEPATH "CCM_VNT128.rsp"

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

static int ciphertest(uint8_t* key, uint8_t* iv, uint8_t* p, uint8_t* a, uint8_t* c, uint8_t np, uint8_t na, char* r)
{
    char sk[40], si[40], sp[80], sc[96], sa[80], msg[30];
    uint8_t tmp[64], t = 0;
    sprintf(msg, "%s", "success");

    AES_CCM_encrypt(key, iv, p, np, a, na, tmp, tmp + np);
    if (memcmp(c, tmp, np + CCM_TAG_LEN))
    {
        sprintf(msg, "%s", "encrypt failure");
        t = 1;
    }
    memset(tmp, 0xcc , sizeof tmp);
    t |= AES_CCM_decrypt(key, iv, c, np, a, na, c + np, CCM_TAG_LEN, tmp) ? 2 : 0;
    if (t > 1)
    {
        sprintf(msg, "%sdecrypt failure", t & 1 ? "encrypt & " : "");
    }
    bytes2str(key, sk, 16);
    bytes2str(iv, si, CCM_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + CCM_TAG_LEN);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return t;
}

int main()
{
    const char *linehdr[] = { "Key = ", "Nonce = ", "Adata = ", "Payload = ", "CT = " };
    char buffer[0x800], *value = "";
    size_t i, n = 0, pass = 0, df = 0, ef = 0, skip = 0, sp = 0, sc = 0, sa = 0;
    uint8_t key[16], iv[16], p[64], c[80], a[64];
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
        for (i = 0; i < 5; i++)
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
            skip = (strlen(value + 1) != 2 * CCM_NONCE_LEN);
            str2bytes(value + 1, iv);
            break;
        case 2:
            sa = strlen(value + 1) / 2;
            str2bytes(value + 1, a);
            break;
        case 3:
            if (!skip) ++n;
            sp = strlen(value + 1) / 2;
            str2bytes(value + 1, p);
            break;
        case 4:
            if (!skip) ++n;
            sc = strlen(value + 1) / 2;
            str2bytes(value + 1, c);
            break;
        default:
            continue;
        }
        if (n == 2)
        {
            skip |= (CCM_TAG_LEN + sp != sc);
            n = skip ? 0 : ciphertest(key, iv, p, a, c, sp, sa, buffer);
            if (skip)  continue;

            fprintf(n ? ferr : fs, "%s\n", buffer); /* save the log */
            if (n == 0) ++pass;
            else
            {
                if (n & 1) ++ef;
                if (n & 2) ++df;
                n = 0;
            }
        }
    }
    printf ("test cases: %d\nsuccessful: %d\nfailed encrypt: %d, failed decrypt: %d\n",
        pass + ef + df, pass, ef, df);

    fclose(fp); fclose(fs); fclose(ferr);
    if (ef + df == 0)
    {
        remove("passed.log"); remove("failed.log");
    }
    return 0;
}
