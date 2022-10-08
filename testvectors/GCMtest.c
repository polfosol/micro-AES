/*
 ==============================================================================
 Name        : GCMtest.c
 Author      : polfosol
 Version     : 1.5.1.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how the NIST's vectors for AES-GCM mode are used
 ==============================================================================
 */

#include <stdio.h>
#include "../micro_aes.h"

#define TESTFILEPATH "GCM_EncryptExtIV128.rsp"

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

static int ciphertest(uint8_t* key, uint8_t* iv, uint8_t* p, uint8_t* a, uint8_t* c,
                      uint8_t np, uint8_t na, uint8_t nt, char* r)
{
    char sk[70], si[GCM_NONCE_LEN*2+6], sp[0x100], sc[0x100], sa[0x100], msg[30];
    uint8_t tmp[0x80], t = 0;
    sprintf(msg, "%s", "success");

    AES_GCM_encrypt(key, iv, p, np, a, na, tmp, tmp + np);
    if (memcmp(c, tmp, np + nt))
    {
        sprintf(msg, "%s", "encrypt failure");
        t = 1;
    }
    memset(tmp, 0xcc , sizeof tmp);
    t |= AES_GCM_decrypt(key, iv, c, np, a, na, c + np, nt, tmp) ? 2 : 0;
    if (t > 1)
    {
        sprintf(msg, "%sdecrypt failure", t & 1 ? "encrypt & " : "");
    }
    bytes2str(key, sk, AES_KEY_LENGTH);
    bytes2str(iv, si, GCM_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + nt);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return t;
}

int main()
{
    const char *linehdr[] = { "Key = ", "IV = ", "AAD = ", "PT = ", "CT = ", "Tag = " };
    char buffer[0x800], *value = "";
    size_t i, n = 0, pass = 0, df = 0, ef = 0, skip = 0, sp = 0, st = 0, sa = 0;
    uint8_t key[AES_KEY_LENGTH], iv[GCM_NONCE_LEN], p[96], c[112], a[96], t[16];
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
            skip |= (strlen(value) != 2 * AES_KEY_LENGTH);
            if (!skip) str2bytes(value, key);
            break;
        case 1:
            skip |= (strlen(value) != 2 * GCM_NONCE_LEN);
            if (!skip) str2bytes(value, iv);
            break;
        case 2:
            sa = strlen(value) / 2;
            str2bytes(value, a);
            break;
        case 3:
            if (!skip) ++n;
            sp = strlen(value) / 2;
            str2bytes(value, p);
            break;
        case 4:
            if (!skip) ++n;
            str2bytes(value, c);
            break;
        case 5:
            if (!skip) ++n;
            st = strlen(value) / 2;
            str2bytes(value, t);
            break;
        default:
            continue;
        }
        if (n == 3)
        {
            if (skip)
            {
                n = skip = 0;
                continue;
            }
            memcpy(c + sp, t, st); /* put tag at the end */
            n = ciphertest(key, iv, p, a, c, sp, sa, st, buffer);
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
