/*
 ==============================================================================
 Name        : OCBtest.c
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating how the OpenSSL's vectors for AES-OCB mode are used
 ==============================================================================
 */

#include <stdio.h>
#include "../micro_aes.h"

#define TESTFILEPATH "OCB_AES128.tv"

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
                      uint8_t np, uint8_t na, uint8_t err, char* r)
{
    char sk[70], si[30], sp[0x100], sc[0x100], sa[0x100], msg[30];
    uint8_t tmp[0x90], t = 0;
    sprintf(msg, "%s", "success");

    AES_OCB_encrypt(key, iv, p, np, a, na, tmp, tmp + np);
    if (memcmp(c, tmp, np + OCB_TAG_LEN) && !err)
    {
        sprintf(msg, "%s", "encrypt failure");
        t = 1;
    }
    memset(tmp, 0xcc , sizeof tmp);
    t |= 2 * (AES_OCB_decrypt(key, iv, c, np, a, na, OCB_TAG_LEN, tmp) && !err);
    if (t > 1)
    {
        sprintf(msg, "%sdecrypt failure", t & 1 ? "encrypt & " : "");
    }
    bytes2str(key, sk, AES_KEY_LENGTH);
    bytes2str(iv, si, OCB_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + OCB_TAG_LEN);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return t;
}

int main()
{
    const char *linehdr[] =
    { "Key = ", "IV = ", "AAD = ", "Plaintext = ", "Ciphertext = ", "Tag = ", "Result = " };
    char buffer[0x800], *value = "";
    size_t pass = 0, df = 0, ef = 0, sk = 0, sn = 0, sp = 0, sa = 0, st = 0;
    uint8_t key[AES_KEY_LENGTH], tmp[AES_KEY_LENGTH], iv[OCB_NONCE_LEN];
    uint8_t i, p[0x80], c[0x90], a[0x80], t[16], rc = 1;
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
        for (i = 0; i < 7; i++)
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
            if (sk == AES_KEY_LENGTH) str2bytes(value, tmp);
            break;
        case 1:
            sn = strlen(value) / 2;
            if (sn == OCB_NONCE_LEN) str2bytes(value, iv);
            break;
        case 2:
            sa = strlen(value) / 2;
            str2bytes(value, a);
            break;
        case 3:
            sp = strlen(value) / 2;
            str2bytes(value, p);
            break;
        case 4:
            str2bytes(value, c);
            break;
        case 5:
            st = strlen(value) / 2;
            str2bytes(value, t);
            break;
        case 6:
            i = strstr(value, "ERROR") - value;
            i = 7 + (i > 0 && i < 0x100);
            break;
        }
        if (i == 0 || i > 7)
        {
            if (!rc && sk == AES_KEY_LENGTH && sn == OCB_NONCE_LEN && st == OCB_TAG_LEN)
            {
                memcpy(c + sp, t, st);   /* put tag at the end */
                rc = ciphertest(key, iv, p, a, c, sp, sa, i, buffer);
                fprintf(rc ? ferr : fs, "%s\n", buffer); /* save the log */
                if (rc == 0) ++pass;
                else
                {
                    if (rc & 1) ++ef;
                    if (rc & 2) ++df;
                }
            }
            memcpy(key, tmp, sizeof key);
            rc = 0;
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
