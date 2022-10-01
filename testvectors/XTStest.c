#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int ciphertest(uint8_t* key, uint8_t* iv, uint8_t* p, uint8_t* c, uint8_t n, char* r)
{
    char sk[70], si[40], sp[70], sc[70], msg[30];
    int false_negative = (n == 17 && (p[16] & 0x1F) == 0 && (c[16] & 0x1F) == 0);
    uint8_t tmp[32], t = 0;
    sprintf(msg, "%s", "success");

    AES_XTS_encrypt(key, iv, p, n, tmp);
    if (memcmp(c, tmp, n) && !false_negative)
    {
        sprintf(msg, "%s", "encrypt failure");
        t = 1;
    }
    memset(tmp, 0xcc , sizeof tmp);
    AES_XTS_decrypt(key, iv, c, n, tmp);
    if (memcmp(p, tmp, n) && !false_negative)
    {
        sprintf(msg, "%sdecrypt failure", t ? "encrypt & " : "");
        t |= 2;
    }
    bytes2str(key, sk, 32);
    bytes2str(iv, si, 16);
    bytes2str(p, sp, n);
    bytes2str(c, sc, n);
    sprintf(r, "%s\nk: %s\ni: %s\np: %s\nc: %s", msg, sk, si, sp, sc);
    return t;
}

int main()
{
    int n = 0, m = 0, pass = 0, df = 0, ef = 0;
    char buffer[256], *value;
    uint8_t key[32], iv[16], p[32], c[32], s = 0;
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
        if (strcspn(buffer, "Key =") == 0)
        {
            value = strrchr(buffer, ' ');
            str2bytes(value + 1, key);
        }
        else if (strcspn(buffer, "i =") == 0)
        {
            value = strrchr(buffer, ' ');
            str2bytes(value + 1, iv);
        }
        else if (buffer[1] == 'T' && (buffer[0] == 'P' || buffer[0] == 'C'))
        {
            value = strrchr(buffer, ' '); ++n;
            s = strlen(value + 1) / 2;
            str2bytes(value + 1, buffer[0] == 'P' ? p : c);
        }
        if (n == m + 2)
        {
            char report[640];
            m = ciphertest(key, iv, p, c, s, report);
            if (m == 0)
            {
                fprintf(fs, "%s\n", report);
                ++pass;
            }
            else
            {
                fprintf(ferr, "%s\n", report); /* test has failed :(( */
                if (m & 1) ++ef;
                if (m & 2) ++df;
            }
            m = n;
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
