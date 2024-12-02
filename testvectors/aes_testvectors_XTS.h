/*
 ==============================================================================
 Name        : aes_testvectors_XTS.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-XTS
 ==============================================================================
 */

#ifndef _TESTING_XTS_H_
#define _TESTING_XTS_H_

#include "aes_testvectors.h"
#ifdef XTS_TEST_FILE

static int verifyxts(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* c,
                     size_t np, char* r)
{
    char sk[4 * AES_KEY_SIZE + 1], si[33], sp[0x80], sc[0x80], msg[30];
    uint8_t tmp[0x80], v = 0;
    strcpy(msg, "passed the test");

    AES_XTS_encrypt(key, i, p, np, tmp);
    if (memcmp(c, tmp, np))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    AES_XTS_decrypt(key, i, c, np, tmp);
    if (memcmp(p, tmp, np))
    {
        sprintf(msg, "%sdecrypt failure", v ? "encrypt & " : "");
        v |= 2;
    }
    bytes2str(key, sk, 2 * AES_KEY_SIZE);
    bytes2str(i, si, 16);
    bytes2str(p, sp, np);
    bytes2str(c, sc, np);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nC: %s", msg, sk, si, sp, sc);
    return v;
}

static void aes_xts_test(FILE** files, unsigned* count)
{
    const char *linehdr[] = XTS_HEADLINES;
    char buffer[0x800], *value = NULL;
    size_t s = 0, sk = 0;
    uint8_t j, n = 0, key[2 * AES_KEY_SIZE], iv[16], p[0x80], c[0x80], ul[2];

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) < 4)  continue;
        for (j = 0; j < 5; j++)
        {
            if (strncmp(buffer, linehdr[j], strlen(linehdr[j])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                n += (j == 2 || j == 3);
                break;
            }
        }
        switch (j)
        {
        case 0:
            sk = strlen(value) / 4;
            if (sk == AES_KEY_SIZE) str2bytes(value, key);
            break;
        case 1:
            str2bytes(value, iv);
            break;
        case 2:
            str2bytes(value, p);
            break;
        case 3:
            str2bytes(value, c);
            break;
        case 4:
            str2bytes(value, ul);
            s = (ul[0] >> 4) *100 + (ul[0] & 15) *10 + (ul[1] >> 4);
            break;
        }
        if (n == 2)
        {
            if (sk == AES_KEY_SIZE && s % 8 == 0)
            {
                n = verifyxts(key, iv, p, c, s / 8, buffer);
                fprintf(files[2 - !n], "%s\n", buffer); /* save the log */
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
