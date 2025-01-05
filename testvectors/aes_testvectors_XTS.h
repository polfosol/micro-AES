/*
 ==============================================================================
 Name        : aes_testvectors_XTS.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-XTS
 ==============================================================================
 */

#include "aes_testvectors.h"

#if defined(_TESTING_XTS_H_) ^ defined(XTS_TEST_FILE)
#define _TESTING_XTS_H_

int verifyxts(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* c,
              size_t np, char* r)
{
    char sk[4 * AES_KEYLENGTH + 1], si[33], sp[0x80], sc[0x80], msg[30];
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
        strcat(strcpy(msg, v ? "encrypt & " : ""), "decrypt failure");
        v |= 2;
    }
    bytes2str(key, sk, 2 * AES_KEYLENGTH);
    bytes2str(i, si, 16);
    bytes2str(p, sp, np);
    bytes2str(c, sc, np);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nC: %s", msg, sk, si, sp, sc);
    return v;
}

void aes_xts_test(FILE** files, unsigned* count)
{
    const char* head[] = XTS_HEADLINES;
    char buffer[0x800], *value = NULL;
    size_t s[5] = { 0 };
    uint8_t h, e = 0, key[2 * AES_KEYLENGTH], iv[16], p[0x80], c[0x80];

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[ strcspn(buffer, "\n") ] = 0;
        for (h = strlen(buffer) < 4 ? 5 : 0; h < 5; ++h)
        {
            if (strncmp(buffer, head[h], strlen(head[h])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                s[h] = strlen(value) / 2;
                e += (h == 2 || h == 3);
                break;
            }
        }
        switch (h)
        {
        case 0:
            if (s[0] == sizeof key)  str2bytes(value, key);
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
            for (s[4] = 0; *value; s[4] *= 10)  s[4] += *value++ - '0';
            break;
        }
        if (e == 2)
        {
            if (s[0] == sizeof key && s[4] == s[2] * 80)
            {
                e = verifyxts(key, iv, p, c, s[2], buffer);
                fprintf(files[2 - !e], "%s\n", buffer); /* save the log */
                ++count[0];
                if (e & 1) ++count[1];
                if (e & 2) ++count[2];
            }
            e = 0;
        }
    }
}

#endif /* header guard */
