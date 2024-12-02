/*
 ==============================================================================
 Name        : aes_testvectors_CCM.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-CCM
 ==============================================================================
 */

#ifndef _TESTING_CCM_H_
#define _TESTING_CCM_H_

#include "aes_testvectors.h"
#ifdef CCM_TEST_FILE

static int verifyccm(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* a, uint8_t* c,
                     size_t np, size_t na, char* r)
{
    char sk[2 * AES_KEY_SIZE + 1], si[33], sp[80], sc[96], sa[80], msg[30];
    uint8_t tmp[64], v = 0;
    strcpy(msg, "passed the test");

    AES_CCM_encrypt(key, i, p, np, a, na, tmp, tmp + np);
    if (memcmp(c, tmp, np + CCM_TAG_LEN))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    *sk = AES_CCM_decrypt(key, i, c, np, a, na, CCM_TAG_LEN, tmp);
    if (*sk || memcmp(p, tmp, np))
    {
        sprintf(msg, "%sdecrypt failure", v ? "encrypt & " : "");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEY_SIZE);
    bytes2str(i, si, CCM_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + CCM_TAG_LEN);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return v;
}

static void aes_ccm_test(FILE** files, unsigned* count)
{
    const char *linehdr[] = CCM_HEADLINES;
    char buffer[0x800], *value = NULL;
    size_t s[5] = { 0 };
    uint8_t j, n = 0, key[AES_KEY_SIZE], iv[16], p[64], c[80], a[64];

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) < 4)  continue;
        for (j = 0; j < 5; j++)
        {
            if (strncmp(buffer, linehdr[j], strlen(linehdr[j])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                s[j] = strlen(value) / 2;
                n += j > 2;
                break;
            }
        }
        switch (j)
        {
        case 0:
            if (s[0] == AES_KEY_SIZE) str2bytes(value, key);
            break;
        case 1:
            if (s[1] == CCM_NONCE_LEN) str2bytes(value, iv);
            break;
        case 2:
            str2bytes(value, a);
            break;
        case 3:
            str2bytes(value, p);
            break;
        case 4:
            s[4] -= CCM_TAG_LEN;
            str2bytes(value, c);
            break;
        }
        if (n == 2)
        {
            if (s[0] == AES_KEY_SIZE && s[1] == CCM_NONCE_LEN && s[3] == s[4])
            {
                n = verifyccm(key, iv, p, a, c, s[3], s[2], buffer);
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
