/*
 ==============================================================================
 Name        : aes_testvectors_GCMSIV.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-GCM-SIV
 ==============================================================================
 */

#ifndef _TESTING_GCMSIV_H_
#define _TESTING_GCMSIV_H_

#include "aes_testvectors.h"
#ifdef GCMSIV_TEST_FILE

static int verifygcmsiv(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* a, uint8_t* c,
                        size_t np, size_t na, char* r)
{
    char sk[2 * AES_KEY_SIZE + 1], si[25], sp[0x100], sc[0x100], sa[0x100], msg[30];
    uint8_t tmp[0x90], v = 0;
    strcpy(msg, "passed the test");

    GCM_SIV_encrypt(key, i, p, np, a, na, tmp, tmp + np);
    if (memcmp(c, tmp, np + 16))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    *sk = GCM_SIV_decrypt(key, i, c, np, a, na, 16, tmp);
    if (*sk || memcmp(p, tmp, np))
    {
        sprintf(msg, "%sdecrypt failure", v ? "encrypt & " : "");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEY_SIZE);
    bytes2str(i, si, 12);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + 16);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return v;
}

static void aes_gcmsiv_test(FILE** files, unsigned* count)
{
    const char *linehdr[] = GCMSIV_HEADLINES;
    char buffer[0x400], *value = NULL;
    size_t s[5] = { 0 };
    uint8_t key[AES_KEY_SIZE], iv[12], p[80], c[96], a[80], j, n = 0;

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
            if (s[1] == 12) str2bytes(value, iv);
            break;
        case 2:
            str2bytes(value, a);
            break;
        case 3:
            str2bytes(value, p);
            break;
        case 4:
            str2bytes(value, c);
            break;
        }
        if (n == 2)
        {
            if (s[0] == AES_KEY_SIZE)
            {
                n = verifygcmsiv(key, iv, p, a, c, s[3], s[2], buffer);
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
