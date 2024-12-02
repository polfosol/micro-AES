/*
 ==============================================================================
 Name        : aes_testvectors_GCM.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-GCM
 ==============================================================================
 */

#ifndef _TESTING_GCM_H_
#define _TESTING_GCM_H_

#include "aes_testvectors.h"
#ifdef GCM_TEST_FILE

static int verifygcm(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* a, uint8_t* c,
                     size_t np, size_t na, uint8_t nt, char* r)
{
    char sk[65], si[2 * GCM_NONCE_LEN + 1], sp[0x100], sc[0x100], sa[0x100], msg[30];
    uint8_t tmp[0x80], v = 0;
    strcpy(msg, "passed the test");

    AES_GCM_encrypt(key, i, p, np, a, na, tmp, tmp + np);
    if (memcmp(c, tmp, np + nt))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    *sk = AES_GCM_decrypt(key, i, c, np, a, na, nt, tmp);
    if (*sk || memcmp(p, tmp, np))
    {
        sprintf(msg, "%sdecrypt failure", v ? "encrypt & " : "");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEY_SIZE);
    bytes2str(i, si, GCM_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + nt);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return v;
}

static void aes_gcm_test(FILE** files, unsigned* count)
{
    const char *linehdr[] = GCM_HEADLINES;
    char buffer[0x800], *value = NULL, *line = NULL;
    size_t s[6] = { 0 };
    uint8_t key[AES_KEY_SIZE], tmp[AES_KEY_SIZE], iv[GCM_NONCE_LEN];
    uint8_t j, p[96], c[112], a[96], t[16], r = 1;

    do
    {
        if ((line = fgets(buffer, sizeof buffer, *files)) != NULL)
        {
            buffer[strcspn(buffer, "\n")] = 0;
            if (strlen(buffer) < 4)  continue;
        }
        for (j = 0; j < 6; j++)
        {
            if (strncmp(buffer, linehdr[j], strlen(linehdr[j])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                s[j] = strlen(value) / 2;
                break;
            }
        }
        switch (j)
        {
        case 0:
            if (s[0] == AES_KEY_SIZE) str2bytes(value, tmp);
            break;
        case 1:
            if (s[1] == GCM_NONCE_LEN) str2bytes(value, iv);
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
        case 5:
            str2bytes(value, t);
            break;
        }
        if (j == 0 || line == NULL)
        {
            if (!r && s[1] == GCM_NONCE_LEN && s[0] == AES_KEY_SIZE)
            {
                memcpy(c + s[3], t, s[5]);    /* put the tag at the end */
                r = verifygcm(key, iv, p, a, c, s[3], s[2], s[5], buffer);
                fprintf(files[2 - !r], "%s\n", buffer); /* save the log */
                ++count[0];
                if (r & 1) ++count[1];
                if (r & 2) ++count[2];
            }
            memcpy(key, tmp, sizeof key);
            r = 0;
        }
    } while (line != NULL);
}

#endif
#endif /* header guard */
