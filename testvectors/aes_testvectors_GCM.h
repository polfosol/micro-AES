/*
 ==============================================================================
 Name        : aes_testvectors_GCM.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-GCM
 ==============================================================================
 */

#include "aes_testvectors.h"

#if defined(_TESTING_GCM_H_) ^ defined(GCM_TEST_FILE)
#define _TESTING_GCM_H_

int verifygcm(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* a, uint8_t* c,
              size_t np, size_t na, char* r)
{
    char sk[65], si[2 * GCM_NONCE_LEN + 1], sp[0x100], sc[0x100], sa[0x100], msg[30];
    uint8_t tmp[0x80], v = 0;
    strcpy(msg, "passed the test");

    AES_GCM_encrypt(key, i, a, na, p, np, tmp);
    if (memcmp(c, tmp, np + GCM_TAG_LEN))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    *r = AES_GCM_decrypt(key, i, a, na, c, np, tmp);
    if (*r || memcmp(p, tmp, np))
    {
        strcat(strcpy(msg, v ? "encrypt & " : ""), "decrypt failure");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEYLENGTH);
    bytes2str(i, si, GCM_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + GCM_TAG_LEN);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return v;
}

void aes_gcm_test(FILE** files, unsigned* count)
{
    const char* head[] = GCM_HEADLINES;
    char buffer[0x800], *value = NULL;
    size_t s[6] = { 0 };
    uint8_t h, e = 0, key[32], iv[GCM_NONCE_LEN], p[96], c[112], a[96];

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[ strcspn(buffer, "\n") ] = 0;
        for (h = strlen(buffer) < 4 ? 6 : 0; h < 6; ++h)
        {
            if (strncmp(buffer, head[h], strlen(head[h])) != 0) continue;

            value = strrchr(buffer, ' ') + 1;
            s[h] = strlen(value) / 2;
            switch (h)
            {
            case 0:
                str2bytes(value, key);
                break;
            case 1:
                if (s[1] == sizeof iv) str2bytes(value, iv);
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
                str2bytes(value, c + s[4]);
                break;
            }
            e += (h == 3 || h == 4 || h == 5);
        }
        if (e == 3)
        {
            if (AES_KEYLENGTH == *s && GCM_NONCE_LEN == s[1] && s[5] >= GCM_TAG_LEN)
            {
                e = verifygcm(key, iv, p, a, c, s[3], s[2], buffer);
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
