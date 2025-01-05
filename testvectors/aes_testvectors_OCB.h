/*
 ==============================================================================
 Name        : aes_testvectors_OCB.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-OCB
 ==============================================================================
 */

#include "aes_testvectors.h"

#if defined(_TESTING_OCB_H_) ^ defined(OCB_TEST_FILE)
#define _TESTING_OCB_H_

int verifyocb(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* a, uint8_t* c,
              size_t np, size_t na, uint8_t err, char* r)
{
    char sk[65], si[31], sp[0x100], sc[0x100], sa[0x100], msg[30];
    uint8_t tmp[0x90], v = 0;
    strcpy(msg, "passed the test");

    AES_OCB_encrypt(key, i, a, na, p, np, tmp);
    if (memcmp(c, tmp, np + OCB_TAG_LEN) && !err)
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    *r = AES_OCB_decrypt(key, i, a, na, c, np, tmp);
    if (*r && !err || memcmp(p, tmp, np))
    {
        strcat(strcpy(msg, v ? "encrypt & " : ""), "decrypt failure");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEYLENGTH);
    bytes2str(i, si, OCB_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + OCB_TAG_LEN);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return v;
}

void aes_ocb_test(FILE** files, unsigned* count)
{
    const char* head[] = OCB_HEADLINES;
    char buffer[0x800], *value = NULL;
    size_t s[7] = { 0 };
    uint8_t key[AES_KEYLENGTH], tmp[AES_KEYLENGTH], iv[OCB_NONCE_LEN];
    uint8_t j, p[0x80], c[0x90], a[0x80], t[16], e = 1;

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        j = strlen(buffer) < 4 ? 7 : 0;

        for (; j < 7 && strncmp(buffer, head[j], strlen(head[j])); ++j);

        if (j != 7)
        {
            value = strrchr(buffer, ' ') + 1;
            s[j] = strlen(value) / 2;
        }
        switch (j)
        {
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
            memcpy(c + s[4], t, s[5]); /* append the tag */
            break;
        case 5:
            str2bytes(value, t);
            break;
        case 6:
            j = strstr(value, "ERROR") != NULL ? 8 : 0;
            break;
        }
        if ((j == 0 || j > 7) && s[0] == AES_KEYLENGTH)
        {
            str2bytes(value, tmp);
            if (s[1] == OCB_NONCE_LEN && s[5] == OCB_TAG_LEN && !e)
            {
                e = verifyocb(key, iv, p, a, c, s[3], s[2], j, buffer);
                fprintf(files[2 - !e], "%s\n", buffer); /* save the log */
                ++count[0];
                if (e & 1) ++count[1];
                if (e & 2) ++count[2];
            }
            memcpy(key, tmp, sizeof key);
            e = 0;
        }
    }
}

#endif /* header guard */
