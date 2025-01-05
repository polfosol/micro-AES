/*
 ==============================================================================
 Name        : aes_testvectors_CCM.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-CCM
 ==============================================================================
 */

#include "aes_testvectors.h"

#if defined(_TESTING_CCM_H_) ^ defined(CCM_TEST_FILE)
#define _TESTING_CCM_H_

int verifyccm(uint8_t* key, uint8_t* i, uint8_t* p, uint8_t* a, uint8_t* c,
              size_t np, size_t na, char* r)
{
    char sk[2 * AES_KEYLENGTH + 1], si[33], sp[80], sc[96], sa[80], msg[30];
    uint8_t tmp[64], v = 0;
    strcpy(msg, "passed the test");

    AES_CCM_encrypt(key, i, a, na, p, np, tmp);
    if (memcmp(c, tmp, np + CCM_TAG_LEN))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    *r = AES_CCM_decrypt(key, i, a, na, c, np, tmp);
    if (*r || memcmp(p, tmp, np))
    {
        strcat(strcpy(msg, v ? "encrypt & " : ""), "decrypt failure");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEYLENGTH);
    bytes2str(i, si, CCM_NONCE_LEN);
    bytes2str(p, sp, np);
    bytes2str(a, sa, na);
    bytes2str(c, sc, np + CCM_TAG_LEN);
    sprintf(r, "%s\nK: %s\ni: %s\nP: %s\nA: %s\nC: %s", msg, sk, si, sp, sa, sc);
    return v;
}

void aes_ccm_test(FILE** files, unsigned* count)
{
    const char* head[] = CCM_HEADLINES;
    char buffer[0x800], *value = NULL;
    size_t s[5] = { 0 };
    uint8_t j, e = 0, key[AES_KEYLENGTH], iv[CCM_NONCE_LEN], p[64], c[80], a[64];

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        j = strlen(buffer) < 4 ? 5 : 0;

        for (; j < 5 && strncmp(buffer, head[j], strlen(head[j])); ++j);

        if (j != 5)
        {
            value = strrchr(buffer, ' ') + 1;
            s[j] = strlen(value) / 2 - CCM_TAG_LEN * (j == 4);
            e += (j == 3 || j == 4);
        }
        switch (j)
        {
        case 0:
            if (s[0] == sizeof key) str2bytes(value, key);
            break;
        case 1:
            if (s[1] == sizeof  iv) str2bytes(value, iv);
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
        if (e == 2)
        {
            if (s[0] == AES_KEYLENGTH && s[1] == CCM_NONCE_LEN && s[3] == s[4])
            {
                e = verifyccm(key, iv, p, a, c, s[3], s[2], buffer);
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
