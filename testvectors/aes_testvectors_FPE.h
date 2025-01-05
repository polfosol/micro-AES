/*
 ==============================================================================
 Name        : aes_testvectors_FPE.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-FPE
 ==============================================================================
 */

#include "aes_testvectors.h"

#if defined(_TESTING_FPE_H_) ^ defined(FPE_TEST_FILE)
#define   _TESTING_FPE_H_
#include "../micro_fpe.h"

int verifyfpe(uint8_t* key, uint8_t* twk, const char* a, char* p, char* c,
              size_t np, size_t nt, char* r)
{
#if FF_X == 3
#define TWK_ARGS twk
#else
#define TWK_ARGS twk, nt
#endif
    char sk[2 * AES_KEYLENGTH + 1], st[65], msg[30], tmp[0x800], v = 0;
    strcpy(msg, "passed the test");

    AES_FPE_encrypt(key, TWK_ARGS, p, np, tmp);
    if (memcmp(c, tmp, np))
    {
        strcpy(msg, "encrypt failure");
        v = 1;
    }
    memset(tmp, 0xcc, sizeof tmp);
    *r = AES_FPE_decrypt(key, TWK_ARGS, c, np, tmp);
    if (*r || memcmp(p, tmp, np))
    {
        strcat(strcpy(msg, v ? "encrypt & " : ""), "decrypt failure");
        v |= 2;
    }
    bytes2str(key, sk, AES_KEYLENGTH);
    bytes2str(twk, st, nt);
    sprintf(r, "%s\nA: %s\nK: %s\nT: %s\nP: %s\nC: %s", msg, a, sk, st, p, c);
    return v;
}

void aes_fpe_test(FILE** files, unsigned* count)
{
    const char *head[] = FPE_HEADLINES, *alphabets[] = FPE_ALPHABETS, *a;
    char buffer[0x1000], p[0x800], c[0x800], *value = NULL;
    size_t s[6] = { 0 };
    uint8_t h, key[32], twk[32], e = 0;

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[ strcspn(buffer, "\n") ] = 0;
        for (h = strlen(buffer) < 4 ? 6 : 0; h < 6; ++h)
        {
            if (strncmp(buffer, head[h], strlen(head[h])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                s[h] = h ? strlen(value) : value[2] != '3'; /* is it FF1 */
                e += (h == 3 || h == 4 || h == 5);
                break;
            }
        }
        switch (h)
        {
        case 1:
            do
                a = alphabets[h - 1];
            while ((strlen(a) != s[1] || memcmp(a, value, s[1])) && h++ < 10);

            s[1] = h - 1;
            break;
        case 2:
            s[2] /= 2;
            str2bytes(value, key);
            break;
        case 3:
            s[3] /= 2;
            str2bytes(value, twk);
            break;
        case 4:
            strcpy(p, value);
            break;
        case 5:
            strcpy(c, value);
            break;
        }
        if (e == 3)
        {
#if FF_X == 3
            s[0] = !*s && (s[3] == FF3_TWEAK_LEN || !(twk[3] + twk[7]));
#endif
            if (s[0] && s[1] == CUSTOM_ALPHABET && s[2] == AES_KEYLENGTH)
            {
                e = verifyfpe(key, twk, a, p, c, s[4], s[3], buffer);
                fprintf(files[2 - !e], "%s\n\n", buffer); /* save the log */
                ++count[0];
                if (e & 1) ++count[1];
                if (e & 2) ++count[2];
            }
            e = 0;
        }
    }
}

#endif /* header guard */
