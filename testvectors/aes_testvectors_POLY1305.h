/*
 ==============================================================================
 Name        : aes_testvectors_POLY1305.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-POLY1305
 ==============================================================================
 */

#include "aes_testvectors.h"

#if defined(_TESTING_POLY1305_H_) ^ defined(POLY_TEST_FILE)
#define _TESTING_POLY1305_H_

int verifypoly(uint8_t* key, uint8_t* non, uint8_t* d, uint8_t* m,
               size_t nd, char* r)
{
    char sk[2 * AES_KEYLENGTH + 33], smac[33], msg[30];
    uint8_t tmp[16], v = 0;
    strcpy(msg, "passed the test");
    AES_Poly1305(key, non, d, nd, tmp);

    if ((v = memcmp(m, tmp, 16)) != 0)  strcpy(msg, "failed");

    bytes2str(key, sk, AES_KEYLENGTH + 16);
    bytes2str(m, smac, 16);
    sprintf(r, "%s\nK: %s\npoly: %s\n", msg, sk, smac);
    return v;
}

void aes_poly1305_test(FILE** files, unsigned* count)
{
    const char* head[] = POLY_HEADLINES;
    size_t s[4] = { 0 };
    uint8_t h, *d, e = 0, key[AES_KEYLENGTH + 16], n[16], m[16];
    char *value = NULL, *buffer;

    count[2] = ~0U;
    if ((buffer = malloc(LINES_MAX_LEN / 2 * 3)) == NULL)
    {
        printf("Memory allocation failed.\n");
        return;
    }
    while (fgets(buffer, LINES_MAX_LEN, *files) != NULL)
    {
        buffer[ strcspn(buffer, "\n") ] = 0;
        for (h = strlen(buffer) < 4 ? 4 : 0; h < 4; ++h)
        {
            if (strncmp(buffer, head[h], strlen(head[h])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                d = (uint8_t*) &buffer[LINES_MAX_LEN];
                s[h] = strlen(value) / 2;
                e += (h == 2 || h == 3);
                break;
            }
        }
        switch (h)
        {
        case 0:
            if (s[0] == sizeof key) str2bytes(value, key);
            break;
        case 1:
            str2bytes(value, n);
            break;
        case 2:
            str2bytes(value, d);
            break;
        case 3:
            str2bytes(value, m);
            break;
        }
        if (e == 2)
        {
            if (s[0] == sizeof key)
            {
                e = verifypoly(key, n, d, m, s[2], buffer);
                fprintf(files[2 - !e], "%s\n", buffer); /* save the log */
                ++count[0];
                count[1] += e != 0;
            }
            e = 0;
        }
    }
    free(buffer);
}

#endif /* header guard */
