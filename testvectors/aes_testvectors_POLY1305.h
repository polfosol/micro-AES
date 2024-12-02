/*
 ==============================================================================
 Name        : aes_testvectors_POLY1305.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-POLY1305
 ==============================================================================
 */

#ifndef _TESTING_POLY1305_H_
#define _TESTING_POLY1305_H_

#include "aes_testvectors.h"
#ifdef POLY_TEST_FILE

static int verifypoly(uint8_t* key, uint8_t* non, uint8_t* d, uint8_t* m,
                      size_t nd, char* r)
{
    char sk[2 * AES_KEY_SIZE + 33], smac[33], msg[30];
    uint8_t tmp[16], v = 0;
    strcpy(msg, "passed the test");
    AES_Poly1305(key, non, d, nd, tmp);

    if ((v = memcmp(m, tmp, 16)) != 0)  strcpy(msg, "failed");

    bytes2str(key, sk, AES_KEY_SIZE + 16);
    bytes2str(m, smac, 16);
    sprintf(r, "%s\nK: %s\npoly: %s\n", msg, sk, smac);
    return v;
}

static void aes_poly1305_test(FILE** files, unsigned* count)
{
    const char *linehdr[] = POLY_HEADLINES;
    char buffer[0x20100], *value = NULL;
    size_t s[4] = { 0 };
    uint8_t j, n = 0, key[AES_KEY_SIZE + 16], nc[16], d[0x10100], m[16];

    count[2] = ~0U;

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) < 4)  continue;
        for (j = 0; j < 4; j++)
        {
            if (strncmp(buffer, linehdr[j], strlen(linehdr[j])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                s[j] = strlen(value) / 2;
                n += j > 1;
                break;
            }
        }
        switch (j)
        {
        case 0:
            if (s[0] == AES_KEY_SIZE + 16) str2bytes(value, key);
            break;
        case 1:
            str2bytes(value, nc);
            break;
        case 2:
            str2bytes(value, d);
            break;
        case 3:
            str2bytes(value, m);
            break;
        }
        if (n == 2)
        {
            if (s[0] == AES_KEY_SIZE + 16)
            {
                n = verifypoly(key, nc, d, m, s[2], buffer);
                fprintf(files[2 - !n], "%s\n", buffer); /* save the log */
                ++count[0];
                if (n)  ++count[1];
            }
            n = 0;
        }
    }
}

#endif
#endif /* header guard */
