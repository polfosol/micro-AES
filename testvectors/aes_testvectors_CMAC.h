/*
 ==============================================================================
 Name        : aes_testvectors_CMAC.h
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-CMAC
 ==============================================================================
 */

#ifndef _TESTING_CMAC_H_
#define _TESTING_CMAC_H_

#include "aes_testvectors.h"
#ifdef CMAC_TEST_FILE

static int verifycmac(uint8_t* key, uint8_t* d, uint8_t* m,
                      size_t nd, size_t nm, char* r)
{
    char sk[2 * AES_KEY_SIZE + 1], smac[33], msg[30];
    uint8_t tmp[16], v = 0;
    strcpy(msg, "passed the test");
    AES_CMAC(key, d, nd, tmp);

    if ((v = memcmp(m, tmp, nm)) != 0)  strcpy(msg, "failed");

    bytes2str(key, sk, AES_KEY_SIZE);
    bytes2str(m, smac, nm);
    sprintf(r, "%s\nK: %s\nmac: %s\n", msg, sk, smac);
    return v;
}

static void aes_cmac_test(FILE** files, unsigned* count)
{
    const char *linehdr[] = CMAC_HEADLINES;
    char buffer[0x20100], *value = NULL;
    size_t s[3] = { 0 };
    uint8_t j, n = 0, key[AES_KEY_SIZE], d[0x10100], m[16];

    count[2] = ~0U;

    while (fgets(buffer, sizeof buffer, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) < 4)  continue;
        for (j = 0; j < 3; j++)
        {
            if (strncmp(buffer, linehdr[j], strlen(linehdr[j])) == 0)
            {
                value = strrchr(buffer, ' ') + 1;
                s[j] = strlen(value) / 2;
                n += j > 0;
                break;
            }
        }
        switch (j)
        {
        case 0:
            if (s[0] == AES_KEY_SIZE) str2bytes(value, key);
            break;
        case 1:
            str2bytes(value, d);
            s[1] -= (s[1] == 1 && d[0] == 0); /* null message */
            break;
        case 2:
            str2bytes(value, m);
            break;
        }
        if (n == 2)
        {
            if (s[0] == AES_KEY_SIZE)
            {
                n = verifycmac(key, d, m, s[1], s[2], buffer);
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
