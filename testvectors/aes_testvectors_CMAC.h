/*
 ==============================================================================
 Name        : aes_testvectors_CMAC.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : checking the test vectors for AES-CMAC
 ==============================================================================
 */

#include "aes_testvectors.h"

#if defined(_TESTING_CMAC_H_) ^ defined(CMAC_TEST_FILE)
#define _TESTING_CMAC_H_

int verifycmac(uint8_t* key, uint8_t* d, uint8_t* m,
               size_t nd, size_t nm, char* r)
{
    char sk[2 * AES_KEYLENGTH + 1], smac[33], msg[30];
    uint8_t tmp[16], v = 0;
    strcpy(msg, "passed the test");
    AES_CMAC(key, d, nd, tmp);

    if ((v = memcmp(m, tmp, nm)) != 0)  strcpy(msg, "failed");

    bytes2str(key, sk, AES_KEYLENGTH);
    bytes2str(m, smac, nm);
    sprintf(r, "%s\nK: %s\nmac: %s\n", msg, sk, smac);
    return v;
}

void aes_cmac_test(FILE** files, unsigned* count)
{
    const char* head[] = CMAC_HEADLINES;
    size_t s[3] = { 0 };
    uint8_t j, *d, e = 0, key[AES_KEYLENGTH], m[16];
    char *value = NULL, *buffer;

    count[2] = ~0U;
    if ((buffer = malloc(LINES_MAX_LEN / 2 * 3)) == NULL)
    {
        printf("Memory allocation failed.\n");
        return;
    }
    while (fgets(buffer, LINES_MAX_LEN, *files) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = 0;
        j = strlen(buffer) < 4 ? 3 : 0;

        for (; j < 3 && strncmp(buffer, head[j], strlen(head[j])); ++j);

        if (j != 3)
        {
            value = strrchr(buffer, ' ') + 1;
            d = (uint8_t*) &buffer[LINES_MAX_LEN];
            s[j] = strlen(value) / 2;
            e += (j == 1 || j == 2);
        }
        switch (j)
        {
        case 0:
            if (s[0] == sizeof key) str2bytes(value, key);
            break;
        case 1:
            str2bytes(value, d);
            s[1] -= (s[1] == !d[0]); /* null message */
            break;
        case 2:
            str2bytes(value, m);
            break;
        }
        if (e == 2)
        {
            if (s[0] == AES_KEYLENGTH)
            {
                e = verifycmac(key, d, m, s[1], s[2], buffer);
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
