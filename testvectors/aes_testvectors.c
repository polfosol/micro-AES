/*
 ==============================================================================
 Name        : aes_testvectors.c
 Author      : polfosol
 Version     : 1.1.0.0
 Copyright   : copyright © 2024 - polfosol
 Description : check the test-vectors for enabled modes of µAES ™
 ==============================================================================
 */

#include "aes_testvectors_GCM.h"
#include "aes_testvectors_CCM.h"
#include "aes_testvectors_XTS.h"
#include "aes_testvectors_FPE.h"
#include "aes_testvectors_OCB.h"
#include "aes_testvectors_GCMSIV.h"
#include "aes_testvectors_CMAC.h"
#include "aes_testvectors_POLY1305.h"

int main(void)
{
#ifdef CMAC_TEST_FILE
    check_testvectors("CMAC", CMAC_TEST_FILE, &aes_cmac_test);
#endif

#ifdef POLY_TEST_FILE
    check_testvectors("POLY1305", POLY_TEST_FILE, &aes_poly1305_test);
#endif

#ifdef GCM_TEST_FILE
    check_testvectors("GCM", GCM_TEST_FILE, &aes_gcm_test);
#endif

#ifdef CCM_TEST_FILE
    check_testvectors("CCM", CCM_TEST_FILE, &aes_ccm_test);
#endif

#ifdef OCB_TEST_FILE
    check_testvectors("OCB", OCB_TEST_FILE, &aes_ocb_test);
#endif

#ifdef GCMSIV_TEST_FILE
    check_testvectors("GCM-SIV", GCMSIV_TEST_FILE, &aes_gcmsiv_test);
#endif

#ifdef XTS_TEST_FILE
    check_testvectors("XTS", XTS_TEST_FILE, &aes_xts_test);
#endif

#ifdef FPE_TEST_FILE
    check_testvectors("FPE", FPE_TEST_FILE, &aes_fpe_test);
#endif
    return 0;
}
