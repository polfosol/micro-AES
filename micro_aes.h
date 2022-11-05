/*
 ==============================================================================
 Name        : micro_aes.h
 Author      : polfosol
 Version     : 9.5.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : μAES ™ is a minimalist all-in-one library for AES encryption
 ==============================================================================
 */

#ifndef _MICRO__AES_
#define _MICRO__AES_

/**----------------------------------------------------------------------------
You can use different AES algorithms by changing this macro. Default is AES-128
 -----------------------------------------------------------------------------*/
#define AES___     128     /* or 256 (or 192; not standardized in some modes) */

/**----------------------------------------------------------------------------
AES block-cipher modes of operation. The following modes can be enabled/disabled
 by setting their corresponding macros to TRUE (1) or FALSE (0).
 -----------------------------------------------------------------------------*/
#define BLOCKCIPHERS 1
#define AEAD_MODES   1     /* authenticated encryption with associated data.  */

#if BLOCKCIPHERS
#define ECB          1     /* electronic code-book (NIST SP 800-38A)          */
#define CBC          1     /* cipher block chaining (NIST SP 800-38A)         */
#define CFB          1     /* cipher feedback (NIST SP 800-38A)               */
#define OFB          1     /* output feedback (NIST SP 800-38A)               */
#define CTR          1     /* counter-block (NIST SP 800-38A)                 */
#define XEX          1     /* xor-encrypt-xor (NIST SP 800-38E)               */
#define KWA          1     /* key wrap with authentication (NIST SP 800-38F)  */
#define FPE          0     /* format-preserving encryption (NIST SP 800-38G)  */
#endif

#if AEAD_MODES
#define CMAC         1     /* message authentication code (NIST SP 800-38B)   */

#if CTR
#define CCM          1     /* counter with CBC-MAC (RFC-3610 & SP 800-38C)    */
#define GCM          1     /* Galois/counter mode with GMAC (NIST SP 800-38D) */
#define EAX          1     /* encrypt-authenticate-translate (ANSI C12.22)    */
#define SIV          1     /* synthetic initialization vector (RFC-5297)      */
#define GCM_SIV      1     /* nonce misuse-resistant AES-GCM (RFC-8452)       */
#endif

#if XEX
#define OCB          1     /* offset codebook mode with PMAC (RFC-7253)       */
#endif

#define POLY1305     1     /* poly1305-AES mac (https://cr.yp.to/mac.html)    */
#endif

#if CBC
#define CTS          1     /* ciphertext stealing (CS3: unconditional swap)   */
#endif

#if XEX
#define XTS          1     /* XEX tweaked-codebook with ciphertext stealing   */
#endif

#if CTR
#define CTR_NA       1     /* pure counter mode, with no authentication       */
#endif

#if EAX
#define EAXP         0     /* EAX-prime, as specified by IEEE Std 1703        */
#endif

#define WTF ! (POLY1305 || CMAC || BLOCKCIPHERS)
#define M_RIJNDAEL  WTF    /* none of above; just rijndael API. dude.., why?  */

/**----------------------------------------------------------------------------
Refer to the BOTTOM OF THIS DOCUMENT for some explanations about these macros:
 -----------------------------------------------------------------------------*/

#if ECB || CBC || XEX || KWA || M_RIJNDAEL
#define DECRYPTION   1
#endif

#if ECB || (CBC && !CTS) || (XEX && !XTS)
#define AES_PADDING  0     /* other valid values:  (1) PKCS#7  (2) IEC7816-4  */
#endif

#if CFB || OFB || CTR || OCB
#define PARTIAL_DATA_PASS  /* supports data units shorter than a full block.  */
#endif

#if CTR_NA
#define CTR_IV_LENGTH  12  /* for using the last 32 bits as counter           */
#define CTR_STARTVALUE  1  /* recommended value according to the RFC-3686.    */
#endif

#if CCM
#define CCM_NONCE_LEN  11  /* for 32-bit count (since one byte is reserved).  */
#define CCM_TAG_LEN    16  /* an even number in the range of 4..16            */
#endif

#if GCM
#define GCM_NONCE_LEN  12  /* RECOMMENDED. but other values are supported.    */
#endif

#if EAX && !EAXP
#define EAX_NONCE_LEN  16  /* practically no limit; can be arbitrarily large  */
#endif

#if OCB
#define OCB_TAG_LEN    16  /* again, please see the bottom of this document!  */
#endif

/**----------------------------------------------------------------------------
Since stdint.h is not a part of ANSI-C, we used a 'trick' that should not cause
 any problems. You may replace the following two lines by: #include <stdint.h>
 -----------------------------------------------------------------------------*/
typedef  unsigned char  uint8_T;
#define  uint8_t  uint8_T
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**----------------------------------------------------------------------------
Encryption/decryption of a single block with Rijndael
 -----------------------------------------------------------------------------*/
#if M_RIJNDAEL
void AES_Cipher( const uint8_t* key,          /* encryption/decryption key    */
                 const char mode,             /* encrypt: 'E', decrypt: 'D'   */
                 const uint8_t* x,            /* input block byte array       */
                 uint8_t* y );                /* output block byte array      */
#endif

/**----------------------------------------------------------------------------
Main functions for ECB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if ECB
void AES_ECB_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* pText,   /* plain text buffer            */
                      const size_t pTextLen,  /* length of input plain text   */
                      uint8_t* cText );       /* cipher-text result           */

char AES_ECB_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* cText,   /* cipher text buffer           */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      uint8_t* pText );       /* plain-text result            */
#endif /* ECB */

/**----------------------------------------------------------------------------
Main functions for CBC-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CBC
char AES_CBC_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* iVec,    /* initialization vector        */
                      const uint8_t* pText,   /* plain text buffer            */
                      const size_t pTextLen,  /* length of input plain text   */
                      uint8_t* cText );       /* cipher-text result           */

char AES_CBC_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* iVec,    /* initialization vector        */
                      const uint8_t* cText,   /* cipher text buffer           */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      uint8_t* pText );       /* plain-text result            */
#endif /* CBC */

/**----------------------------------------------------------------------------
Main functions for CFB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CFB
void AES_CFB_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* iVec,    /* initialization vector        */
                      const uint8_t* pText,   /* plain text buffer            */
                      const size_t pTextLen,  /* length of input plain text   */
                      uint8_t* cText );       /* cipher-text result           */

void AES_CFB_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* iVec,    /* initialization vector        */
                      const uint8_t* cText,   /* cipher text buffer           */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      uint8_t* pText );       /* plain-text result            */
#endif /* CFB */

/**----------------------------------------------------------------------------
Main functions for OFB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if OFB
void AES_OFB_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* iVec,    /* initialization vector        */
                      const uint8_t* pText,   /* plain text buffer            */
                      const size_t pTextLen,  /* length of input plain text   */
                      uint8_t* cText );       /* cipher-text result           */

void AES_OFB_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* iVec,    /* initialization vector        */
                      const uint8_t* cText,   /* cipher text buffer           */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      uint8_t* pText );       /* plain-text result            */
#endif /* OFB */

/**----------------------------------------------------------------------------
Main functions for XTS-AES block ciphering
 -----------------------------------------------------------------------------*/
#if XTS
char AES_XTS_encrypt( const uint8_t* keys,    /* encryption key pair          */
                      const uint8_t* unitId,  /* tweak value (sector ID)      */
                      const uint8_t* pText,   /* plain text buffer            */
                      const size_t pTextLen,  /* length of input plain text   */
                      uint8_t* cText );       /* cipher-text result           */

char AES_XTS_decrypt( const uint8_t* keys,    /* decryption key pair          */
                      const uint8_t* unitId,  /* tweak value (sector ID)      */
                      const uint8_t* cText,   /* cipher text buffer           */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      uint8_t* pText );       /* plain-text result            */
#endif /* XTS */

/**----------------------------------------------------------------------------
Main functions for CTR-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CTR_NA
void AES_CTR_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* iv,      /* initialization vector/ nonce */
                      const uint8_t* pText,   /* plain text buffer            */
                      const size_t pTextLen,  /* length of input plain text   */
                      uint8_t* cText );       /* cipher-text result           */

void AES_CTR_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* iv,      /* initialization vector/ nonce */
                      const uint8_t* cText,   /* cipher text buffer           */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      uint8_t* pText );       /* plain-text result            */
#endif /* CTR */

/**----------------------------------------------------------------------------
Main functions for SIV-AES block ciphering
 -----------------------------------------------------------------------------*/
#if SIV
void AES_SIV_encrypt( const uint8_t* keys,    /* encryption key pair          */
                      const uint8_t* pText,   /* plain text                   */
                      const size_t pTextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* iv,            /* synthesized initial-vector   */
                      uint8_t* cText );       /* cipher-text result           */

char AES_SIV_decrypt( const uint8_t* keys,    /* decryption key pair          */
                      const uint8_t* iv,      /* provided initial-vector      */
                      const uint8_t* cText,   /* cipher text                  */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* pText );       /* plain-text result            */
#endif /* SIV */

/**----------------------------------------------------------------------------
Main functions for GCM-AES block ciphering
 -----------------------------------------------------------------------------*/
#if GCM
void AES_GCM_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* pText,   /* plain text                   */
                      const size_t pTextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* cText,         /* cipher-text result           */
                      uint8_t* auTag );       /* message authentication tag   */

char AES_GCM_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* cText,   /* cipher text + appended tag   */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
                      uint8_t* pText );       /* plain-text result            */
#endif /* GCM */

/**----------------------------------------------------------------------------
Main functions for CCM-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CCM
void AES_CCM_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* pText,   /* plain text                   */
                      const size_t pTextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* cText,         /* cipher-text result           */
                      uint8_t* auTag );       /* message authentication tag   */

char AES_CCM_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* cText,   /* cipher text + appended tag   */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
                      uint8_t* pText );       /* plain-text result            */
#endif /* CCM */

/**----------------------------------------------------------------------------
Main functions for OCB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if OCB
void AES_OCB_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* 96-bit initialization vector */
                      const uint8_t* pText,   /* plain text                   */
                      const size_t pTextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* cText,         /* cipher-text result           */
                      uint8_t* auTag );       /* message authentication tag   */

char AES_OCB_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* 96-bit initialization vector */
                      const uint8_t* cText,   /* cipher text + appended tag   */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
                      uint8_t* pText );       /* plain-text result            */
#endif /* OCB */

/**----------------------------------------------------------------------------
Main functions for EAX-AES mode; more info at the bottom of this document.
 -----------------------------------------------------------------------------*/
#if EAX
void AES_EAX_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* arbitrary-size nonce array   */
                      const uint8_t* pText,   /* plain text                   */
                      const size_t pTextLen,  /* length of input plain text   */
#if EAXP
                      const size_t nonceLen,  /* size of provided nonce       */
                      uint8_t* cText );       /* cipher-text result + mac (4) */
#else
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* cText,         /* cipher-text result           */
                      uint8_t* auTag );       /* message authentication tag   */
#endif

char AES_EAX_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* arbitrary-size nonce array   */
                      const uint8_t* cText,   /* cipher text + appended tag   */
                      const size_t cTextLen,  /* length of input cipher-text  */
#if EAXP
                      const size_t nonceLen,  /* size of provided nonce       */
#else
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
#endif
                      uint8_t* pText );       /* plain-text result            */
#endif /* EAX */

/**----------------------------------------------------------------------------
Main functions for GCM-SIV-AES block ciphering
 -----------------------------------------------------------------------------*/
#if GCM_SIV
void GCM_SIV_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* provided 96-bit nonce        */
                      const uint8_t* pText,   /* plain text                   */
                      const size_t pTextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* cText,         /* cipher-text result           */
                      uint8_t* auTag );       /* 16-bytes mandatory tag       */

char GCM_SIV_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* provided 96-bit nonce        */
                      const uint8_t* cText,   /* cipher text + appended tag   */
                      const size_t cTextLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (must be 16)     */
                      uint8_t* pText );       /* plain-text result            */
#endif /* GCM-SIV */

/**----------------------------------------------------------------------------
Main functions for AES key-wrapping; more info at the bottom of this page.
 -----------------------------------------------------------------------------*/
#if KWA
void AES_KEY_wrap( const uint8_t* kek,        /* key encryption key           */
                   const uint8_t* secret,     /* input secret to be wrapped   */
                   const size_t secretLen,    /* size of input                */
                   uint8_t* wrapped );        /* key-wrapped output           */

char AES_KEY_unwrap( const uint8_t* kek,      /* key encryption key           */
                     const uint8_t* wrapped,  /* key-wrapped secret           */
                     const size_t wrapLen,    /* size of input (secretLen +8) */
                     uint8_t* secret );       /* buffer for unwrapped key     */
#endif /* KWA */

/**----------------------------------------------------------------------------
Main functions for FPE-AES (to be added soon)
 -----------------------------------------------------------------------------*/
#if FPE

#endif /* FPE */

/**----------------------------------------------------------------------------
Main function for Poly1305-AES message authentication code
 -----------------------------------------------------------------------------*/
#if POLY1305
void AES_Poly1305( const uint8_t* keys,       /* encryption/mixing key pair   */
                   const uint8_t* nonce,      /* the 128-bit nonce            */
                   const void* data,          /* input data buffer            */
                   const size_t dataSize,     /* size of data in bytes        */
                   uint8_t* mac );            /* calculated poly1305 hash     */
#endif

/**----------------------------------------------------------------------------
Main function for AES Cipher-based Message Authentication Code
 -----------------------------------------------------------------------------*/
#if CMAC
void AES_CMAC( const uint8_t* key,            /* encryption/cipher key        */
               const void* data,              /* input data buffer            */
               const size_t dataSize,         /* size of data in bytes        */
               uint8_t* mac );                /* calculated CMAC hash         */
#endif

#ifdef __cplusplus
}
#endif

/**----------------------------------------------------------------------------
The error codes and key length should be defined here for external references:
 -----------------------------------------------------------------------------*/
#define ENCRYPTION_FAILURE       0x1E
#define DECRYPTION_FAILURE       0x1D
#define AUTHENTICATION_FAILURE   0x1A
#define ENDED_IN_SUCCESS         0x00

#if (AES___ == 256) || (AES___ == 192)
#define AES_KEY_LENGTH (AES___/8)
#else
#define AES_KEY_LENGTH  16
#endif

#endif /* header guard */

/**--------------------------------------------------------------------------**\
|               Notes and remarks about the above-defined macros               |
+------------------------------------------------------------------------------+

> Some AES modes just use the 'encryption' part of the Rijndael algorithm. So if
    you are NOT using the decryption functions of ECB/CBC/KWA/XEX modes, you can
    safely disable DECRYPTION macro and save a few kilobytes in compiled code.

> In EBC/CBC/XEX modes, the size of input must be a multiple of block-size.
    Otherwise it needs to be padded. The simplest (default) padding mode is to
    fill the rest of block by zeros. Supported standard padding methods are
    PKCS#7 and ISO/IEC 7816-4, which can be enabled by AES_PADDING macro.

> In many texts, you may see that the words 'nonce' and 'initialization vector'
    are used interchangeably. But they have a subtle difference. Sometimes nonce
    is a part of the I.V, which itself can either be a full block or a partial
    one. In CBC/CFB/OFB modes, the provided I.V must be a full block. In pure
    CTR mode (CTR_NA) you can either provide a 96-bit I.V and let the count
    start at CTR_STARTVALUE, or use a full block IV.

> In AEAD modes, the size of nonce and tag might be a parameter of the algorithm
    such that changing them affect the results. The GCM/EAX modes support
    arbitrary sizes for nonce. In CCM, the nonce length may vary from 8 to 13
    bytes. Also the tag size is an EVEN number between 4..16. In OCB, only the
    tag size is a parameter between 0..16 bytes. Note that the 'calculated' tag
    size is always 16 bytes which can later be truncated to desired values. So
    in encryption functions, the provided authTag buffer must be 16 bytes long.

> For the EAX mode of operation, the IEEE-1703 standard defines EAX' which is a
    modified version that combines AAD and nonce. Also the tag size is fixed to
    4 bytes. So EAX-prime functions don't need to take additional authentication
    data and tag-size as separate parameters.

> In SIV mode, multiple separate units of authentication headers can be provided
    for the nonce synthesis. Here we assume that only one unit of AAD (aData) is
    sufficient, which is practically true.

> The key wrapping mode is also denoted by KW. In this mode, the input secret is
    divided into 64bit blocks. Number of blocks is at least 2, and it is assumed
    that no padding is required. For padding, the KWP mode is used which is
    easily implementable, but left as an exercise! In the NIST document you may
    find some mentions of TKW which is for 3DES and irrelevant here. Anyway, the
    wrapped output has an additional block, i.e. wrappedSize = secretSize + 8.

> Let me explain three extra options that are defined in the source file. If the
    length of the input cipher/plain text is 'always' less than 4KB, you can
    enable the SMALL_CIPHER macro to save a few bytes in the compiled code. Note
    that for key-wrapping, this limit is 42 blocks (336 bytes) of secret key.
    These assumptions are likely to be valid for some embedded systems and small
    applications. Furthermore, enabling that other macro, REDUCE_CODE_SIZE had a
    considerable effect on the size of the compiled code in my own tests.
    Nonetheless, others might get a different result from them.

    The INCREASE_SECURITY macro, as its name suggests, is dealing with security
    considerations. For example, since the RoundKey is declared as static array,
    it might be exposed to some attacks. By enabling this macro, round-keys are
    wiped out at the end of ciphering operations. However, please keep in mind
    that this is NOT A GUARANTEE against side-channel attacks.

*/
