/*
 ==============================================================================
 Name        : micro_fpe.h
 Author      : polfosol
 Version     : 1.2.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : this file contains some sample alphabets for FPE mode of μAES ™
 ==============================================================================
 */

#ifndef MICRO_FPE_H_
#define MICRO_FPE_H_

/** If your desired alphabet contains non-ASCII characters, the CUSTOM_ALPHABET
 * macro 'must be' set to a double-digit number, e.g 21. Please note that ANSI-C
 * standard does not support such characters and the code loses its compliance
 * in this case. In what follows, you will find some sample alphabets along with
 * their corresponding macro definitions. It is straightforward to set another
 * custom alphabet according to these samples.  ------------------------------*/

#define NON_ASCII_CHARACTER_SET  (CUSTOM_ALPHABET >= 10)

#if NON_ASCII_CHARACTER_SET
#include <wchar.h>
#include <locale.h>
#define  string_t  wchar_t*
#else
#define  string_t  char*                         /*  string pointer type      */
#endif

#if CUSTOM_ALPHABET == 0
#define ALPHABET "0123456789"
#define RADIX    10                              /*  strlen (ALPHABET)        */
#define LOGRDX   3.321928095                     /*  log2 (RADIX)             */
#endif

/**----------------------------------------------------------------------------
 lowercase english letters
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 1
#define ALPHABET "abcdefghijklmnopqrstuvwxyz"
#define RADIX    26
#define LOGRDX   4.700439718
#endif

/**----------------------------------------------------------------------------
 lowercase alphanumeric strings
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 2
#define ALPHABET "0123456789abcdefghijklmnopqrstuvwxyz"
#define RADIX    36
#define LOGRDX   5.169925001
#endif

/**----------------------------------------------------------------------------
 a character set with length 26
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 3
#define ALPHABET "0123456789abcdefghijklmnop"
#define RADIX    26
#define LOGRDX   4.700439718
#endif

/**----------------------------------------------------------------------------
 uppercase hex strings
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 4
#define ALPHABET "0123456789ABCDEF"
#define RADIX    16
#define LOGRDX   4
#endif

/**----------------------------------------------------------------------------
 the English alphabet
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 5
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define RADIX    52
#define LOGRDX   5.700439718
#endif

/**----------------------------------------------------------------------------
 base-64 encoded strings (RFC-4648), with no padding character
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 6
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define RADIX    64
#define LOGRDX   6
#endif

/**----------------------------------------------------------------------------
 base-85 encoded strings (RFC-1924)
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 7
#define ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
#define RADIX    85
#define LOGRDX   6.409390936
#endif

/**----------------------------------------------------------------------------
 Greek alphabet
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 10
#define ALPHABET L"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψω"
#define RADIX    49
#define LOGRDX   5.614709844
#endif

/**----------------------------------------------------------------------------
 Persian alphabet
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 11
#define ALPHABET L"ءئاآبپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"
#define RADIX    35
#define LOGRDX   5.129283017
#endif


/******************************************************************************
 minimum mandatory length of the input strings: ceiling of (6 / log10 (RADIX))
 -----------------------------------------------------------------------------*/
#if RADIX > 99
#define MINLEN  (2 + (RADIX < 1000))
#elif RADIX > 5
#define MINLEN  (4 + (RADIX < 32) + (RADIX < 16) + (RADIX < 10) + (RADIX < 8))
#else
#define MINLEN  (20 / (RADIX >> 1) - (RADIX & 1) - 6 * (RADIX == 3))
#endif

#if FF_X == 3
#include <math.h>
#define MAXLEN  (2 * (int) (96 / log( RADIX ) * log( 2 )))
#endif

#endif /* header guard */
