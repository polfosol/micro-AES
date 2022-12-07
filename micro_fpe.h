/*
 ==============================================================================
 Name        : micro_fpe.h
 Author      : polfosol
 Version     : 2.0.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : illustrating some sample alphabets for the FPE mode of μAES ™
 ==============================================================================
 */

#ifndef MICRO_FPE_H_
#define MICRO_FPE_H_

/** If your desired alphabet contains non-ASCII characters, the CUSTOM_ALPHABET
 * macro 'must be' set to a double-digit number, e.g 21. Please note that ANSI-C
 * standard does not support such characters and the code loses its compliance
 * in this case. In what follows, you will find some sample alphabets along with
 * their corresponding macro definitions. It is straightforward to set another
 * custom alphabet according to these samples.
 */
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
#endif


/**----------------------------------------------------------------------------
 binary strings
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 1
#define ALPHABET "01"
#define RADIX    2
#endif


/**----------------------------------------------------------------------------
 lowercase english letters
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 2
#define ALPHABET "abcdefghijklmnopqrstuvwxyz"
#define RADIX    26
#endif


/**----------------------------------------------------------------------------
 lowercase alphanumeric strings
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 3
#define ALPHABET "0123456789abcdefghijklmnopqrstuvwxyz"
#define RADIX    36
#endif


/**----------------------------------------------------------------------------
 the English alphabet
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 4
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define RADIX    52
#endif


/**----------------------------------------------------------------------------
 base-64 encoded strings (RFC-4648), with no padding character
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 5
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define RADIX    64
#endif


/**----------------------------------------------------------------------------
 base-85 encoded strings (RFC-1924)
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 6
#define ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
#define RADIX    85
#endif


/**----------------------------------------------------------------------------
 a character set with length 26, used by some test vectors
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 7
#define ALPHABET "0123456789abcdefghijklmnop"
#define RADIX    26
#endif


/**----------------------------------------------------------------------------
 base-64 character set with different ordering, used by some test vectors
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 8
#define ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
#define RADIX    64
#endif


/**----------------------------------------------------------------------------
 Greek alphabet
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 10
#define ALPHABET L"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψω"
#define RADIX    49
#endif


/**----------------------------------------------------------------------------
 Persian alphabet
 -----------------------------------------------------------------------------*/
#if CUSTOM_ALPHABET == 11
#define ALPHABET L"ءئاآبپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"
#define RADIX    35
#endif


/******************************************************************************
 It is mandatory to determine these constants for each alphabet. You can either
 pre-calculate the logarithm value (with at least 10 significant digits) and
 set it as a constant, or let it be calculated dynamically like this:
*/
#include <math.h>
#define LOGRDX  (log( RADIX ) / log( 2 ))        /*  log2( RADIX ) if std=C99 */
#if FF_X == 3
#define MAXLEN  (2 * (int) (96.000001 / LOGRDX))
#endif
#define MINLEN  ((int) (19.931568 / LOGRDX + 1))


/******************************************************************************
 or we can do something like this to set MINLEN:

#if RADIX > 99
#define MINLEN  (2 + (RADIX < 1000))
#elif RADIX > 5
#define MINLEN  (4 + (RADIX < 32) + (RADIX < 16) + (RADIX < 10) + (RADIX < 8))
#else
#define MINLEN  (20 / (RADIX >> 1) - (RADIX & 1) - 6 * (RADIX == 3))
#endif      */

#endif /* header guard */
