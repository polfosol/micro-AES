/*
 ==============================================================================
 Name        : micro_fpe.h
 Author      : polfosol
 Version     : 11
 Copyright   : copyright © 2022 - polfosol
 Description : demonstrating some sample alphabets for the FPE mode of μAES ™
 ==============================================================================
 */

#ifndef MICRO_FPE_H_
#define MICRO_FPE_H_

/**
 * If your desired alphabet contains non-ASCII characters, the CUSTOM_ALPHABET
 * macro 'must be' set to a double-digit number, e.g. 21.
 */
#define ALPHABET_IS_NON_ASCII  (CUSTOM_ALPHABET >= 10)

#if ALPHABET_IS_NON_ASCII
/**
 * Note that C89/ANSI-C standard does not fully support such characters, and the
 * code may lose its compliance in this case.
 */
#include <locale.h>
#include <wchar.h>

#else
/**
 * These strings frequently appear in ASCII-based alphabets.
 */
#define DIGITS01  "01"
#define LLETTERS  "abcdefghijklmnopqrstuvwxyz"
#define ULETTERS  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DECIMALS  DIGITS01"23456789"
#endif


/**
 * In what follows, a few sample alphabets and their corresponding macros are
 * provided. Accordingly, it would be straightforward to work with any kind of
 * alphabets. The declaration of an alphabet must be followed by its number of
 * characters (RADIX).
 */
#if !CUSTOM_ALPHABET
#define ALPHABET  DECIMALS
#define RADIX     10

/**
 lowercase english words
 */
#elif CUSTOM_ALPHABET == 1
#define ALPHABET  LLETTERS
#define RADIX     26

/**
 PLACEHOLDER: define your ASCII alphabet here
 */
#elif CUSTOM_ALPHABET == 2
#define ALPHABET  "my Alphabet"
#define RADIX     11

/**
 binary numbers
 */
#elif CUSTOM_ALPHABET == 3
#define ALPHABET  DIGITS01
#define RADIX     2

/**
 lowercase alphanumeric strings
 */
#elif CUSTOM_ALPHABET == 4
#define ALPHABET  DECIMALS LLETTERS
#define RADIX     36

/**
 base-64 encoded strings (RFC-4648), with no padding character
 */
#elif CUSTOM_ALPHABET == 5
#define ALPHABET  ULETTERS LLETTERS DECIMALS "+/"
#define RADIX     64

/**
 base-85 encoded strings (RFC-1924)
 */
#elif CUSTOM_ALPHABET == 6
#define ALPHABET  DECIMALS ULETTERS LLETTERS "!#$%&()*+-;<=>?@^_`{|}~"
#define RADIX     85

/**
 base-64 character set with DIFFERENT ORDERING, used by some test vectors
 */
#elif CUSTOM_ALPHABET == 7
#define ALPHABET  DECIMALS ULETTERS LLETTERS "+/"
#define RADIX     64

/**
 a character set with length 26, used by some test vectors
 */
#elif CUSTOM_ALPHABET == 8
#define ALPHABET  DECIMALS LLETTERS
#define RADIX     26

/**
 all printable ascii characters
 */
#elif CUSTOM_ALPHABET == 9
#define ALPHABET  " !\"#$%&\'()*+,-./"DECIMALS":;<=>?@"ULETTERS"[\\]^_`"LLETTERS"{|}~"
#define RADIX     95

/**
 And here goes NON-ASCII alphabets. The string literal must have an L-prefix.
 ------------------------------------------------------------------------------
 **
 Greek alphabet (LTR)
 */
#elif CUSTOM_ALPHABET == 10
#define ALPHABET L"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφϕχψω"
#define RADIX    50

/**
 Persian alphabet (RTL)
 */
#elif CUSTOM_ALPHABET == 20
#define ALPHABET L"ءئؤآابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"
#define RADIX    36
#endif


/**
 * You can either pre-calculate the value of logarithm (up to 14 decimal places
 * to be safe) and set it as a constant, or use the standard math library.
 */
#include <math.h>
#ifdef  MATH_ERRNO                               /*  then STDC version >= C99 */
#define LOGRDX  log2( RADIX )
#else
#define LOGRDX  (log( RADIX ) / log( 2 ))
#endif

#define MINLEN  (1 + (int) (19.931561 / LOGRDX))

#if FF_X == 3
#define MAXLEN  (2 * (int) (96.000001 / LOGRDX))
#endif

/**
 * MINLEN can also be defined independently, using pure integer arithmetics:
 * 
#define MINLEN  (RADIX < 5 ? 40 / RADIX  : \
                        32 / (1 + RADIX) + (RADIX < 100) + (RADIX < 1000) + 2)
 */
#endif /* header guard */
