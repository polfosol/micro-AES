/*
 ==============================================================================
 Name        : micro_aes.c
 Author      : polfosol
 Version     : 8.9.0.0
 Copyright   : copyright © 2022 - polfosol
 Description : ANSI-C compatible implementation of µAES ™ library.
 ==============================================================================
 */

#include <string.h>
#include "micro_aes.h"

/**--------------------------------------------------------------------------**\
                 Global constants and important / useful MACROs
\*----------------------------------------------------------------------------*/

#define KEYSIZE  AES_KEY_LENGTH
#define BLOCKSIZE  (128/8)   /* Block length in AES is 'always' 128-bits.     */
#define Nb   (BLOCKSIZE/4)   /* The number of columns comprising a AES state. */
#define Nk     (KEYSIZE/4)   /* The number of 32 bit words in a key.          */
#define ROUNDS      (Nk+6)   /* The number of rounds in AES Cipher.           */

/** Since the RoundKey is a static array, it might be exposed to some attacks.
 * By enabling this macro, the RoundKey buffer is wiped at the end of ciphering
 * operations. However, this is NOT A GUARANTEE against side-channel attacks. */
#define INCREASE_SECURITY  0

/** In my own tests, enabling REDUCE_CODE_SIZE had a considerable effect on the
 * size of the compiled code. Nonetheless, others might get different results */
#define REDUCE_CODE_SIZE   1

#define IMPLEMENT(x)   (x) > 0

/**--------------------------------------------------------------------------**\
                               Private variables:
\*----------------------------------------------------------------------------*/

/* The array that stores the round keys during AES key-expansion process .... */
static uint8_t RoundKey[BLOCKSIZE * (ROUNDS + 1)];

/** Lookup-tables are static constant, so that they can be placed in read-only
 * storage instead of RAM. They can be computed dynamically trading ROM for RAM.
 * This may be useful in (embedded) bootloader applications, where ROM is often
 * limited. Please refer to:   https://en.wikipedia.org/wiki/Rijndael_S-box   */
static const uint8_t sbox[256] =
{
/*  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

#if DECRYPTION
static const uint8_t rsbox[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
#endif

/** state_t represents rijndael state matrix. fixed-size memory blocks have an
 * essential role in all algorithms. so it may be a good aide for readability to
 * define a specific type and a function pointer that applies to these blocks */
typedef uint8_t state_t[Nb][4];
typedef uint8_t block_t[BLOCKSIZE];
typedef void  (*fmix_t)(const block_t, block_t);

/**--------------------------------------------------------------------------**\
                   Auxiliary functions for Rijndael algorithm
\*----------------------------------------------------------------------------*/

#define getSBoxValue(num)  (sbox[(num)])

#if REDUCE_CODE_SIZE

/** multiply by 2 in GF(2^8): left-shift and if carry bit is 1, xor with 0x1b */
#define xtime(x)   ( (x << 1) ^ (x & 0x80 ? 0x1b : 0) )

/** performs XOR operation on two 128-bit blocks ............................ */
static void xorBlock( const block_t src, block_t dest )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)  dest[i] ^= src[i];
}

#else
static uint8_t xtime( uint8_t x )
{
    return (x >> 7 & 1) * 0x1b ^ (x << 1);
}

static void xorBlock( const block_t src, block_t dest )
{
    unsigned long long *d, *s;          /* not supported in ANSI-C or ISO C90 */
    d = (unsigned long long*) dest;
    s = (unsigned long long*) src;
    d[0] ^= s[0];
    d[1] ^= s[1];
}
#endif

/**--------------------------------------------------------------------------**\
              Main functions for the Rijndael encryption algorithm
\*----------------------------------------------------------------------------*/

/**
 * @brief   produces (ROUNDS+1) round keys, which are used in each round
 *          to encrypt/decrypt the intermediate states
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 */
static void KeyExpansion( const uint8_t* key )
{
    uint8_t i, temp, rcon = 1;

    memcpy( RoundKey, key, KEYSIZE );   /* First round key is the key itself. */

    /* All other round keys are found from the previous ones ................ */
    for (i = 0; i < sizeof (RoundKey) - KEYSIZE; ++i)
    {
        switch (i % KEYSIZE)
        {
        case 0:
            temp = getSBoxValue( RoundKey[i + KEYSIZE - 3] ) ^ rcon;
            rcon <<= 1;
#if Nk == 4                             /* RCON may reach 0 only in AES-128.  */
            if (rcon == 0) rcon = 0x1b;
#endif
            break;
        case 1:
        case 2:
            temp = getSBoxValue( RoundKey[i + KEYSIZE - 3] );
            break;
        case 3:
            temp = getSBoxValue( RoundKey[i + KEYSIZE - 7] );
            break;
#if Nk == 8                             /* additional round only for AES-256. */
        case 16:                        /* 0 <= (i % KEYSIZE - BLOCKSIZE) < 4 */
        case 17:
        case 18:
        case 19:
            temp = getSBoxValue( RoundKey[i + KEYSIZE - 4] );
            break;
#endif
        default:
            temp = RoundKey[i + KEYSIZE - 4];
            break;
        }

        RoundKey[i + KEYSIZE] = RoundKey[i] ^ temp;
    }
}

/** This function adds the round key to the state matrix via an XOR function. */
static void AddRoundKey( const uint8_t round, block_t state )
{
    xorBlock( RoundKey + BLOCKSIZE * round, state );
}

/** Substitute values in the state matrix with associated values in the S-box */
static void SubBytes( block_t state )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        state[i] = getSBoxValue( state[i] );
    }
}

/** Shift/rotate the rows of the state matrix to the left. Each row is shifted
 * with a different offset (= Row number). So the first row is not shifted .. */
static void ShiftRows( state_t *state )
{
    uint8_t   temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;          /*  Rotated first row 1 columns to left   */

    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;          /*  Rotated second row 2 columns to left  */

    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;          /*  Rotated third row 3 columns to left   */
}

/** This function mixes the columns of the state matrix in a rotational way.. */
static void MixColumns( state_t *state )
{
    uint8_t a, b, c, d, i;
    for (i = 0; i < Nb; ++i)
    {
        a  = (*state)[i][0] ^ (*state)[i][1];
        b  = (*state)[i][1] ^ (*state)[i][2];
        c  = (*state)[i][2] ^ (*state)[i][3];

        d  = a ^ c;                 /* d is XOR of all the elements in a row  */
        (*state)[i][0] ^= d ^ xtime( a );
        (*state)[i][1] ^= d ^ xtime( b );

        b ^= d;                     /* -> b = (*state)[i][3] ^ (*state)[i][0] */
        (*state)[i][2] ^= d ^ xtime( c );
        (*state)[i][3] ^= d ^ xtime( b );
    }
}

/** Encrypts a plain-text input block, into a cipher text block as output ... */
static void RijndaelEncrypt( const block_t input, block_t output )
{
    uint8_t round = ROUNDS;

    /* copy the input to the state matrix, and beware of undefined behavior.. */
    if (input != output)   memcpy( output, input, BLOCKSIZE );

    /* The encryption is carried out in #ROUNDS iterations, of which the first
     * #ROUNDS-1 are identical. The last round doesn't involve mixing columns */
    do
    {
        AddRoundKey( ROUNDS - round, output );
        SubBytes( output );
        ShiftRows( (state_t*) output );
        if (--round)  MixColumns( (state_t*) output );
    }
    while (round);

    AddRoundKey( ROUNDS, output );  /*  Add the last round key to the state.  */
}

/**--------------------------------------------------------------------------**\
                Block-decryption part of the Rijndael algorithm
\*----------------------------------------------------------------------------*/

#if IMPLEMENT(DECRYPTION)

#define getSBoxInvert(num) (rsbox[(num)])

/** This function does multiplication of two numbers in Galois field GF(2^8). */
#if REDUCE_CODE_SIZE
static uint8_t MulGf8( uint8_t x, uint8_t y )
{
    uint8_t m = 0;
    while (x > 1)                   /* in general, we should check if x != 0  */
    {
        m ^= (x & 1) * y;
        y = xtime( y );
        x >>= 1;
    }
    return m ^ y;                   /* or use lookup tables for 9, 11, 13, 14 */
}
#else
#define MulGf8(x, y)                           \
     ( ((x      & 1) * y)                    ^ \
       ((x >> 1 & 1) * xtime(y))             ^ \
       ((x >> 2 & 1) * xtime(xtime(y)))      ^ \
       ((x >> 3 & 1) * xtime(xtime(xtime(y)))) )
#endif

/** Substitutes the values in the state matrix with values of inverted S-box. */
static void InvSubBytes( block_t state )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        state[i] = getSBoxInvert( state[i] );
    }
}

/** This function shifts/rotates the rows of the state matrix to right ...... */
static void InvShiftRows( state_t *state )
{
    uint8_t   temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;          /*  Rotated first row 1 columns to right  */

    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;          /*  Rotated second row 2 columns to right */

    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;          /*  Rotated third row 3 columns to right  */
}

/** Mixes the columns of (already-mixed) state matrix to reverse the process. */
static void InvMixColumns( state_t *state )
{
    uint8_t a, b, c, d, i;

    for (i = 0; i < Nb; ++i)        /*  see: crypto.stackexchange.com/q/48872 */
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = MulGf8( 14, a ) ^ MulGf8( 11, b ) ^ MulGf8( 13, c ) ^ MulGf8(  9, d );
        (*state)[i][1] = MulGf8(  9, a ) ^ MulGf8( 14, b ) ^ MulGf8( 11, c ) ^ MulGf8( 13, d );
        (*state)[i][2] = MulGf8( 13, a ) ^ MulGf8(  9, b ) ^ MulGf8( 14, c ) ^ MulGf8( 11, d );
        (*state)[i][3] = MulGf8( 11, a ) ^ MulGf8( 13, b ) ^ MulGf8(  9, c ) ^ MulGf8( 14, d );
    }
}

/** Decrypts a cipher-text input block, into a 128-bit plain text as output.. */
static void RijndaelDecrypt( const block_t input, block_t output )
{
    uint8_t round = ROUNDS;

    /* copy the input into state matrix, i.e. state is initialized by input.. */
    if (input != output)   memcpy( output, input, BLOCKSIZE );

    AddRoundKey( ROUNDS, output );  /* First, add the last round key to state */

    /* The decryption completes after #ROUNDS iterations, of which the first
     * #ROUNDS-1 are identical. The last round doesn't involve mixing columns */
    while (round--)
    {
        InvShiftRows( (state_t*) output );
        InvSubBytes( output );
        AddRoundKey( round, output );
        if (round)  InvMixColumns( (state_t*) output );
    }
}
#endif /* DECRYPTION */


#if !BLOCK_CIPHER_MODES
/**
 * @brief   encrypt or decrypt a single block with a given key
 * @param   key       a byte array with a fixed size specified by KEYSIZE
 * @param   mode      mode of operation: 'E' (1) to encrypt, 'D' (0) to decrypt
 * @param   x         input byte array with BLOCKSIZE bytes
 * @param   y         output byte array with BLOCKSIZE bytes
 */
void AES_Cipher( const uint8_t* key, const char mode, const block_t x, block_t y )
{
    fmix_t cipher = mode & 1 ? &RijndaelEncrypt : &RijndaelDecrypt;
    KeyExpansion( key );
    cipher( x, y );
}
#endif

/**--------------------------------------------------------------------------**\
 *              Implementation of different block ciphers modes               *
 *                            Auxiliary Functions                             *
\*----------------------------------------------------------------------------*/

#ifdef AES_PADDING

/** in ECB or CBC without CTS, the last (partial) block is padded ........... */
static char padBlock( const uint8_t* input, const uint8_t len, block_t output )
{
#if AES_PADDING == 2
    memset( output + len, 0, BLOCKSIZE - len );  /*   ISO/IEC 7816-4 padding  */
    output[len] = 0x80;
#elif AES_PADDING
    uint8_t p = BLOCKSIZE - len;                 /*   PKCS#7 padding          */
    memset( output + len, p, p );
#else
    if (len == 0)  return 0;                     /*   default padding         */
    memset( output + len, 0, BLOCKSIZE - len );
#endif

    memcpy( output, input, len );
    return 1;
}
#endif /* PADDING */

#if defined(AEAD_MODES) || CTS

/** The input block `y` is xor-ed with `x` and then mixed with block `src`... */
static void xorThenMix( const uint8_t* x, const uint8_t len,
                        const block_t src, fmix_t mix, block_t y )
{
    uint8_t i;
    for (i = 0; i < len; ++i)  y[i] ^= x[i];

    mix( src, y );                               /*  Y = mix( S, Y ^ X )      */
}
#endif

#if defined(PARTIAL_BLOCK_PASS) || CTS

/** Result of applying a function to block `b` is xor-ed with `x` up to length
 * `len` to get `y`. A temporary block, `tmp` holds the intermediate values.. */
static void mixThenXor( const block_t b, fmix_t mix, block_t tmp,
                        const uint8_t* x, const uint8_t len, uint8_t* y )
{
    uint8_t i;
    if (len == 0)  return;                       /*  Y = f( B ) ^ X           */

    mix( b, tmp );
    for (i = 0; i < len; ++i)  y[i] = tmp[i] ^ x[i];
}
#endif

#if XTS || GCM_SIV
#if SMALL_CIPHER

/** copy little endian value to the block, starting at the specified position */
#define putValueL(block, pos, val)  block[pos + 1] = val >> 8;  block[pos] = val
#else

static void putValueL( block_t block, uint8_t pos, size_t val )
{
    do
        block[pos++] = (uint8_t) val;
    while (val >>= 8);
}
#endif
#endif /* XTS */

#if CTR
#if SMALL_CIPHER

/** increase the value of block-counter / copy big endian value to the block. */
#define incBlockB(block, len)     ++block[len - 1]
#define putValueB(block, pos, val)  block[pos - 1] = val >> 8;  block[pos] = val
#else

static void incBlockB( block_t block, uint8_t len )
{
    while (len--)
    {
        if (++block[len])  return;               /* return if no overflow,    */
    }
}

static void putValueB( block_t block, uint8_t pos, size_t val )
{
    do
        block[pos--] = (uint8_t) val;            /* copying big-endian value  */
    while (val >>= 8);
}
#endif
#endif /* CTR */

#if EAX && !EAXP || SIV || OCB

/** Multiply a block by two in GF(2^128) field: the big-endian version ...... */
static void doubleGf128B( block_t block )
{
    uint8_t c = 0, m, i = BLOCKSIZE;
    while (i--)                                  /* loop through bytes, from  */
    {                                            /* ..last to first, carry    */
        m = block[i] >> 7;                       /* ..the MSB, and then shift */
        block[i] <<= 1;                          /* ..each byte to the left.  */
        block[i] |= c;                           /* if carry was set, set LSB */
        c = m;                                   /* ..and update carry bit    */
    }
                                                 /* if first MSB is carried:  */
    if (c)  block[BLOCKSIZE - 1] ^= 0x87;        /*   B ^= 10000111b (B.E.)   */
}
#endif

#if XTS || EAXP || GCM_SIV

/** Multiply a block by two in GF(2^128) field: this is little-endian version */
static void doubleGf128L( block_t block )
{
    uint8_t c = 0, m, i;
    for (i = 0; i < BLOCKSIZE; ++i)              /* loop through bytes, from  */
    {                                            /* ..first to last, carry    */
        m = block[i] >> 7;                       /* ..the MSB, and then shift */
        block[i] <<= 1;                          /* ..each byte to the left.  */
        block[i] |= c;                           /* if carry was set, set LSB */
        c = m;                                   /* ..and update carry bit    */
    }
                                                 /* if last MSB is carried:   */
    if (c)  block[0] ^= 0x87;                    /*   B ^= 10000111b (L.E.)   */
}
#endif

#if GCM

/** Divide a block by two in GF(2^128) field: bit-shift right and carry LSB.. */
static void halveGf128B( block_t block )
{
    uint8_t c = 0, l, i;
    for (i = 0; i < BLOCKSIZE; ++i)              /* loop through bytes, from  */
    {                                            /* ..first to last, carry    */
        l = block[i] << 7;                       /* ..the LSB, and then shift */
        block[i] >>= 1;                          /* ..each byte to the right. */
        block[i] |= c;                           /* if carry was set, set MSB */
        c = l;                                   /* ..and update carry bit    */
    }
                                                 /* for odd blocks LSB was 1: */
    if (c)  block[0] ^= 0xe1;                    /*   B ^= 11100001b << 120   */
}

/** This function carries out multiplication in 128bit Galois field GF(2^128) */
static void MulGf128( const block_t x, block_t y )
{
    uint8_t i, j, result[BLOCKSIZE] = { 0 };     /*  working memory           */

    for (i = 0; i < BLOCKSIZE; ++i)
    {
        for (j = 0x80; j != 0; j >>= 1)          /*  check all the bits of X, */
        {
            if (x[i] & j)                        /*  ..and if any bit is set  */
            {
                xorBlock( y, result );           /*  M ^= Y                   */
            }
            halveGf128B( y );                    /*  Y_next = (Y / 2) in GF   */
        }
    }
    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* GCM */

#if OCB

static void nop( const block_t x, block_t y ) {}

/** get the offset block (Δ_i) at a specified index for a given L$ and Δ_0 .. */
static void getOffset( const block_t Ld, const count_t index, block_t delta )
{
    count_t b = 1;
    block_t L;
    memcpy( L, Ld, sizeof L );

    while (b <= index)                           /* loop through all the bits */
    {                                            /* L_0 = double( L_$ )       */
        doubleGf128B( L );                       /* L_{i+1} = double( L_i )   */
        if ((4 * b - 1 & (index - b)) < 2 * b)
        {
            xorBlock( L, delta );                /* Δ_new = Δ ^ L_j           */
        }
        if (!(b <<= 1))  break;                  /* reached the last bit      */
    }
}
#endif

#ifdef AEAD_MODES

/** the overall scheme of CMAC or GMAC hash functions: divide data into 128-bit
 * blocks; then xor and apply the digest/mixing function to each xor-ed block */
static void MAC( const void* data, const size_t dataSize,
                 const block_t seed, fmix_t mix, block_t result )
{
    const uint8_t *x = data;
    count_t n = dataSize / BLOCKSIZE;            /*   number of full blocks   */

    while (n--)
    {
        xorBlock( x, result );                   /* H_next = mix(seed, H ^ X) */
        mix( seed, result );                     /* and move on to next block */
        x += BLOCKSIZE;
    }                                            /*  do the same to the last  */
    n = dataSize % BLOCKSIZE;                    /*  ..partial block (if any) */
    if (n)  xorThenMix( x, n, seed, mix, result );
}
#endif

/**--------------------------------------------------------------------------**\
                             Frequently used MACROs
\*----------------------------------------------------------------------------*/

#define AES_SetKey(key)  KeyExpansion( key )

#define GOTO_NEXT_BLOCK  c += BLOCKSIZE;   p += BLOCKSIZE;

#if INCREASE_SECURITY
#define BURN_AFTER_READ  memset( RoundKey, 0, sizeof RoundKey );
#else
#define BURN_AFTER_READ  {}                      /*  see  #line 26  above ↑↑  */
#endif


/**--------------------------------------------------------------------------**\
                  ECB-AES (electronic codebook mode) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(ECB)
/**
 * @brief   encrypt the input plaintext using ECB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   pText     input plaintext buffer
 * @param   pTextLen  size of input buffer
 * @param   cText     cipher-text buffer
 */
void AES_ECB_encrypt( const uint8_t* key,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    uint8_t *p = (uint8_t*) pText, *c = cText;
    count_t n = pTextLen / BLOCKSIZE;            /*  number of full blocks    */

    AES_SetKey( key );
    while (n--)
    {
        RijndaelEncrypt( p, c );                 /*  C = Enc(P)               */
        GOTO_NEXT_BLOCK
    }
    if (padBlock( p, pTextLen % BLOCKSIZE, c ))
    {
        RijndaelEncrypt( c, c );
    }
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using ECB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   cText     input ciphertext buffer
 * @param   cTextLen  size of input buffer
 * @param   pText     plain-text output buffer
 * @return            whether size of ciphertext is a multiple of BLOCKSIZE
 */
char AES_ECB_decrypt( const uint8_t* key,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    uint8_t *c = (uint8_t*) cText, *p = pText;
    count_t n = cTextLen / BLOCKSIZE;

    AES_SetKey( key );
    while (n--)
    {
        RijndaelDecrypt( c, p );                 /*  P = Dec(C)               */
        GOTO_NEXT_BLOCK
    }
    BURN_AFTER_READ

    /* if padding is enabled, check whether the result is properly padded. error
     * must be thrown if it's not. we skip this here and just check the size. */
    return cTextLen % BLOCKSIZE ? DECRYPTION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* ECB */


/**--------------------------------------------------------------------------**\
                   CBC-AES (cipher block chaining) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CBC)
/**
 * @brief   encrypt the input plaintext using CBC-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   cText     cipher-text buffer
 */
void AES_CBC_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    const uint8_t *p = pText, *iv = iVec;
    uint8_t *c = cText;
    count_t n = pTextLen / BLOCKSIZE;            /*  number of full blocks    */

#if CTS
    n -= (n > 1 && pTextLen % BLOCKSIZE == 0);   /*  hold the last block      */
#endif
    memcpy( cText, pText, n * BLOCKSIZE );       /*  copy plaintext to output */

    AES_SetKey( key );
    while (n--)
    {
        xorBlock( iv, c );                       /*  C = P because of memcpy  */
        RijndaelEncrypt( c, c );                 /*  C = Enc(IV ^ P)          */
        iv = c;                                  /*  IV_next = C              */
        GOTO_NEXT_BLOCK
    }
#if CTS
    if (pTextLen > BLOCKSIZE)                    /*  cipher-text stealing CS3 */
    {
        n = (pTextLen - 1) % BLOCKSIZE + 1;      /*  'steal' the cipher-text  */
        memcpy( c, c - BLOCKSIZE, n );           /*  ..to fill the last block */
        xorThenMix( p, n, iv, &RijndaelEncrypt, c - BLOCKSIZE );
    }
#else
    if (padBlock( p, pTextLen % BLOCKSIZE, c ))
    {
        xorBlock( iv, c );
        RijndaelEncrypt( c, c );
    }
#endif
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using CBC-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   pText     plain-text output buffer
 * @return            whether size of ciphertext is a multiple of BLOCKSIZE
 */
char AES_CBC_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    const uint8_t *c = cText, *iv = iVec;
    uint8_t *p = pText;
    count_t n = cTextLen / BLOCKSIZE;

#if CTS
    if (!n)  return DECRYPTION_FAILURE;
    n -= cTextLen % BLOCKSIZE ? 1 : 2 * (n > 1);
#endif

    AES_SetKey( key );
    while (n--)
    {
        RijndaelDecrypt( c, p );                 /*  P = Dec(C) ^ IV          */
        xorBlock( iv, p );                       /*  IV_next = C              */
        iv = c;
        GOTO_NEXT_BLOCK
    }
#if CTS
    if (cTextLen > BLOCKSIZE)                    /*  last two blocks swapped  */
    {
        n = (cTextLen - 1) % BLOCKSIZE + 1;      /*  size of C2               */
        mixThenXor( c, &RijndaelDecrypt, p, c + BLOCKSIZE, n, p + BLOCKSIZE );

        memcpy( p, c + BLOCKSIZE, n );           /*  P2  =  Dec(C1) ^ C2      */
        RijndaelDecrypt( p, p );                 /*  copy C2 to Dec(C1): -> T */
        xorBlock( iv, p );                       /*  P1 = IV ^ Dec(T)         */
    }
#endif
    BURN_AFTER_READ

    /* note: if padding was applied, check whether output is properly padded. */
    return !CTS && cTextLen % BLOCKSIZE ? DECRYPTION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* CBC */


/**--------------------------------------------------------------------------**\
                      CFB-AES (cipher feedback) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CFB)
/**
 * @brief   encrypt the input plaintext using CFB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   cText     cipher-text buffer
 */
void AES_CFB_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    const uint8_t *p = pText, *iv = iVec;
    uint8_t *c = cText, tmp[BLOCKSIZE];
    count_t n = pTextLen / BLOCKSIZE;

    AES_SetKey( key );
    while (n--)
    {
        RijndaelEncrypt( iv, c );                /*  C = Enc(IV) ^ P          */
        xorBlock( p, c );                        /*  IV_next = C              */
        iv = c;
        GOTO_NEXT_BLOCK
    }
    mixThenXor( iv, &RijndaelEncrypt, tmp, p, pTextLen % BLOCKSIZE, c );
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using CFB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   pText     plain-text output buffer
 */
void AES_CFB_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    const uint8_t *c = cText, *iv = iVec;
    uint8_t *p = pText, tmp[BLOCKSIZE];
    count_t n = cTextLen / BLOCKSIZE;            /*  number of full blocks    */

    AES_SetKey( key );
    while (n--)
    {
        RijndaelEncrypt( iv, p );                /*  P = Enc(IV) ^ C          */
        xorBlock( c, p );                        /*  IV_next = C              */
        iv = c;
        GOTO_NEXT_BLOCK
    }
    mixThenXor( iv, &RijndaelEncrypt, tmp, c, cTextLen % BLOCKSIZE, p );
    BURN_AFTER_READ
}
#endif /* CFB */


/**--------------------------------------------------------------------------**\
                      OFB-AES (output feedback) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(OFB)
/**
 * @brief   encrypt the input plaintext using OFB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   cText     cipher-text buffer
 */
void AES_OFB_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    uint8_t *y = cText;
    block_t iv;
    count_t n = pTextLen / BLOCKSIZE;

    memcpy( iv, iVec, sizeof iv );
    memcpy( cText, pText, pTextLen );            /* copy plain text to output */

    AES_SetKey( key );
    while (n--)
    {
        RijndaelEncrypt( iv, iv );               /*  C = Enc(IV) ^ P          */
        xorBlock( iv, y );                       /*  IV_next = Enc(IV)        */
        y += BLOCKSIZE;
    }
    mixThenXor( iv, &RijndaelEncrypt, iv, y, pTextLen % BLOCKSIZE, y );
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using OFB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   pText     plain-text output buffer
 */
void AES_OFB_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    AES_OFB_encrypt( key, iVec, cText, cTextLen, pText );
}
#endif /* OFB */


/**--------------------------------------------------------------------------**\
    Parallelizable, counter-based modes of AES: demonstrating the main idea
\*----------------------------------------------------------------------------*/
#if CTR
/**
 * @brief   the overall scheme of operation in block-counter mode
 * @param   iVec      initialization vector a.k.a. nonce
 * @param   preInc    pre-increment the counter block (for GCM)
 * @param   input     plain/cipher-text input buffer
 * @param   dataSize  size of input buffer
 * @param   output    cipher/plain-text buffer
 */
static void CTR_Cipher( const uint8_t* iVec, const int preInc,
                        const void* input, const size_t dataSize, void* output )
{
    const uint8_t *p = input;
    uint8_t *c = output, ctr[BLOCKSIZE];
    count_t n = dataSize / BLOCKSIZE;

    memcpy( ctr, iVec, sizeof ctr );
    if (preInc)
    {
        incBlockB( ctr, sizeof ctr );
    }
    while (n--)
    {
        RijndaelEncrypt( ctr, c );               /*  both in (en/de)cryption: */
        xorBlock( p, c );                        /*  Y = Enc(Ctr) ^ X         */
        incBlockB( ctr, sizeof ctr );            /*  Ctr_next = Ctr + 1       */
        GOTO_NEXT_BLOCK
    }
    mixThenXor( ctr, &RijndaelEncrypt, ctr, p, dataSize % BLOCKSIZE, c );
}
#endif


/**--------------------------------------------------------------------------**\
         CTR-AES (counter mode without authentication): main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CTR_NA)
/**
 * @brief   encrypt the input plaintext using CTR-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iv        initialization vector a.k.a. nonce
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   cText     cipher-text buffer
 */
void AES_CTR_encrypt( const uint8_t* key, const uint8_t* iv,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    block_t ctr = { 0 };
    AES_SetKey( key );
    memcpy( ctr, iv, CTR_IV_LENGTH < sizeof ctr ? CTR_IV_LENGTH : sizeof ctr );
#if CTR_IV_LENGTH < BLOCKSIZE
    putValueB( ctr, BLOCKSIZE - 1, CTR_STARTVALUE );
#endif
    CTR_Cipher( ctr, 0, pText, pTextLen, cText );
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using CTR-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iv        initialization vector a.k.a. nonce
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   pText     plain-text output buffer
 */
void AES_CTR_decrypt( const uint8_t* key, const uint8_t* iv,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    AES_CTR_encrypt( key, iv, cText, cTextLen, pText );    /* similar to OFB  */
}
#endif /* CTR */


/**--------------------------------------------------------------------------**\
       XEX-AES based modes (xor-encrypt-xor): demonstrating the main idea
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(XTS)
/**
 * @brief   encrypt or decrypt a data unit with given key-pair using XEX method
 * @param   keypair   pair of encryption keys, each one has KEYSIZE bytes
 * @param   cipher    block cipher function: RijndaelEncrypt or RijndaelDecrypt
 * @param   dataSize  size of input data, to be encrypted/decrypted
 * @param   scid      sector id: if the given value is -1, use tweak value
 * @param   tweakid   data unit identifier, similar to nonce in CTR mode
 * @param   pad       one-time pad which is xor-ed with both plain/cipher text
 * @param   output    working memory; result of encryption/decryption process
 */
static void XEX_Cipher( const uint8_t* keypair, fmix_t cipher,
                        const size_t dataSize, const size_t scid,
                        const block_t tweakid, block_t pad, void* output )
{
    uint8_t *y = output;
    count_t n = dataSize / BLOCKSIZE;

    if (scid == (size_t) ~0)
    {                                            /* the `i` block is either   */
        memcpy( pad, tweakid, BLOCKSIZE );       /* ..a little-endian number  */
    }                                            /* ..or a byte array.        */
    else
    {
        putValueL( pad, 0, scid );
    }
    AES_SetKey( keypair + KEYSIZE );             /* T = encrypt `i` with key2 */
    RijndaelEncrypt( pad, pad );

    AES_SetKey( keypair );                       /* key1 is set as cipher key */
    while (n--)
    {
        xorBlock( pad, y );                      /*  X was copied to Y before */
        cipher( y, y );
        xorBlock( pad, y );                      /*  Y = T ^ Cipher( T ^ X )  */
        doubleGf128L( pad );                     /*  T_next = T * alpha       */
        y += BLOCKSIZE;
    }
}

/**--------------------------------------------------------------------------**\
    XTS-AES (XEX Tweaked-codebook with ciphertext Stealing): main functions
\*----------------------------------------------------------------------------*/
/**
 * @brief   encrypt the input plaintext using XTS-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   twkId     tweak value of data unit, a.k.a sector ID (little-endian)
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   cText     cipher-text buffer
 */
char AES_XTS_encrypt( const uint8_t* keys, const uint8_t* twkId,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    block_t T = { 0 };
    uint8_t r = pTextLen % BLOCKSIZE, *c;
    size_t len = pTextLen - r;

    if (len == 0)  return ENCRYPTION_FAILURE;
    memcpy( cText, pText, len );                 /* copy input data to output */

    XEX_Cipher( keys, &RijndaelEncrypt, len, ~0, twkId, T, cText );
    if (r)
    {                                            /*  XTS for partial block    */
        c = cText + len - BLOCKSIZE;
        memcpy( cText + len, c, r );             /* 'steal' the cipher-text   */
        memcpy( c, pText + len, r );             /*  ..for the partial block  */
        xorBlock( T, c );
        RijndaelEncrypt( c, c );
        xorBlock( T, c );
    }

    BURN_AFTER_READ
    return ENDED_IN_SUCCESS;
}

/**
 * @brief   encrypt the input ciphertext using XTS-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   twkId     tweak value of data unit, a.k.a sector ID (little-endian)
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   pText     plain-text output buffer
 */
char AES_XTS_decrypt( const uint8_t* keys, const uint8_t* twkId,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    block_t TT, T = { 0 };
    uint8_t r = cTextLen % BLOCKSIZE, *p;
    size_t len = cTextLen - r;

    if (len == 0)  return DECRYPTION_FAILURE;
    memcpy( pText, cText, len );                 /* copy input data to output */
    p = pText + len - BLOCKSIZE;

    XEX_Cipher( keys, &RijndaelDecrypt, len - BLOCKSIZE, ~0, twkId, T, pText );
    if (r)
    {
        memcpy( TT, T, sizeof T );
        doubleGf128L( TT );                      /*  TT = T * alpha,          */
        xorBlock( TT, p );                       /*  because the stolen       */
        RijndaelDecrypt( p, p );                 /*  ..ciphertext was xor-ed  */
        xorBlock( TT, p );                       /*  ..with TT in encryption  */
        memcpy( pText + len, p, r );
        memcpy( p, cText + len, r );
    }
    xorBlock( T, p );
    RijndaelDecrypt( p, p );
    xorBlock( T, p );

    BURN_AFTER_READ
    return ENDED_IN_SUCCESS;
}
#endif /* XTS */


/**--------------------------------------------------------------------------**\
    AES-CMAC (cipher-based message authentication code): main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CMAC)

/** calculate key-dependent constants D and Q for CMAC, regarding endianness: */
static void GetSubkeys( const uint8_t* key, const int LE, block_t D, block_t Q )
{
    AES_SetKey( key );
    RijndaelEncrypt( D, D );                     /*  H or L_* = Enc(zeros)    */
    if (LE)                                      /*  little endian!           */
    {
#if EAXP
        doubleGf128L( D );                       /*  D or L_$ = double(L_*)   */
        memcpy( Q, D, BLOCKSIZE );
        doubleGf128L( Q );                       /*  Q or L_0 = double(L_$)   */
        return;
#endif
    }
#if SIV || !EAXP
    doubleGf128B( D );
    memcpy( Q, D, BLOCKSIZE );
    doubleGf128B( Q );
#endif
}

/** calculate the CMAC hash of input data using pre-calculated keys: D and Q. */
static void Cmac( const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    block_t M = { 0 };
    uint8_t r = dataSize ? (dataSize - 1) % BLOCKSIZE + 1 : 0;
    const void *last_ptr = (const char*) data + dataSize - r;

    if (r < sizeof M)  M[r] = 0x80;
    memcpy( M, last_ptr, r );                    /*  copy last block into M   */
    xorBlock( r < sizeof M ? Q : D, M );         /*  ..and pad( M; D, Q )     */

    MAC( data, dataSize - r, mac, &RijndaelEncrypt, mac );
    xorThenMix( M, sizeof M, mac, &RijndaelEncrypt, mac );
}

/**
 * @brief   derive the AES-CMAC hash of input data using an encryption key
 * @param   key       AES encryption key
 * @param   data      buffer of input data
 * @param   dataSize  size of data in bytes
 * @param   mac       calculated CMAC hash
 */
void AES_CMAC( const uint8_t* key,
               const void* data, const size_t dataSize, block_t mac )
{
    block_t D = { 0 }, Q;
    memset( mac, 0, BLOCKSIZE );
    GetSubkeys( key, 0, D, Q );
    Cmac( D, Q, data, dataSize, mac );
}
#endif /* CMAC */


/**--------------------------------------------------------------------------**\
    GCM-AES (Galois counter mode): authentication with GMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM)

/** calculates GMAC hash of ciphertext and AAD using authentication subkey AK */
static void GHash( const block_t AK, const uint8_t* cText, const uint8_t* aData,
                   const size_t ctextLen, const size_t adataLen, block_t GH )
{
    block_t sizeBuf = { 0 };

    MAC( aData, adataLen, AK, &MulGf128, GH );   /* first digest AAD and then */
    MAC( cText, ctextLen, AK, &MulGf128, GH );   /* ..ciphertext into GHash   */

    /* copy length info (bit-length) of hashed data into sizeBuf, then GMAC.. */
    putValueB( sizeBuf, BLOCKSIZE - 9, adataLen * 8 );
    putValueB( sizeBuf, BLOCKSIZE - 1, ctextLen * 8 );
    MAC( sizeBuf, sizeof sizeBuf, AK, &MulGf128, GH );
}

/** encrypt zeros to get authentication subkey H, and prepare the IV for GCM. */
static void GCM_GetIVH( const uint8_t* key, const uint8_t* nonce,
                        block_t authKey, block_t iv )
{
    AES_SetKey( key );
    RijndaelEncrypt( authKey, authKey );         /* authKey = Enc(zero block) */
#if GCM_NONCE_LEN != 12
    GHash( authKey, nonce, NULL, GCM_NONCE_LEN, 0, iv );
#else
    memcpy( iv, nonce, GCM_NONCE_LEN );
    iv[BLOCKSIZE - 1] = 1;
#endif
}

/**
 * @brief   encrypt the input plaintext using GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size GCM_NONCE_LEN
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     encrypted cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_GCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    block_t H = { 0 }, iv = { 0 }, g = { 0 };
    GCM_GetIVH( key, nonce, H, iv );             /*  get IV & auth. subkey H  */

    CTR_Cipher( iv, 1, pText, pTextLen, cText );
    GHash( H, cText, aData, pTextLen, aDataLen, g );
    CTR_Cipher( iv, 0, g, sizeof g, auTag );     /*  auth. tag = Enc( GHASH ) */
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size GCM_NONCE_LEN
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   auTag     message authentication tag (if any)
 * @param   tagSize   length of authentication tag
 * @param   pText     plain-text output buffer
 * @return            whether message authentication was successful
 */
char AES_GCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t* auTag, const uint8_t tagSize,
                      uint8_t* pText )
{
    block_t H = { 0 }, iv = { 0 }, g = { 0 };
    GCM_GetIVH( key, nonce, H, iv );

    GHash( H, cText, aData, cTextLen, aDataLen, g );
    CTR_Cipher( iv, 0, g, sizeof g, H );         /*  save the tag into H!     */
    if (memcmp( H, auTag, tagSize ) != 0)        /*  compare tags and proceed */
    {                                            /*  ..if they match.         */
        BURN_AFTER_READ
        return AUTHENTICATION_FAILURE;
    }
    CTR_Cipher( iv, 1, cText, cTextLen, pText );
    BURN_AFTER_READ
    return ENDED_IN_SUCCESS;
}
#endif /* GCM */


/**--------------------------------------------------------------------------**\
    CCM-AES (counter with CBC-MAC): CBC-MAC authentication & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CCM)

/** this function calculates CBC-MAC authentication tag in CCM-AES block-cipher
 * method. calculated tag's size is 16 bytes which can be truncated afterward */
static void CCM_GetTag( const block_t iv,
                        const uint8_t* pText, const uint8_t* aData,
                        const size_t pTextLen, const size_t aDataLen,
                        block_t tag )
{
    block_t S = { 0 }, A = { 0 };
    uint8_t p, m = BLOCKSIZE - 2;

    memcpy( S, iv, CCM_NONCE_LEN + 1 );
    RijndaelEncrypt( S, tag );                   /*  Tag_0 = Enc(IV_0)        */

    S[0] |= (CCM_TAG_LEN - 2) << 2;
    putValueB( S, BLOCKSIZE - 1, pTextLen );     /*  copy data size into S_0  */
    if (aDataLen)
    {
        if (aDataLen < m)  m = aDataLen;
        p = aDataLen < 0xFF00 ? 1 : 5;
        putValueB( A, p, aDataLen );             /*  len_id = aDataLen (B.E.) */
        if (p == 5)
        {
            m -= 4;
            putValueB( A, 1, 0xFFFE );           /*  prepend FFFE to len_id   */
        }
        memcpy( A + p + 1, aData, m );           /*  A = len_id ~~ ADATA      */
        S[0] |= 0x40;
        RijndaelEncrypt( S, S );                 /*  S_1 = Enc(S_0) ^ A       */
        xorBlock( A, S );
    }
    RijndaelEncrypt( S, S );                     /*  S_2 = Enc(S_1)           */

    if (aDataLen > m)                            /*  get CBC-MAC of the rest  */
    {
        MAC( aData + m, aDataLen - m, S, &RijndaelEncrypt, S );
    }
    MAC( pText, pTextLen, S, &RijndaelEncrypt, S );
    xorBlock( S, tag );                          /*  Tag = Tag_0 ^ S_n        */
}

/**
 * @brief   encrypt the input plaintext using CCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size CCM_NONCE_LEN
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     encrypted cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_CCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 };
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );
    iv[sizeof iv - 1] = 1;

    AES_SetKey( key );
    CCM_GetTag( iv, pText, aData, pTextLen, aDataLen, auTag );
    CTR_Cipher( iv, 0, pText, pTextLen, cText );
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using CCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size CCM_NONCE_LEN
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   auTag     message authentication tag (if any)
 * @param   tagSize   length of authentication tag
 * @param   pText     plain-text output buffer
 * @return            whether message authentication was successful
 */
char AES_CCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t* auTag, const uint8_t tagSize,
                      uint8_t* pText )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 };
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );
    iv[sizeof iv - 1] = 1;

    AES_SetKey( key );
    CTR_Cipher( iv, 0, cText, cTextLen, pText );
    CCM_GetTag( iv, pText, aData, cTextLen, aDataLen, iv );
    BURN_AFTER_READ                              /*   tag is saved into iv!   */

    if (memcmp( iv, auTag, tagSize ) != 0)       /* sabotage results ↓ maybe? */
    {                                            /* memset(pText, 0, Length); */
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* CCM */


/**--------------------------------------------------------------------------**\
       SIV-AES (synthetic init-vector): nonce synthesis & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(SIV)

/** calculate the CMAC* of AAD unit(s), then plaintext, and synthesize the IV */
static void S2V( const uint8_t* key,
                 const uint8_t* aData, const uint8_t* pText,
                 const size_t aDataLen, const size_t pTextLen, block_t V )
{
    block_t T = { 0 }, D = { 0 }, Q;
    uint8_t r = pTextLen >= BLOCKSIZE ? BLOCKSIZE : pTextLen % BLOCKSIZE;
    const uint8_t *p = pText + pTextLen - r;

    GetSubkeys( key, 0, D, Q );
    Cmac( D, Q, T, sizeof T, T );                /*  T_0 = CMAC(zero block)   */
    if (aDataLen)                                /*  process each ADATA unit  */
    {                                            /*  ..the same way as this:  */
        doubleGf128B( T );
        Cmac( D, Q, aData, aDataLen, V );        /*  C_A = CMAC(ADATA)        */
        xorBlock( V, T );                        /*  T_1 = double(T_0) ^ C_A  */
        memset( V, 0, BLOCKSIZE );
    }
    if (r < BLOCKSIZE)
    {
        doubleGf128B( T );
        T[r] ^= 0x80;                            /*  T = double(T_n) ^ pad(X) */
        while (r--)  T[r] ^= p[r];
    }
    else  xorBlock( p, T );                      /*  T = T_n  xor_end  X      */

    Cmac( D, Q, T, sizeof T, V );                /*  I.V = CMAC*(T)           */
}

/**
 * @brief   encrypt the input plaintext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   iv        synthesized I.V block, for secure encryption & validation
 * @param   cText     encrypted cipher-text buffer
 */
void AES_SIV_encrypt( const uint8_t* keys,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      block_t iv, uint8_t* cText )
{
    block_t IV = { 0 };
    S2V( keys, aData, pText, aDataLen, pTextLen, IV );
    memcpy( iv, IV, sizeof IV );
    IV[8] &= 0x7F;  IV[12] &= 0x7F;

    AES_SetKey( keys + KEYSIZE );
    CTR_Cipher( IV, 0, pText, pTextLen, cText );
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   iv        provided I.V block to validate
 * @param   pText     plain-text output buffer
 * @return            whether synthesized I.V. matched the provided one
 */
char AES_SIV_decrypt( const uint8_t* keys,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const block_t iv, uint8_t* pText )
{
    block_t IV;
    AES_SetKey( keys + KEYSIZE );
    memcpy( IV, iv, sizeof IV );
    IV[8] &= 0x7F;  IV[12] &= 0x7F;

    CTR_Cipher( IV, 0, cText, cTextLen, pText );
    memset( IV, 0, sizeof IV );
    S2V( keys, aData, pText, aDataLen, cTextLen, IV );
    BURN_AFTER_READ

    if (memcmp( iv, IV, sizeof IV ) != 0)        /* sabotage results ↓ maybe? */
    {                                            /* memset(pText, 0, Length); */
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* SIV */


/**--------------------------------------------------------------------------**\
   EAX-AES (encrypt-then-authenticate-then-translate): OMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(EAX)

/** this function calculates the OMAC hash of a data array using D (K1) and Q */
static void Omac( const uint8_t t, const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
#if EAXP
    if (dataSize == 0 && t)  return;             /*  ignore null ciphertext   */
    memcpy( mac, t ? Q : D, BLOCKSIZE );
#else
    block_t M = { 0 };
    if (dataSize == 0)
    {
        memcpy( M, D, sizeof M );                /*  OMAC = Enc( D ^ [t]_n )  */
    }
    M[BLOCKSIZE - 1] ^= t;                       /*  else: C1 = Enc( [t]_n )  */
    RijndaelEncrypt( M, mac );
#endif
    Cmac( D, Q, data, dataSize, mac );
}

/**
 * @brief   encrypt the input plaintext using EAX-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes if not EAX'
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     encrypted cipher-text buffer
 * @param   auTag     authentication tag; 16 bytes in EAX or 4 bytes in EAX'
 */
void AES_EAX_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
#if EAXP
                      const size_t nonceLen,
#else
                      const uint8_t* aData, const size_t aDataLen,
#endif
                      uint8_t* cText, uint8_t* auTag )
{
    block_t mac, tag = { 0 }, D = { 0 }, K2;
    GetSubkeys( key, EAXP, D, K2 );

#if EAXP
    Omac( 0, D, K2, nonce, nonceLen, mac );      /*  N = CMAC'( nonce )       */
    memcpy( auTag, mac + 12, 4 );
    mac[12] &= 0x7F;                             /*  clear 2 bits to get N'   */
    mac[14] &= 0x7F;
    CTR_Cipher( mac, 0, pText, pTextLen, cText );

    Omac( 2, D, K2, cText, pTextLen, tag );      /*  C' = CMAC'( ciphertext ) */
    for (*D = 0; *D < 4; ++*D)                   /*  using D[0] as counter!   */
    {
        auTag[*D] ^= tag[12 + *D];               /*  last 4 bytes of C' ^ N'  */
    }
#else
    Omac( 0, D, K2, nonce, EAX_NONCE_LEN, mac ); /*  N = OMAC(0; nonce)       */
    Omac( 1, D, K2, aData, aDataLen, tag );      /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );
    memcpy( auTag, tag, sizeof tag );
    CTR_Cipher( mac, 0, pText, pTextLen, cText );

    Omac( 2, D, K2, cText, pTextLen, mac );      /*  C = OMAC(2; ciphertext)  */
    xorBlock( mac, auTag );                      /*  tag = N ^ H ^ C          */
#endif
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using EAX-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes if not EAX'
 * @param   cText     input cipher-text buffer; +4 bytes tag at the end in EAX'
 * @param   cTextLen  size of input buffer; excluding added 4 bytes in EAX'
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data; ignored in EAX'
 * @param   aDataLen  size of additional authentication data
 * @param   auTag     message authentication tag; ignored in EAX'
 * @param   tagSize   length of authentication tag (if any)
 * @param   pText     plain-text output buffer
 * @return            whether message authentication was successful
 */
char AES_EAX_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
#if EAXP
                      const size_t nonceLen,
#else
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t* auTag, const uint8_t tagSize,
#endif
                      uint8_t* pText )
{
    block_t mac, tag = { 0 }, D = { 0 }, K2;
    GetSubkeys( key, EAXP, D, K2 );
    Omac( 2, D, K2, cText, cTextLen, tag );      /*  C = OMAC(2; ciphertext)  */

#if EAXP
    Omac( 0, D, K2, nonce, nonceLen, mac );      /*  N = CMAC'( nonce )       */
    for (*K2 = *D = 0; *D < 4; ++*D)             /* authenticate/compare tags */
    {
        *K2 |= cText[cTextLen + *D] ^ tag[12 + *D] ^ mac[12 + *D];
    }
    mac[12] &= 0x7F;                             /*  clear 2 bits to get N'   */
    mac[14] &= 0x7F;
    if (*K2 != 0)                                /*  result of tag comparison */
#else
    Omac( 1, D, K2, aData, aDataLen, mac );      /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );                        /*  N = OMAC(0; nonce)       */
    Omac( 0, D, K2, nonce, EAX_NONCE_LEN, mac );
    xorBlock( mac, tag );                        /*  tag = N ^ H ^ C          */

    if (memcmp( tag, auTag, tagSize ) != 0)      /* authenticate then decrypt */
#endif
    {
        BURN_AFTER_READ
        return AUTHENTICATION_FAILURE;
    }
    CTR_Cipher( mac, 0, cText, cTextLen, pText );

    BURN_AFTER_READ
    return ENDED_IN_SUCCESS;
}
#endif /* EAX */


/**--------------------------------------------------------------------------**\
              OCB-AES (offset codebook mode): auxiliary functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(OCB)
/**
 * @brief   encrypt or decrypt a data unit using OCB-AES method
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   cipher    block-cipher function: RijndaelEncrypt or RijndaelDecrypt
 * @param   input     input plain/cipher-text buffer
 * @param   dataSize  size of data
 * @param   Ls        L_* is the result of the encryption of a zero block
 * @param   Ld        L_$ = double(L_*) in GF(2^128)
 * @param   Del       Δ_m  a.k.a last offset (sometimes Δ*, which is Δ_m ^ L_*)
 * @param   output    encrypted/decrypted data
 */
static void OCB_Cipher( const uint8_t* nonce, fmix_t cipher,
                        const uint8_t* input, const size_t dataSize,
                        block_t Ls, block_t Ld, block_t Del, uint8_t* output )
{
    uint8_t Kt[2 * BLOCKSIZE] = { OCB_TAG_LEN << 4 & 0xFE, 0, 0, 1 };
    uint8_t r, *y = output;
    count_t i, n;
    memcpy( output, input, dataSize );           /* copy input data to output */

    n = nonce[11] % 64 >> 3;
    r = nonce[11] % 8;                           /* take last 6 bits of nonce */
    memcpy( Kt + 4, nonce, 12 );
    Kt[BLOCKSIZE - 1] &= 0xC0;                   /* clear last 6 bits         */

    RijndaelEncrypt( Kt, Kt );                   /* construct K_top           */
    memcpy( Kt + BLOCKSIZE, Kt + 1, 8 );         /* stretch K_top             */
    xorBlock( Kt, Kt + BLOCKSIZE );
    for (i = 0; i < BLOCKSIZE; ++i, ++n)         /* shift the stretched K_top */
    {
        Kt[i] = Kt[n] << r | Kt[n + 1] >> (8 - r);
    }
    n = dataSize / BLOCKSIZE;
    r = dataSize % BLOCKSIZE;
    i = 0;

    RijndaelEncrypt( Ls, Ls );                   /*  L_* = Enc(zero block)    */
    memcpy( Ld, Ls, BLOCKSIZE );
    doubleGf128B( Ld );                          /*  L_$ = double(L_*)        */
    if (n == 0)                                  /*  processed nonce is Δ_0   */
    {
        memcpy( Del, Kt, BLOCKSIZE );            /*  initialize Δ_0           */
    }
    while (i < n)
    {
        memcpy( Del, Kt, BLOCKSIZE );            /*  calculate Δ_i using my   */
        getOffset( Ld, ++i, Del );               /*  .. 'magic' algorithm     */
        xorBlock( Del, y );
        cipher( y, y );                          /* Y = Δ_i ^ Cipher(Δ_i ^ X) */
        xorBlock( Del, y );
        y += BLOCKSIZE;
    }
    if (r)                                       /*  Δ_* = Δ_n ^ L_* and then */
    {                                            /*  Y_* = Enc(Δ_*) ^ X       */
        xorBlock( Ls, Del );
        mixThenXor( Del, &RijndaelEncrypt, Kt, y, r, y );
    }
}

/** this function calculates the authentication tag in OCB-AES method. the first
 * three arguments must be pre-calculated. Ls denotes L_* which is encryption of
 * zero block. Ld denotes L_$ = double(L_*), and Ds is Δ_* (or sometimes Δ_m) */
static void OCB_GetTag( const block_t Ds,
                        const block_t Ls, const block_t Ld,
                        const uint8_t* pText, const uint8_t* aData,
                        const size_t pTextLen, const size_t aDataLen,
                        block_t tag )
{
    const uint8_t *x = aData;
    count_t i = pTextLen % BLOCKSIZE, n;
    block_t S = { 0 };                           /*  checksum, i.e. ...       */

    MAC( pText, pTextLen, NULL, &nop, S );       /*  ..xor of all plaintext   */
    xorThenMix( Ds, sizeof S, Ld, &xorBlock, S );
    if (i)  S[i] ^= 0x80;                        /*  pad if partial block     */

    RijndaelEncrypt( S, tag );                   /* Tag0 = Enc(L_$ ^ Δ_* ^ S) */
    if (!aDataLen)  return;

    memset( S, 0, sizeof S );
    n = aDataLen / BLOCKSIZE;
    i = 0;
    while (i < n)
    {
        getOffset( Ld, ++i, S );
        xorBlock( x, S );
        RijndaelEncrypt( S, S );                 /*  S_i = Enc(A_i ^ Δ_i)     */
        xorBlock( S, tag );                      /*  Tag_{i+1} = Tag_i ^ S_i  */
        memset( S, 0, sizeof S );
        x += BLOCKSIZE;
    }
    i = aDataLen % BLOCKSIZE;
    if (i)
    {
        getOffset( Ld, n, S );                   /*  S = calculated Δ_n       */
        xorThenMix( x, i, Ls, &xorBlock, S );    /*  S_* = A_* ^ L_* ^ Δ_n    */
        S[i] ^= 0x80;                            /*  ..A_* = A || 1  (padded) */
        RijndaelEncrypt( S, S );
        xorBlock( S, tag );                      /*  Tag = Enc(S_*) ^ Tag_n   */
    }
}

/**--------------------------------------------------------------------------**\
                 OCB-AES (offset codebook mode): main functions
\*----------------------------------------------------------------------------*/
/**
 * @brief   encrypt the input stream using OCB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     encrypted cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_OCB_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    block_t Ls = { 0 }, Ld, delta;
    AES_SetKey( key );
    OCB_Cipher( nonce, &RijndaelEncrypt, pText, pTextLen, Ls, Ld, delta, cText );
    OCB_GetTag( delta, Ls, Ld, pText, aData, pTextLen, aDataLen, auTag );
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input stream using OCB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   auTag     message authentication tag (if any)
 * @param   tagSize   length of authentication tag
 * @param   pText     plain-text output buffer
 * @return            whether message authentication was successful
 */
char AES_OCB_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t* auTag, const uint8_t tagSize,
                      uint8_t* pText )
{
    block_t Ls = { 0 }, Ld, delta;
    AES_SetKey( key );
    OCB_Cipher( nonce, &RijndaelDecrypt, cText, cTextLen, Ls, Ld, delta, pText );
    OCB_GetTag( delta, Ls, Ld, pText, aData, cTextLen, aDataLen, delta );
    BURN_AFTER_READ                              /* saved the tag into delta! */

    if (memcmp( delta, auTag, tagSize ) != 0)    /* sabotage results ↓ maybe? */
    {                                            /* memset(pText, 0, Length); */
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* OCB */


/**--------------------------------------------------------------------------**\
      SIV-GCM-AES (Galois counter mode with synthetic i.v): main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM_SIV)
/**
 * @brief   encrypt the input plaintext using SIV-GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     encrypted cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void GCM_SIV_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    BURN_AFTER_READ
}

/**
 * @brief   decrypt the input ciphertext using SIV-GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of input buffer
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   auTag     message authentication tag (if any)
 * @param   tagSize   length of authentication tag
 * @param   pText     plain-text output buffer
 * @return            whether message authentication was successful
 */
char GCM_SIV_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t* auTag, const uint8_t tagSize,
                      uint8_t* pText )
{
    BURN_AFTER_READ
    return ENDED_IN_SUCCESS;
}
#endif /* GCM-SIV */


/**--------------------------------------------------------------------------**\
                  AES key-wrapping functions based on RFC-3394
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(KWA)

#if SMALL_CIPHER
#define xorWith(block, p, t)   block[p] ^= (t)   /* secret size <= 336 bytes  */
#else
static void xorWith( uint8_t* block, uint8_t p, size_t t )
{
    do
        block[p--] ^= (uint8_t) t;               /* Xor with big-endian value */
    while (t >>= 8);
}
#endif

/**
 * @brief   wrap the input secret whose size is a multiple of 8 and >= 16
 * @param   kek       key-encryption-key a.k.a master key
 * @param   secret    input plain text secret
 * @param   secretLen size of input buffer, must be a multiple of 8
 * @param   wrapped   wrapped secret. note: size of output = secretLen + 8
 */
void AES_KEY_wrap( const uint8_t* kek,
                   const uint8_t* secret, const size_t secretLen, uint8_t* wrapped )
{
    uint8_t A[16], *r, i;
    count_t j, nb = secretLen / 8;               /*  number of blocks         */

    memset( A, 0xA6, 8 );                        /*  initialization vector    */
    memcpy( wrapped + 8, secret, secretLen );

    AES_SetKey( kek );
    for (i = 0; i < 6; ++i)
    {
        r = wrapped;
        for (j = 0; j++ < nb; )
        {
            r += 8;
            memcpy( A + 8, r, 8 );               /*  B = Enc(A | R[j])        */
            RijndaelEncrypt( A, A );             /*  R[j] = LSB(64, B)        */
            memcpy( r, A + 8, 8 );               /*  A = MSB(64, B) ^ t       */
            xorWith( A, 7, nb * i + j );
        }
    }
    BURN_AFTER_READ

    memcpy( wrapped, A, 8 );
}

/**
 * @brief   unwrap a wrapped input key whose size is a multiple of 8 and >= 24
 * @param   kek       key-encryption-key a.k.a master key
 * @param   wrapped   cipher-text, i.e. wrapped secret to be unwrapped.
 * @param   wrapLen   size of input buffer
 * @param   secret    unwrapped secret. note: size of secret = wLength - 8
 * @return            a value indicating whether decryption was successful
 */
char AES_KEY_unwrap( const uint8_t* kek,
                     const uint8_t* wrapped, const size_t wrapLen, uint8_t* secret )
{
    uint8_t A[16], *r, i;
    count_t j, nb = wrapLen / 8 - 1;             /*  number of secret blocks  */

    memcpy( A, wrapped, 8 );                     /*  authentication vector    */
    memcpy( secret, wrapped + 8, wrapLen - 8 );

    AES_SetKey( kek );
    for (i = 6; i--; )
    {
        r = secret + 8 * nb;
        for (j = nb; j; --j)
        {
            r -= 8;
            xorWith( A, 7, nb * i + j );
            memcpy( A + 8, r, 8 );               /*  B = Dec(A ^ t | R[j])    */
            RijndaelDecrypt( A, A );             /*  A = MSB(64, B)           */
            memcpy( r, A + 8, 8 );               /*  R[j] = LSB(64, B)        */
        }
    }
    BURN_AFTER_READ

    for (i = 0; i < 8; ++i)                      /*  error checking...        */
    {
        if (A[i] != 0xA6)  return DECRYPTION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* KWA */
