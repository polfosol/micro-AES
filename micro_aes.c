/*
 ==============================================================================
 Name        : micro_aes.c
 Author      : polfosol
 Version     : 9.8.1.0
 Copyright   : copyright © 2022 - polfosol
 Description : ANSI-C compatible implementation of µAES ™ library.
 ==============================================================================
 */

#include "micro_aes.h"

/*----------------------------------------------------------------------------*\
          Global constants, data types, and important / useful MACROs
\*----------------------------------------------------------------------------*/

#define KEYSIZE  AES_KEY_LENGTH
#define BLOCKSIZE   (128/8)  /* Block length in AES is 'always' 128-bits.     */
#define Nb    (BLOCKSIZE/4)  /* The number of columns comprising a AES state. */
#define Nk      (KEYSIZE/4)  /* The number of 32 bit words in a key.          */
#define LAST  (BLOCKSIZE-1)  /* The index at the end of block, or last index  */
#define ROUNDS       (Nk+6)  /* The number of rounds in AES Cipher.           */

#define IMPLEMENT(x)  (x) > 0

#define INCREASE_SECURITY 0  /* refer to the bottom of the header file for    */
#define SMALL_CIPHER      0  /* ... some explanations and the rationale of    */
#define REDUCE_CODE_SIZE  1  /* ... these three macros                        */

/** state_t represents rijndael state matrix. fixed-size memory blocks have an
 * essential role in all algorithms. so it may be a good aide for readability to
 * define a specific type and a function pointer that applies to these blocks */
typedef uint8_t  state_t[Nb][4];
typedef uint8_t  block_t[BLOCKSIZE];
typedef void   (*fmix_t)(const block_t, block_t);

#if SMALL_CIPHER
typedef unsigned char count_t;
#else
typedef size_t   count_t;
#endif

/*----------------------------------------------------------------------------*\
                               Private variables:
\*----------------------------------------------------------------------------*/

/** The array that stores the round keys during AES key-expansion process ... */
static uint8_t RoundKey[BLOCKSIZE * ROUNDS + KEYSIZE];

/** Lookup-tables are static constant, so that they can be placed in read-only
 * storage instead of RAM. They can be computed dynamically trading ROM for RAM.
 * This may be useful in (embedded) bootloader applications, where ROM is often
 * limited. Please refer to:   https://en.wikipedia.org/wiki/Rijndael_S-box   */
static const uint8_t sbox[256] =
{
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

/*----------------------------------------------------------------------------*\
                 Auxiliary functions for the Rijndael algorithm
\*----------------------------------------------------------------------------*/

#define getSBoxValue(num)  (sbox[(num)])
#define getSBoxInvert(num)  (rsbox[num])

#if REDUCE_CODE_SIZE

/** this function carries out XOR operation on two 128-bit blocks ........... */
static void xorBlock( const block_t src, block_t dest )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)  dest[i] ^= src[i];
}

/** doubling in GF(2^8): left-shift and if carry bit is set, xor it with 0x1b */
static uint8_t xtime( uint8_t x )
{
    return (x > 0x7F) * 0x1b ^ (x << 1);
}

#if DECRYPTION

/** This function multiplies two numbers in the Galois field GF(2^8) ........ */
static uint8_t mulGF8( uint8_t x, uint8_t y )
{
    uint8_t m;
    for (m = 0; x > 1; x >>= 1)          /* optimized algorithm for nonzero x */
    {
        m ^= (x & 1) * y;
        y = xtime( y );
    }
    return m ^ y;                        /* or use (9 11 13 14) lookup tables */
}
#endif

#else
#define xtime(x)   ((x & 0x80 ? 0x1b : 0x00) ^ (x << 1))

#define mulGF8(x, y)                           \
     ( ((x      & 1) * y)                    ^ \
       ((x >> 1 & 1) * xtime(y))             ^ \
       ((x >> 2 & 1) * xtime(xtime(y)))      ^ \
       ((x >> 3 & 1) * xtime(xtime(xtime(y)))) )

static void xorBlock( const block_t src, block_t dest )
{
    long long *d = (void*) dest;         /* not supported in ANSI-C / ISO-C90 */
    long long const *s = (const void*) src;
    d[0] ^= s[0];
    d[1] ^= s[1];
}
#endif

/*----------------------------------------------------------------------------*\
              Main functions for the Rijndael encryption algorithm
\*----------------------------------------------------------------------------*/

/** This function produces (ROUNDS+1) round keys, which are used in each round
 * to encrypt/decrypt the intermediate states. First round key is the main key
 * itself, and other rounds are constructed from the previous ones as follows */
static void KeyExpansion( const uint8_t* key )
{
    uint8_t rcon = 1, i;
    memcpy( RoundKey, key, KEYSIZE );

    for (i = KEYSIZE; i < (ROUNDS + 1) * BLOCKSIZE; ++i)
    {
        switch (i % KEYSIZE)
        {
        case 0:
            memcpy( &RoundKey[i], &RoundKey[i - KEYSIZE], KEYSIZE );
#if Nk == 4
            if (rcon == 0) rcon = 0x1b;  /* RCON may reach 0 only in AES-128. */
#endif
            RoundKey[i] ^= getSBoxValue( RoundKey[i - 3] ) ^ rcon;
            rcon <<= 1;
            break;
        case 1:
        case 2:
            RoundKey[i] ^= getSBoxValue( RoundKey[i - 3] );
            break;
        case 3:
            RoundKey[i] ^= getSBoxValue( RoundKey[i - 7] );
            break;
#if Nk == 8                              /* additional round only for AES-256 */
        case 16:                         /*  0 <= i % KEYSIZE - BLOCKSIZE < 4 */
        case 17:
        case 18:
        case 19:
            RoundKey[i] ^= getSBoxValue( RoundKey[i - 4] );
            break;
#endif
        default:
            RoundKey[i] ^= RoundKey[i - 4];
            break;
        }
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
    (*state)[3][1] = temp;          /*  Rotated the 1st row 1 columns to left */

    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;          /*  Rotated the 2nd row 2 columns to left */

    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;          /*  Rotated the 3rd row 3 columns to left */
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
static void rijndaelEncrypt( const block_t input, block_t output )
{
    uint8_t round = ROUNDS;

    /* copy the input to the state matrix, and beware of undefined behavior.. */
    if (input != output)   memcpy( output, input, BLOCKSIZE );

    AddRoundKey( 0, output );       /*  Add the first round key to the state  */

    /* The encryption is carried out in #ROUNDS iterations, of which the first
     * #ROUNDS-1 are identical. The last round doesn't involve mixing columns */
    while (round)
    {
        SubBytes( output );
        ShiftRows( (state_t*) output );
        if (--round)  MixColumns( (state_t*) output );
        AddRoundKey( ROUNDS - round, output );
    }
}

/*----------------------------------------------------------------------------*\
                Block-decryption part of the Rijndael algorithm
\*----------------------------------------------------------------------------*/

#if IMPLEMENT(DECRYPTION)

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
    for (i = 0; i < Nb; ++i)
    {                               /*  see: crypto.stackexchange.com/q/48872 */
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = mulGF8( 14, a ) ^ mulGF8( 11, b ) ^ mulGF8( 13, c ) ^ mulGF8( 9, d );
        (*state)[i][1] = mulGF8( 14, b ) ^ mulGF8( 11, c ) ^ mulGF8( 13, d ) ^ mulGF8( 9, a );
        (*state)[i][2] = mulGF8( 14, c ) ^ mulGF8( 11, d ) ^ mulGF8( 13, a ) ^ mulGF8( 9, b );
        (*state)[i][3] = mulGF8( 14, d ) ^ mulGF8( 11, a ) ^ mulGF8( 13, b ) ^ mulGF8( 9, c );
    }
}

/** Decrypts a cipher-text input block, into a 128-bit plain text as output.. */
static void rijndaelDecrypt( const block_t input, block_t output )
{
    uint8_t round = ROUNDS;

    /* copy the input into state matrix, i.e. state is initialized by input.. */
    if (input != output)   memcpy( output, input, BLOCKSIZE );

    AddRoundKey( ROUNDS, output );  /* First, add the last round key to state */

    /* The decryption completes after #ROUNDS iterations, of which the first
     * #ROUNDS-1 are identical. The last round doesn't involve mixing columns */
    while (round)
    {
        InvShiftRows( (state_t*) output );
        InvSubBytes( output );
        AddRoundKey( --round, output );
        if (round)  InvMixColumns( (state_t*) output );
    }
}
#endif /* DECRYPTION */


#if M_RIJNDAEL
/**
 * @brief   encrypt or decrypt a single block with a given key
 * @param   key       a byte array with a fixed size specified by KEYSIZE
 * @param   mode      mode of operation: 'E' (1) to encrypt, 'D' (0) to decrypt
 * @param   x         input byte array with BLOCKSIZE bytes
 * @param   y         output byte array with BLOCKSIZE bytes
 */
void AES_Cipher( const uint8_t* key, const char mode, const block_t x, block_t y )
{
    fmix_t cipher = mode & 1 ? &rijndaelEncrypt : &rijndaelDecrypt;
    KeyExpansion( key );
    cipher( x, y );
}
#endif

/*----------------------------------------------------------------------------*\
 *              Implementation of different block ciphers modes               *
 *                            Auxiliary Functions                             *
\*----------------------------------------------------------------------------*/

#define AES_SetKey(key)     KeyExpansion( key )

#if INCREASE_SECURITY
#define BURN(key)           memset( key, 0, sizeof key )
#define SABOTAGE(buf, len)  memset( buf, 0, len )
#define MISMATCH            constmemcmp          /*  constant-time comparison */
#else
#define MISMATCH            memcmp
#define SABOTAGE(buf, len)  (void)  buf
#define BURN(key)           (void)  key
#endif

#if SMALL_CIPHER
#define putValueB(block, pos, val)  block[pos - 1] = val >> 8;  block[pos] = val
#define putValueL(block, pos, val)  block[pos + 1] = val >> 8;  block[pos] = val
#define xorWith(block, pos, val)    block[pos] ^= (val)
#define incBlock(block, big)      ++block[big ? LAST : 0]
#else

#if CTR

/** increment the value of a counter block, regarding its endian-ness ....... */
static void incBlock( block_t block, const char big )
{
    uint8_t i;
    if (big)                                     /*  big-endian counter       */
    {
        for (i = LAST; !++block[i] && i--; );    /*  (inc until no overflow)  */
    }
    else
    {
        for (i = 0; !++block[i] && i < 4; ++i);
    }
}

/** copy big endian value to the block, starting at the specified position... */
static void putValueB( block_t block, uint8_t pos, size_t val )
{
    do
        block[pos--] = (uint8_t) val;
    while (val >>= 8);
}
#endif

#if XTS || GCM_SIV

/** copy little endian value to the block, starting at the specified position */
static void putValueL( block_t block, uint8_t pos, size_t val )
{
    do
        block[pos++] = (uint8_t) val;
    while (val >>= 8);
}
#endif

#if KWA

/** xor a big endian value with a half-block.                                 */
static void xorWith( uint8_t* block, uint8_t pos, size_t val )
{
    do
        block[pos--] ^= (uint8_t) val;
    while (val >>= 8);
}
#endif
#endif /* SMALL CIPHER */


#ifdef AES_PADDING

/** in ECB or CBC without CTS, the last (partial) block has to be padded .... */
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

#if CTS || AEAD_MODES

/** The input block `y` is xor-ed with `x` and then mixed with block `src`... */
static void xorThenMix( const uint8_t* x, const uint8_t len,
                        const block_t src, fmix_t mix, block_t y )
{
    uint8_t i;
    for (i = 0; i < len; ++i)  y[i] ^= x[i];

    mix( src, y );                               /*  Y = mix( S, Y ^ X )      */
}
#endif

#if CBC || CFB || OFB || CTR || OCB

/** Result of applying a function to block `b` is xor-ed with `x` to get `y`. */
static void mixThenXor( const block_t b, fmix_t mix, block_t tmp,
                        const uint8_t* x, const uint8_t len, uint8_t* y )
{
    uint8_t i;
    if (len == 0)  return;                       /* f(B) = temp; Y = temp ^ X */

    mix( b, tmp );
    for (i = 0; i < len; ++i)  y[i] = tmp[i] ^ x[i];
}
#endif

#if EAX && !EAXP || SIV || OCB || CMAC

/** Multiply a block by two in Galois bit field GF(2^128): big-endian version */
static void doubleGF128B( block_t block )
{
    int i, s = 0;
    for (i = BLOCKSIZE; i--; s >>= 8)            /* loop from last to first,  */
    {                                            /* left-shift each byte and  */
        s |= block[i] << 1;                      /* ..add the previous MSB.   */
        block[i] = (uint8_t) s;
    }                                            /* if first MSB is carried:  */
    if (s)  block[LAST] ^= 0x87;                 /*   B ^= 10000111b (B.E.)   */
}
#endif

#if XTS || EAXP

/** Multiply a block by two in GF(2^128) field: this is little-endian version */
static void doubleGF128L( block_t block )
{
    int s = 0, i;
    for (i = 0; i < BLOCKSIZE; s >>= 8)          /* the same as doubleGF128B  */
    {                                            /* ..but with reversed bytes */
        s |= block[i] << 1;
        block[i++] = (uint8_t) s;
    }
    if (s)  block[0] ^= 0x87;                    /*   B ^= 10000111b (L.E.)   */
}
#endif

#if GCM

/** Divide a block by two in GF(2^128) field: used in big endian, 128bit mul. */
static void halveGF128B( block_t block )
{
    unsigned i, t = 0;
    for (i = 0; i < BLOCKSIZE; t <<= 8)          /* loop first to last byte,  */
    {                                            /* add the previous LSB then */
        t |= block[i];                           /* ..shift it to the right.  */
        block[i++] = (uint8_t) (t >> 1);
    }                                            /* if block is odd (LSB = 1) */
    if (t & 0x100)  block[0] ^= 0xe1;            /* .. B ^= 11100001b << 120  */
}

/** This function carries out multiplication in 128bit Galois field GF(2^128) */
static void mulGF128( const block_t x, block_t y )
{
    uint8_t i, j, result[BLOCKSIZE] = { 0 };     /*  working memory           */

    for (i = 0; i < BLOCKSIZE; ++i)
    {
        for (j = 0; j < 8; ++j)                  /*  check all the bits of X, */
        {
            if (x[i] << j & 0x80)                /*  ..and if any bit is set  */
            {
                xorBlock( y, result );           /*  M ^= Y                   */
            }
            halveGF128B( y );                    /*  Y_next = (Y / 2) in GF   */
        }
    }
    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* GCM */

#if GCM_SIV

/** Divide a block by two in GF(2^128) field: the little-endian version (duh) */
static void halveGF128L( block_t block )
{
    unsigned t = 0, i;
    for (i = BLOCKSIZE; i--; t <<= 8)            /* the same as halveGF128B ↑ */
    {                                            /* ..but with reversed bytes */
        t |= block[i];
        block[i] = (uint8_t) (t >> 1);
    }
    if (t & 0x100)  block[LAST] ^= 0xe1;         /* B ^= L.E 11100001b << 120 */
}

/** Dot multiplication in GF(2^128) field: used in POLYVAL hash for GCM-SIV.. */
static void dotGF128( const block_t x, block_t y )
{
    uint8_t i, j, result[BLOCKSIZE] = { 0 };

    for (i = BLOCKSIZE; i--; )
    {
        for (j = 8; j--; )                       /*  pretty much the same as  */
        {                                        /*  ..(reversed) mulGF128    */
            halveGF128L( y );
            if (x[i] >> j & 1)
            {
                xorBlock( y, result );
            }
        }
    }
    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* GCM-SIV */

#if AEAD_MODES

/** the overall scheme of CMAC or GMAC hash functions: divide data into 128-bit
 * blocks; then xor and apply the digest/mixing function to each xor-ed block */
static void MAC( const void* data, const size_t dataSize,
                 const block_t seed, fmix_t mix, block_t result )
{
    uint8_t const r = dataSize % BLOCKSIZE, *x;
    count_t n = dataSize / BLOCKSIZE;            /*   number of full blocks   */

    for (x = data; n--; x += BLOCKSIZE)
    {
        xorBlock( x, result );                   /* M_next = mix(seed, M ^ X) */
        mix( seed, result );
    }
    if (r == 0)  return;                         /* do the same with the last */
    xorThenMix( x, r, seed, mix, result );       /*  ..partial block (if any) */
}

#if CMAC || SIV || EAX

/** calculate the CMAC hash of input data using pre-calculated keys: D and Q. */
static void cMac( const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    block_t M = { 0 };
    uint8_t r = dataSize ? (dataSize - 1) % BLOCKSIZE + 1 : 0;
    const void* endblock = (const char*) data + dataSize - r;

    if (r < sizeof M)  M[r] = 0x80;
    memcpy( M, endblock, r );                    /*  copy last block into M   */
    xorBlock( r < sizeof M ? Q : D, M );         /*  ..and pad( M; D, Q )     */

    MAC( data, dataSize - r, mac, &rijndaelEncrypt, mac );
    xorThenMix( M, sizeof M, mac, &rijndaelEncrypt, mac );
}

typedef void (*fdouble_t)(block_t);              /* block-double function ptr */

/** calculate key-dependent constants D and Q for CMAC, regarding endianness: */
static void getSubkeys( const uint8_t* key, fdouble_t dou, block_t D, block_t Q )
{
    AES_SetKey( key );
    rijndaelEncrypt( D, D );                     /*  H or L_* = Enc(zeros)    */
    dou( D );                                    /*  D or L_$ = double(L_*)   */
    memcpy( Q, D, BLOCKSIZE );
    dou( Q );                                    /*  Q or L_0 = double(L_$)   */
}
#endif

#if INCREASE_SECURITY

/** for constant-time comparison of memory blocks, to avoid timing attacks:   */
static uint8_t constmemcmp( const uint8_t* src, const uint8_t* dst, uint8_t len )
{
    uint8_t i, cmp = 0;
    for (i = 0; i < len; ++i)  cmp |= src[i] ^ dst[i];
    return cmp;
}
#endif
#endif /* AEAD */


/*----------------------------------------------------------------------------*\
                  ECB-AES (electronic codebook mode) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(ECB)
/**
 * @brief   encrypt the input plaintext using ECB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 */
void AES_ECB_encrypt( const uint8_t* key,
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
    uint8_t const *x;
    uint8_t *y = crtxt;
    count_t n = ptextLen / BLOCKSIZE;            /*  number of full blocks    */

    AES_SetKey( key );
    for (x = pntxt; n--; x += BLOCKSIZE)
    {
        rijndaelEncrypt( x, y );                 /*  C = Enc(P)               */
        y += BLOCKSIZE;
    }
    if (padBlock( x, ptextLen % BLOCKSIZE, y ))
    {
        rijndaelEncrypt( y, y );
    }
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using ECB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 * @return            whether size of ciphertext is a multiple of BLOCKSIZE
 */
char AES_ECB_decrypt( const uint8_t* key,
                      const uint8_t* crtxt, const size_t crtxtLen, uint8_t* pntxt )
{
    uint8_t const *x;
    uint8_t *y = pntxt;
    count_t n = crtxtLen / BLOCKSIZE;

    AES_SetKey( key );
    for (x = crtxt; n--; x += BLOCKSIZE)
    {
        rijndaelDecrypt( x, y );                 /*  P = Dec(C)               */
        y += BLOCKSIZE;
    }
    BURN( RoundKey );

    /* if padding is enabled, check whether the result is properly padded. error
     * must be thrown if it's not. we skip this here and just check the size. */
    return crtxtLen % BLOCKSIZE ? DECRYPTION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* ECB */


/*----------------------------------------------------------------------------*\
                   CBC-AES (cipher block chaining) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CBC)
/**
 * @brief   encrypt the input plaintext using CBC-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 * @return            whether plaintext size is >= BLOCKSIZE for CTS mode
 */
char AES_CBC_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
    uint8_t const *x = pntxt, *iv = iVec;
    uint8_t r = ptextLen % BLOCKSIZE, *y;
    count_t n = ptextLen / BLOCKSIZE;

#if CTS
    if (!n)  return ENCRYPTION_FAILURE;
    r += (r == 0 && n > 1) * BLOCKSIZE;
    n -= (r == BLOCKSIZE);                       /*  hold the last block      */
#endif
    x += ptextLen - r;
    memcpy( crtxt, pntxt, ptextLen - r );        /*  copy plaintext to output */

    AES_SetKey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        xorBlock( iv, y );                       /*  Y = P because of memcpy  */
        rijndaelEncrypt( y, y );                 /*  C = Enc(IV ^ P)          */
        iv = y;                                  /*  IV_next = C              */
    }
#if CTS                                          /*  cipher-text stealing CS3 */
    if (r)
    {
        memcpy( y, y - BLOCKSIZE, r );           /*  'steal' the cipher-text  */
        y -= BLOCKSIZE;                          /*  ..to fill the last block */
        xorThenMix( x, r, y, &rijndaelEncrypt, y );
#else
    if (padBlock( x, r, y ))
    {
        xorBlock( iv, y );
        rijndaelEncrypt( y, y );
#endif
    }
    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}

/**
 * @brief   decrypt the input ciphertext using CBC-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 * @return            whether size of ciphertext is a multiple of BLOCKSIZE
 */
char AES_CBC_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* crtxt, const size_t crtxtLen, uint8_t* pntxt )
{
    uint8_t const *x = crtxt, *iv = iVec;
    uint8_t r = crtxtLen % BLOCKSIZE, *y;
    count_t n = crtxtLen / BLOCKSIZE;

#if CTS
    if (!n)  return DECRYPTION_FAILURE;
    r += (r == 0 && n > 1) * BLOCKSIZE;
    n -= (r == BLOCKSIZE) + (r != 0);            /*  last two blocks swapped  */
#else
    if (r)  return DECRYPTION_FAILURE;
#endif

    AES_SetKey( key );
    for (y = pntxt; n--; y += BLOCKSIZE)
    {
        rijndaelDecrypt( x, y );                 /*  P = Dec(C) ^ IV          */
        xorBlock( iv, y );                       /*  IV_next = C              */
        iv = x;
        x += BLOCKSIZE;
    }                                            /*  #if !CTS, surely r = 0   */
    if (r)
    {                                            /*  P2  =  Dec(C1) ^ C2      */
        mixThenXor( x, &rijndaelDecrypt, y, x + BLOCKSIZE, r, y + BLOCKSIZE );
        memcpy( y, x + BLOCKSIZE, r );
        rijndaelDecrypt( y, y );                 /*  copy C2 to Dec(C1): -> T */
        xorBlock( iv, y );                       /*  P1 = IV ^ Dec(T)         */
    }
    BURN( RoundKey );

    /* note: if padding was applied, check whether output is properly padded. */
    return ENDED_IN_SUCCESS;
}
#endif /* CBC */


/*----------------------------------------------------------------------------*\
                      CFB-AES (cipher feedback) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CFB)
/**
 * @brief   the general scheme of CFB-AES block-ciphering algorithm
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   mode      mode of operation: (1) to encrypt, (0) to decrypt
 * @param   input     buffer of the input plain/cipher-text
 * @param   dataSize  size of input in bytes
 * @param   output    buffer of the resulting cipher/plain-text
 */
static void CFB_Cipher( const uint8_t* key, const block_t iVec, const char mode,
                        const void* input, const size_t dataSize, void* output )
{
    uint8_t const *iv = iVec, *x;
    uint8_t *y = output, tmp[BLOCKSIZE];
    count_t n = dataSize / BLOCKSIZE;            /*  number of full blocks    */

    AES_SetKey( key );
    for (x = input; n--; x += BLOCKSIZE)
    {
        rijndaelEncrypt( iv, y );                /*  both in en[de]cryption:  */
        xorBlock( x, y );                        /*  Y = Enc(IV) ^ X          */
        iv = mode ? y : x;                       /*  IV_next = Ciphertext     */
        y += BLOCKSIZE;
    }
    mixThenXor( iv, &rijndaelEncrypt, tmp, x, dataSize % BLOCKSIZE, y );
    BURN( RoundKey );
}

/**
 * @brief   encrypt the input plaintext using CFB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 */
void AES_CFB_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
    CFB_Cipher( key, iVec, 1, pntxt, ptextLen, crtxt );
}

/**
 * @brief   decrypt the input ciphertext using CFB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 */
void AES_CFB_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* crtxt, const size_t crtxtLen, uint8_t* pntxt )
{
    CFB_Cipher( key, iVec, 0, crtxt, crtxtLen, pntxt );
}
#endif /* CFB */


/*----------------------------------------------------------------------------*\
                      OFB-AES (output feedback) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(OFB)
/**
 * @brief   encrypt the input plaintext using OFB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 */
void AES_OFB_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
    block_t iv;
    uint8_t *y;
    count_t n = ptextLen / BLOCKSIZE;            /*  number of full blocks    */
    memcpy( crtxt, pntxt, ptextLen );            /*  copy plaintext to output */
    memcpy( iv, iVec, sizeof iv );

    AES_SetKey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( iv, iv );               /*  C = Enc(IV) ^ P          */
        xorBlock( iv, y );                       /*  IV_next = Enc(IV)        */
    }

    mixThenXor( iv, &rijndaelEncrypt, iv, y, ptextLen % BLOCKSIZE, y );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using OFB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 */
void AES_OFB_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* crtxt, const size_t crtxtLen, uint8_t* pntxt )
{
    AES_OFB_encrypt( key, iVec, crtxt, crtxtLen, pntxt );
}
#endif /* OFB */


/*----------------------------------------------------------------------------*\
    Parallelizable, counter-based modes of AES: demonstrating the main idea
               + How to use it in a simple, non-authenticated API
\*----------------------------------------------------------------------------*/
#if CTR
/**
 * @brief   the overall scheme of operation in block-counter mode
 * @param   iCtr      initialized counter block
 * @param   big       big-endian block increment (1, 2) or little endian (0)
 * @param   input     buffer of the input plain/cipher-text
 * @param   dataSize  size of input in bytes
 * @param   output    buffer of the resulting cipher/plain-text
 */
static void CTR_Cipher( const block_t iCtr, const char big,
                        const void* input, const size_t dataSize, void* output )
{
    block_t c, enc;
    count_t n = dataSize / BLOCKSIZE;
    uint8_t *y = output;
    if (input != output)  memcpy( output, input, dataSize );

    memcpy( c, iCtr, sizeof c );
    if (big > 1)  incBlock( c, 1 );              /* pre-increment for CCM/GCM */

    for ( ; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( c, enc );               /*  both in en[de]cryption:  */
        xorBlock( enc, y );                      /*  Y = Enc(Ctr) ^ X         */
        incBlock( c, big );                      /*  Ctr_next = Ctr + 1       */
    }
    mixThenXor( c, &rijndaelEncrypt, c, y, dataSize % BLOCKSIZE, y );
}
#endif

#if IMPLEMENT(CTR_NA)
/**
 * @brief   encrypt the input plaintext using CTR-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iv        initialization vector a.k.a. nonce
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 */
void AES_CTR_encrypt( const uint8_t* key, const uint8_t* iv,
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
#if CTR_IV_LENGTH == BLOCKSIZE
#define CTRBLOCK  iv
#else
    block_t CTRBLOCK = { 0 };
    memcpy( CTRBLOCK, iv, CTR_IV_LENGTH );
    putValueB( CTRBLOCK, LAST, CTR_STARTVALUE );
#endif
    AES_SetKey( key );
    CTR_Cipher( CTRBLOCK, 1, pntxt, ptextLen, crtxt );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using CTR-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iv        initialization vector a.k.a. nonce
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 */
void AES_CTR_decrypt( const uint8_t* key, const uint8_t* iv,
                      const uint8_t* crtxt, const size_t crtxtLen, uint8_t* pntxt )
{
    AES_CTR_encrypt( key, iv, crtxt, crtxtLen, pntxt );
}
#endif /* CTR */


/*----------------------------------------------------------------------------*\
       XEX-AES based modes (xor-encrypt-xor): demonstrating the main idea
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(XTS)
/**
 * @brief   encrypt or decrypt a data unit with given key-pair using XEX method
 * @param   keypair   pair of encryption keys, each one has KEYSIZE bytes
 * @param   cipher    block cipher function: rijndaelEncrypt or rijndaelDecrypt
 * @param   dataSize  size of input data, to be encrypted/decrypted
 * @param   scid      sector id: if the given value is -1, use tweak value
 * @param   tweakid   data unit identifier, similar to nonce in CTR mode
 * @param   T         one-time pad which is xor-ed with both plain/cipher text
 * @param   storage   working memory; result of encryption/decryption process
 */
static void XEX_Cipher( const uint8_t* keypair, fmix_t cipher,
                        const size_t dataSize, const size_t scid,
                        const block_t tweakid, block_t T, void* storage )
{
    uint8_t *y;
    count_t n = dataSize / BLOCKSIZE;

    if (scid == (size_t) ~0)
    {                                            /* the `i` block is either   */
        memcpy( T, tweakid, BLOCKSIZE );         /* ..a little-endian number  */
    }                                            /* ..or a byte array.        */
    else
    {
        putValueL( T, 0, scid );
    }
    AES_SetKey( keypair + KEYSIZE );             /* T = encrypt `i` with key2 */
    rijndaelEncrypt( T, T );

    AES_SetKey( keypair );                       /* key1 is set as cipher key */
    for (y = storage; n--; y += BLOCKSIZE)
    {
        xorBlock( T, y );                        /*  xor T with input         */
        cipher( y, y );
        xorBlock( T, y );                        /*  Y = T ^ Cipher( T ^ X )  */
        doubleGF128L( T );                       /*  T_next = T * alpha       */
    }
}

/*----------------------------------------------------------------------------*\
    XTS-AES (XEX Tweaked-codebook with ciphertext Stealing): main functions
\*----------------------------------------------------------------------------*/
/**
 * @brief   encrypt the input plaintext using XTS-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   twkId     tweak value of data unit, a.k.a sector ID (little-endian)
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 */
char AES_XTS_encrypt( const uint8_t* keys, const uint8_t* twkId,
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
    block_t T = { 0 };
    uint8_t r = ptextLen % BLOCKSIZE, *c;
    size_t len = ptextLen - r;

    if (len == 0)  return ENCRYPTION_FAILURE;
    memcpy( crtxt, pntxt, len );                 /* copy input data to output */

    XEX_Cipher( keys, &rijndaelEncrypt, len, ~0, twkId, T, crtxt );
    if (r)
    {                                            /*  XTS for partial block    */
        c = crtxt + len - BLOCKSIZE;
        memcpy( crtxt + len, c, r );             /* 'steal' the cipher-text   */
        memcpy( c, pntxt + len, r );             /*  ..for the partial block  */
        xorBlock( T, c );
        rijndaelEncrypt( c, c );
        xorBlock( T, c );
    }

    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}

/**
 * @brief   encrypt the input ciphertext using XTS-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   twkId     tweak value of data unit, a.k.a sector ID (little-endian)
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 */
char AES_XTS_decrypt( const uint8_t* keys, const uint8_t* twkId,
                      const uint8_t* crtxt, const size_t crtxtLen, uint8_t* pntxt )
{
    block_t TT, T = { 0 };
    uint8_t r = crtxtLen % BLOCKSIZE, *p;
    size_t len = crtxtLen - r;

    if (len == 0)  return DECRYPTION_FAILURE;
    memcpy( pntxt, crtxt, len );                 /* copy input data to output */
    p = pntxt + len - BLOCKSIZE;

    XEX_Cipher( keys, &rijndaelDecrypt, len - BLOCKSIZE, ~0, twkId, T, pntxt );
    if (r)
    {
        memcpy( TT, T, sizeof T );
        doubleGF128L( TT );                      /*  TT = T * alpha,          */
        xorBlock( TT, p );                       /*  because the stolen       */
        rijndaelDecrypt( p, p );                 /*  ..ciphertext was xor-ed  */
        xorBlock( TT, p );                       /*  ..with TT in encryption  */
        memcpy( pntxt + len, p, r );
        memcpy( p, crtxt + len, r );
    }
    xorBlock( T, p );
    rijndaelDecrypt( p, p );
    xorBlock( T, p );

    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}
#endif /* XTS */


/*----------------------------------------------------------------------------*\
       CMAC-AES (cipher-based message authentication code): main function
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CMAC)
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
    block_t K1 = { 0 }, K2;
    memset( mac, 0, BLOCKSIZE );
    getSubkeys( key, &doubleGF128B, K1, K2 );
    cMac( K1, K2, data, dataSize, mac );
    BURN( RoundKey );
}
#endif /* CMAC */


/*----------------------------------------------------------------------------*\
    GCM-AES (Galois counter mode): authentication with GMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM)

/** calculates GMAC hash of ciphertext and AAD using authentication subkey H: */
static void GHash( const block_t H, const void* aData, const void* crtxt,
                   const size_t adataLen, const size_t crtxtLen, block_t gsh )
{
    block_t buf = { 0 };                         /*  save bit-sizes into buf  */
    putValueB( buf, BLOCKSIZE - 9, adataLen * 8 );
    putValueB( buf, BLOCKSIZE - 1, crtxtLen * 8 );

    MAC( aData, adataLen, H, &mulGF128, gsh );   /*  first digest AAD, then   */
    MAC( crtxt, crtxtLen, H, &mulGF128, gsh );   /*  ..ciphertext, and then   */
    MAC( buf, sizeof buf, H, &mulGF128, gsh );   /*  ..bit sizes into GHash   */
}

/** encrypt zeros to get authentication subkey H, and prepare the IV for GCM. */
static void GInitialize( const uint8_t* key,
                         const uint8_t* nonce, block_t authKey, block_t iv )
{
    AES_SetKey( key );
    rijndaelEncrypt( authKey, authKey );         /* authKey = Enc(zero block) */
#if GCM_NONCE_LEN != 12
    GHash( authKey, NULL, nonce, 0, GCM_NONCE_LEN, iv );
#else
    memcpy( iv, nonce, 12 );
    iv[LAST] = 1;
#endif
}

/**
 * @brief   encrypt the input plaintext using GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: GCM_NONCE_LEN
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     resulting cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_GCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, block_t auTag )
{
    block_t H = { 0 }, iv = { 0 }, gsh = { 0 };
    GInitialize( key, nonce, H, iv );            /*  get IV & auth. subkey H  */

    CTR_Cipher( iv, 2, pntxt, ptextLen, crtxt );
    rijndaelEncrypt( iv, auTag );                /*  tag = Enc(iv) ^ GHASH    */
    BURN( RoundKey );
    GHash( H, aData, crtxt, aDataLen, ptextLen, gsh );
    xorBlock( gsh, auTag );
}

/**
 * @brief   decrypt the input ciphertext using GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: GCM_NONCE_LEN
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_GCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    block_t H = { 0 }, iv = { 0 }, gsh = { 0 };
    GInitialize( key, nonce, H, iv );
    GHash( H, aData, crtxt, aDataLen, crtxtLen, gsh );

    rijndaelEncrypt( iv, H );
    xorBlock( H, gsh );                          /*   tag = Enc(iv) ^ GHASH   */
    if (MISMATCH( gsh, crtxt + crtxtLen, tagLen ))
    {                                            /*  compare tags and         */
        BURN( RoundKey );                        /*  ..proceed if they match  */
        return AUTHENTICATION_FAILURE;
    }
    CTR_Cipher( iv, 2, crtxt, crtxtLen, pntxt );
    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}
#endif /* GCM */


/*----------------------------------------------------------------------------*\
    CCM-AES (counter with CBC-MAC): CBC-MAC authentication & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CCM)

/** this function calculates the CBC-MAC of plaintext and authentication data */
static void CBCMac( const block_t iv, const void* aData, const void* pntxt,
                    const size_t aDataLen, const size_t ptextLen, block_t cm )
{
    block_t A = { 0 };
    uint8_t p, s = BLOCKSIZE - 2;
    memcpy( cm, iv, BLOCKSIZE );                 /*  initialize CBC-MAC       */

    cm[0] |= (CCM_TAG_LEN - 2) << 2;             /*  set some flags on M_0    */
    putValueB( cm, LAST, ptextLen );             /*  copy data size into M_0  */
    if (aDataLen)                                /*  <-- else: M_* = M_0      */
    {
        if (aDataLen < s)  s = aDataLen;
        p = aDataLen < 0xFF00 ? 1 : 5;
        putValueB( A, p, aDataLen );             /*  len_id = aDataLen        */
        if (p == 5)
        {
            s -= 4;
            putValueB( A, 1, 0xFFFE );           /*  prepend FFFE to len_id   */
        }
        memcpy( A + p + 1, aData, s );           /*  A = len_id ~~ ADATA      */
        cm[0] |= 0x40;
        rijndaelEncrypt( cm, cm );               /*  M_* = Enc( flagged M_0 ) */
        xorBlock( A, cm );
    }

    rijndaelEncrypt( cm, cm );                   /*  M_1 = Enc( M_* ^ A ),    */
    if (aDataLen > s)                            /*  CBC-MAC rest of adata    */
    {
        MAC( (char const*) aData + s, aDataLen - s, cm, &rijndaelEncrypt, cm );
    }
    MAC( pntxt, ptextLen, cm, &rijndaelEncrypt, cm );
}

/**
 * @brief   encrypt the input plaintext using CCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: CCM_NONCE_LEN
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     resulting cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_CCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, block_t auTag )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, cbc;
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );

    AES_SetKey( key );
    CBCMac( iv, aData, pntxt, aDataLen, ptextLen, cbc );
    CTR_Cipher( iv, 2, pntxt, ptextLen, crtxt );
    rijndaelEncrypt( iv, auTag );
    xorBlock( cbc, auTag );                      /*  tag = Enc(iv) ^ CBC-MAC  */
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using CCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: CCM_NONCE_LEN
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag (if any)
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_CCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, cbc;
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );
    if (tagLen && tagLen != CCM_TAG_LEN)  return DECRYPTION_FAILURE;

    AES_SetKey( key );
    CTR_Cipher( iv, 2, crtxt, crtxtLen, pntxt );
    CBCMac( iv, aData, pntxt, aDataLen, crtxtLen, cbc );
    rijndaelEncrypt( iv, iv );                   /*  tag = Enc(iv) ^ CBC-MAC  */
    BURN( RoundKey );

    xorBlock( iv, cbc );                         /*  verify the resulting tag */
    if (MISMATCH( cbc, crtxt + crtxtLen, tagLen ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* CCM */


/*----------------------------------------------------------------------------*\
       SIV-AES (synthetic init-vector): nonce synthesis & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(SIV)

/** calculate the CMAC* of AAD unit(s), then plaintext, and synthesize the IV */
static void S2V( const uint8_t* key,
                 const void* aData, const void* pntxt,
                 const size_t aDataLen, const size_t ptextLen, block_t V )
{
    block_t T = { 0 }, D = { 0 }, Q;
    uint8_t r = ptextLen >= BLOCKSIZE ? BLOCKSIZE : ptextLen % BLOCKSIZE;
    uint8_t const* x = (uint8_t const*) pntxt - r + ptextLen;

    getSubkeys( key, &doubleGF128B, D, Q );
    cMac( D, Q, T, sizeof T, T );                /*  T_0 = CMAC(zero block)   */
    if (aDataLen)                                /*  process each ADATA unit  */
    {                                            /*  ..the same way as this:  */
        doubleGF128B( T );
        cMac( D, Q, aData, aDataLen, V );        /*  C_A = CMAC(ADATA)        */
        xorBlock( V, T );                        /*  T_1 = double(T_0) ^ C_A  */
        memset( V, 0, BLOCKSIZE );
    }
    if (r < sizeof T)
    {
        doubleGF128B( T );
        T[r] ^= 0x80;                            /*  T = double(T_n) ^ pad(X) */
        while (r--)  T[r] ^= x[r];
    }
    else  xorBlock( x, T );                      /*  T = T_n  xor_end  X      */

    cMac( D, Q, T, sizeof T, V );                /*  I.V = CMAC*(T)           */
}

/**
 * @brief   encrypt the input plaintext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   iv        synthesized I.V block, naturally prepended to ciphertext
 * @param   crtxt     resulting cipher-text buffer
 */
void AES_SIV_encrypt( const uint8_t* keys,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      block_t iv, uint8_t* crtxt )
{
    block_t IV = { 0 };
    S2V( keys, aData, pntxt, aDataLen, ptextLen, IV );
    memcpy( iv, IV, sizeof IV );
    IV[8] &= 0x7F;  IV[12] &= 0x7F;              /*  clear 2 bits for cipher  */

    AES_SetKey( keys + KEYSIZE );
    CTR_Cipher( IV, 1, pntxt, ptextLen, crtxt );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   iv        provided I.V block to validate
 * @param   crtxt     input cipher-text buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   pntxt     resulting plaintext buffer
 * @return            whether synthesized I.V. matched the provided one
 */
char AES_SIV_decrypt( const uint8_t* keys, const block_t iv,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* pntxt )
{
    block_t IV;
    memcpy( IV, iv, sizeof IV );
    IV[8] &= 0x7F;  IV[12] &= 0x7F;              /*  clear two bits           */

    AES_SetKey( keys + KEYSIZE );
    CTR_Cipher( IV, 1, crtxt, crtxtLen, pntxt );
    memset( IV, 0, sizeof IV );
    S2V( keys, aData, pntxt, aDataLen, crtxtLen, IV );
    BURN( RoundKey );

    if (MISMATCH( IV, iv, sizeof IV ))           /* verify the synthesized IV */
    {
        SABOTAGE( pntxt, crtxtLen );
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* SIV */


/*----------------------------------------------------------------------------*\
      SIV-GCM-AES (Galois counter mode with synthetic i.v): main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM_SIV)

/** calculates the POLYVAL of plaintext and AAD using authentication subkey H */
static void Polyval( const block_t H, const void* aData, const void* pntxt,
                     const size_t aDataLen, const size_t ptextLen, block_t pv )
{
    block_t buf = { 0 };                         /*  save bit-sizes into buf  */
    putValueL( buf, 0, aDataLen * 8 );
    putValueL( buf, 8, ptextLen * 8 );

    MAC( aData, aDataLen, H, &dotGF128, pv );    /*  first digest AAD, then   */
    MAC( pntxt, ptextLen, H, &dotGF128, pv );    /*  ..plaintext, and then    */
    MAC( buf, sizeof buf, H, &dotGF128, pv );    /*  ..bit sizes into POLYVAL */
}

/** derive the pair of authentication-encryption-keys from main key and nonce */
static void DeriveGSKeys( const uint8_t* key, const uint8_t* nonce, block_t AK )
{
    uint8_t AEKeypair[KEYSIZE + 24];
    uint8_t iv[BLOCKSIZE], *k = AEKeypair;
    memcpy( iv + 4, nonce, 12 );

    AES_SetKey( key );
    for (*(int32_t*) iv = 0; *iv < KEYSIZE / 8 + 2; ++*iv)
    {
        rijndaelEncrypt( iv, k );                /* encrypt & take half, then */
        k += 8;                                  /* ..increment iv's LSB      */
    }
    AES_SetKey( AEKeypair + BLOCKSIZE );         /*  set the main cipher-key  */
    memcpy( AK, AEKeypair, BLOCKSIZE );          /*  take authentication key  */
}

/**
 * @brief   encrypt the input plaintext using SIV-GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     provided 96-bit nonce
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     resulting cipher-text buffer,
 * @param   auTag     appended authentication tag. must be 16-bytes long
 */
void GCM_SIV_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, block_t auTag )
{
    block_t H, S = { 0 };
    DeriveGSKeys( key, nonce, H );               /* get authentication subkey */

    Polyval( H, aData, pntxt, aDataLen, ptextLen, S );
    for (*H = 0; *H < 12; ++*H)
    {                                            /* using H[0] as counter!    */
        S[*H] ^= nonce[*H];                      /* xor nonce with POLYVAL    */
    }
    S[LAST] &= 0x7F;                             /* clear one bit & encrypt,  */
    rijndaelEncrypt( S, S );                     /* ..to get auth. tag        */
    memcpy( auTag, S, sizeof S );

    S[LAST] |= 0x80;                             /* set 1 bit to get CTR's IV */
    CTR_Cipher( S, 0, pntxt, ptextLen, crtxt );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using SIV-GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     provided 96-bit nonce
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag; MUST be 16 bytes
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message authentication/decryption was successful
 */
char GCM_SIV_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    block_t H, S;
    if (tagLen != sizeof S)  return DECRYPTION_FAILURE;

    DeriveGSKeys( key, nonce, H );               /* get authentication subkey */
    memcpy( S, crtxt + crtxtLen, sizeof S );     /* tag is IV for CTR cipher  */
    S[LAST] |= 0x80;
    CTR_Cipher( S, 0, crtxt, crtxtLen, pntxt );

    memset( S, 0, sizeof S );
    Polyval( H, aData, pntxt, aDataLen, crtxtLen, S );
    for (*H = 0; *H < 12; ++*H)
    {                                            /* using H[0] as counter!    */
        S[*H] ^= nonce[*H];                      /* xor nonce with POLYVAL    */
    }
    S[LAST] &= 0x7F;                             /* clear one bit & encrypt,  */
    rijndaelEncrypt( S, S );                     /* ..to get tag & verify it  */

    BURN( RoundKey );
    if (MISMATCH( S, crtxt + crtxtLen, sizeof S ))
    {                                            /*  tag verification failed  */
        SABOTAGE( pntxt, crtxtLen );
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* GCM-SIV */


/*----------------------------------------------------------------------------*\
   EAX-AES (encrypt-then-authenticate-then-translate): OMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(EAX)

/** this function calculates the OMAC hash of a data array using D (K1) and Q */
static void OMac( const uint8_t t, const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    block_t M = { 0 };
#if EAXP
    memcpy( mac, t ? (dataSize ? Q : M) : D, sizeof M );
    if (dataSize || !t)                          /*   ignore null ciphertext  */
#else
    if (dataSize == 0)
    {
        memcpy( M, D, sizeof M );                /*  OMAC = Enc( D ^ [t]_n )  */
    }
    M[LAST] ^= t;                                /*  else: C1 = Enc( [t]_n )  */
    rijndaelEncrypt( M, mac );
#endif
    cMac( D, Q, data, dataSize, mac );
}

/**
 * @brief   encrypt the input plaintext using EAX-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes if not EAX'
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     resulting cipher-text buffer; 4 bytes mac appended in EAX'
 * @param   auTag     authentication tag; buffer must be 16 bytes long in EAX
 */
void AES_EAX_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
#if EAXP
                      const size_t nonceLen, uint8_t* crtxt )
#define fDouble       doubleGF128L
#else
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, uint8_t* auTag )
#define fDouble       doubleGF128B
#define nonceLen      EAX_NONCE_LEN
#endif
{
    block_t D = { 0 }, Q, mac;
    getSubkeys( key, &fDouble, D, Q );
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = OMAC(0; nonce)       */

#if EAXP
    *(int32_t*) &crtxt[ptextLen] = *(int32_t*) &mac[12];
    mac[12] &= 0x7F;
    mac[14] &= 0x7F;                             /*  clear 2 bits to get N'   */
    CTR_Cipher( mac, 1, pntxt, ptextLen, crtxt );
    OMac( 2, D, Q, crtxt, ptextLen, mac );       /*  C' = CMAC'( ciphertext ) */

    *(int32_t*) &crtxt[ptextLen] ^= *(int32_t*) &mac[12];
#else
    OMac( 1, D, Q, aData, aDataLen, auTag );     /*  H = OMAC(1; adata)       */
    xorBlock( mac, auTag );
    CTR_Cipher( mac, 1, pntxt, ptextLen, crtxt );

    OMac( 2, D, Q, crtxt, ptextLen, mac );       /*  C = OMAC(2; ciphertext)  */
    xorBlock( mac, auTag );                      /*  tag = N ^ H ^ C          */
#endif
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using EAX-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes if not EAX'
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of cipher-text; excluding tag / 4-bytes mac in EAX'
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data; ignored in EAX'
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag; mandatory 4 bytes in EAX'
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_EAX_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
#if EAXP
                      const size_t nonceLen,
#else
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen,
#endif
                      uint8_t* pntxt )
{
    block_t D = { 0 }, Q, mac, tag;
    getSubkeys( key, &fDouble, D, Q );
    OMac( 2, D, Q, crtxt, crtxtLen, tag );       /*  C = OMAC(2; ciphertext)  */

#if EAXP
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = CMAC'( nonce )       */
    *(int32_t*) &tag[12] ^= *(int32_t*) &mac[12];
    *(int32_t*) &tag[12] ^= *(int32_t*) &crtxt[crtxtLen];

    mac[12] &= 0x7F;                             /*  clear 2 bits to get N'   */
    mac[14] &= 0x7F;
    if (0 != *(int32_t*) &tag[12])               /*  result of mac validation */
#else
    OMac( 1, D, Q, aData, aDataLen, mac );       /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = OMAC(0; nonce)       */
    xorBlock( mac, tag );                        /*  tag = N ^ H ^ C          */

    if (MISMATCH( tag, crtxt + crtxtLen, tagLen ))
#endif
    {                                            /* authenticate then decrypt */
        BURN( RoundKey );
        return AUTHENTICATION_FAILURE;
    }
    CTR_Cipher( mac, 1, crtxt, crtxtLen, pntxt );

    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}
#endif /* EAX */


/*----------------------------------------------------------------------------*\
              OCB-AES (offset codebook mode): auxiliary functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(OCB)

/** Get the offset block (Δ_i) which is initialized by Δ_0, at the specified
 * index for a given L$. This method has minimum memory usage, but it is slow */
static void OffsetB( const block_t Ld, const count_t index, block_t delta )
{
    size_t m, b = 1;
    block_t L;
    memcpy( L, Ld, sizeof L );                   /*  initialize L_$           */

    while (b <= index && b)                      /*  we can pre-calculate all */
    {                                            /*  ..L_{i}s to boost speed  */
        m = (4 * b - 1) & (index - b);
        b <<= 1;                                 /*  L_0 = double( L_$ )      */
        doubleGF128B( L );                       /*  L_i = double( L_{i-1} )  */
        if (b > m)  xorBlock( L, delta );        /*  Δ_new = Δ ^ L_i          */
    }
}

/**
 * @brief   encrypt or decrypt a data unit using OCB-AES method
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   cipher    block-cipher function: rijndaelEncrypt or rijndaelDecrypt
 * @param   input     input plain/cipher-text buffer
 * @param   dataSize  size of data
 * @param   Ls        L_* is the result of the encryption of a zero block
 * @param   Ld        L_$ = double(L_*) in GF(2^128)
 * @param   Del       Δ_m  a.k.a last offset (sometimes Δ*, which is Δ_m ^ L_*)
 * @param   output    encrypted/decrypted data storage
 */
static void OCB_Cipher( const uint8_t* nonce, fmix_t cipher,
                        const void* input, const size_t dataSize,
                        block_t Ls, block_t Ld, block_t Del, void* output )
{
    uint8_t kt[2 * BLOCKSIZE] = { OCB_TAG_LEN << 4 & 0xFF };
    count_t i, n = nonce[OCB_NONCE_LEN - 1] & 0x3F;
    uint8_t *y = output, r = n % 8;

    memcpy( output, input, dataSize );           /* copy input data to output */

    memcpy( kt + BLOCKSIZE - OCB_NONCE_LEN, nonce, OCB_NONCE_LEN );
    kt[LAST - OCB_NONCE_LEN] |= 1;
    kt[LAST] &= 0xC0;                            /* clear last 6 bits         */
    n /= 8;                                      /* copy last 6 bits to (n,r) */

    rijndaelEncrypt( kt, kt );                   /* construct K_top           */
    memcpy( kt + BLOCKSIZE, kt + 1, 8 );         /* stretch K_top             */
    xorBlock( kt, kt + BLOCKSIZE );
    for (i = 0; i < BLOCKSIZE; ++n)              /* shift the stretched K_top */
    {
        kt[i++] = kt[n] << r | kt[n + 1] >> (8 - r);
    }
    n = dataSize / BLOCKSIZE;
    r = dataSize % BLOCKSIZE;

    rijndaelEncrypt( Ls, Ls );                   /*  L_* = Enc(zero block)    */
    memcpy( Ld, Ls, BLOCKSIZE );
    doubleGF128B( Ld );                          /*  L_$ = double(L_*)        */
    if (n == 0)                                  /*  processed nonce is Δ_0   */
    {
        memcpy( Del, kt, BLOCKSIZE );            /*  initialize Δ_0           */
    }
    for (i = 0; i < n; y += BLOCKSIZE)
    {
        memcpy( Del, kt, BLOCKSIZE );            /*  calculate Δ_i using my   */
        OffsetB( Ld, ++i, Del );                 /*  .. 'magic' algorithm     */
        xorBlock( Del, y );
        cipher( y, y );                          /* Y = Δ_i ^ Cipher(Δ_i ^ X) */
        xorBlock( Del, y );
    }
    if (r)                                       /*  Δ_* = Δ_n ^ L_* and then */
    {                                            /*  Y_* = Enc(Δ_*) ^ X       */
        xorBlock( Ls, Del );
        mixThenXor( Del, &rijndaelEncrypt, kt, y, r, y );
        Del[r] ^= 0x80;                          /*    pad it for checksum    */
    }
}

static void nop( const block_t x, block_t y ) {}

/** derives OCB authentication tag. the first three arguments are pre-calculated
 * namely, Δ_* (or sometimes Δ_m), L_* = encrypt(zeros) and L_$ = double(L_*) */
static void OCB_GetTag( const block_t Ds,
                        const block_t Ls, const block_t Ld,
                        const void* pntxt, const void* aData,
                        const size_t ptextLen, const size_t aDataLen,
                        block_t tag )
{
    uint8_t const r = aDataLen % BLOCKSIZE, *x = aData;
    count_t i, n = aDataLen / BLOCKSIZE;
    block_t S = { 0 };                           /*  checksum, i.e.           */
    MAC( pntxt, ptextLen, NULL, &nop, S );       /*  ..xor of all plaintext   */

    xorBlock( Ds, S );
    xorBlock( Ld, S );
    rijndaelEncrypt( S, tag );                   /* Tag0 = Enc(L_$ ^ Δ_* ^ S) */
    if (aDataLen == 0)  return;

    memset( S, 0, sizeof S );                    /*  PMAC authentication:     */
    for (i = 0; i < n; x += BLOCKSIZE)
    {
        OffsetB( Ld, ++i, S );
        xorBlock( x, S );
        rijndaelEncrypt( S, S );                 /*  S_i = Enc(A_i ^ Δ_i)     */
        xorBlock( S, tag );                      /*  Tag_{i+1} = Tag_i ^ S_i  */
        memset( S, 0, sizeof S );
    }
    if (r)
    {
        OffsetB( Ld, n, S );                     /*  S = calculated Δ_n       */
        S[r] ^= 0x80;                            /*  A_* = A || 1  (padded)   */
        xorThenMix( x, r, Ls, &xorBlock, S );    /*  S_* = A_* ^ L_* ^ Δ_n    */
        rijndaelEncrypt( S, S );
        xorBlock( S, tag );                      /*  Tag = Enc(S_*) ^ Tag_n   */
    }
}

/*----------------------------------------------------------------------------*\
                 OCB-AES (offset codebook mode): main functions
\*----------------------------------------------------------------------------*/
/**
 * @brief   encrypt the input stream using OCB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     resulting cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_OCB_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, block_t auTag )
{
    block_t Ls = { 0 }, Ld, delta;
    AES_SetKey( key );
    OCB_Cipher( nonce, &rijndaelEncrypt, pntxt, ptextLen, Ls, Ld, delta, crtxt );
    OCB_GetTag( delta, Ls, Ld, pntxt, aData, ptextLen, aDataLen, auTag );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input stream using OCB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag (if any)
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_OCB_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    block_t Ls = { 0 }, Ld, delta;
    if (tagLen && tagLen != OCB_TAG_LEN)  return DECRYPTION_FAILURE;

    AES_SetKey( key );
    OCB_Cipher( nonce, &rijndaelDecrypt, crtxt, crtxtLen, Ls, Ld, delta, pntxt );
    OCB_GetTag( delta, Ls, Ld, pntxt, aData, crtxtLen, aDataLen, delta );
    BURN( RoundKey );                            /* tag was saved into delta  */

    if (MISMATCH( delta, crtxt + crtxtLen, tagLen ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* OCB */


/*----------------------------------------------------------------------------*\
             KW-AES: Main functions for AES key-wrapping (RFC-3394)
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(KWA)
#define Hb  (BLOCKSIZE / 2)                      /*  size of half-blocks      */
/**
 * @brief   wrap the input secret whose size is a multiple of 8 and >= 16
 * @param   kek       key-encryption-key a.k.a master key
 * @param   secret    input plain text secret
 * @param   secretLen size of input, must be a multiple of Hb (half-block size)
 * @param   wrapped   wrapped secret. note: size of output = secretLen + Hb
 * @return            error if # of half-blocks is less than 2 or needs padding
 */
char AES_KEY_wrap( const uint8_t* kek,
                   const uint8_t* secret, const size_t secretLen, uint8_t* wrapped )
{
    uint8_t A[BLOCKSIZE], *r, i;
    count_t n = secretLen / Hb, j;               /*  number of semi-blocks    */
    if (n < 2 || secretLen % Hb)  return ENCRYPTION_FAILURE;

    memset( A, 0xA6, Hb );                       /*  initialization vector    */
    memcpy( wrapped + Hb, secret, secretLen );   /*  copy input to the output */
    AES_SetKey( kek );

    for (i = 0; i < 6; ++i)
    {
        r = wrapped;
        for (j = 0; j++ < n; )
        {
            r += Hb;
            memcpy( A + Hb, r, Hb );             /*  B = Enc(A | R[j])        */
            rijndaelEncrypt( A, A );             /*  R[j] = LSB(64, B)        */
            memcpy( r, A + Hb, Hb );             /*  A = MSB(64, B) ^ t       */
            xorWith( A, Hb - 1, n * i + j );
        }
    }
    memcpy( wrapped, A, Hb );

    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}

/**
 * @brief   unwrap a wrapped input key whose size is a multiple of 8 and >= 24
 * @param   kek       key-encryption-key a.k.a master key
 * @param   wrapped   cipher-text input, i.e. wrapped secret.
 * @param   wrapLen   size of ciphertext/wrapped input in bytes
 * @param   secret    unwrapped secret whose size = wrapLen - Hb
 * @return            a value indicating whether decryption was successful
 */
char AES_KEY_unwrap( const uint8_t* kek,
                     const uint8_t* wrapped, const size_t wrapLen, uint8_t* secret )
{
    uint8_t A[BLOCKSIZE], *r, i;
    count_t n = wrapLen / Hb - 1, j;             /*  number of semi-blocks    */
    if (n < 2 || wrapLen % Hb)  return DECRYPTION_FAILURE;

    memcpy( A, wrapped, Hb );                    /*  authentication vector    */
    memcpy( secret, wrapped + Hb, wrapLen - Hb );
    AES_SetKey( kek );

    for (i = 6; i--; )
    {
        r = secret + n * Hb;
        for (j = n; j; --j)
        {
            r -= Hb;
            xorWith( A, Hb - 1, n * i + j );
            memcpy( A + Hb, r, Hb );             /*  B = Dec(A ^ t | R[j])    */
            rijndaelDecrypt( A, A );             /*  A = MSB(64, B)           */
            memcpy( r, A + Hb, Hb );             /*  R[j] = LSB(64, B)        */
        }
    }
    while (++i != Hb)  j |= A[i] ^ 0xA6;         /*  authenticate/error check */

    BURN( RoundKey );
    return j ? AUTHENTICATION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* KWA */


/*----------------------------------------------------------------------------*\
     Poly1305-AES message authentication: auxiliary functions and main API
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(POLY1305)
#define Sp   (BLOCKSIZE + 1)                     /* size of poly1305 blocks   */

/** derive modulo(2^130-5) for a little endian block, by repeated subtraction */
static void modLPoly( uint8_t* block, const uint8_t ovrfl )
{
    int i = BLOCKSIZE, n = 0x40 * ovrfl + block[Sp - 1] / 4;
    int32_t q = n - (block[Sp - 1] < 3);
    while (q == 0 && --i)                        /* n = B / (2 ^ 130)         */
    {                                            /* compare block to 2^130-5  */
        q -= 0xFF - block[i];                    /* proceed if B >= (2^130-5) */
    }
    n += (i == 0 && block[0] >= 0xFB);

    for ( ; n != 0; n = block[Sp - 1] > 3)       /* mod = B - n * (2^130-5)   */
    {
        for (q = 5 * n, i = 0; q && i < Sp; q >>= 8)
        {
            q += block[i];                       /* to get mod, first derive  */
            block[i++] = (uint8_t) q;            /* .. B + (5 * n) and then   */
        }                                        /* .. subtract n * (2^130)   */
        block[Sp - 1] -= 4 * (uint8_t) n;
    }
}

/** add two little-endian poly1305 blocks. use modular addition if necessary. */
static void addLBlocks( const uint8_t* x, const uint8_t len, uint8_t* y )
{
    int s = 0, i;
    for (i = 0; i < len; s >>= 8)
    {
        s += x[i] + y[i];
        y[i++] = (uint8_t) s;                    /*  s >> 8 is the overflow   */
    }
    if (len == Sp)  modLPoly( y, (uint8_t) s );
}

/** modular multiplication of a block by 2^s, i.e. left shift block to s bits */
static void shiftLBlock( uint8_t* block, const uint8_t shl )
{
    unsigned i, t = 0;
    for (i = 0; i < Sp; t >>= 8)                 /*  similar to doubleGF128L  */
    {
        t |= block[i] << shl;                    /*  shl may vary from 1 to 8 */
        block[i++] = (uint8_t) t;
    }
    modLPoly( block, (uint8_t) t );
}

/** modular multiplication of two little-endian poly1305 blocks. y *= x mod P */
static void mulLBlocks( const uint8_t* x, uint8_t* y )
{
    uint8_t i, b, t, nz, result[Sp] = { 0 };

    for (i = 0; i < Sp; ++i)
    {
        for (t = x[i], b = 1; b != 0; )          /*  check every bit of x[i]  */
        {                                        /*  ..and if any bit was set */
            if (t & b)                           /*  ..add y to the result.   */
            {                                    /*  then, calculate the      */
                addLBlocks( y, Sp, result );     /*  ..distance to the next   */
                t ^= b;                          /*  ..set bit, i.e. nz       */
            }
            for (nz = 0; !(t & b) && b; ++nz)  b <<= 1;
            shiftLBlock( y, nz );
        }
    }
    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}

/**
 * @brief   derive the Poly1305-AES hash of message using a nonce and key pair.
 * @param   keys      pair of encryption/mixing keys (k, r); size = KEYSIZE + 16
 * @param   nonce     a 128 bit string which is encrypted by AES_k
 * @param   data      buffer of input data
 * @param   dataSize  size of data in bytes
 * @param   mac       calculated Poly1305-AES mac
 */
void AES_Poly1305( const uint8_t* keys, const block_t nonce,
                   const void* data, const size_t dataSize, block_t mac )
{
    uint8_t r[Sp], poly[Sp] = { 0 }, c[Sp] = { 0 }, rn[Sp] = { 1 };
    uint8_t i = (dataSize > 0);
    uint8_t m = (dataSize - i) % BLOCKSIZE + i;
    count_t q = (dataSize - i) / BLOCKSIZE + i;
    uint8_t const* x = (uint8_t const*) data;

    memcpy( r, keys + KEYSIZE, BLOCKSIZE );      /* extract r from (k,r) pair */
    for (i = 3; i < BLOCKSIZE; ++i)
    {
        if (i % 4 == 0)  r[i] &= 0xFC;           /* clear bottom 2 bits       */
        if (i % 4 == 3)  r[i] &= 0x0F;           /* clear top 4 bits          */
    }
    r[i] = 0;
    while (q--)
    {
        memcpy( c, x + q * BLOCKSIZE, m );       /* copy message to chunk     */
        c[m] = 1;                                /* append 1 to each chunk    */
        mulLBlocks( r, rn );                     /* r^n = r^{n-1} * r         */
        mulLBlocks( rn, c );                     /* calculate c_{q-n} * r^n   */
        addLBlocks( c, sizeof c, poly );         /* add to poly (mod 2^130-5) */
        m = BLOCKSIZE;
    }

    AES_SetKey( keys );
    rijndaelEncrypt( nonce, mac );               /* derive AES_k(nonce)       */
    BURN( RoundKey );
    addLBlocks( poly, BLOCKSIZE, mac );          /* mac = poly + AES_k(nonce) */
}
#endif /* POLY1305 */


/*----------------------------------------------------------------------------*\
   FPE-AES (format-preserving encryption): definitions & auxiliary functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(FPE)

#if CUSTOM_ALPHABET
#include "micro_fpe.h"
#else
#define ALPHABET "0123456789"
#define string_t char*                           /*  string pointer type      */
#define RADIX    10                              /*  strlen( ALPHABET )       */
#define LOGRDX   3.321928095                     /*  log2( RADIX )            */
#define MINLEN   6                               /*  ceil(6 / log10( RADIX )) */
#endif

#if RADIX <= 0xFF
typedef uint8_t  rbase_t;                        /*  num type in base-radix   */
#else
typedef unsigned short  rbase_t;
#endif

/** append a digit d in base-RADIX to a big-endian number, denoted by num     */
static void addRxdigit( uint8_t* num, size_t N, size_t d )
{
    while (N--)
    {
        d += num[N] * RADIX;
        num[N] = (uint8_t) d;                    /*  num = num * RADIX + d    */
        d >>= 8;
    }
}

/** convert a string in base-RADIX to a big-endian number, denoted by num     */
static void numRadix( const rbase_t* s, size_t len, uint8_t* num, size_t bytes )
{
    size_t i;
    memset( num, 0, bytes );
    for (i = 0; i < len; ++i)  addRxdigit( num, bytes, s[i] );
}

/** append a byte to a big-endian number, represented as a base-RADIX string. */
static void appendByte( rbase_t* str, size_t N, size_t b )
{
    while (N--)
    {
        b += str[N] << 8;
        str[N] = b % RADIX;                      /*  num = num << 8 + b       */
        b /= RADIX;
    }
}

/** convert a big-endian number to its base-RADIX representation string: s    */
static void strRadix( const uint8_t* num, size_t bytes, rbase_t* s, size_t len )
{
    size_t i;
    memset( s, 0, sizeof (rbase_t) * len );
    for (i = 0; i < bytes; ++i)  appendByte( s, len, num[i] );
}

/** add two numbers in base-RADIX represented by q and p, so that p = p + q   */
static void numstrAdd( const rbase_t* q, size_t N, rbase_t* p )
{
    size_t a, c;
    for (c = 0; N--; c = a >= RADIX)
    {
        a = p[N] + q[N] + c;
        p[N] = a % RADIX;
    }
}

/** subtract two numbers in base-RADIX represented by q and p, so that p -= q */
static void numstrSub( const rbase_t* q, size_t N, rbase_t* p )
{
    size_t s, c;
    for (c = 0; N--; c = s < RADIX)
    {
        s = RADIX + p[N] - q[N] - c;
        p[N] = s % RADIX;
    }
}

/*----------------------------------------------------------------------------*\
                            FPE-AES: main functions
\*----------------------------------------------------------------------------*/
#include <stdlib.h>
#if FF_X == 3

static void FF3round()
{
}

static void FF3_Cipher()
{
    memcpy( P, tweak, 4 );
    memcpy( P + 8, tweak + 4, 3 );
    P[11] = P[3] << 4 & 0xF0;
    P[3] &= 0xF0;                                /*  P[0..3]=TL,  P[8..11]=TR */
}
#else

static size_t bf1, df1;                          /*  b and d constants in FF1 */

/** apply the FF1 round at step i to the input string X with length `len`     */
static void FF1round( const uint8_t i, const block_t P, const size_t u,
                      const size_t len, rbase_t* X )
{
    block_t R = { 0 };
    uint8_t *num = (void*) (X + (len + 1) / 2);  /*  use pre-allocated memory */
    size_t t = len - (~i & 1) * u;

    numRadix( X - t, len - u, num, bf1 );        /*  get NUM_radix(B)         */
    t = bf1 % BLOCKSIZE;
    R[LAST - t] = i;
    memcpy( R + BLOCKSIZE - t, num, t );         /* feed NUMradix(B) into PRF */
    MAC( P, BLOCKSIZE, R, &rijndaelEncrypt, R );
    MAC( num + t, bf1 - t, R, &rijndaelEncrypt, R );

    t = (df1 - 1) / BLOCKSIZE;
    memcpy( num, R, sizeof R );                  /* R = PRF(P || Q)           */
    for (num += t * BLOCKSIZE; t; num -= BLOCKSIZE)
    {
        memcpy( num, R, sizeof R );              /* num = R || R || R || ...  */
        xorWith( num, LAST, t-- );               /* num = R || R ^ [i] ||...  */
        rijndaelEncrypt( num, num );             /* S = R || Enc(R ^ [i])...  */
    }
    strRadix( num, df1, X, u );                  /* take first d bytes of S   */
}

/** encrypt/decrypt a base-RADIX string X with length len using FF1 algorithm */
static void FF1_Cipher( const char mode, const uint8_t* key, const size_t len,
                        const uint8_t* tweak, const size_t tweakLen, rbase_t* X )
{
    block_t P = { 1, 2, 1 };
    uint8_t i = tweakLen % BLOCKSIZE, r = mode ? 0 : 10;
    size_t u = (len + 1 - mode) >> 1, t = tweakLen - i;

    X += len;                                    /* go to end of the input    */
    putValueB( P, 5, RADIX );
    putValueB( P, 7, (len / 2 & 0xFF) + 0xA00 );
    putValueB( P, 11, len );
    putValueB( P, 15, tweakLen );                /* P=[1][2][1][radix][10]... */

    AES_SetKey( key );
    rijndaelEncrypt( P, P );
    MAC( tweak, t, P, &rijndaelEncrypt, P );     /* P = PRF(P || tweak)       */
    if (i < BLOCKSIZE - bf1 % BLOCKSIZE)
    {
        for (t = tweakLen; i; )  P[--i] ^= tweak[--t];
    }
    else                                         /* zero pad and feed to PRF  */
    {
        xorThenMix( &tweak[t], i, P, &rijndaelEncrypt, P );
    }
    for (i = r; i < 10; ++i, u = len - u)
    {
        FF1round( i, P, u, len, X );             /* encryption rounds         */
        numstrAdd( X, u, X - (i & 1 ? u : len) );
    }
    for (i = r; i--; u = len - u)
    {
        FF1round( i, P, u, len, X );             /* decryption rounds         */
        numstrSub( X, u, X - (i & 1 ? u : len) );
    }
}
#endif /* FF_X */

/** allocate the required memory and validate the input string in FPE mode... */
static char FPEsetup( const string_t str, const size_t len, rbase_t** indices )
{
    string_t alpha = ALPHABET;
    size_t i = (len + 1) / 2;
    size_t j = (len + i) * sizeof (rbase_t);

#if FF_X != 3                                    /*  extra memory is required */
    bf1 = (size_t) (LOGRDX * i + 8 - 1e-10) >> 3;
    df1 = (bf1 + 7) & ~3UL;                      /*  ..whose size is at least */
    j += (df1 + LAST) & ~LAST;                   /*  ..ceil(d/16) blocks      */
#endif
    if (len < MINLEN || (*indices = malloc( j )) == NULL)
    {
        return 'M';                              /*  memory allocation failed */
    }
    for (i = 0; i < len; ++i, ++str)
    {
        for (j = RADIX; --j && alpha[j] != *str; ) {}
        if (*str != alpha[j])
        {
            free( *indices );                    /*  invalid character found  */
            return 'I';
        }
        (*indices)[i] = (rbase_t) j;
    }
    return 0;
}

/** make the output string after completing FPE encrypt/decryption procedures */
static void FPEfinalize( const rbase_t* index, const size_t len, void** output )
{
    string_t alpha = ALPHABET, *s = *output;
    size_t i;
    for (i = 0; i < len; ++i)  s[i] = alpha[*index++];
}

/**
 * @brief   encrypt the input string using FPE-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   tweak     tweak byte array; similar to nonce in other schemes
 * @param   tweakLen  size of tweak. must be exactly 7 in FF3-1
 * @param   pntxt     input plaintext string, consisted of ALPHABET characters
 * @param   ptextLen  size of plaintext string, or number of characters
 * @param   crtxt     resulting ciphertext string
 * @return            whether all conditions of the algorithm were satisfied
 */
char AES_FPE_encrypt( const uint8_t* key, const uint8_t* tweak,
#if FF_X != 3
                      const size_t tweakLen,
#endif
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    rbase_t *index = NULL;
    if (FPEsetup( pntxt, ptextLen, &index ) != 0)  return ENCRYPTION_FAILURE;

#if FF_X == 3
    FF3_Cipher( 1, key, ptextLen, tweak, index );
#else
    FF1_Cipher( 1, key, ptextLen, tweak, tweakLen, index );
#endif
    BURN( RoundKey );
    FPEfinalize( index, ptextLen, &crtxt );
    free( index );
    return ENDED_IN_SUCCESS;
}

/**
 * @brief   decrypt a ciphertext string using FPE-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   tweak     tweak byte array; similar to nonce in other schemes
 * @param   tweakLen  size of tweak. must be exactly 7 in FF3-1
 * @param   crtxt     input ciphertext string, consisted of ALPHABET characters
 * @param   crtxtLen  size of ciphertext string, or number of characters
 * @param   pntxt     resulting plaintext string
 * @return            whether all conditions of the algorithm were satisfied
 */
char AES_FPE_decrypt( const uint8_t* key, const uint8_t* tweak,
#if FF_X != 3
                      const size_t tweakLen,
#endif
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    rbase_t *index = NULL;
    if (FPEsetup( crtxt, crtxtLen, &index ) != 0)  return DECRYPTION_FAILURE;

#if FF_X == 3
    FF3_Cipher( 0, key, crtxtLen, tweak, index );
#else
    FF1_Cipher( 0, key, crtxtLen, tweak, tweakLen, index );
#endif
    BURN( RoundKey );
    FPEfinalize( index, crtxtLen, &pntxt );
    free( index );
    return ENDED_IN_SUCCESS;
}
#endif /* FPE */
