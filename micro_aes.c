/*
 ==============================================================================
 Name        : micro_aes.c
 Author      : polfosol
 Version     : 9.5.1.0
 Copyright   : copyright © 2022 - polfosol
 Description : ANSI-C compatible implementation of µAES ™ library.
 ==============================================================================
 */

#include "micro_aes.h"

/**--------------------------------------------------------------------------**\
          Global constants, data types, and important / useful MACROs
\*----------------------------------------------------------------------------*/

#define KEYSIZE  AES_KEY_LENGTH
#define BLOCKSIZE  (128/8)   /* Block length in AES is 'always' 128-bits.     */
#define Nb   (BLOCKSIZE/4)   /* The number of columns comprising a AES state. */
#define Nk     (KEYSIZE/4)   /* The number of 32 bit words in a key.          */
#define ROUNDS      (Nk+6)   /* The number of rounds in AES Cipher.           */

/** The rationale of these macros is explained at the bottom of header file:  */
#define INCREASE_SECURITY   0
#define SMALL_CIPHER        0
#define REDUCE_CODE_SIZE    1

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

#define Np  (BLOCKSIZE+1)    /* The length of a block with added carry byte.  */
#define Nh  (BLOCKSIZE/2)    /* The length of a half-block!                   */
#define IMPLEMENT(x)  (x) > 0

/**--------------------------------------------------------------------------**\
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

/**--------------------------------------------------------------------------**\
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

/**--------------------------------------------------------------------------**\
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
    while (round--)
    {
        InvShiftRows( (state_t*) output );
        InvSubBytes( output );
        AddRoundKey( round, output );
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

/**--------------------------------------------------------------------------**\
 *              Implementation of different block ciphers modes               *
 *                            Auxiliary Functions                             *
\*----------------------------------------------------------------------------*/

#define AES_SetKey(key)     KeyExpansion( key )

#if INCREASE_SECURITY
#define MISMATCH            constmemcmp          /*  constant-time comparison */
#define SABOTAGE(buf, len)  memset( buf, 0, len )
#define BURN(key)           memset( key, 0, sizeof key )
#else
#define MISMATCH            memcmp
#define SABOTAGE(buf, len)  (void)  buf
#define BURN(key)           (void)  key
#endif

#if SMALL_CIPHER
#define putValueB(block, pos, val)  block[pos - 1] = val >> 8;  block[pos] = val
#define putValueL(block, pos, val)  block[pos + 1] = val >> 8;  block[pos] = val
#define xorWith(block, pos, val)    block[pos] ^= (val)
#define incBlock(block, big)      ++block[big ? BLOCKSIZE - 1 : 0]
#else

#if CTR

/** increment the value of a counter block, regarding its endian-ness ....... */
static void incBlock( block_t block, const char big )
{
    uint8_t i;
    if (big)                                     /*  big-endian counter       */
    {
        for (i = BLOCKSIZE - 1; !++block[i] && i--; );
    }
    else                                         /*  (inc until no overflow)  */
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

#if CTS || defined(PARTIAL_DATA_PASS)

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
    int i, d = 0;
    for (i = BLOCKSIZE; i--; d >>= 8)            /* loop from last to first,  */
    {                                            /* left-shift each byte and  */
        d |= block[i] << 1;                      /* ..add the previous MSB.   */
        block[i] = (uint8_t) d;
    }                                            /* if first MSB is carried:  */
    if (d)  block[BLOCKSIZE - 1] ^= 0x87;        /*   B ^= 10000111b (B.E.)   */
}
#endif

#if XTS || EAXP

/** Multiply a block by two in GF(2^128) field: this is little-endian version */
static void doubleGF128L( block_t block )
{
    int d = 0, i;
    for (i = 0; i < BLOCKSIZE; d >>= 8)          /* the same as doubleGF128B  */
    {                                            /* ..but with reversed bytes */
        d |= block[i] << 1;
        block[i++] = (uint8_t) d;
    }
    if (d)  block[0] ^= 0x87;                    /*   B ^= 10000111b (L.E.)   */
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
    if (t & 0x100)  block[BLOCKSIZE - 1] ^= 0xe1;
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

#if POLY1305

/** derive modulo(2^130-5) for a little endian block, by repeated subtraction */
static void modLPoly( uint8_t* block, uint8_t carry )
{
    int i = Np - 1, n = block[Np - 1] / 4 + carry * 0x40;
    long q = n - (block[i] < 3);
    while (q == 0 && --i)                        /* n = B / (2 ^ 130)         */
    {                                            /* compare block to 2^130-5  */
        q -= 0xFF - block[i];                    /* return if B < (2^130-5)   */
    }
    if (q < 0 || (i == 0 && ++n && *block < 0xFB))  return;

    q = 5 * n;
    for (i = 0; q && i < Np; q >>= 8)            /* mod = B - n * (2^130-5)   */
    {                                            /* to get mod, first derive  */
        q += block[i];                           /* .. B + (5 * n) and then   */
        block[i++] = (uint8_t) q;                /* .. subtract n * (2^130)   */
    }
    block[BLOCKSIZE] -= 4 * (uint8_t) n;
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
    if (len == Np)  modLPoly( y, (uint8_t) s );
}

/** modular multiplication of a block by 2^s, i.e. left shift block to s bits */
static void shiftLBlock( uint8_t* block, const uint8_t shl )
{
    unsigned i, t = 0;
    for (i = 0; i < Np; t >>= 8)                 /*  similar to doubleGF128L  */
    {
        t |= block[i] << shl;                    /*  shl may vary from 1 to 8 */
        block[i++] = (uint8_t) t;
    }
    modLPoly( block, (uint8_t) t );
}

/** modular multiplication of two little-endian poly1305 blocks. y *= x mod P */
static void mulLBlocks( const uint8_t* x, uint8_t* y )
{
    uint8_t i, b, t, nz, result[Np] = { 0 };

    for (i = 0; i < Np; ++i)
    {
        for (t = x[i], b = 1; b != 0; )          /*  check every bit of x[i]  */
        {                                        /*  ..and if any bit was set */
            if (t & b)                           /*  ..add y to the result.   */
            {                                    /*  then, calculate the      */
                addLBlocks( y, Np, result );     /*  ..distance to the next   */
                t ^= b;                          /*  ..set bit, i.e. nz       */
            }
            for (nz = 0; !(t & b) && b; ++nz)  b <<= 1;
            shiftLBlock( y, nz );
        }
    }
    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* POLY1305 */

#if AEAD_MODES

/** the overall scheme of CMAC or GMAC hash functions: divide data into 128-bit
 * blocks; then xor and apply the digest/mixing function to each xor-ed block */
static void MAC( const void* data, const size_t dataSize,
                 const block_t seed, fmix_t mix, block_t result )
{
    uint8_t const r = dataSize % BLOCKSIZE, *x = data;
    count_t n = dataSize / BLOCKSIZE;            /*   number of full blocks   */

    while (n--)
    {
        xorBlock( x, result );
        mix( seed, result );                     /* H_next = mix(seed, H ^ X) */
        x += BLOCKSIZE;
    }
    if (r == 0)  return;                         /* do the same with the last */
    xorThenMix( x, r, seed, mix, result );       /*  ..partial block (if any) */
}

#if INCREASE_SECURITY

/** for constant-time comparison of memory blocks, to avoid timing attacks:   */
static uint8_t constmemcmp( const uint8_t* src, const uint8_t* dst, uint8_t len )
{
    uint8_t i, cmp = 0;
    for (i = 0; i < len; ++i)  cmp |= src[i] ^ dst[i];
    return cmp;
}
#endif

#if CMAC || SIV || EAX

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

/** calculate the CMAC hash of input data using pre-calculated keys: D and Q. */
static void cMac( const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    block_t M = { 0 };
    uint8_t r = dataSize ? (dataSize - 1) % BLOCKSIZE + 1 : 0;
    const void *last_ptr = (const char*) data + dataSize - r;

    if (r < sizeof M)  M[r] = 0x80;
    memcpy( M, last_ptr, r );                    /*  copy last block into M   */
    xorBlock( r < sizeof M ? Q : D, M );         /*  ..and pad( M; D, Q )     */

    MAC( data, dataSize - r, mac, &rijndaelEncrypt, mac );
    xorThenMix( M, sizeof M, mac, &rijndaelEncrypt, mac );
}
#endif
#endif /* AEAD */

#define GOTO_NEXT_BLOCK  x += BLOCKSIZE;   y += BLOCKSIZE;


/**--------------------------------------------------------------------------**\
                  ECB-AES (electronic codebook mode) functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(ECB)
/**
 * @brief   encrypt the input plaintext using ECB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   pText     input plaintext buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   cText     resulting cipher-text buffer
 */
void AES_ECB_encrypt( const uint8_t* key,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    uint8_t *x = (void*) pText, *y = cText;
    count_t n = pTextLen / BLOCKSIZE;            /*  number of full blocks    */

    AES_SetKey( key );
    while (n--)
    {
        rijndaelEncrypt( x, y );                 /*  C = Enc(P)               */
        GOTO_NEXT_BLOCK
    }
    if (padBlock( x, pTextLen % BLOCKSIZE, y ))
    {
        rijndaelEncrypt( y, y );
    }
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using ECB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   cText     input ciphertext buffer
 * @param   cTextLen  size of ciphertext in bytes
 * @param   pText     resulting plaintext buffer
 * @return            whether size of ciphertext is a multiple of BLOCKSIZE
 */
char AES_ECB_decrypt( const uint8_t* key,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    uint8_t *x = (void*) cText, *y = pText;
    count_t n = cTextLen / BLOCKSIZE;

    AES_SetKey( key );
    while (n--)
    {
        rijndaelDecrypt( x, y );                 /*  P = Dec(C)               */
        GOTO_NEXT_BLOCK
    }
    BURN( RoundKey );

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
 * @param   pText     input plaintext buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   cText     resulting cipher-text buffer
 * @return            whether plaintext size is >= BLOCKSIZE if CTS was enabled
 */
char AES_CBC_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    uint8_t const *x = pText, *iv = iVec;
    uint8_t r = pTextLen % BLOCKSIZE, *y = cText;
    count_t n = pTextLen / BLOCKSIZE;

#if CTS
    if (!n)  return ENCRYPTION_FAILURE;
    r += (r == 0 && n > 1) * BLOCKSIZE;
    n -= (r == BLOCKSIZE);                       /*  hold the last block      */
#endif
    x += pTextLen - r;
    memcpy( cText, pText, pTextLen - r );        /*  copy plaintext to output */

    AES_SetKey( key );
    while (n--)
    {
        xorBlock( iv, y );                       /*  Y = P because of memcpy  */
        rijndaelEncrypt( y, y );                 /*  C = Enc(IV ^ P)          */
        iv = y;                                  /*  IV_next = C              */
        y += BLOCKSIZE;
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
 * @param   cText     input ciphertext buffer
 * @param   cTextLen  size of ciphertext in bytes
 * @param   pText     resulting plaintext buffer
 * @return            whether size of ciphertext is a multiple of BLOCKSIZE
 */
char AES_CBC_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    uint8_t const *x = cText, *iv = iVec;
    uint8_t r = cTextLen % BLOCKSIZE, *y = pText;
    count_t n = cTextLen / BLOCKSIZE;

    if (!n)  return DECRYPTION_FAILURE;
#if CTS
    r += (r == 0 && n > 1) * BLOCKSIZE;
    n -= (r == BLOCKSIZE) + (r != 0);
#endif

    AES_SetKey( key );
    while (n--)
    {
        rijndaelDecrypt( x, y );                 /*  P = Dec(C) ^ IV          */
        xorBlock( iv, y );                       /*  IV_next = C              */
        iv = x;
        GOTO_NEXT_BLOCK
    }
#if CTS                                          /*  last two blocks swapped  */
    if (r)
    {                                            /*  P2  =  Dec(C1) ^ C2      */
        mixThenXor( x, &rijndaelDecrypt, y, x + BLOCKSIZE, r, y + BLOCKSIZE );
        memcpy( y, x + BLOCKSIZE, r );
        rijndaelDecrypt( y, y );                 /*  copy C2 to Dec(C1): -> T */
        xorBlock( iv, y );                       /*  P1 = IV ^ Dec(T)         */
    }
#endif
    BURN( RoundKey );

    /* note: if padding was applied, check whether output is properly padded. */
    return !CTS && r ? DECRYPTION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* CBC */


/**--------------------------------------------------------------------------**\
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
    uint8_t const *x = input, *iv = iVec;
    uint8_t *y = output, tmp[BLOCKSIZE];
    count_t n = dataSize / BLOCKSIZE;            /*  number of full blocks    */

    AES_SetKey( key );
    while (n--)
    {
        rijndaelEncrypt( iv, y );                /*  both in en[de]cryption:  */
        xorBlock( x, y );                        /*  Y = Enc(IV) ^ X          */
        iv = mode ? y : x;                       /*  IV_next = Ciphertext     */
        GOTO_NEXT_BLOCK
    }
    mixThenXor( iv, &rijndaelEncrypt, tmp, x, dataSize % BLOCKSIZE, y );
    BURN( RoundKey );
}

/**
 * @brief   encrypt the input plaintext using CFB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   pText     input plaintext buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   cText     resulting cipher-text buffer
 */
void AES_CFB_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    CFB_Cipher( key, iVec, 1, pText, pTextLen, cText );
}

/**
 * @brief   decrypt the input ciphertext using CFB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   cText     input ciphertext buffer
 * @param   cTextLen  size of ciphertext in bytes
 * @param   pText     resulting plaintext buffer
 */
void AES_CFB_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    CFB_Cipher( key, iVec, 0, cText, cTextLen, pText );
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
 * @param   pText     input plaintext buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   cText     resulting cipher-text buffer
 */
void AES_OFB_encrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    uint8_t *y = cText, iv[BLOCKSIZE];
    count_t n = pTextLen / BLOCKSIZE;            /*  number of full blocks    */

    memcpy( iv, iVec, sizeof iv );
    memcpy( cText, pText, pTextLen );            /*  copy plaintext to output */

    AES_SetKey( key );
    while (n--)
    {
        rijndaelEncrypt( iv, iv );               /*  C = Enc(IV) ^ P          */
        xorBlock( iv, y );                       /*  IV_next = Enc(IV)        */
        y += BLOCKSIZE;
    }
    mixThenXor( iv, &rijndaelEncrypt, iv, y, pTextLen % BLOCKSIZE, y );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using OFB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   cText     input ciphertext buffer
 * @param   cTextLen  size of ciphertext in bytes
 * @param   pText     resulting plaintext buffer
 */
void AES_OFB_decrypt( const uint8_t* key, const block_t iVec,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    AES_OFB_encrypt( key, iVec, cText, cTextLen, pText );
}
#endif /* OFB */


/**--------------------------------------------------------------------------**\
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
    uint8_t const *x = input;
    uint8_t *y = output, c[BLOCKSIZE];
    count_t n = dataSize / BLOCKSIZE;

    memcpy( c, iCtr, sizeof c );
    if (big > 1)  incBlock( c, 1 );              /* pre-increment for CCM/GCM */

    while (n--)
    {
        rijndaelEncrypt( c, y );                 /*  both in en[de]cryption:  */
        xorBlock( x, y );                        /*  Y = Enc(Ctr) ^ X         */
        incBlock( c, big );                      /*  Ctr_next = Ctr + 1       */
        GOTO_NEXT_BLOCK
    }
    mixThenXor( c, &rijndaelEncrypt, c, x, dataSize % BLOCKSIZE, y );
}
#endif

#if IMPLEMENT(CTR_NA)
/**
 * @brief   encrypt the input plaintext using CTR-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   iv        initialization vector a.k.a. nonce
 * @param   pText     input plaintext buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   cText     resulting cipher-text buffer
 */
void AES_CTR_encrypt( const uint8_t* key, const uint8_t* iv,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    block_t ctr = { 0 };
    memcpy( ctr, iv, CTR_IV_LENGTH );

#if CTR_IV_LENGTH < BLOCKSIZE
    putValueB( ctr, BLOCKSIZE - 1, CTR_STARTVALUE );
#endif
    AES_SetKey( key );
    CTR_Cipher( ctr, 1, pText, pTextLen, cText );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using CTR-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iv        initialization vector a.k.a. nonce
 * @param   cText     input ciphertext buffer
 * @param   cTextLen  size of ciphertext in bytes
 * @param   pText     resulting plaintext buffer
 */
void AES_CTR_decrypt( const uint8_t* key, const uint8_t* iv,
                      const uint8_t* cText, const size_t cTextLen, uint8_t* pText )
{
    AES_CTR_encrypt( key, iv, cText, cTextLen, pText );
}
#endif /* CTR */


/**--------------------------------------------------------------------------**\
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
    uint8_t *y = storage;
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
    while (n--)
    {                                            /*  X was copied to Y before */
        xorBlock( T, y );
        cipher( y, y );
        xorBlock( T, y );                        /*  Y = T ^ Cipher( T ^ X )  */
        doubleGF128L( T );                       /*  T_next = T * alpha       */
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
 * @param   pText     input plaintext buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   cText     resulting cipher-text buffer
 */
char AES_XTS_encrypt( const uint8_t* keys, const uint8_t* twkId,
                      const uint8_t* pText, const size_t pTextLen, uint8_t* cText )
{
    block_t T = { 0 };
    uint8_t r = pTextLen % BLOCKSIZE, *c;
    size_t len = pTextLen - r;

    if (len == 0)  return ENCRYPTION_FAILURE;
    memcpy( cText, pText, len );                 /* copy input data to output */

    XEX_Cipher( keys, &rijndaelEncrypt, len, ~0, twkId, T, cText );
    if (r)
    {                                            /*  XTS for partial block    */
        c = cText + len - BLOCKSIZE;
        memcpy( cText + len, c, r );             /* 'steal' the cipher-text   */
        memcpy( c, pText + len, r );             /*  ..for the partial block  */
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
 * @param   cText     input ciphertext buffer
 * @param   cTextLen  size of ciphertext in bytes
 * @param   pText     resulting plaintext buffer
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

    XEX_Cipher( keys, &rijndaelDecrypt, len - BLOCKSIZE, ~0, twkId, T, pText );
    if (r)
    {
        memcpy( TT, T, sizeof T );
        doubleGF128L( TT );                      /*  TT = T * alpha,          */
        xorBlock( TT, p );                       /*  because the stolen       */
        rijndaelDecrypt( p, p );                 /*  ..ciphertext was xor-ed  */
        xorBlock( TT, p );                       /*  ..with TT in encryption  */
        memcpy( pText + len, p, r );
        memcpy( p, cText + len, r );
    }
    xorBlock( T, p );
    rijndaelDecrypt( p, p );
    xorBlock( T, p );

    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}
#endif /* XTS */


/**--------------------------------------------------------------------------**\
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


/**--------------------------------------------------------------------------**\
    GCM-AES (Galois counter mode): authentication with GMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM)

/** calculates GMAC hash of ciphertext and AAD using authentication subkey H: */
static void GHash( const block_t H, const void* aData, const void* cText,
                   const size_t adataLen, const size_t ctextLen, block_t gsh )
{
    block_t buf = { 0 };                         /*  save bit-sizes into buf  */
    putValueB( buf, BLOCKSIZE - 9, adataLen * 8 );
    putValueB( buf, BLOCKSIZE - 1, ctextLen * 8 );

    MAC( aData, adataLen, H, &mulGF128, gsh );   /*  first digest AAD, then   */
    MAC( cText, ctextLen, H, &mulGF128, gsh );   /*  ..ciphertext, and then   */
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
    iv[BLOCKSIZE - 1] = 1;
#endif
}

/**
 * @brief   encrypt the input plaintext using GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: GCM_NONCE_LEN
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     resulting cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_GCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    block_t H = { 0 }, iv = { 0 }, gsh = { 0 };
    GInitialize( key, nonce, H, iv );            /*  get IV & auth. subkey H  */

    CTR_Cipher( iv, 2, pText, pTextLen, cText );
    rijndaelEncrypt( iv, auTag );                /*  tag = Enc(iv) ^ GHASH    */
    BURN( RoundKey );
    GHash( H, aData, cText, aDataLen, pTextLen, gsh );
    xorBlock( gsh, auTag );
}

/**
 * @brief   decrypt the input ciphertext using GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: GCM_NONCE_LEN
 * @param   cText     input cipher-text buffer + appended authentication tag
 * @param   cTextLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag
 * @param   pText     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_GCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pText )
{
    block_t H = { 0 }, iv = { 0 }, gsh = { 0 };
    GInitialize( key, nonce, H, iv );
    GHash( H, aData, cText, aDataLen, cTextLen, gsh );

    rijndaelEncrypt( iv, H );
    xorBlock( H, gsh );                          /*   tag = Enc(iv) ^ GHASH   */
    if (MISMATCH( gsh, cText + cTextLen, tagLen ))
    {                                            /*  compare tags and         */
        BURN( RoundKey );                        /*  ..proceed if they match  */
        return AUTHENTICATION_FAILURE;
    }
    CTR_Cipher( iv, 2, cText, cTextLen, pText );
    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}
#endif /* GCM */


/**--------------------------------------------------------------------------**\
    CCM-AES (counter with CBC-MAC): CBC-MAC authentication & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CCM)

/** this function calculates the CBC-MAC of plaintext and authentication data */
static void CBCMac( const block_t iv, const void* aData, const void* pText,
                    const size_t aDataLen, const size_t pTextLen, block_t cm )
{
    block_t A = { 0 };
    uint8_t q = BLOCKSIZE - 2, p;
    memcpy( cm, iv, BLOCKSIZE );                 /*  initialize CBC-MAC       */

    cm[0] |= (CCM_TAG_LEN - 2) << 2;             /*  set some flags on M_0    */
    putValueB( cm, BLOCKSIZE - 1, pTextLen );    /*  copy data size into M_0  */
    if (aDataLen)                                /*  <-- else: M_* = M_0      */
    {
        if (aDataLen < q)  q = aDataLen;
        p = aDataLen < 0xFF00 ? 1 : 5;
        putValueB( A, p, aDataLen );             /*  len_id = aDataLen        */
        if (p == 5)
        {
            q -= 4;
            putValueB( A, 1, 0xFFFE );           /*  prepend FFFE to len_id   */
        }
        memcpy( A + p + 1, aData, q );           /*  A = len_id ~~ ADATA      */
        cm[0] |= 0x40;
        rijndaelEncrypt( cm, cm );               /*  M_* = Enc( flagged M_0 ) */
        xorBlock( A, cm );
    }

    rijndaelEncrypt( cm, cm );                   /*  M_1 = Enc( M_* ^ A ),    */
    if (aDataLen > q)                            /*  CBC-MAC rest of adata    */
    {
        MAC( (char const*) aData + q, aDataLen - q, cm, &rijndaelEncrypt, cm );
    }
    MAC( pText, pTextLen, cm, &rijndaelEncrypt, cm );
}

/**
 * @brief   encrypt the input plaintext using CCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: CCM_NONCE_LEN
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     resulting cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_CCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, cm;
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );

    AES_SetKey( key );
    CBCMac( iv, aData, pText, aDataLen, pTextLen, cm );
    CTR_Cipher( iv, 2, pText, pTextLen, cText );
    rijndaelEncrypt( iv, auTag );
    xorBlock( cm, auTag );                       /*  tag = Enc(iv) ^ CBC-MAC  */
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using CCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: CCM_NONCE_LEN
 * @param   cText     input cipher-text buffer + appended authentication tag
 * @param   cTextLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag
 * @param   pText     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_CCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pText )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, cm;
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );

    AES_SetKey( key );
    CTR_Cipher( iv, 2, cText, cTextLen, pText );
    CBCMac( iv, aData, pText, aDataLen, cTextLen, cm );
    rijndaelEncrypt( iv, iv );                   /*  tag = Enc(iv) ^ CBC-MAC  */
    BURN( RoundKey );

    xorBlock( iv, cm );                          /*  verify the resulting tag */
    if (MISMATCH( cm, cText + cTextLen, tagLen ))
    {
        SABOTAGE( pText, cTextLen );
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
                 const void* aData, const void* pText,
                 const size_t aDataLen, const size_t pTextLen, block_t V )
{
    block_t T = { 0 }, D = { 0 }, Q;
    uint8_t r = pTextLen >= BLOCKSIZE ? BLOCKSIZE : pTextLen % BLOCKSIZE;
    uint8_t const* x = (uint8_t const*) pText - r + pTextLen;

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
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   iv        synthesized I.V block, naturally prepended to ciphertext
 * @param   cText     resulting cipher-text buffer
 */
void AES_SIV_encrypt( const uint8_t* keys,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      block_t iv, uint8_t* cText )
{
    block_t IV = { 0 };
    S2V( keys, aData, pText, aDataLen, pTextLen, IV );
    memcpy( iv, IV, sizeof IV );
    IV[8] &= 0x7F;  IV[12] &= 0x7F;              /*  clear 2 bits for cipher  */

    AES_SetKey( keys + KEYSIZE );
    CTR_Cipher( IV, 1, pText, pTextLen, cText );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   iv        provided I.V block to validate
 * @param   cText     input cipher-text buffer
 * @param   cTextLen  size of ciphertext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   pText     resulting plaintext buffer
 * @return            whether synthesized I.V. matched the provided one
 */
char AES_SIV_decrypt( const uint8_t* keys, const block_t iv,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* pText )
{
    block_t IV;
    memcpy( IV, iv, sizeof IV );
    IV[8] &= 0x7F;  IV[12] &= 0x7F;              /*  clear two bits           */

    AES_SetKey( keys + KEYSIZE );
    CTR_Cipher( IV, 1, cText, cTextLen, pText );
    memset( IV, 0, sizeof IV );
    S2V( keys, aData, pText, aDataLen, cTextLen, IV );
    BURN( RoundKey );

    if (MISMATCH( IV, iv, sizeof IV ))           /* verify the synthesized IV */
    {
        SABOTAGE( pText, cTextLen );
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* SIV */


/**--------------------------------------------------------------------------**\
      SIV-GCM-AES (Galois counter mode with synthetic i.v): main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM_SIV)

/** calculates the POLYVAL of plaintext and AAD using authentication subkey H */
static void Polyval( const block_t H, const void* aData, const void* pText,
                     const size_t aDataLen, const size_t pTextLen, block_t pv )
{
    block_t buf = { 0 };                         /*  save bit-sizes into buf  */
    putValueL( buf, 0, aDataLen * 8 );
    putValueL( buf, 8, pTextLen * 8 );

    MAC( aData, aDataLen, H, &dotGF128, pv );    /*  first digest AAD, then   */
    MAC( pText, pTextLen, H, &dotGF128, pv );    /*  ..plaintext, and then    */
    MAC( buf, sizeof buf, H, &dotGF128, pv );    /*  ..bit sizes into POLYVAL */
}

/** derive the pair of authentication-encryption-keys from main key and nonce */
static void DeriveGSKeys( const uint8_t* key, const uint8_t* nonce, block_t AK )
{
    uint8_t AEKeypair[KEYSIZE + 24], *k = AEKeypair;
    block_t iv = { 0 };
    memcpy( iv + 4, nonce, 12 );

    AES_SetKey( key );
    for ( ; *iv < KEYSIZE / 8 + 2; ++*iv)
    {                                            /* increment iv's LSB after  */
        rijndaelEncrypt( iv, k );                /* ..encrypting & taking MSB */
        k += 8;
    }
    AES_SetKey( AEKeypair + BLOCKSIZE );         /*  set the main cipher-key  */
    memcpy( AK, AEKeypair, BLOCKSIZE );          /*  take authentication key  */
}

/**
 * @brief   encrypt the input plaintext using SIV-GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     provided 96-bit nonce
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     resulting cipher-text buffer,
 * @param   auTag     appended authentication tag. must be 16-bytes long
 */
void GCM_SIV_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    block_t H, S = { 0 };
    DeriveGSKeys( key, nonce, H );               /* get authentication subkey */

    Polyval( H, aData, pText, aDataLen, pTextLen, S );
    for (*H = 0; *H < 12; ++*H)
    {                                            /* using H[0] as counter!    */
        S[*H] ^= nonce[*H];                      /* xor nonce with POLYVAL    */
    }
    S[sizeof S - 1] &= 0x7F;                     /* clear one bit & encrypt,  */
    rijndaelEncrypt( S, S );                     /* ..to get auth. tag        */
    memcpy( auTag, S, sizeof S );

    S[sizeof S - 1] |= 0x80;                     /* set 1 bit to get CTR's IV */
    CTR_Cipher( S, 0, pText, pTextLen, cText );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using SIV-GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     provided 96-bit nonce
 * @param   cText     input cipher-text buffer + appended authentication tag
 * @param   cTextLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag; MUST be 16 bytes
 * @param   pText     resulting plaintext buffer
 * @return            whether message authentication/decryption was successful
 */
char GCM_SIV_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pText )
{
    block_t H, S;
    if (tagLen < sizeof S)  return DECRYPTION_FAILURE;

    DeriveGSKeys( key, nonce, H );               /* get authentication subkey */
    memcpy( S, cText + cTextLen, sizeof S );     /* tag is IV for CTR cipher  */
    S[sizeof S - 1] |= 0x80;
    CTR_Cipher( S, 0, cText, cTextLen, pText );

    memset( S, 0, sizeof S );
    Polyval( H, aData, pText, aDataLen, cTextLen, S );
    for (*H = 0; *H < 12; ++*H)
    {                                            /* using H[0] as counter!    */
        S[*H] ^= nonce[*H];                      /* xor nonce with POLYVAL    */
    }
    S[sizeof S - 1] &= 0x7F;                     /* clear one bit & encrypt,  */
    rijndaelEncrypt( S, S );                     /* ..to get tag & verify it  */

    BURN( RoundKey );
    if (MISMATCH( S, cText + cTextLen, sizeof S ))
    {                                            /*  tag verification failed  */
        SABOTAGE( pText, cTextLen );
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* GCM-SIV */


/**--------------------------------------------------------------------------**\
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
    M[sizeof M - 1] ^= t;                        /*  else: C1 = Enc( [t]_n )  */
    rijndaelEncrypt( M, mac );
#endif
    cMac( D, Q, data, dataSize, mac );
}

/**
 * @brief   encrypt the input plaintext using EAX-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes if not EAX'
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     resulting cipher-text buffer; 4 bytes mac appended in EAX'
 * @param   auTag     authentication tag; buffer must be 16 bytes long in EAX
 */
void AES_EAX_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
#if EAXP
                      const size_t nonceLen, uint8_t* cText )
#define gfDouble      doubleGF128L
#else
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, uint8_t* auTag )
#define gfDouble      doubleGF128B
#define nonceLen      EAX_NONCE_LEN
#endif
{
    block_t D = { 0 }, K2, mac, tag;
    getSubkeys( key, &gfDouble, D, K2 );
    OMac( 0, D, K2, nonce, nonceLen, mac );      /*  N = OMAC(0; nonce)       */

#if EAXP
    memcpy( cText + pTextLen, mac + 12, 4 );
    mac[12] &= 0x7F;                             /*  clear 2 bits to get N'   */
    mac[14] &= 0x7F;
    CTR_Cipher( mac, 1, pText, pTextLen, cText );

    OMac( 2, D, K2, cText, pTextLen, tag );      /*  C' = CMAC'( ciphertext ) */
    for (*D = 0; *D < 4; ++*D)                   /*  using D[0] as counter!   */
    {
        cText[pTextLen + *D] ^= tag[12 + *D];    /*  last 4 bytes of C' ^ N'  */
    }
#else
    OMac( 1, D, K2, aData, aDataLen, tag );      /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );
    memcpy( auTag, tag, sizeof tag );
    CTR_Cipher( mac, 1, pText, pTextLen, cText );

    OMac( 2, D, K2, cText, pTextLen, mac );      /*  C = OMAC(2; ciphertext)  */
    xorBlock( mac, auTag );                      /*  tag = N ^ H ^ C          */
#endif
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using EAX-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes if not EAX'
 * @param   cText     input cipher-text buffer + appended authentication tag
 * @param   cTextLen  size of cipher-text; excluding tag / 4-bytes mac in EAX'
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data; ignored in EAX'
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag; mandatory 4 bytes in EAX'
 * @param   pText     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_EAX_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
#if EAXP
                      const size_t nonceLen,
#else
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen,
#endif
                      uint8_t* pText )
{
    block_t D = { 0 }, K2, mac, tag;
    getSubkeys( key, &gfDouble, D, K2 );
    OMac( 2, D, K2, cText, cTextLen, tag );      /*  C = OMAC(2; ciphertext)  */

#if EAXP
    OMac( 0, D, K2, nonce, nonceLen, mac );      /*  N = CMAC'( nonce )       */
    for (*K2 = *D = 0; *D < 4; ++*D)             /* authenticate/compare tags */
    {
        *K2 |= cText[cTextLen + *D] ^ tag[12 + *D] ^ mac[12 + *D];
    }
    mac[12] &= 0x7F;                             /*  clear 2 bits to get N'   */
    mac[14] &= 0x7F;
    if (*K2 != 0)                                /*  result of tag comparison */
#else
    OMac( 1, D, K2, aData, aDataLen, mac );      /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );
    OMac( 0, D, K2, nonce, nonceLen, mac );      /*  N = OMAC(0; nonce)       */
    xorBlock( mac, tag );                        /*  tag = N ^ H ^ C          */

    if (MISMATCH( tag, cText + cTextLen, tagLen ))
#endif
    {                                            /* authenticate then decrypt */
        BURN( RoundKey );
        return AUTHENTICATION_FAILURE;
    }
    CTR_Cipher( mac, 1, cText, cTextLen, pText );

    BURN( RoundKey );
    return ENDED_IN_SUCCESS;
}
#endif /* EAX */


/**--------------------------------------------------------------------------**\
              OCB-AES (offset codebook mode): auxiliary functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(OCB)

/** Get the offset block (Δ_i) which is initialized by Δ_0, at the specified
 * index for a given L$. This method has minimum memory usage, but it is slow */
static void OffsetB( const block_t Ld, const count_t index, block_t delta )
{
    size_t b, m;
    block_t L;
    memcpy( L, Ld, sizeof L );                   /*  initialize L_$           */

    for (b = 1; b <= index && b; )               /*  we can pre-calculate all */
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
    uint8_t Kt[2 * BLOCKSIZE] = { OCB_TAG_LEN << 4 & 0xFF, 0, 0, 1 };
    uint8_t r, *y = output;
    count_t i, n;
    memcpy( output, input, dataSize );           /* copy input data to output */

    n = nonce[11] % 64 >> 3;
    r = nonce[11] % 8;                           /* take last 6 bits of nonce */
    memcpy( Kt + 4, nonce, 12 );
    Kt[BLOCKSIZE - 1] &= 0xC0;                   /* clear last 6 bits         */

    rijndaelEncrypt( Kt, Kt );                   /* construct K_top           */
    memcpy( Kt + BLOCKSIZE, Kt + 1, 8 );         /* stretch K_top             */
    xorBlock( Kt, Kt + BLOCKSIZE );
    for (i = 0; i < BLOCKSIZE; ++n)              /* shift the stretched K_top */
    {
        Kt[i++] = Kt[n] << r | Kt[n + 1] >> (8 - r);
    }
    n = dataSize / BLOCKSIZE;
    r = dataSize % BLOCKSIZE;

    rijndaelEncrypt( Ls, Ls );                   /*  L_* = Enc(zero block)    */
    memcpy( Ld, Ls, BLOCKSIZE );
    doubleGF128B( Ld );                          /*  L_$ = double(L_*)        */
    if (n == 0)                                  /*  processed nonce is Δ_0   */
    {
        memcpy( Del, Kt, BLOCKSIZE );            /*  initialize Δ_0           */
    }
    for (i = 0; i < n; y += BLOCKSIZE)
    {
        memcpy( Del, Kt, BLOCKSIZE );            /*  calculate Δ_i using my   */
        OffsetB( Ld, ++i, Del );                 /*  .. 'magic' algorithm     */
        xorBlock( Del, y );
        cipher( y, y );                          /* Y = Δ_i ^ Cipher(Δ_i ^ X) */
        xorBlock( Del, y );
    }
    if (r)                                       /*  Δ_* = Δ_n ^ L_* and then */
    {                                            /*  Y_* = Enc(Δ_*) ^ X       */
        xorBlock( Ls, Del );
        mixThenXor( Del, &rijndaelEncrypt, Kt, y, r, y );
        Del[r] ^= 0x80;                          /*    pad it for checksum    */
    }
}

static void nop( const block_t x, block_t y ) {}

/** derives OCB authentication tag. the first three arguments are pre-calculated
 * namely, Δ_* (or sometimes Δ_m), L_* = encrypt(zeros) and L_$ = double(L_*) */
static void OCB_GetTag( const block_t Ds,
                        const block_t Ls, const block_t Ld,
                        const void* pText, const void* aData,
                        const size_t pTextLen, const size_t aDataLen,
                        block_t tag )
{
    uint8_t const r = aDataLen % BLOCKSIZE, *x = aData;
    count_t i, n = aDataLen / BLOCKSIZE;

    block_t S = { 0 };                           /*  checksum, i.e.           */
    MAC( pText, pTextLen, NULL, &nop, S );       /*  ..xor of all plaintext   */

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

/**--------------------------------------------------------------------------**\
                 OCB-AES (offset codebook mode): main functions
\*----------------------------------------------------------------------------*/
/**
 * @brief   encrypt the input stream using OCB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   pText     input plain-text buffer
 * @param   pTextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   cText     resulting cipher-text buffer
 * @param   auTag     message authentication tag. buffer must be 16-bytes long
 */
void AES_OCB_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pText, const size_t pTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* cText, block_t auTag )
{
    block_t Ls = { 0 }, Ld, delta;
    AES_SetKey( key );
    OCB_Cipher( nonce, &rijndaelEncrypt, pText, pTextLen, Ls, Ld, delta, cText );
    OCB_GetTag( delta, Ls, Ld, pText, aData, pTextLen, aDataLen, auTag );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input stream using OCB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a init-vector with a fixed size of 12 bytes
 * @param   cText     input cipher-text buffer + appended authentication tag
 * @param   cTextLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag
 * @param   pText     resulting plaintext buffer
 * @return            whether message authentication was successful
 */
char AES_OCB_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* cText, const size_t cTextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pText )
{
    block_t Ls = { 0 }, Ld, delta;
    AES_SetKey( key );
    OCB_Cipher( nonce, &rijndaelDecrypt, cText, cTextLen, Ls, Ld, delta, pText );
    OCB_GetTag( delta, Ls, Ld, pText, aData, cTextLen, aDataLen, delta );
    BURN( RoundKey );                            /* tag was saved into delta  */

    if (MISMATCH( delta, cText + cTextLen, tagLen ))
    {
        SABOTAGE( pText, cTextLen );
        return AUTHENTICATION_FAILURE;
    }
    return ENDED_IN_SUCCESS;
}
#endif /* OCB */


/**--------------------------------------------------------------------------**\
             KW-AES: Main functions for AES key-wrapping (RFC-3394)
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(KWA)
/**
 * @brief   wrap the input secret whose size is a multiple of 8 and >= 16
 * @param   kek       key-encryption-key a.k.a master key
 * @param   secret    input plain text secret
 * @param   secretLen size of input, must be a multiple of Nh (half-block size)
 * @param   wrapped   wrapped secret. note: size of output = secretLen + Nh
 */
void AES_KEY_wrap( const uint8_t* kek,
                   const uint8_t* secret, const size_t secretLen, uint8_t* wrapped )
{
    uint8_t A[BLOCKSIZE], *r, i;
    count_t j, ns = secretLen / Nh;              /*  number of semi-blocks    */

    memset( A, 0xA6, Nh );                       /*  initialization vector    */
    memcpy( wrapped + Nh, secret, secretLen );   /*  copy input to the output */

    AES_SetKey( kek );
    for (i = 0; i < 6; ++i)
    {
        r = wrapped;
        for (j = 0; j++ < ns; )
        {
            r += Nh;
            memcpy( A + Nh, r, Nh );             /*  B = Enc(A | R[j])        */
            rijndaelEncrypt( A, A );             /*  R[j] = LSB(64, B)        */
            memcpy( r, A + Nh, Nh );             /*  A = MSB(64, B) ^ t       */
            xorWith( A, 7, ns * i + j );
        }
    }
    BURN( RoundKey );

    memcpy( wrapped, A, Nh );
}

/**
 * @brief   unwrap a wrapped input key whose size is a multiple of 8 and >= 24
 * @param   kek       key-encryption-key a.k.a master key
 * @param   wrapped   cipher-text input, i.e. wrapped secret.
 * @param   wrapLen   size of ciphertext/wrapped input in bytes
 * @param   secret    unwrapped secret whose size = wrapLen - Nh
 * @return            a value indicating whether decryption was successful
 */
char AES_KEY_unwrap( const uint8_t* kek,
                     const uint8_t* wrapped, const size_t wrapLen, uint8_t* secret )
{
    uint8_t A[BLOCKSIZE], *r, i;
    count_t j, ns = wrapLen / Nh - 1;            /*  number of semi-blocks    */

    memcpy( A, wrapped, Nh );                    /*  authentication vector    */
    memcpy( secret, wrapped + Nh, wrapLen - Nh );

    AES_SetKey( kek );
    for (i = 6; i--; )
    {
        r = secret + ns * Nh;
        for (j = ns; j; --j)
        {
            r -= Nh;
            xorWith( A, 7, ns * i + j );
            memcpy( A + Nh, r, Nh );             /*  B = Dec(A ^ t | R[j])    */
            rijndaelDecrypt( A, A );             /*  A = MSB(64, B)           */
            memcpy( r, A + Nh, Nh );             /*  R[j] = LSB(64, B)        */
        }
    }
    while (++i != Nh)  j |= A[i] ^ 0xA6;         /*  authenticate/error check */

    BURN( RoundKey );
    return j ? DECRYPTION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* KWA */


/**--------------------------------------------------------------------------**\
             Main function for Poly1305-AES message authentication
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(POLY1305)
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
    uint8_t r[Np], result[Np] = { 0 }, c[Np] = { 0 }, rn[Np] = { 1 };
    uint8_t i = dataSize > 0;
    uint8_t m = (dataSize - i) % BLOCKSIZE + i;
    count_t q = dataSize / BLOCKSIZE + (m < BLOCKSIZE && i);
    uint8_t const* x = (uint8_t const*) data + dataSize;

    memcpy( r, keys + KEYSIZE, BLOCKSIZE );      /* initialize r              */
    for (i = 3; i < BLOCKSIZE; ++i)
    {
        if (i % 4 == 0)  r[i] &= 0xFC;           /* clear bottom 2 bits       */
        if (i % 4 == 3)  r[i] &= 0x0F;           /* clear top 4 bits          */
    }
    r[i] = 0;
    while (q--)
    {
        x -= m;
        memcpy( c, x, m );                       /* copy message to chunk     */
        c[m] = 1;                                /* append 1 to each chunk    */
        mulLBlocks( r, rn );                     /* r^n = r^{n-1} * r         */
        mulLBlocks( rn, c );                     /* calculate c_{q-n} * r^n   */
        addLBlocks( c, sizeof c, result );       /* add to poly (mod 2^130-5) */
        m = BLOCKSIZE;
    }

    AES_SetKey( keys );
    rijndaelEncrypt( nonce, mac );
    BURN( RoundKey );
    addLBlocks( result, BLOCKSIZE, mac );        /* adding AES_k(nonce)       */
}
#endif /* POLY1305 */


/**--------------------------------------------------------------------------**\
                     FPE-AES (format-preserving encryption)
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(FPE)

TODO

#endif
