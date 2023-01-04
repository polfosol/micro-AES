/*
 ==============================================================================
 Name        : micro_aes.c
 Author      : polfosol
 Version     : 9.9.9.3
 Copyright   : copyright © 2022 - polfosol
 Description : ANSI-C compatible implementation of µAES ™ library.
 ==============================================================================
 */

#include "micro_aes.h"

/*----------------------------------------------------------------------------*\
          Global constants, data types, and important / useful MACROs
\*----------------------------------------------------------------------------*/

#define KEYSIZE AES_KEY_LENGTH
#define BLOCKSIZE  (128 / 8)  /* Block length in AES is 'always' 128-bits.    */
#define Nb   (BLOCKSIZE / 4)  /* The number of rows comprising a AES state.   */
#define Nk     (KEYSIZE / 4)  /* The number of 32 bit words in a key.         */
#define LAST (BLOCKSIZE - 1)  /* The index at the end of block, or last index */
#define ROUNDS      (Nk + 6)  /* The number of rounds in AES Cipher.          */

#define IMPLEMENT(x)  (x) > 0

#define INCREASE_SECURITY 0   /* refer to the bottom of the header file for   */
#define SMALL_CIPHER      0   /* ... some explanations and the rationale of   */
#define REDUCE_CODE_SIZE  1   /* ... these three macros                       */

/** state_t represents rijndael state matrix. since fixed-size memory block has
 * an essential role in all algorithms, it is represented by a specific type: */
typedef uint8_t  state_t[Nb][4];
typedef uint8_t  block_t[BLOCKSIZE];

/** these types are function pointers, whose arguments are fixed-size blocks: */
typedef  void  (*fdouble_t)( block_t );
typedef  void  (*fmix_t)( const block_t, block_t );

#if SMALL_CIPHER
typedef uint8_t  count_t;
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

#define COPY32BIT(x, y)   *(int32_t*) &y =  *(int32_t*) &x
#define XOR32BITS(x, y)   *(int32_t*) &y ^= *(int32_t*) &x
#define SBoxValue(x)       ( sbox[x])
#define InvSBoxValue(x)    (rsbox[x])    /* use tables instead of calculating */

#if !REDUCE_CODE_SIZE

#define xtime(x)    (x & 0x80 ? x * 2 ^ 0x1b : x * 2)

#define mul8(x, y)                           \
    ( ((y     & 1) * x)                      \
    ^ ((y / 2 & 1) * xtime(x))               \
    ^ ((y / 4 & 1) * xtime(xtime(x)))        \
    ^ ((y / 8 & 1) * xtime(xtime(xtime(x)))) )

static void xorBlock( const block_t src, block_t dest )
{
    long long *d = (void*) dest;         /* not supported in ANSI-C / ISO-C90 */
    long long const *s = (const void*) src;
    d[0] ^= s[0];
    d[1] ^= s[1];
}
#else

/** this function carries out XOR operation on two 128bit blocks: dest ^= src */
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

/** This function multiplies two numbers in the Galois bit field GF(2^8) .... */
static uint8_t mul8( uint8_t x, uint8_t y )
{
    uint8_t m;
    for (m = 0; y > 1; y >>= 1)          /* optimized algorithm for nonzero x */
    {
        m ^= (y & 1) * x;
        x = xtime( x );
    }
    return m ^ x;                        /* or use (9 11 13 14) lookup tables */
}
#endif
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

    for (i = KEYSIZE; i < (KEYSIZE + 28) * Nb; i += 4)
    {
        switch (i % KEYSIZE)
        {
        case 0:
            memcpy( &RoundKey[i], &RoundKey[i - KEYSIZE], KEYSIZE );
#if Nk == 4
            if (!rcon)  rcon = 0x1b;     /* RCON may reach 0 only in AES-128. */
#endif
            RoundKey[i    ] ^= SBoxValue( RoundKey[i - 3] ) ^ rcon;
            RoundKey[i + 1] ^= SBoxValue( RoundKey[i - 2] );
            RoundKey[i + 2] ^= SBoxValue( RoundKey[i - 1] );
            RoundKey[i + 3] ^= SBoxValue( RoundKey[i - 4] );
            rcon <<= 1;
            break;
#if Nk == 8                              /* additional round only for AES-256 */
        case 16:
            RoundKey[i    ] ^= SBoxValue( RoundKey[i - 4] );
            RoundKey[i + 1] ^= SBoxValue( RoundKey[i - 3] );
            RoundKey[i + 2] ^= SBoxValue( RoundKey[i - 2] );
            RoundKey[i + 3] ^= SBoxValue( RoundKey[i - 1] );
            break;
#endif
        default:
            XOR32BITS( RoundKey[i - 0x4], RoundKey[i] );
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
        state[i] = SBoxValue( state[i] );
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
    uint8_t r;
    state_t *state = (void*) output;

    /* copy the input to the state matrix, and beware of undefined behavior.. */
    if (input != output)   memcpy( state, input, BLOCKSIZE );

    /* The encryption is carried out in #ROUNDS iterations, of which the first
     * #ROUNDS-1 are identical. The last round doesn't involve mixing columns */
    for (r = 0; r != ROUNDS; )
    {
        AddRoundKey( r, output );
        SubBytes( output );
        ShiftRows( state );
        ++r != ROUNDS ? MixColumns( state ) : AddRoundKey( ROUNDS, output );
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
        state[i] = InvSBoxValue( state[i] );
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
    uint8_t i, x[4];
    for (i = 0; i < Nb; ++i)        /*  see: crypto.stackexchange.com/q/2569  */
    {
        COPY32BIT( (*state)[i][0], x[0] );

        (*state)[i][0] = mul8( x[0], 14 ) ^ mul8( x[1], 11 ) ^ mul8( x[2], 13 ) ^ mul8( x[3], 9 );
        (*state)[i][1] = mul8( x[1], 14 ) ^ mul8( x[2], 11 ) ^ mul8( x[3], 13 ) ^ mul8( x[0], 9 );
        (*state)[i][2] = mul8( x[2], 14 ) ^ mul8( x[3], 11 ) ^ mul8( x[0], 13 ) ^ mul8( x[1], 9 );
        (*state)[i][3] = mul8( x[3], 14 ) ^ mul8( x[0], 11 ) ^ mul8( x[1], 13 ) ^ mul8( x[2], 9 );
    }
}

/** Decrypts a cipher-text input block, into a 128-bit plain text as output.. */
static void rijndaelDecrypt( const block_t input, block_t output )
{
    uint8_t r;
    state_t *state = (void*) output;

    /* copy the input into state matrix, i.e. state is initialized by input.. */
    if (input != output)   memcpy( state, input, BLOCKSIZE );

    /* Decryption completes after #ROUNDS iterations. All rounds except the 1st
     * one are identical. The first round doesn't involve [inv]mixing columns */
    for (r = ROUNDS; r != 0; )
    {
        r-- != ROUNDS ? InvMixColumns( state ) : AddRoundKey( ROUNDS, output );
        InvShiftRows( state );
        InvSubBytes( output );
        AddRoundKey( r, output );
    }
}
#endif /* DECRYPTION */


#if M_RIJNDAEL
/**
 * @brief   encrypt or decrypt a single block with a given key
 * @param   key       a byte array with a fixed size of KEYSIZE
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
#define xorByEnd(buf, num, pos)     buf[pos - 1] ^= (num) >> 8;  buf[pos] ^= num
#define copyNumL(buf, num, pos)     buf[pos + 1]  = (num) >> 8;  buf[pos]  = num
#define incBlock(block, big)    ++block[big ? LAST : 0]
#else

#if CTR || KWA || FPE

/** xor a byte array with a big-endian number, whose LSB is at specified pos. */
static void xorByEnd( uint8_t* buf, size_t num, uint8_t pos )
{
    do
        buf[pos--] ^= (uint8_t) num;
    while (num >>= 8);
}
#endif

#if XTS || GCM_SIV

/** copy a little endian number to the block, with LSB at specified position. */
static void copyNumL( block_t block, size_t num, uint8_t pos )
{
    do
        block[pos++] = (uint8_t) num;
    while (num >>= 8);
}
#endif

#if CTR

/** increment the value of a counter block, regarding its endian-ness ....... */
static void incBlock( block_t block, const char big )
{
    uint8_t i = big ? LAST : 0;
    if (i)                                       /*  big-endian counter       */
    {
        while (!++block[i])  --i;                /* (inc until no overflow)   */
    }
    else
    {
        while (!++block[i] && i < 4)  ++i;
    }
}
#endif
#endif /* SMALL CIPHER */

#ifdef AES_PADDING

/** in ECB or CBC without CTS, the last (partial) block has to be padded .... */
static char padBlock( const uint8_t len, block_t block )
{
#if AES_PADDING == 2
    memset( block + len, 0, BLOCKSIZE - len );   /*   ISO/IEC 7816-4 padding  */
    block[len] = 0x80;
#elif AES_PADDING
    uint8_t p = BLOCKSIZE - len;                 /*   PKCS#7 padding          */
    memset( block + len, p, p );
#else
    if (len == 0)  return 0;                     /*   default padding         */
    memset( block + len, 0, BLOCKSIZE - len );
#endif
    return 'p';

}
#endif /* PADDING */

#if CBC || CFB || OFB || CTR || OCB

/** Result of applying a function to block `b` is xor-ed with `x` to get `y`. */
static void mixThenXor( const block_t b, fmix_t mix, block_t tmp,
                        const uint8_t* x, const uint8_t len, uint8_t* y )
{
    uint8_t i;
    if (len == 0)  return;                       /*  Y = temp{=f(B)} ^ X      */

    mix( b, tmp );
    for (i = 0; i < len; ++i)  y[i] = tmp[i] ^ x[i];
}
#endif

#if EAX && !EAXP || SIV || OCB || CMAC

/** Multiply a block by two in Galois bit field GF(2^128): big-endian version */
static void doubleGF128B( block_t block )
{
    int i, s = 0;
    for (i = BLOCKSIZE; i; s >>= 8)              /* from last byte (LSB) to   */
    {                                            /* first: left-shift, then   */
        s |= block[--i] << 1;                    /* append the previous MSBit */
        block[i] = (uint8_t) s;
    }                                            /* if first MSBit is carried */
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
    for (i = 0; i < BLOCKSIZE; t <<= 8)          /* from first to last byte,  */
    {                                            /*  prepend the previous LSB */
        t |= block[i];                           /*  then shift it to right.  */
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
    for (i = BLOCKSIZE; i; t <<= 8)              /* the same as halveGF128B ↑ */
    {                                            /* ..but with reversed bytes */
        t |= block[--i];
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

#if AEAD_MODES || FPE

/** xor the result with input data and then apply the digest/mixing function.
 * repeat the process for each block of data until all blocks are digested... */
static void xMac( const void* data, const size_t dataSize,
                  const block_t seed, fmix_t mix, block_t result )
{
    uint8_t const *x;
    count_t n = dataSize / BLOCKSIZE;            /*   number of full blocks   */

    for (x = data; n--; x += BLOCKSIZE)
    {
        xorBlock( x, result );                   /* M_next = mix(seed, M ^ X) */
        mix( seed, result );
    }
    if ((n = dataSize % BLOCKSIZE) != 0)
    {
        while (n--)  result[n] ^= x[n];
        mix( seed, result );
    }
}
#endif

#if CMAC || SIV || EAX

/** calculate the CMAC hash of input data using pre-calculated keys: D and Q. */
static void cMac( const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    block_t M = { 0 };
    uint8_t r = dataSize ? (dataSize - 1) % BLOCKSIZE + 1 : 0;
    const char* endblock = (const char*) data + dataSize - r;

    if (r < sizeof M)  M[r] = 0x80;
    memcpy( M, endblock, r );                    /*  copy last block into M   */
    xorBlock( r < sizeof M ? Q : D, M );         /*  ..and pad( M; D, Q )     */

    xMac( data, dataSize - r, mac, &rijndaelEncrypt, mac );
    xMac( M, sizeof M, mac, &rijndaelEncrypt, mac );
}
#endif

#if CMAC || SIV || EAX || OCB

/** calculate key-dependent constants D and Q using a given doubling function */
static void getSubkeys( const uint8_t* key, fdouble_t fdouble, const char quad,
                        block_t D, block_t Q )
{
    AES_SetKey( key );
    rijndaelEncrypt( D, D );                     /*  H or L_* = Enc(zeros)    */
    if (quad)  fdouble( D );                     /*  D or L_$ = double(L_*)   */
    memcpy( Q, D, BLOCKSIZE );
    fdouble( Q );                                /*  Q or L_0 = double(L_$)   */
}
#endif

#if AEAD_MODES && INCREASE_SECURITY

/** for constant-time comparison of memory blocks, to avoid timing attacks:   */
static uint8_t constmemcmp( const uint8_t* src, const uint8_t* dst, uint8_t n )
{
    uint8_t cmp = 0;
    while (n--)  cmp |= src[n] ^ dst[n];
    return cmp;
}
#endif


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
    uint8_t *y;
    count_t n = ptextLen / BLOCKSIZE;            /*  number of full blocks    */
    memcpy( crtxt, pntxt, ptextLen );            /*  copy plaintext to output */

    AES_SetKey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( y, y );                 /*  C = Enc(P)               */
    }
    if (padBlock( ptextLen % BLOCKSIZE, y ))
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
    uint8_t *y;
    count_t n = crtxtLen / BLOCKSIZE;
    memcpy( pntxt, crtxt, crtxtLen );

    AES_SetKey( key );
    for (y = pntxt; n--; y += BLOCKSIZE)
    {
        rijndaelDecrypt( y, y );                 /*  P = Dec(C)               */
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
    uint8_t const *iv = iVec;
    uint8_t r = ptextLen % BLOCKSIZE, *y;
    count_t n = ptextLen / BLOCKSIZE;
#if CTS
    block_t last = { 0 };

    if (!n)  return ENCRYPTION_FAILURE;
    r += (r == 0 && n > 1) * BLOCKSIZE;
    n -= (r == BLOCKSIZE);
    memcpy( last, pntxt + n * BLOCKSIZE, r );    /*  hold the last block      */
#endif
    memcpy( crtxt, pntxt, ptextLen );            /*  do in-place encryption   */

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
        iv = last;
        memcpy( y, y - BLOCKSIZE, r );           /*  'steal' the cipher-text  */
        y -= BLOCKSIZE;                          /*  ..to fill the last block */
#else
    if (padBlock( r, y ))
    {
#endif
        xorBlock( iv, y );
        rijndaelEncrypt( y, y );
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
    }                                            /*  r = 0 unless CTS enabled */
    if (r)
    {                                            /*  P2 =  Dec(C1) ^ C2       */
        mixThenXor( x, &rijndaelDecrypt, y, x + BLOCKSIZE, r, y + BLOCKSIZE );
        memcpy( y, x + BLOCKSIZE, r );
        rijndaelDecrypt( y, y );                 /*  copy C2 to Dec(C1): -> T */
        xorBlock( iv, y );                       /*  P1 =  IV ^ Dec(T)        */
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
    memcpy( crtxt, pntxt, ptextLen );            /* do in-place en/decryption */
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
    uint8_t *y;

    memcpy( output, input, dataSize );           /* do in-place en/decryption */
    memcpy( c, iCtr, sizeof c );
    if (big > 1)  incBlock( c, 1 );              /* pre-increment for CCM/GCM */

    for (y = output; n--; y += BLOCKSIZE)
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
    xorByEnd( CTRBLOCK, CTR_STARTVALUE, LAST );  /*  initialize the counter   */
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
  + main functions of XTS-AES (XEX Tweaked-codebook with ciphertext Stealing)
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(XTS)
/**
 * @brief   encrypt or decrypt a data unit with given key-pair using XEX method
 * @param   cipher    block cipher function: rijndaelEncrypt or rijndaelDecrypt
 * @param   keypair   pair of encryption keys, each one has KEYSIZE bytes
 * @param   tweakid   data unit identifier, similar to nonce in CTR mode
 * @param   sctid     sector id: if the given value is -1, use tweak value
 * @param   dataSize  size of input data, to be encrypted/decrypted
 * @param   T         one-time pad which is xor-ed with both plain/cipher text
 * @param   storage   working memory; result of encryption/decryption process
 */
static void XEX_Cipher( fmix_t cipher, const uint8_t* keypair,
                        const block_t tweakid, const size_t sctid,
                        const size_t dataSize, block_t T, void* storage )
{
    uint8_t *y;
    count_t n = dataSize / BLOCKSIZE;

    if (sctid == (size_t) ~0)
    {                                            /* the `i` block is either   */
        memcpy( T, tweakid, BLOCKSIZE );         /* ..a little-endian number  */
    }                                            /* ..or a byte array.        */
    else
    {
        memset( T, 0, BLOCKSIZE );
        copyNumL( T, sctid, 0 );
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

/**
 * @brief   encrypt the input plaintext using XTS-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   tweak     tweak bytes of data unit, a.k.a sector ID (little-endian)
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 */
char AES_XTS_encrypt( const uint8_t* keys, const uint8_t* tweak,
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
    block_t T;
    uint8_t r = ptextLen % BLOCKSIZE, *c;
    size_t len = ptextLen - r;

    if (len == 0)  return ENCRYPTION_FAILURE;
    memcpy( crtxt, pntxt, len );                 /* copy input data to output */

    XEX_Cipher( &rijndaelEncrypt, keys, tweak, ~0, len, T, crtxt );
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
 * @param   tweak     tweak bytes of data unit, a.k.a sector ID (little-endian)
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 */
char AES_XTS_decrypt( const uint8_t* keys, const uint8_t* tweak,
                      const uint8_t* crtxt, const size_t crtxtLen, uint8_t* pntxt )
{
    block_t TT, T;
    uint8_t r = crtxtLen % BLOCKSIZE, *p;
    size_t len = crtxtLen - r;

    if (len == 0)  return DECRYPTION_FAILURE;
    memcpy( pntxt, crtxt, len );                 /* copy input data to output */
    p = pntxt + len - BLOCKSIZE;

    XEX_Cipher( &rijndaelDecrypt, keys, tweak, ~0, len - BLOCKSIZE, T, pntxt );
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
    memcpy( mac, K1, sizeof K1 );                /*  initialize mac           */
    getSubkeys( key, &doubleGF128B, 1, K1, K2 );
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
    block_t len = { 0 };
    xorByEnd( len, adataLen * 8, LAST / 2 );
    xorByEnd( len, crtxtLen * 8, LAST );         /*  save bit-sizes into len  */

    xMac( aData, adataLen, H, &mulGF128, gsh );  /*  first digest AAD, then   */
    xMac( crtxt, crtxtLen, H, &mulGF128, gsh );  /*  ..ciphertext, and then   */
    xMac( len, sizeof len, H, &mulGF128, gsh );  /*  ..bit sizes into GHash   */
}

/** encrypt zeros to get authentication subkey H, and prepare the IV for GCM. */
static void GCM_Init( const uint8_t* key,
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
    GCM_Init( key, nonce, H, iv );               /*  get IV & auth. subkey H  */

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
    GCM_Init( key, nonce, H, iv );
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
                    const size_t aDataLen, const size_t ptextLen, block_t M )
{
    block_t A = { 0 };
    uint8_t p, s = BLOCKSIZE - 2;
    memcpy( M, iv, BLOCKSIZE );                  /*  initialize CBC-MAC       */

    M[0] |= (CCM_TAG_LEN - 2) << 2;              /*  set some flags on M_*    */
    xorByEnd( M, ptextLen, LAST );               /*  copy data size into M_*  */
    if (aDataLen)                                /*  feed aData into CBC-MAC  */
    {
        if (aDataLen < s)  s = aDataLen;
        p = aDataLen < 0xFF00 ? 1 : 5;
        xorByEnd( A, aDataLen, p );              /*  copy aDataLen into A     */
        if (p == 5)
        {                                        /*  assuming aDataLen < 2^32 */
            s -= 4;
            A[0] = 0xFF;  A[1] = 0xFE;           /*  prepend FFFE to aDataLen */
        }
        memcpy( A + p + 1, aData, s );           /*  append ADATA             */
        M[0] |= 0x40;
        rijndaelEncrypt( M, M );                 /*  flag M_* and encrypt it  */
    }

    xMac( A, sizeof A, M, &rijndaelEncrypt, M ); /*  CBC-MAC start of aData   */
    if (aDataLen > s)                            /*  CBC-MAC rest of aData    */
    {
        xMac( (char const*) aData + s, aDataLen - s, M, &rijndaelEncrypt, M );
    }
    xMac( pntxt, ptextLen, M, &rijndaelEncrypt, M );
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
                 const size_t aDataLen, const size_t ptextLen, block_t IV )
{
    block_t K[2], Y;
    uint8_t s = ptextLen < BLOCKSIZE, r = ptextLen % BLOCKSIZE, *D = K[0];

    memset( IV, 0, BLOCKSIZE );                  /*  initialize/clear IV      */
    memset( D, 0, BLOCKSIZE );
    getSubkeys( key, &doubleGF128B, 1, D, K[1] );
    rijndaelEncrypt( D, Y );                     /*  Y_0 = CMAC(zero block)   */

    /* in case of several aData units, each one must be processed in a same way.
     * let aData and aDataLen be arrays, and assume aDataLen is null-terminated.
     * then we can write something like this instead of the next three lines:
     * for (i=0; aDataLen[i]; ++i) { cMac(D, K[1], aData[i], aDataLen[i], IV) */
    if (aDataLen)
    {
        cMac( D, K[1], aData, aDataLen, IV );
        doubleGF128B( Y );                       /*  Y_* = double( Y_{i-1} )  */
        xorBlock( IV, Y );                       /*  Y_i = Y_* ^ CMAC(AAD_i)  */
        memset( IV, 0, BLOCKSIZE );
    }
    if (r)  memset( K[s], 0, BLOCKSIZE );
    if (s)
    {                                            /*  for short messages:      */
        doubleGF128B( Y );                       /*  Y = double( Y_n )        */
        r = 0;
    }
    xorBlock( Y, D + r );

    cMac( D, D, pntxt, ptextLen - r, IV );       /*  CMAC*( Y  xor_end  M )   */
    if (r)
    {
        cMac( D, K[1], (const char*) pntxt + ptextLen - r, r, IV );
    }
}

/**
 * @brief   encrypt the input plaintext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   iv        synthesized I.V block, typically prepended to ciphertext
 * @param   crtxt     resulting cipher-text buffer
 */
void AES_SIV_encrypt( const uint8_t* keys,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      block_t iv, uint8_t* crtxt )
{
    block_t IV;
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
    block_t len = { 0 };                         /*  save bit-sizes into len  */
    copyNumL( len, aDataLen * 8, 0 );
    copyNumL( len, ptextLen * 8, 8 );

    xMac( aData, aDataLen, H, &dotGF128, pv );   /*  first digest AAD, then   */
    xMac( pntxt, ptextLen, H, &dotGF128, pv );   /*  ..plaintext, and then    */
    xMac( len, sizeof len, H, &dotGF128, pv );   /*  ..bit sizes into POLYVAL */
}

/** derive the pair of authentication-encryption-keys from main key and nonce */
static void GSIVsubkeys( const uint8_t* key, const uint8_t* nonce, block_t AK )
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
    GSIVsubkeys( key, nonce, H );                /* get authentication subkey */

    Polyval( H, aData, pntxt, aDataLen, ptextLen, S );
    XOR32BITS( nonce[0], S[0] );
    XOR32BITS( nonce[4], S[4] );
    XOR32BITS( nonce[8], S[8] );                 /* xor POLYVAL with nonce    */

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

    GSIVsubkeys( key, nonce, H );                /* get authentication subkey */
    memcpy( S, crtxt + crtxtLen, sizeof S );     /* tag is IV for CTR cipher  */
    S[LAST] |= 0x80;
    CTR_Cipher( S, 0, crtxt, crtxtLen, pntxt );

    memset( S, 0, sizeof S );
    Polyval( H, aData, pntxt, aDataLen, crtxtLen, S );
    XOR32BITS( nonce[0], S[0] );
    XOR32BITS( nonce[4], S[4] );
    XOR32BITS( nonce[8], S[8] );                 /* xor POLYVAL with nonce    */

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
    if (dataSize == 0 && t)  return;             /*   ignore null ciphertext  */
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
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes unless EAX'
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data; for EAX only, not EAX'
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     resulting cipher-text buffer; 4 bytes mac appended in EAX'
 * @param   auTag     authentication tag; buffer must be 16 bytes long in EAX
 */
void AES_EAX_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
#if EAXP
                      const size_t nonceLen, uint8_t* crtxt )
#define GFDOUBLE      doubleGF128L
#else
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, uint8_t* auTag )
#define GFDOUBLE      doubleGF128B
#define nonceLen      EAX_NONCE_LEN
#endif
{
    block_t D = { 0 }, Q, mac;
    getSubkeys( key, &GFDOUBLE, 1, D, Q );
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = OMAC(0; nonce)       */

#if EAXP
    COPY32BIT( mac[12], crtxt[ptextLen] );
    mac[12] &= 0x7F;
    mac[14] &= 0x7F;                             /*  clear 2 bits to get N'   */
    CTR_Cipher( mac, 1, pntxt, ptextLen, crtxt );

    OMac( 2, D, Q, crtxt, ptextLen, mac );       /*  C' = CMAC'( ciphertext ) */
    XOR32BITS( mac[12], crtxt[ptextLen] );       /*  tag (i.e mac) = N ^ C'   */
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
 * @param   nonce     a.k.a init-vector with EAX_NONCE_LEN bytes unless EAX'
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of cipher-text; excluding tag / 4-bytes mac in EAX'
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data; for EAX only, not EAX'
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
    getSubkeys( key, &GFDOUBLE, 1, D, Q );
    OMac( 2, D, Q, crtxt, crtxtLen, tag );       /*  C = OMAC(2; ciphertext)  */

#if EAXP
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = CMAC'( nonce )       */
    XOR32BITS( crtxt[crtxtLen], tag[12] );
    XOR32BITS( mac[12], tag[12] );
    mac[12] &= 0x7F;
    mac[14] &= 0x7F;                             /*  clear 2 bits to get N'   */

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
        OCB-AES (offset codebook mode): how to parallelize the algorithm
                by independent calculation of the offset values
                 + auxiliary functions along with the main API
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(OCB)

static block_t OCBsubkeys[4];                    /*  [L_$] [L_*] [Δ_0] [Δ_*]  */

/** Derive the offset block (Δ_i) at a specified index, using pre-calculated Δ_0
 * and L$ blocks. This method has minimum memory usage, but it's clearly slow */
static void offsetAt( const count_t index, block_t delta )
{
    size_t m, b = 1;
    block_t L;
    memcpy( L, OCBsubkeys[0], sizeof L );        /*  initialize L_$           */
    memcpy( delta, OCBsubkeys[2], BLOCKSIZE );   /*  .. and Δ_i               */

    while (b <= index && b)                      /*  we can pre-calculate all */
    {                                            /*  .. L_{i}s to boost speed */
        m = (4 * b - 1) & (index - b);
        b <<= 1;                                 /*  L_0 = double( L_$ )      */
        doubleGF128B( L );                       /*  L_i = double( L_{i-1} )  */
        if (b > m)  xorBlock( L, delta );        /*  Δ_i = Δ_{i-1} ^ L_ntz(i) */
    }
}

/** encrypt or decrypt the input data with OCB method. cipher function is either
 * rijndaelEncrypt or rijndaelDecrypt, and nonce size must be = OCB_NONCE_LEN */
static void OCB_Cipher( fmix_t cipher, const uint8_t* nonce,
                        const size_t dataSize, void* data )
{
    uint8_t *Ls = OCBsubkeys[1], *kt = OCBsubkeys[2], *del = OCBsubkeys[3];
    count_t n = nonce[OCB_NONCE_LEN - 1] & 0x3F, i;
    uint8_t r = n % 8, *y = data;
    n /= 8;                                      /* copy last 6 bits to (n,r) */

    memcpy( kt + BLOCKSIZE - OCB_NONCE_LEN, nonce, OCB_NONCE_LEN );
    kt[0] = OCB_TAG_LEN << 4 & 0xFF;
    kt[LAST - OCB_NONCE_LEN] |= 1;
    kt[LAST] &= 0xC0;                            /* clear last 6 bits         */

    rijndaelEncrypt( kt, kt );                   /* construct K_top           */
    memcpy( del, kt + 1, 8 );                    /* stretch K_top             */
    xorBlock( kt, del );
    for (i = 0; i < BLOCKSIZE; ++n)              /* shift the stretched K_top */
    {
        kt[i++] = kt[n] << r | kt[n + 1] >> (8 - r);
    }
    n = dataSize / BLOCKSIZE;
    r = dataSize % BLOCKSIZE;

    if (n == 0)  memcpy( del, kt, BLOCKSIZE );   /*  initialize Δ_0           */

    for (i = 0; i < n; y += BLOCKSIZE)
    {
        offsetAt( ++i, del );                    /*  calculate Δ_i using my   */
        xorBlock( del, y );                      /*  .. 'magic' algorithm     */
        cipher( y, y );
        xorBlock( del, y );                      /* Y = Δ_i ^ Cipher(Δ_i ^ X) */
    }
    if (r)                                       /*  Δ_* = Δ_n ^ L_* and then */
    {                                            /*  Y_* = Enc(Δ_*) ^ X       */
        xorBlock( Ls, del );
        mixThenXor( del, &rijndaelEncrypt, kt, y, r, y );
        del[r] ^= 0x80;                          /*    pad it for checksum    */
    }
    xorBlock( OCBsubkeys[0], del );              /*    last offset ^= L_$     */
}

static void nop( const block_t x, block_t y ) {}

/** derive authentication tag, using checksum of plaintext, and PMAC of aData */
static void OCB_GetTag( const void* pntxt, const void* aData,
                        const size_t ptextLen, const size_t aDataLen,
                        block_t tag )
{
    uint8_t const r = aDataLen % BLOCKSIZE, *x, *Ls = OCBsubkeys[1];
    count_t i = 0, n = aDataLen / BLOCKSIZE;
    block_t S;

    memset( OCBsubkeys[2], 0, BLOCKSIZE );       /*  Δ_0 = 0                  */
    memcpy( S, OCBsubkeys[3], BLOCKSIZE );       /*  S = Δ_* ^ L_$            */
    xMac( pntxt, ptextLen, NULL, &nop, S );      /*  add plaintext checksum   */
    rijndaelEncrypt( S, tag );                   /*  Tag0 = Enc(checksum ^ S) */

    for (x = aData; i < n; x += BLOCKSIZE)       /*  PMAC authentication:     */
    {
        offsetAt( ++i, S );
        xorBlock( x, S );
        rijndaelEncrypt( S, S );                 /*  S_i = Enc(A_i ^ Δ_i)     */
        xorBlock( S, tag );                      /*  Tag_{i+1} = Tag_i ^ S_i  */
    }
    if (r)
    {
        offsetAt( n, S );
        xorBlock( Ls, S );                       /*  S = L_* ^ Δ_n            */
        S[r] ^= 0x80;                            /*  pad it                   */
        xMac( x, r, S, &rijndaelEncrypt, S );    /*  S_* = Enc(A_* ^ S)       */
        xorBlock( S, tag );                      /*  Tag = S_* ^ Tag_n        */
    }
}

/**
 * @brief   encrypt the input stream using OCB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: OCB_NONCE_LEN
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
    uint8_t *Ld = OCBsubkeys[0], *Ls = OCBsubkeys[1];

    memcpy( crtxt, pntxt, ptextLen);             /* doing in-place encryption */
    memset( Ls, 0, 2 * BLOCKSIZE );
    getSubkeys( key, &doubleGF128B, 0, Ls, Ld );
    OCB_Cipher( &rijndaelEncrypt, nonce, ptextLen, crtxt );
    OCB_GetTag( pntxt, aData, ptextLen, aDataLen, auTag );

    BURN( RoundKey );
    BURN( OCBsubkeys );
}

/**
 * @brief   decrypt the input stream using OCB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: OCB_NONCE_LEN
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
    uint8_t *Ld = OCBsubkeys[0], *Ls = OCBsubkeys[1], *tag = OCBsubkeys[3];
    if (tagLen && tagLen != OCB_TAG_LEN)  return DECRYPTION_FAILURE;

    memcpy( pntxt, crtxt, crtxtLen);             /* in-place decryption       */
    memset( Ls, 0, 2 * BLOCKSIZE );
    getSubkeys( key, &doubleGF128B, 0, Ls, Ld );
    OCB_Cipher( &rijndaelDecrypt, nonce, crtxtLen, pntxt );
    OCB_GetTag( pntxt, aData, crtxtLen, aDataLen, tag );

    BURN( RoundKey );
    if (MISMATCH( tag, crtxt + crtxtLen, tagLen ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return AUTHENTICATION_FAILURE;
    }
    BURN( OCBsubkeys );
    return ENDED_IN_SUCCESS;
}
#endif /* OCB */


/*----------------------------------------------------------------------------*\
             KW-AES: Main functions for AES key-wrapping (RFC-3394)
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(KWA)
#define HB  (BLOCKSIZE / 2)                      /*  size of half-blocks      */
/**
 * @brief   wrap the input secret whose size is a multiple of 8 and >= 16
 * @param   kek       key-encryption-key a.k.a master key
 * @param   secret    input plain text secret
 * @param   secretLen size of input, must be a multiple of HB (half-block size)
 * @param   wrapped   wrapped secret. note: size of output = secretLen + HB
 * @return            error if size is not a multiple of HB, or size < BLOCKSIZE
 */
char AES_KEY_wrap( const uint8_t* kek,
                   const uint8_t* secret, const size_t secretLen, uint8_t* wrapped )
{
    size_t i = 0, q, n = secretLen / HB;         /*  number of semi-blocks    */
    block_t A;
    if (n < 2 || secretLen % HB)  return ENCRYPTION_FAILURE;

    memset( A, 0xA6, HB );                       /*  initialization vector    */
    memcpy( wrapped + HB, secret, secretLen );   /*  copy input to the output */
    AES_SetKey( kek );

    for (q = 6 * n; i++ < q; )
    {
        uint8_t *r = wrapped + ((i - 1) % n + 1) * HB;
        memcpy( A + HB, r, HB );
        rijndaelEncrypt( A, A );                 /*  A = Enc( V | R[k] )      */
        memcpy( r, A + HB, HB );                 /*  R[k] = LSB(64, A)        */
        xorByEnd( A, i, HB - 1 );                /*  V = MSB(64, A) ^ i       */
    }
    BURN( RoundKey );

    memcpy( wrapped, A, HB );
    return ENDED_IN_SUCCESS;
}

/**
 * @brief   unwrap a wrapped input key whose size is a multiple of 8 and >= 24
 * @param   kek       key-encryption-key a.k.a master key
 * @param   wrapped   cipher-text input, i.e. wrapped secret.
 * @param   wrapLen   size of ciphertext/wrapped input in bytes
 * @param   secret    unwrapped secret whose size = wrapLen - HB
 * @return            a value indicating whether decryption was successful
 */
char AES_KEY_unwrap( const uint8_t* kek,
                     const uint8_t* wrapped, const size_t wrapLen, uint8_t* secret )
{
    size_t i, q = 0, n = wrapLen / HB - 1;       /*  number of semi-blocks    */
    block_t A;
    if (n < 2 || wrapLen % HB)  return DECRYPTION_FAILURE;

    memcpy( A, wrapped, HB );                    /*  authentication vector    */
    memcpy( secret, wrapped + HB, wrapLen - HB );
    AES_SetKey( kek );

    for (i = 6 * n; i; --i)
    {
        uint8_t *r = secret + ((i - 1) % n) * HB;
        xorByEnd( A, i, HB - 1 );
        memcpy( A + HB, r, HB );                 /*  V = MSB(64, A) ^ i       */
        rijndaelDecrypt( A, A );                 /*  A = Dec( V | R[k] )      */
        memcpy( r, A + HB, HB );                 /*  R[k] = LSB(64, A)        */
    }
    BURN( RoundKey );

    while (i < HB)  q |= A[i++] ^ 0xA6;          /*  authenticate/error check */

    return q ? AUTHENTICATION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* KWA */


/*----------------------------------------------------------------------------*\
     Poly1305-AES message authentication: auxiliary functions and main API
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(POLY1305)
#define SP   (BLOCKSIZE + 1)                     /* size of poly1305 blocks   */

/** derive modulo(2^130-5) for a little endian block, by repeated subtraction */
static void modLPoly( uint8_t* block, const int ovrfl )
{
    int32_t q = ovrfl << 6 | block[SP - 1] / 4, t;
    uint8_t i = 0;
    if (!q)  return;                             /*   q = B / (2 ^ 130)       */

    for (t = 5 * q; t && i < SP; t >>= 8)        /* mod = B - q * (2^130-5)   */
    {
        t += block[i];                           /* to get mod, first derive  */
        block[i++] = (uint8_t) t;                /* .. B + (5 * q) and then   */
    }                                            /* .. subtract q * (2^130)   */
    block[SP - 1] -= 4 * (uint8_t) q;
}

/** add two little-endian poly1305 blocks. use modular addition if necessary. */
static void addLBlocks( const uint8_t* x, const uint8_t len, uint8_t* y )
{
    int a, i;
    for (i = a = 0; i < len; a >>= 8)
    {
        a += x[i] + y[i];
        y[i++] = (uint8_t) a;                    /*  s >> 8 is overflow/carry */
    }
    if (i == SP)  modLPoly( y, a );
}

/** modular multiplication of two little-endian poly1305 blocks: y *= x mod P */
static void mulLBlocks( const uint8_t* x, uint8_t* y )
{
    uint8_t n = SP, i, s, result[SP] = { 0 };    /*  Y = [Y_0][Y_1]...[Y_n]   */
    int32_t m;
    while (n--)                                  /* multiply X by MSB of Y    */
    {                                            /* ..and add to the result   */
        s = n ? 8 : 0;                           /* ..shift the result if Y   */
        for (m = i = 0; i < SP; m >>= 8)         /* ..has other byte in queue */
        {                                        /* ..but don't shift for Y_0 */
            m += (result[i] + x[i] * y[n]) << s;
            result[i++] = (uint8_t) m;
        }
        modLPoly( result, m );                   /*  modular multiplication   */
    }
    memcpy( y, result, sizeof result );
}

/** handle some special/rare cases that might be missed by modLPoly function. */
static void cmpToP1305( uint8_t* block )
{
    uint8_t i = (block[SP - 1] == 3) * BLOCKSIZE;
    int c = block[SP - 1] > 3 || (i && block[0] >= 0xFB);

    while (c && i)  c = block[--i] == 0xFF;      /* compare block to 2^130-5  */
    for (c *= 5; c; c >>= 8)
    {
        c += *block;                             /* and if (block >= 2^130-5) */
        *block++ = (uint8_t) c;                  /* .. add it with 5          */
    }
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
    uint8_t r[SP], rk[SP] = { 1 }, c[SP] = { 0 }, poly[SP] = { 0 };
    uint8_t s = (dataSize > 0);
    uint8_t i = (dataSize - s) % BLOCKSIZE + s, j = BLOCKSIZE;
    count_t q = (dataSize - s) / BLOCKSIZE;
    const char* ptr = (const char*) data + q * BLOCKSIZE;

    AES_SetKey( keys );
    rijndaelEncrypt( nonce, mac );               /* derive AES_k(nonce)       */
    BURN( RoundKey );

    memcpy( r, keys + KEYSIZE, BLOCKSIZE );      /* extract r from (k,r) pair */
    for (r[j] = 0; j; j -= 4)
    {
        r[j] &= 0xFC;                            /* clear bottom 2 bits       */
        r[j - 1] &= 0x0F;                        /* clear top 4 bits          */
    }

    for (q += s; q--; ptr -= (i = BLOCKSIZE))
    {
        memcpy( c, ptr, i );                     /* copy message to chunk     */
        c[i] = 1;                                /* append 1 to each chunk    */
        mulLBlocks( r, rk );                     /* r^k = r^{k-1} * r         */
        mulLBlocks( rk, c );                     /* calculate c_{q-k} * r^k   */
        addLBlocks( c, sizeof c, poly );         /* add to poly (mod 2^130-5) */
    }
    cmpToP1305( poly );
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
#define RADIX    10                              /*  strlen (ALPHABET)        */
#define LOGRDX   3.321928095                     /*  log2 (RADIX)             */
#define MINLEN   6                               /*  ceil (6 / log10 (RADIX)) */
#define MAXLEN   56                              /*  for FF3-1 only           */
#endif

#if RADIX > 0x100
typedef unsigned short  rbase_t;                 /*  digit type in base-radix */
#else
typedef uint8_t  rbase_t;
#endif

#if FF_X == 3

/** convert a string in base-RADIX to a little-endian number, denoted by num  */
static void numRadix( const rbase_t* s, uint8_t len, uint8_t* num, uint8_t bytes )
{
    memset( num, 0, bytes );
    while (len--)
    {
        size_t i, d = s[len];
        for (i = 0; i < bytes; d >>= 8)
        {
            d += num[i] * RADIX;                 /*  num = num * RADIX + d    */
            num[i++] = (uint8_t) d;
        }
    }
}

/** convert a little-endian number to its base-RADIX representation string: s */
static void strRadix( const uint8_t* num, uint8_t bytes, rbase_t* s, uint8_t len )
{
    memset( s, 0, sizeof (rbase_t) * len );
    while (bytes--)
    {
        size_t i, b = num[bytes];
        for (i = 0; i < len; b /= RADIX)
        {
            b += s[i] << 8;                      /*  numstr = numstr << 8 + b */
            s[i++] = b % RADIX;
        }
    }
}

/** add two numbers in base-RADIX represented by q and p, so that p = p + q   */
static void numstrAdd( const rbase_t* q, const uint8_t N, rbase_t* p )
{
    size_t i, c, a;
    for (i = c = 0; i < N; c = a >= RADIX)       /* little-endian addition    */
    {
        a = p[i] + q[i] + c;
        p[i++] = a % RADIX;
    }
}

/** subtract two numbers in base-RADIX represented by q and p, so that p -= q */
static void numstrSub( const rbase_t* q, const uint8_t N, rbase_t* p )
{
    size_t i, c, s;
    for (i = c = 0; i < N; c = s < RADIX)        /* little-endian subtraction */
    {
        s = RADIX + p[i] - q[i] - c;
        p[i++] = s % RADIX;
    }
}

/** apply the FF3-1 round at step `i` to the input string X with length `len` */
static void FF3round( const uint8_t i, const uint8_t* T, const uint8_t u,
                      const uint8_t len, rbase_t* X )
{
    uint8_t P[BLOCKSIZE], s = i & 1 ? len : len - u;

    T += (s < len) * 4;                          /* W=TL if i is odd, else TR */
    P[15] = T[0];  P[14] = T[1];
    P[13] = T[2];  P[12] = T[3] ^ i;

    numRadix( X - s, len - u, P, 12 );           /*  B = *X_end - s           */
    rijndaelEncrypt( P, P );
    strRadix( P, sizeof P, X, u );               /*  C = *X = REV( STRm(c) )  */
}

/** encrypt/decrypt a base-RADIX string X with size len using FF3-1 algorithm */
static void FF3_Cipher( const uint8_t* key, const uint8_t* tweak,
                        const char mode, const uint8_t len, rbase_t* X )
{
    rbase_t *Xc = X + len;
    uint8_t T[8], i, *k = (void*) Xc, u = (len + mode) / 2, r = mode ? 0 : 8;

    memcpy( T, tweak, 7 );
    T[7] = (uint8_t) (T[3] << 4);
    T[3] &= 0xF0;

    /* note that the official test vectors are based on the old version of FF3,
     * which uses a 64-bit tweak. you can uncomment this line to verify them:
    memcpy( T, tweak, 8 );                                                    */

    for (i = KEYSIZE; i--; )  k[i] = *key++;
    AES_SetKey( k );                             /*  key is reversed          */

    for (i = r; i < 8; u = len - u)              /*  Feistel procedure        */
    {
        FF3round( i++, T, u, len, Xc );          /*  encryption rounds        */
        numstrAdd( Xc, u, i & 1 ? X : Xc - u );
    }
    for (i = r; i > 0; u = len - u)              /* A → X, C → Xc, B → Xc - u */
    {
        FF3round( --i, T, u, len, Xc );          /*  decryption rounds        */
        numstrSub( Xc, u, i & 1 ? Xc - u : X );
    }
}
#else /* FF1: */

/** convert a string in base-RADIX to a big-endian number, denoted by num     */
static void numRadix( const rbase_t* s, size_t len, uint8_t* num, size_t bytes )
{
    memset( num, 0, bytes );
    while (len--)
    {
        size_t i, d = *s++;
        for (i = bytes; i; d >>= 8)
        {
            d += num[--i] * RADIX;               /*  num = num * RADIX + d    */
            num[i] = (uint8_t) d;
        }
    }
}

/** convert a big-endian number to its base-RADIX representation string: s    */
static void strRadix( const uint8_t* num, size_t bytes, rbase_t* s, size_t len )
{
    memset( s, 0, sizeof (rbase_t) * len );
    while (bytes--)
    {
        size_t i, b = *num++;
        for (i = len; i; b /= RADIX)
        {
            b += s[--i] << 8;                    /*  numstr = numstr << 8 + b */
            s[i] = b % RADIX;
        }
    }
}

/** add two numbers in base-RADIX represented by q and p, so that p = p + q   */
static void numstrAdd( const rbase_t* q, size_t N, rbase_t* p )
{
    size_t c, a;
    for (c = 0; N--; c = a >= RADIX)             /*  big-endian addition      */
    {
        a = p[N] + q[N] + c;
        p[N] = a % RADIX;
    }
}

/** subtract two numbers in base-RADIX represented by q and p, so that p -= q */
static void numstrSub( const rbase_t* q, size_t N, rbase_t* p )
{
    size_t c, s;
    for (c = 0; N--; c = s < RADIX)              /*  big-endian subtraction   */
    {
        s = RADIX + p[N] - q[N] - c;
        p[N] = s % RADIX;
    }
}

static size_t bf, df;                            /*  b and d constants in FF1 */

/** apply the FF1 round at step `i` to the input string X with length `len`   */
static void FF1round( const uint8_t i, const block_t P, const size_t u,
                      const size_t len, rbase_t* Xc )
{
    size_t k = bf % BLOCKSIZE, s = i & 1 ? len : len - u;
    block_t R = { 0 };
    uint8_t *num = (void*) (Xc + u);             /* use pre-allocated memory  */

    R[LAST - k] = i;
    numRadix( Xc - s, len - u, num, bf );        /* get NUM_radix(B)          */
    memcpy( R + BLOCKSIZE - k, num, k );         /* feed NUMradix(B) into PRF */
    xMac( P, BLOCKSIZE, R, &rijndaelEncrypt, R );
    xMac( num + k, bf - k, R, &rijndaelEncrypt, R );

    memcpy( num, R, sizeof R );                  /* R = PRF(P || Q)           */
    k = (df - 1) / BLOCKSIZE;                    /* total additional blocks   */
    for (num += k * sizeof R; k; --k)
    {
        memcpy( num, R, sizeof R );
        xorByEnd( num, k, LAST );                /* num = R || R ^ [j] ||...  */
        rijndaelEncrypt( num, num );             /* S = R || Enc(R ^ [j])...  */
        num -= sizeof R;
    }
    strRadix( num, df, Xc, u );                  /* take first d bytes of S   */
}

/** encrypt/decrypt a base-RADIX string X with length len using FF1 algorithm */
static void FF1_Cipher( const uint8_t* key, const uint8_t* tweak,
                        const char mode, const size_t tweakLen, const size_t len,
                        rbase_t* X )
{
    block_t P = { 1, 2, 1, RADIX >> 16, RADIX >> 8 & 0xFF, RADIX & 0xFF, 10 };
    rbase_t *Xc;
    uint8_t i = tweakLen % BLOCKSIZE, r = mode ? 0 : 10;
    size_t u = (len + 1 - mode) >> 1, t = tweakLen - i;

    P[7] = len / 2 & 0xFF;
    xorByEnd( P, len, 11 );
    xorByEnd( P, tweakLen, LAST );               /* P = [1,2,1][radix][10]... */
    Xc = X + len;

    AES_SetKey( key );
    rijndaelEncrypt( P, P );
    xMac( tweak, t, P, &rijndaelEncrypt, P );    /* P = PRF(P || tweak)       */
    if (i < BLOCKSIZE - bf % BLOCKSIZE)
    {
        for (t = tweakLen; i; )  P[--i] ^= tweak[--t];
    }
    else                                         /* zero pad and feed to PRF  */
    {
        xMac( tweak + t, i, P, &rijndaelEncrypt, P );
    }
    for (i = r; i < 10; u = len - u)             /* Feistel procedure         */
    {
        FF1round( i++, P, u, len, Xc );          /* encryption rounds         */
        numstrAdd( Xc, u, i & 1 ? X : Xc - u );
    }
    for (i = r; i != 0; u = len - u)             /* A → X, C → Xc, B → Xc - u */
    {
        FF1round( --i, P, u, len, Xc );          /* decryption rounds         */
        numstrSub( Xc, u, i & 1 ? Xc - u : X );
    }
}
#endif /* FF_X */

/*----------------------------------------------------------------------------*\
                            FPE-AES: main functions
\*----------------------------------------------------------------------------*/
#include <stdlib.h>

/** allocate the required memory and validate the input string in FPE mode... */
static char FPEsetup( const string_t str, const size_t len, rbase_t** indices )
{
    string_t alpha = ALPHABET;
    size_t i = (len + 1) / 2;
    size_t j = (len + i) * sizeof (rbase_t);

#if FF_X == 3
    if (len > MAXLEN)  return 'L';
    i *= sizeof (rbase_t);
    j += (i < KEYSIZE) * (KEYSIZE - i);
#else
    bf = (size_t) (LOGRDX * i + 8 - 1e-10) / 8;  /*  extra memory is required */
    df = (bf + 7) & ~3UL;                        /*  ..whose size is at least */
    j += (df + 12) & ~15UL;                      /*  ..ceil( d/16 ) blocks    */
#endif
    if (len < MINLEN || (*indices = malloc( j )) == NULL)
    {
        return 'M';                              /*  memory allocation failed */
    }
    for (i = 0; i < len; ++str)
    {
        for (j = RADIX; --j && alpha[j] != *str; ) {}
        if (alpha[j] != *str)
        {
            free( *indices );                    /*  invalid character found  */
            return 'I';
        }
        (*indices)[i++] = (rbase_t) j;
    }
    return 0;
}

/** make the output string after completing FPE encrypt/decryption procedures */
static void FPEfinalize( const rbase_t* index, size_t size, void** output )
{
    string_t alpha = ALPHABET, *s = *output;
    while (size--)  *s++ = alpha[*index++];
    *s = 0;
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
    FF3_Cipher( key, tweak, 1, ptextLen, index );
#else
    FF1_Cipher( key, tweak, 1, tweakLen, ptextLen, index );
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
    FF3_Cipher( key, tweak, 0, crtxtLen, index );
#else
    FF1_Cipher( key, tweak, 0, tweakLen, crtxtLen, index );
#endif
    BURN( RoundKey );
    FPEfinalize( index, crtxtLen, &pntxt );
    free( index );
    return ENDED_IN_SUCCESS;
}
#endif /* FPE */
