/*
 ==============================================================================
 Name        : micro_aes.c
 Author      : polfosol
 Version     : 11
 Copyright   : copyright © 2022 - polfosol
 Description : ANSI-C compatible implementation of µAES ™ library.
 ==============================================================================
 */

#include "micro_aes.h"

/*----------------------------------------------------------------------------*\
                              Constants and MACROs
\*----------------------------------------------------------------------------*/
enum basic_constants
{
    BLOCKSIZE =       128 / 8,   /* Block length in AES is 'always' 128-bits. */
    KEYSIZE   = AES_KEYLENGTH,
    Nb        = BLOCKSIZE / 4,   /* number of columns comprising a AES state. */
    Nk        =   KEYSIZE / 4,   /* number of 32 bit words in a key.          */
    ROUNDS    =        Nk + 6,   /* number of rounds in AES Cipher.           */
    HB        = BLOCKSIZE / 2,   /* length of a half-block unit.              */
    LAST      = BLOCKSIZE - 1,   /* index of last element (LSB) in a block.   */
    MIDST     =      LAST / 2,   /* index of half-block LSB.                  */
    PL        = BLOCKSIZE + 1    /* length of arithmetic blocks in poly-1305. */
};

#define IMPLEMENT(x)  (x) > 0

#define INCREASE_SECURITY   0    /* see the comments at the bottom of header. */
#define INLINE_SUBROUTINES  0
#define SMALL_CIPHER        0

/** Lookup-tables are "static constant", so that they can be placed in read-only
 * storage instead of RAM. They can be computed dynamically trading ROM for RAM.
 * This may be useful in (embedded) bootloader applications, where ROM is often
 * limited. Note that sbox[y] = x, if and only if rsbox[x] = y. For more details
 * on dynamic sbox computation, see https://en.wikipedia.org/wiki/Rijndael_S-box
 */
static const char sbox[256] =
    "c|w{\362ko\3050\01g+\376\327\253v\312\202\311}""\372YG\360\255\324\242\257"
    "\234\244r\300\267\375\223&6\?\367\3144\245\345\361q\3301\25\4\307#\303\030"
    "\226\5\232\a\22\200\342\353\'\262u\t\203,\32\33nZ\240R;\326\263)\343/\204S"
    "\321\0\355 \374\261[j\313\2769JLX\317\320\357\252\373CM3\205E\371\02\177P<"
    "\237\250Q\243@\217\222\2358\365\274\266\332!\20\377\363\322\315\f\023\354_"
    "\227D\27\304\247~=d]\31s`\201O\334\"*\220\210F\356\270\24\336^\v\333\3402:"
    "\nI\06$\\\302\323\254b\221\225\344y\347\3107m\215\325N\251lV\364\352ez\256"
    "\b\272x%.\034\246\264\306\350\335t\37K\275\213\212p>\265fH\3\366\16a5W\271"
    "\206\301\035\236\341\370\230\21i\331\216\224\233\036\207\351\316U(\337\214"
    "\241\211\r\277\346BhA\231-\17\260T\273\26";

#if DECRYPTION
static const char rsbox[256] =
    "R\tj\32506\2458\277@\243\236\201\363\327\373|\3439\202\233/\377\2074\216CD"
    "\304\336\351\313T{\2242\246\302#=\356L\225\vB\372\303N\b.\241f(\331$\262v["
    "\242Im\213\321%r\370\366d\206h\230\026\324\244\\\314]e\266\222lpHP\375\355"
    "\271\332^\25FW\247\215\235\204\220\330\253\0\214\274\323\n\367\344X\05\270"
    "\263E\6\320,\036\217\312?\17\2\301\257\275\3\1\023\212k:\221\21AOg\334\352"
    "\227\362\317\316\360\264\346s\226\254t\"\347\2555\205\342\3717\350\34u\337"
    "nG\361\32q\35)\305\211o\267b\16\252\30\276\33\374V>K\306\322y \232\333\300"
    "\376x\315Z\364\037\335\2503\210\a\3071\261\22\20Y\'\200\354_`Q\177\251\031"
    "\265J\r-\345z\237\223\311\234\357\240\340;M\256*\365\260\310\353\273<\203S"
    "\231a\027+\004~\272w\326&\341i\024cU!\f}";
#endif

/*----------------------------------------------------------------------------*\
                        Data types and private variables
\*----------------------------------------------------------------------------*/

/** The array that stores all round keys during the AES key-expansion process */
static uint8_t RoundKey[BLOCKSIZE * ROUNDS + KEYSIZE];

/** block_t indicates fixed-size memory blocks, and state_t represents the state
 * matrix. note that state[i][j] means the i-th COLUMN and j-th ROW of matrix */
typedef uint8_t block_t[BLOCKSIZE];
typedef uint8_t state_t[Nb][4];

/*----------------------------------------------------------------------------*\
                 Auxiliary functions for the Rijndael algorithm
\*----------------------------------------------------------------------------*/

#define SBoxValue(x)       ( sbox[x])
#define InvSBoxValue(x)    (rsbox[x])    /* omitted dynamic s-box calculation */

#define COPYDWORD(x, y)   *(int32_t*) &y  = *(int32_t*) &x
#define XOR32BITS(x, y)   *(int32_t*) &y ^= *(int32_t*) &x

#if INLINE_SUBROUTINES

/** note: 'long long' type is NOT supported in C89. so this may throw errors: */
#define xorBlock(x, y)                                    \
(                                                         \
    *(long long*) &(y)[0] ^= *(long long const*) &(x)[0], \
    *(long long*) &(y)[8] ^= *(long long const*) &(x)[8]  \
)

#define xtime(x)  ((x) & 0x80 ? (x) * 2 ^ 0x11b : (x) << 1)

#define mixG8(a, b, c, d)                     b ^ c ^ d ^ \
        xtime(a ^ b ^ xtime(a ^ c ^ xtime(a ^ b ^ c ^ d )))
#else

/** XOR two 128bit blocks, i.e. add two numbers in Galois bit field GF(2^128) */
static void xorBlock( const block_t src, block_t dest )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)      /* many CPUs have single instruction */
    {                                    /*  such as XORPS for 128-bit-xor.   */
        dest[i] ^= src[i];               /* see the file: x86-improvements    */
    }
}

/** doubling in GF(2^8): left-shift and if carry bit is set, xor it with 0x1b */
static uint8_t xtime( uint8_t x )
{
    return (x > 0x7f) * 0x1b ^ (x << 1);
}

#if DECRYPTION

/** inverse multiply in 8bit GF: mul(a,14) ^ mul(b,11) ^ mul(c,13) ^ mul(d,9) */
static uint8_t mixG8( uint8_t a, uint8_t b, uint8_t c, uint8_t d )
{
    b ^= a;
    d ^= b ^ c;
    c ^= a;
    a ^= d;
    c ^= xtime( d );
    b ^= xtime( c );
    a ^= xtime( b );
    return a;                            /* or use (9 11 13 14) lookup tables */
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

    for (i = KEYSIZE; i < BLOCKSIZE * (ROUNDS + 1); i += 4)
    {
        switch (i % KEYSIZE)
        {
        case 0:
            memcpy( &RoundKey[i], &RoundKey[i - KEYSIZE], KEYSIZE );
            if (4 / Nk && !rcon)
            {
                rcon = 0x1b;     /* RCON reaches 0 only in AES-128, when Nk=4 */
            }
            RoundKey[i    ] ^= SBoxValue( RoundKey[i - 3] ) ^ rcon;
            RoundKey[i + 1] ^= SBoxValue( RoundKey[i - 2] );
            RoundKey[i + 2] ^= SBoxValue( RoundKey[i - 1] );
            RoundKey[i + 3] ^= SBoxValue( RoundKey[i - 4] );
            rcon <<= 1;
            break;
#if AES___== 256
        case 48 - KEYSIZE:
            RoundKey[i    ] ^= SBoxValue( RoundKey[i - 4] );
            RoundKey[i + 1] ^= SBoxValue( RoundKey[i - 3] );
            RoundKey[i + 2] ^= SBoxValue( RoundKey[i - 2] );
            RoundKey[i + 3] ^= SBoxValue( RoundKey[i - 1] );
            break;
#endif
        default:
            XOR32BITS( RoundKey[ i - 4 ], RoundKey[ i ] );
            break;
        }
    }
}

/** XOR the round keys with the rijndael state matrix; namely, add them in GF */
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
 * with a different offset (= Row number). So the "zeroth" row is not shifted */
static void ShiftRows( state_t state )
{
    uint8_t tmp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = tmp;           /* the first row rotates 1 column(s) to left */

    tmp         = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = tmp;
    tmp         = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = tmp;           /* the second row rotates 2 columns to left, */

    tmp         = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = tmp;           /* and the 3rd row rotates 3 columns to left */
}

/** Use matrix multiplication in Galois field to mix the columns of the state */
static void MixColumns( state_t state )
{
    uint8_t C[4], i;
    for (i = 0; i < Nb; ++i)     /*-> https://crypto.stackexchange.com/q/2402 */
    {
        COPYDWORD( state[i], C[0] );
        C[3] ^= C[1];
        C[1] ^= C[0];
        C[0] ^= C[2];
        C[2]  = xtime( C[0] );
        C[0] ^= xtime( C[1] );
        C[1]  = xtime( C[3] );

        state[i][0] ^= C[0] ^= C[3];
        state[i][1] ^= C[0] ^= C[2];
        state[i][2] ^= C[0] ^= C[1];
        state[i][3] ^= C[0] ^= C[2];
    }
}

/** Encrypt a plaintext input block and save the result/ciphertext as output. */
static void rijndaelEncrypt( const block_t input, block_t output )
{
    uint8_t r;
    state_t* mat = (void*) output;

    /* copy plaintext into the state matrix, and beware of undefined behavior */
    if (input != output)   memcpy( mat, input, BLOCKSIZE );

    /* The encryption is carried out in #ROUNDS iterations, of which the first
     * #ROUNDS-1 are identical. The last round doesn't involve mixing columns */
    for (r = 0; r != ROUNDS; )
    {
        AddRoundKey( r, output );
        SubBytes( output );
        ShiftRows( *mat );
        ++r != ROUNDS ? MixColumns( *mat ) : AddRoundKey( ROUNDS, output );
    }
}

/*----------------------------------------------------------------------------*\
                Block-decryption part of the Rijndael algorithm
\*----------------------------------------------------------------------------*/

#if IMPLEMENT(DECRYPTION)

/** Substitutes the values in state matrix with values of the inverted S-box. */
static void InvSubBytes( block_t state )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        state[i] = InvSBoxValue( state[i] );
    }
}

/** This function shifts (i.e rotates) the rows of the state matrix to right. */
static void InvShiftRows( state_t state )
{
    uint8_t tmp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = tmp;           /* the first row rotates 1 columns to right, */

    tmp         = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = tmp;
    tmp         = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = tmp;           /* the second row rotates 2 columns to right */

    tmp         = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = tmp;           /* the third row rotates 3 columns to right. */
}

/** Reverse the process of mixing columns by matrix multiplication in GF(2^8) */
static void InvMixColumns( state_t state )
{
    uint8_t C[4], i;
    for (i = 0; i < Nb; ++i)     /*-> https://crypto.stackexchange.com/q/2569 */
    {
        COPYDWORD( state[i], C[0] );
        state[i][0] = mixG8( C[0], C[1], C[2], C[3] );
        state[i][1] = mixG8( C[1], C[2], C[3], C[0] );
        state[i][2] = mixG8( C[2], C[3], C[0], C[1] );
        state[i][3] = mixG8( C[3], C[0], C[1], C[2] );
    }
}

/** Decrypt a ciphertext input block and save the result/plaintext to output. */
static void rijndaelDecrypt( const block_t input, block_t output )
{
    uint8_t r;
    state_t* mat = (void*) output;

    /* copy input to the state matrix, i.e initialize the state by ciphertext */
    if (input != output)   memcpy( mat, input, BLOCKSIZE );

    /* Decryption is carried out in #ROUNDS iterations. The rounds are similar
     * except for the first one which doesn't involve [reverse]mixing columns */
    for (r = ROUNDS; r != 0; )
    {
        r-- != ROUNDS ? InvMixColumns( *mat ) : AddRoundKey( ROUNDS, output );
        InvShiftRows( *mat );
        InvSubBytes( output );
        AddRoundKey( r, output );
    }
}
#endif /* DECRYPTION */

#if MICRO_RJNDL
/**
 * @brief   encrypt or decrypt a single block with a given key
 * @param   key       a byte array with a fixed size of KEYSIZE
 * @param   mode      mode of operation: 'E' (1) to encrypt, 'D' (0) to decrypt
 * @param   x         input byte array with BLOCKSIZE bytes
 * @param   y         output byte array with BLOCKSIZE bytes
 */
void AES_Cipher( const uint8_t* key, const char mode, const block_t x, block_t y )
{
    KeyExpansion( key );
    mode & 1 ? rijndaelEncrypt( x, y ) : rijndaelDecrypt( x, y );
}
#endif


/*----------------------------------------------------------------------------*\
 *              Implementation of different block ciphers modes               *
 *                     Definitions & Auxiliary Functions                      *
\*----------------------------------------------------------------------------*/

/** function-pointer types, indicating functions that take fixed-size blocks: */
typedef void (*fmix_t)( const block_t, block_t ) SDCC_REENT;
typedef void (*fdouble_t)( block_t );

#define AES_setkey(key)     KeyExpansion( key )

#if INCREASE_SECURITY
#define BURN(key)           memset( key, 0, sizeof key )
#define SABOTAGE(buf, len)  memset( buf, 0, len )
#if AEAD_MODES

/** for constant-time comparison of memory blocks, to avoid "timing attacks". */
static uint8_t memcmp_s( const void* src, const void* dest, const uint8_t len )
{
    const volatile char *p1 = src, *p2 = (const volatile char*) dest;
    volatile uint8_t result = 0;
    char i;
    for (i = 0; i != len; i++)
    {
        result |= p1[i] ^ p2[i];
    }
    return result;
}
#endif
#else
#define BURN(key)           (void)  key          /*  the line will be ignored */
#define SABOTAGE(buf, len)  (void)  buf
#define memcmp_s            memcmp
#endif

#if SMALL_CIPHER
typedef uint8_t count_t;

#define incBlock(block, index)    ++block[index]
#define xorBEint(buf, num, pos)     buf[pos - 1] ^= (num) >> 8,  buf[pos] ^= num
#define copyLint(buf, num, pos)     buf[pos + 1]  = (num) >> 8,  buf[pos]  = num

#else
typedef size_t  count_t;

#if XTS || GCM_SIV

/** copy a little endian integer to the block, with LSB at specified position */
static void copyLint( block_t block, size_t num, uint8_t pos )
{
    do
        block[pos++] = (uint8_t) num;
    while (num >>= 8);
}
#endif

#if CTR || KWA || FPE

/** xor a byte array with a big-endian integer, whose LSB is at specified pos */
static void xorBEint( uint8_t* buff, size_t num, uint8_t pos )
{
    do
        buff[pos--] ^= (uint8_t) num;
    while (num >>= 8);
}
#endif

#if CTR

/** increment the value of a 128-bit counter block, regarding its endian-ness */
static void incBlock( block_t block, uint8_t index )
{
    do                                           /*  increment the LSBs,      */
        if (++block[index])                      /*  ..until no overflow      */
            break;
    while ((index < 4 && ++index < 4) || --index > 8);
}
#endif
#endif /* SMALL CIPHER */

#if EAX && !EAXP || SIV || OCB || CMAC

/** Multiply a block by two in Galois bit field GF(2^128): big-endian version */
static void doubleBblock( block_t array )
{
    int c = 0, i;
    for (i = BLOCKSIZE; i > 0; c >>= 8)          /* from last byte (LSB) to   */
    {                                            /* first: left-shift, then   */
        c |= array[--i] << 1;                    /* append the previous MSBit */
        array[i] = (uint8_t) c;
    }                                            /* if first MSBit is carried */
    array[LAST] ^= c * 0x87;                     /* .. A ^= 10000111b (B.E.)  */
}
#endif

#if XTS || EAXP

/** Multiply a block by two in Galois field GF(2^128): little-endian version. */
static void doubleLblock( block_t array )
{
    int i, c = 0;
    for (i = 0; i < BLOCKSIZE; c >>= 8)          /* the same as doubleBblock  */
    {                                            /* ..but with reversed bytes */
        c |= array[i] << 1;
        array[i++] = (uint8_t) c;
    }
    array[0] ^= c * 0x87;                        /*    A ^= 10000111b (L.E.)  */
}
#endif

#if GCM

/** Divide a 128-bit big-endian integer by two in Galois bit field GF(2^128). */
static void divideBblock( block_t array )
{
    unsigned i, c = 0;
    for (i = 0; i < BLOCKSIZE; ++i)              /* from first to last byte,  */
    {                                            /*  prepend the previous LSB */
        c = c << 8 | array[i];                   /*  then shift it to right.  */
        array[i] = c >> 1;
    }                                            /* if block is odd (LSB = 1) */
    if (c & 1)  array[0] ^= 0xe1;                /* .. A ^= 11100001b << 120  */
}

/** Multiply two 128-bit numbers (big-endian blocks) in the Galois bit field. */
static void mulGF128( const block_t x, block_t y )
{
    uint8_t b, i;
    block_t result = { 0 };                      /*  working memory           */

    for (i = 0; i < BLOCKSIZE; ++i)
    {
        for (b = 0x80; b; b >>= 1)               /*  check all the bits of X, */
        {
            if (x[i] & b)                        /*  ..and if any bit is set, */
            {
                xorBlock( y, result );           /*  ..add Y to the result    */
            }
            divideBblock( y );                   /*  Y_next = (Y / 2) in GF   */
        }
    }
    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* GCM */

#if GCM_SIV

/** Divide a block by two in 128-bit Galois field: the little-endian version. */
static void divideLblock( block_t array )
{
    unsigned c = 0, i;
    for (i = BLOCKSIZE; i--; )                   /* similar to divideBblock ↑ */
    {                                            /* ..but with reversed bytes */
        c = c << 8 | array[i];
        array[i] = c >> 1;
    }
    if (c & 1)  array[LAST] ^= 0xe1;             /* (L.E) A ^= 11100001b<<120 */
}

/** The so-called "dot multiplying" in GF(2^128), used in POLYVAL calculation */
static void dotGF128( const block_t x, block_t y )
{
    uint8_t b, i;
    block_t result = { 0 };

    for (i = BLOCKSIZE; i--; )
    {
        for (b = 0x80; b; b >>= 1)               /*  pretty much the same as  */
        {                                        /*  ..(reversed) mulGF128    */
            divideLblock( y );
            if (x[i] & b)
            {
                xorBlock( y, result );
            }
        }
    }
    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* GCM-SIV */

#if CTR || CFB || OFB || CTS || OCB

/** mix/cipher the block B and then xor the result with n bytes of X to get Y */
static void mixThenXor( fmix_t mix, const block_t B, block_t f,
                        const uint8_t* X, uint8_t n, uint8_t* Y )
{
    if (n == 0)  return;

    mix( B, f );                                 /*  Y = f(B) ^ X             */
    while (n--)
    {
        Y[n] = f[n] ^ X[n];
    }
}
#endif

#if AEAD_MODES || FPE

/** xor the result with input data and then apply the digest/mixing function.
 * repeat this process for each block of data, until all blocks are digested. */
static void xMac( const void* data, const size_t dataSize,
                  const block_t seed, fmix_t mix, block_t result )
{
    uint8_t const* x;
    count_t n = dataSize / BLOCKSIZE;            /*   number of full blocks   */

    for (x = data; n--; x += BLOCKSIZE)
    {
        xorBlock( x, result );                   /* M_next = mix(seed, M ^ X) */
        mix( seed, result );
    }
    if ((n = dataSize % BLOCKSIZE) > 0)          /* if any partial block left */
    {
        while (n--)
        {
            result[n] ^= x[n];
        }
        mix( seed, result );
    }
}
#endif

#if CMAC || SIV || EAX || OCB

/** calculate CMAC of input data using pre-calculated keys: K1 (D) and K2 (Q) */
static void cMac( const block_t K1, const block_t K2,
                  const void* data, const size_t dataSize, block_t mac )
{
    const uint8_t s = dataSize ? (dataSize - 1) % BLOCKSIZE + 1 : 0;
    const uint8_t *k = K1, *ps = s ? (uint8_t*) data + dataSize - s : &s;

    xMac( data, dataSize - s, mac, &rijndaelEncrypt, mac );
    if (s < BLOCKSIZE)
    {
        mac[s] ^= 0x80;                          /*  pad( M_last; K1, K2 )    */
        k = K2;
    }
    xorBlock( k, mac );
    xMac( ps, s + !s, mac, &rijndaelEncrypt, mac );
}

/** calculate key-dependent constants D and Q using a given doubling function */
static void getSubkeys( fdouble_t gfdouble, const char quad,
                        const uint8_t* key, block_t D, block_t Q )
{
    AES_setkey( key );
    rijndaelEncrypt( D, D );                     /*  H or L_* = Enc(zeros)    */
    if (quad)
    {
        gfdouble( D );                           /*  D or L_$ = double(L_*)   */
    }
    memcpy( Q, D, BLOCKSIZE );
    gfdouble( Q );                               /*  Q or L_0 = double(L_$)   */
}
#endif

#ifdef AES_PADDING

/** in ECB mode & CBC without CTS, the last (partial) block has to be padded. */
static char padBlock( const uint8_t len, block_t block )
{
    uint8_t n = BLOCKSIZE - len, *p = &block[len];

#if AES_PADDING
    memset( p, n * (AES_PADDING != 2), n );
    *p ^= (0x80) * (AES_PADDING == 2);           /* either PKCS#7 / IEC7816-4 */
#else
    memset( p, 0, n % BLOCKSIZE );               /* default (zero) padding    */
#endif
    return len || AES_PADDING;
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
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t* y;
    count_t n = ptextLen / BLOCKSIZE;            /*  number of full blocks    */
    memcpy( crtxt, pntxt, ptextLen );            /*  copy plaintext to output */

    AES_setkey( key );
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
 * @return            error if the ciphertext has a partial block
 */
char AES_ECB_decrypt( const uint8_t* key,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t* y;
    count_t n = crtxtLen / BLOCKSIZE;
    memcpy( pntxt, crtxt, crtxtLen );            /*  do in-place decryption   */

    AES_setkey( key );
    for (y = pntxt; n--; y += BLOCKSIZE)
    {
        rijndaelDecrypt( y, y );                 /*  P = Dec(C)               */
    }
    BURN( RoundKey );

    /* if padding is enabled, check whether the result is properly padded. error
     * must be thrown if it's not. here we skip that and just check the size. */
    return crtxtLen % BLOCKSIZE ? M_DECRYPTION_ERROR : M_RESULT_SUCCESS;
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
 * @return            error in CTS mode, if plaintext is a single partial block
 */
char AES_CBC_encrypt( const uint8_t* key, const block_t iVec,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t const* iv = iVec;
    uint8_t r = ptextLen % BLOCKSIZE, *y;
    count_t n = ptextLen / BLOCKSIZE;

#if CTS
    if (n > 1 && !r && --n)  r = BLOCKSIZE;      /*  CS3 ciphertext stealing  */

    if (n == 0)  return M_DATALENGTH_ERROR;      /*  data size >= BLOCKSIZE   */
#endif
    memcpy( crtxt, pntxt, ptextLen );            /*  do in-place encryption   */

    AES_setkey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        xorBlock( iv, y );                       /*  C = Enc(IV ^ P)          */
        rijndaelEncrypt( y, y );                 /*  IV_next = C              */
        iv = y;
    }
#if CTS
    if (r)
    {
        block_t L = { 0 };
        memcpy( L, y, r );                       /*  backup the last chunk    */
        memcpy( y, y - BLOCKSIZE, r );           /*  'steal' the cipher-text  */
        y -= BLOCKSIZE;                          /*  ..to fill the last chunk */
        iv = L;
#else
    if (padBlock( r, y ))
    {
#endif
        xorBlock( iv, y );
        rijndaelEncrypt( y, y );
    }
    BURN( RoundKey );
    return M_RESULT_SUCCESS;
}

/**
 * @brief   decrypt the input ciphertext using CBC-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   iVec      initialization vector
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 * @return            error if the size of ciphertext is not a valid value
 */
char AES_CBC_decrypt( const uint8_t* key, const block_t iVec,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t const *x = crtxt, *iv = iVec;
    uint8_t r = crtxtLen % BLOCKSIZE, *y;
    count_t n = crtxtLen / BLOCKSIZE;

#if CTS
    if (n > 1 && !r && --n)  r = BLOCKSIZE;

    if (n == 0)  return M_DATALENGTH_ERROR;
#else
    if (r != 0)  return M_DATALENGTH_ERROR;
#endif
    n -= r > 0;                                  /* hold last 2 blocks in CTS */

    AES_setkey( key );
    for (y = pntxt; n--; y += BLOCKSIZE)
    {
        rijndaelDecrypt( x, y );                 /*  P = Dec(C) ^ IV          */
        xorBlock( iv, y );                       /*  IV_next = C              */
        iv = x;
        x += BLOCKSIZE;
#if CTS
    }
    if (r)
    {                                            /*  last two blocks: {X, Z}  */
        const uint8_t* z = x + BLOCKSIZE;
        mixThenXor( &rijndaelDecrypt, x, y, z, r, y + BLOCKSIZE );
        memcpy( y, z, r );
        rijndaelDecrypt( y, y );                 /*  P2 = Z ^ Dec(X) = Z ^ Y  */
        xorBlock( iv, y );                       /*  P1 = IV ^ Dec(Z | *Y)    */
#endif
    }
    BURN( RoundKey );
    return M_RESULT_SUCCESS;
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
static void CFB_cipher( const uint8_t* key, const block_t iVec, const char mode,
                        const void* input, const size_t dataSize, void* output )
{
    uint8_t const *iv = iVec, *x = input;
    uint8_t* y;
    block_t tmp;
    count_t n = dataSize / BLOCKSIZE;            /*  number of full blocks    */

    AES_setkey( key );
    for (y = output; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( iv, y );                /*  both in en[de]cryption:  */
        xorBlock( x, y );                        /*  Y = Enc(IV) ^ X          */
        iv = mode ? y : x;                       /*  IV_next = Ciphertext     */
        x += BLOCKSIZE;
    }
    mixThenXor( &rijndaelEncrypt, iv, tmp, x, dataSize % BLOCKSIZE, y );
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
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    CFB_cipher( key, iVec, 1, pntxt, ptextLen, crtxt );
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
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    CFB_cipher( key, iVec, 0, crtxt, crtxtLen, pntxt );
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
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    count_t n = ptextLen / BLOCKSIZE;
    uint8_t* y;
    block_t iv;

    memcpy( iv, iVec, sizeof iv );
    memcpy( crtxt, pntxt, ptextLen );            /*  i.e. in-place encryption */

    AES_setkey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( iv, iv );               /*  IV_next = Enc(IV)        */
        xorBlock( iv, y );                       /*  C = IV_next ^ P          */
    }
    mixThenXor( &rijndaelEncrypt, iv, iv, y, ptextLen % BLOCKSIZE, y );
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
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    AES_OFB_encrypt( key, iVec, crtxt, crtxtLen, pntxt );
}
#endif /* OFB */


/*----------------------------------------------------------------------------*\
    Parallelizable, counter-based modes of AES: demonstrating the main idea
               + How to use it in a simple, non-authenticated API
\*----------------------------------------------------------------------------*/
#if CTR

enum ctr_based_modes
{
    CTR_DEFAULT,
    SIV_CTR    = 5,                              /*  RFC-5297                 */
    SIVGCM_CTR = 8,                              /*  RFC-8452 (GCM-SIV)       */
    CCM_GCM    = 2                               /*  either CCM or GCM        */
};

/**
 * @brief   the general scheme of operation in block-counter mode
 * @param   iCtr      initialized counter block
 * @param   mode      specifies the "counter based" block-cipher or AEAD mode
 * @param   input     buffer of the input plain/cipher-text
 * @param   dataSize  size of input in bytes
 * @param   output    buffer of the resulting cipher/plain-text
 */
static void CTR_cipher( const block_t iCtr, const char mode,
                        const void* input, const size_t dataSize, void* output )
{
    block_t c, enc;
    count_t n = dataSize / BLOCKSIZE;
    uint8_t index = LAST, *y;

    memcpy( output, input, dataSize );           /* do in-place en/decryption */
    memcpy( c, iCtr, sizeof c );

    switch (mode)
    {
    case SIV_CTR:
        c[+8] &= 0x7F;                           /*  clear 2 bits in SIV mode */
        c[12] &= 0x7F;
        break;
    case SIVGCM_CTR:
        c[LAST] |= 0x80;                         /*  set 1 bit of L.E counter */
        index = 0;
        break;
    case CCM_GCM:
        incBlock( c, index );                    /*  pre-increment in CCM/GCM */
        break;
    }
    for (y = output; n--; y += BLOCKSIZE)
    {
        rijndaelEncrypt( c, enc );               /*  both in en[de]cryption:  */
        xorBlock( enc, y );                      /*  Y = Enc(Ctr) ^ X         */
        incBlock( c, index );                    /*  Ctr_next = Ctr + 1       */
    }
    mixThenXor( &rijndaelEncrypt, c, c, y, dataSize % BLOCKSIZE, y );
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
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
#if PRESET_COUNTER
    uint8_t const* ctr = iv;                     /*  block is pre-initialized */
#else
    block_t ctr = { 0 };
    memcpy( ctr, iv, CTR_IV_LENGTH );

    xorBEint( ctr, CTR_START_VALUE, LAST );      /*  initialize the counter   */
#endif
    AES_setkey( key );
    CTR_cipher( ctr, CTR_DEFAULT, pntxt, ptextLen, crtxt );
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
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    AES_CTR_encrypt( key, iv, crtxt, crtxtLen, pntxt );
}
#endif /* CTR */


/*----------------------------------------------------------------------------*\
             XEX-AES based modes (xor-encrypt-xor): the basic idea
  + main functions of XTS-AES (XEX Tweaked-codebook with ciphertext Stealing)
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(XTS)
/**
 * @brief   encrypt or decrypt a data unit with XTS method
 * @param   keypair   pair of encryption keys, each one has KEYSIZE bytes
 * @param   mode      mode of operation: encrypting (1) or decrypting (0)
 * @param   tweak     data unit identifier block, similar to nonce in CTR mode
 * @param   sectid    sector id: in case of a null tweak, use this instead
 * @param   dataSize  size of input data, to be encrypted/decrypted
 * @param   storage   result of encryption/decryption process
 */
static void XTS_cipher( const uint8_t* keypair, const char mode,
                        const block_t tweak, const size_t sectid,
                        const size_t dataSize, void* storage )
{
    fmix_t cipher = mode ? &rijndaelEncrypt : &rijndaelDecrypt;
    uint8_t r = dataSize % BLOCKSIZE, *y;
    count_t n = dataSize / BLOCKSIZE - (r > 0);
    block_t T;

    if (tweak == NULL)
    {                                            /* the `i` block is either   */
        memset( T, 0, sizeof T );                /* ..a little-endian number  */
        copyLint( T, sectid, 0 );                /* ..or a byte array (tweak) */
    }
    else
    {
        memcpy( T, tweak, sizeof T );
    }
    AES_setkey( keypair + KEYSIZE );             /* T = encrypt `i` with key2 */
    rijndaelEncrypt( T, T );

    AES_setkey( keypair );                       /*  now key1 is cipher key   */
    for (y = storage; n--; y += BLOCKSIZE)
    {                                            /*  XEX: xor-encrypt-xor     */
        xorBlock( T, y );
        cipher( y, y );
        xorBlock( T, y );                        /*  Y = T ^ Cipher( T ^ X )  */
        doubleLblock( T );                       /*  T_next = alpha · T       */
    }
    if (r)
    {                                            /*  XTS: ciphertext stealing */
        block_t L;
        memcpy( L, T, sizeof L );
        doubleLblock( mode ? T : L );            /*  T = α·L   or   L = α·T   */

        xorBlock( L, y );
        cipher( y, y );
        xorBlock( L, y );
        memcpy( L, y, sizeof L );
        memcpy( y, y + BLOCKSIZE, r );           /* 'steal' the cipher-text   */
        memcpy( y + BLOCKSIZE, L, r );           /*  ..to fill the last chunk */

        xorBlock( T, y );
        cipher( y, y );                          /*  encrypt or decrypt the   */
        xorBlock( T, y );                        /*  ..block we stole from    */
    }
    BURN( RoundKey );
}

/**
 * @brief   encrypt the input plaintext using XTS-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   tweak     tweak bytes of data unit, a.k.a sector ID (little-endian)
 * @param   pntxt     input plaintext buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer
 * @return            error if plaintext is a single partial block
 */
char AES_XTS_encrypt( const uint8_t* keys, const uint8_t* tweak,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    if (ptextLen < BLOCKSIZE)  return M_DATALENGTH_ERROR;

    memcpy( crtxt, pntxt, ptextLen );            /*  do in-place encryption   */
    XTS_cipher( keys, 1, tweak, 0, ptextLen, crtxt );
    return M_RESULT_SUCCESS;
}

/**
 * @brief   encrypt the input ciphertext using XTS-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   tweak     tweak bytes of data unit, a.k.a sector ID (little-endian)
 * @param   crtxt     input ciphertext buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 * @return            error if ciphertext is a single partial block
 */
char AES_XTS_decrypt( const uint8_t* keys, const uint8_t* tweak,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    if (crtxtLen < BLOCKSIZE)  return M_DATALENGTH_ERROR;

    memcpy( pntxt, crtxt, crtxtLen );            /*  in-place decryption      */
    XTS_cipher( keys, 0, tweak, 0, crtxtLen, pntxt );
    return M_RESULT_SUCCESS;
}
#endif /* XTS */


/*----------------------------------------------------------------------------*\
       CMAC-AES (cipher-based message authentication code): main function
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CMAC)
/**
 * @brief   derive the AES-CMAC of input data using an encryption key
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

    getSubkeys( &doubleBblock, 1, key, K1, K2 );
    cMac( K1, K2, data, dataSize, mac );
    BURN( RoundKey );
}
#endif /* CMAC */


/*----------------------------------------------------------------------------*\
    GCM-AES (Galois counter mode): authentication with GMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM)

/** calculate G-Hash of ciphertext and AAD using an authentication subkey `H` */
static void gHash( const block_t H, const void* aData, const void* crtxt,
                   const size_t aDataLen, const size_t crtxtLen, block_t gh )
{
    block_t len = { 0 };
    xorBEint( len, aDataLen * 8, MIDST );
    xorBEint( len, crtxtLen * 8, LAST );         /*  save bit-sizes into len  */

    xMac( aData, aDataLen, H, &mulGF128, gh );   /*  first digest AAD, then   */
    xMac( crtxt, crtxtLen, H, &mulGF128, gh );   /*  ..ciphertext, and then   */
    xMac( len, sizeof len, H, &mulGF128, gh );   /*  ..bit sizes into GHash   */
}

/** encrypt zeros to get authentication subkey H, and prepare the IV for GCM. */
static void GCMsetup( const uint8_t* key,
                      const uint8_t* nonce, block_t auKey, block_t iv )
{
    AES_setkey( key );
    rijndaelEncrypt( auKey, auKey );             /* auKey = Enc( zero block ) */
    if (GCM_NONCE_LEN != 12)
    {
        gHash( auKey, NULL, nonce, 0, GCM_NONCE_LEN, iv );
        return;
    }
    memcpy( iv, nonce, 12 );
    iv[LAST] = 1;
}

/**
 * @brief   encrypt the input plaintext using GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: GCM_NONCE_LEN
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer + message authentication tag
 */
void AES_GCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t* tag = (uint8_t*) crtxt + ptextLen;
    block_t iv = { 0 }, H = { 0 }, G = { 0 };

    GCMsetup( key, nonce, H, iv );               /*  get IV & auth. subkey H  */
    CTR_cipher( iv, CCM_GCM, pntxt, ptextLen, crtxt );
    rijndaelEncrypt( iv, iv );
    BURN( RoundKey );

    gHash( H, aData, crtxt, aDataLen, ptextLen, G );
    xorBlock( iv, G );
    memcpy( tag, G, GCM_TAG_LEN );               /*  GMAC = Enc(iv) ^ G-HASH  */
}

/**
 * @brief   decrypt the input ciphertext using GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: GCM_NONCE_LEN
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message authentication/decryption was successful
 */
char AES_GCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t const* tag = (uint8_t*) crtxt + crtxtLen;
    block_t H = { 0 }, iv = { 0 }, G = { 0 };

    GCMsetup( key, nonce, H, iv );
    gHash( H, aData, crtxt, aDataLen, crtxtLen, G );
    rijndaelEncrypt( iv, H );
    xorBlock( H, G );                            /*  tag = Enc(iv) ^ G-HASH   */

    if (memcmp_s( tag, G, GCM_TAG_LEN ))
    {                                            /*  compare tags and         */
        BURN( RoundKey );                        /*  ..proceed if they match  */
        return M_AUTHENTICATION_ERROR;
    }
    CTR_cipher( iv, CCM_GCM, crtxt, crtxtLen, pntxt );
    BURN( RoundKey );
    return M_RESULT_SUCCESS;
}
#endif /* GCM */


/*----------------------------------------------------------------------------*\
    CCM-AES (counter with CBC-MAC): CBC-MAC authentication & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(CCM)

/** this function calculates the CBC-MAC of plaintext and authentication data */
static void CCMtag( const block_t iv, const void* aData, const void* pntxt,
                    const size_t aDataLen, const size_t ptextLen, block_t M )
{
    block_t A = { 0 };
    uint8_t p = 1, s = 0;

    memcpy( M, iv, BLOCKSIZE );                  /*  initialize CBC-MAC       */
    M[0] |= (CCM_TAG_LEN - 2) << 2;              /*  set some flags on M_*    */
    xorBEint( M, ptextLen, LAST );               /*  copy data size into M_*  */

    if (aDataLen)                                /*  construct the 'A' block  */
    {
        M[0] |= 0x40;
        rijndaelEncrypt( M, M );                 /*  flag M_* and encrypt it  */
        if (aDataLen > 0xFEFFL)
        {                                        /*  assuming aDataLen < 2^32 */
            p += 4;
            A[0] = 0xFF,  A[1] = 0xFE;           /*  prepend FFFE to aDataLen */
        }
        xorBEint( A, aDataLen, p );              /*  copy aDataLen into A     */
        s = sizeof A - ++p;
        memcpy( A + p, aData, aDataLen < s ? aDataLen : s );
    }

    /* digest the first s bytes of aData, the rest of it, and then plaintext: */
    xMac( A, sizeof A, M, &rijndaelEncrypt, M );
    if (aDataLen > s)
    {
        xMac( (char*) aData + s, aDataLen - s, M, &rijndaelEncrypt, M );
    }
    xMac( pntxt, ptextLen, M, &rijndaelEncrypt, M );

    rijndaelEncrypt( iv, A );                    /*  tag = Enc(iv) ^ CBCMac   */
    xorBlock( A, M );
}

/**
 * @brief   encrypt the input plaintext using CCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: CCM_NONCE_LEN
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer + message authentication tag
 */
void AES_CCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    uint8_t* tag = (uint8_t*) crtxt + ptextLen;
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, C;

    memcpy( iv + 1, nonce, CCM_NONCE_LEN );
    AES_setkey( key );
    CCMtag( iv, aData, pntxt, aDataLen, ptextLen, C );
    CTR_cipher( iv, CCM_GCM, pntxt, ptextLen, crtxt );
    BURN( RoundKey );

    memcpy( tag, C, CCM_TAG_LEN );
}

/**
 * @brief   decrypt the input ciphertext using CCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: CCM_NONCE_LEN
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message decryption/authentication was successful
 */
char AES_CCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    uint8_t const* tag = (uint8_t*) crtxt + crtxtLen;
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, C;

    memcpy( iv + 1, nonce, CCM_NONCE_LEN );
    AES_setkey( key );
    CTR_cipher( iv, CCM_GCM, crtxt, crtxtLen, pntxt );
    CCMtag( iv, aData, pntxt, aDataLen, crtxtLen, C );
    BURN( RoundKey );

    if (memcmp_s( tag, C, CCM_TAG_LEN ))
    {
        SABOTAGE( pntxt, crtxtLen );             /*  invalid tag: clear pntxt */
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
#endif /* CCM */


/*----------------------------------------------------------------------------*\
       SIV-AES (synthetic init-vector): nonce synthesis & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(SIV)

/** calculate the CMAC* of AAD unit(s), then plaintext, and synthesize the IV */
static void S2V( const uint8_t* key, const void* aData, const void* pntxt,
                 const size_t aDataLen, const size_t ptextLen, block_t IV )
{
    block_t K[2] = { { 0 } }, Y;
    uint8_t r, *Q = K[1];

    memcpy( IV, *K, BLOCKSIZE );                 /*  initialize/clear IV      */
    getSubkeys( &doubleBblock, 1, key, *K, Q );
    rijndaelEncrypt( *K, Y );                    /*  Y_0 = CMAC(zero block)   */

    /* in case of multiple AAD units, each one must be handled in a similar way.
     * for example, let aData be a 2-D array and aDataLen a null-terminated one.
     * then instead of `if (aDataLen) { cMac(*K, Q, aData, aDataLen, IV)` write:
     * for (r = 0; *aDataLen; ) { cMac( *K, Q, aData[r++], *aDataLen++, IV ); */
    if (aDataLen)
    {
        cMac( *K, Q, aData, aDataLen, IV );
        doubleBblock( Y );                       /*  Y_$ = double( Y_{i-1} )  */
        xorBlock( IV, Y );                       /*  Y_i = Y_$ ^ CMAC(AAD_i)  */
        memset( IV, 0, BLOCKSIZE );
    }
    if (ptextLen < sizeof Y)
    {                                            /*  for short messages:      */
        doubleBblock( Y );                       /*  Y = double( Y_n )        */
        r = 0;
    }
    else if ((r = ptextLen % sizeof Y) > 0)
    {
        memset( *K, 0, BLOCKSIZE );
    }
    xorBlock( Y, *K + r );
    cMac( *K, *K, pntxt, ptextLen - r, IV );     /*  CMAC*( Y xor_end MSG )   */

    if (r == 0)  return;

    cMac( NULL, Q, (char*) pntxt + ptextLen - r, r, IV );
}

/**
 * @brief   encrypt the input plaintext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   iv        synthesized I.V block, typically prepended to ciphertext
 * @param   crtxt     resulting cipher-text buffer
 */
void AES_SIV_encrypt( const uint8_t* keys,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen,
                      block_t iv, void* crtxt )
{
    S2V( keys, aData, pntxt, aDataLen, ptextLen, iv );
    AES_setkey( keys + KEYSIZE );
    CTR_cipher( iv, SIV_CTR, pntxt, ptextLen, crtxt );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using SIV-AES block-cipher method
 * @param   keys      two-part encryption key with a fixed size of 2*KEYSIZE
 * @param   iv        provided I.V block to validate
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     input cipher-text buffer
 * @param   crtxtLen  size of ciphertext in bytes
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message decryption/authentication was successful
 */
char AES_SIV_decrypt( const uint8_t* keys, const block_t iv,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t IV;
    AES_setkey( keys + KEYSIZE );
    CTR_cipher( iv, SIV_CTR, crtxt, crtxtLen, pntxt );
    S2V( keys, aData, pntxt, aDataLen, crtxtLen, IV );
    BURN( RoundKey );

    if (memcmp_s( IV, iv, sizeof IV ))           /* verify the synthesized IV */
    {
        SABOTAGE( pntxt, crtxtLen );
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
#endif /* SIV */


/*----------------------------------------------------------------------------*\
              SIV-GCM-AES (Galois counter mode with synthetic i.v)
          authentication & i.v synthesis with polyval + main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM_SIV)

/** calculate the POLYVAL of plaintext and AAD using authentication subkey H. */
static void polyval( const block_t H, const void* aData, const void* pntxt,
                     const size_t aDataLen, const size_t ptextLen, block_t pv )
{
    block_t len = { 0 };                         /*  save bit-sizes into len  */
    copyLint( len, aDataLen * 8, 0 );
    copyLint( len, ptextLen * 8, HB );

    xMac( aData, aDataLen, H, &dotGF128, pv );   /*  first digest AAD, then   */
    xMac( pntxt, ptextLen, H, &dotGF128, pv );   /*  ..plaintext, and then    */
    xMac( len, sizeof len, H, &dotGF128, pv );   /*  ..bit sizes into POLYVAL */
}

/** derive the pair of authentication-encryption-keys from main key and nonce */
static void GCM_SIVsetup( const uint8_t* key, const uint8_t* nonce, block_t AK )
{
    uint8_t iv[5 * HB + KEYSIZE], *h, *k;
    k = h = iv + BLOCKSIZE;
    memcpy( iv + 4, nonce, SIVGCM_NONCE_LEN );

    AES_setkey( key );
    for (*(int32_t*) iv = 0; *iv < 2 + Nk / 2; ++*iv)
    {
        rijndaelEncrypt( iv, k );                /* encrypt & take half, then */
        k += HB;                                 /* ..increment iv's LSB      */
    }
    AES_setkey( k - KEYSIZE );                   /*  set the main cipher-key  */
    memcpy( AK, h, BLOCKSIZE );                  /*  take authentication key  */
}

/** get the tag in GCM-SIV mode, given the nonce and calculated POLYVAL block */
static void GCM_SIVtag( const uint8_t* nonce, block_t pv, block_t tag )
{
    XOR32BITS( nonce[0], pv[0] );
    XOR32BITS( nonce[4], pv[4] );                /*  xor POLYVAL with nonce   */
    XOR32BITS( nonce[8], pv[8] );
    pv[LAST] &= 0x7F;                            /*  clear one bit & encrypt, */
    rijndaelEncrypt( pv, tag );
}

/**
 * @brief   encrypt the input plaintext using SIV-GCM-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     provided 96-bit nonce
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer + message authentication tag
 */
void GCM_SIV_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    block_t P = { 0 };
    uint8_t *H, *tag = (uint8_t*) crtxt + ptextLen;

    H = tag;                                     /* use a pre-allocated space */
    GCM_SIVsetup( key, nonce, H );
    polyval( H, aData, pntxt, aDataLen, ptextLen, P );
    GCM_SIVtag( nonce, P, tag );
    CTR_cipher( tag, SIVGCM_CTR, pntxt, ptextLen, crtxt );
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using SIV-GCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     provided 96-bit nonce
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message decryption/authentication was successful
 */
char GCM_SIV_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t H, P = { 0 };
    uint8_t const* tag = (uint8_t*) crtxt + crtxtLen;

    GCM_SIVsetup( key, nonce, H );               /* get authentication subkey */
    CTR_cipher( tag, SIVGCM_CTR, crtxt, crtxtLen, pntxt );
    polyval( H, aData, pntxt, aDataLen, crtxtLen, P );
    GCM_SIVtag( nonce, P, P );
    BURN( RoundKey );

    if (memcmp_s( tag, P, SIVGCM_TAG_LEN ))
    {                                            /*  tag verification failed  */
        SABOTAGE( pntxt, crtxtLen );
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
#endif /* GCM-SIV */


/*----------------------------------------------------------------------------*\
   EAX-AES (encrypt-then-authenticate-then-translate): OMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(EAX)
#if EAXP
#define GFDOUBLE  doubleLblock
#else
#define GFDOUBLE  doubleBblock
#define nonceLen  EAX_NONCE_LEN
#endif

/** this function calculates the OMAC of a data array using D (K1) and Q (K2) */
static void oMac( const uint8_t t, const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
#if EAXP
    if (!dataSize && t)
    {
        memset( mac, 0, BLOCKSIZE );
        return;                                  /* ignoring null ciphertext  */
    }
    memcpy( mac, t ? Q : D, BLOCKSIZE );
#else
    dataSize ? memset( mac, 0, BLOCKSIZE ) : memcpy( mac, D, BLOCKSIZE );

    mac[LAST] ^= t;
    rijndaelEncrypt( mac, mac );

    if (dataSize == 0)  return;                  /* then OMAC = CMAC( [t]_n ) */
#endif
    cMac( D, Q, data, dataSize, mac );
}

/**
 * @brief   encrypt the input plaintext using EAX-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     initialization vector with EAX_NONCE_LEN bytes unless EAX'
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data; for EAX only, not EAX'
 * @param   aDataLen  size of additional authentication data
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     ciphertext result + auth. tag (4 bytes mac in EAX')
 */
void AES_EAX_encrypt( const uint8_t* key, const uint8_t* nonce,
#if EAXP
                      const size_t nonceLen,
#else
                      const void* aData, const size_t aDataLen,
#endif
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    block_t D = { 0 }, Q, mac;
#if !EAXP
    block_t tag;
#endif
    uint8_t* auth = (uint8_t*) crtxt + ptextLen;

    getSubkeys( &GFDOUBLE, 1, key, D, Q );
    oMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = OMAC(0; nonce)       */
#if EAXP
    COPYDWORD( mac[12], *auth );
    mac[12] &= 0x7F;                             /*  clear 2 bits to get N'   */
    mac[14] &= 0x7F;
#endif
    CTR_cipher( mac, CTR_DEFAULT, pntxt, ptextLen, crtxt );

#if EAXP
    oMac( 2, D, Q, crtxt, ptextLen, mac );       /*  C' = CMAC'( ciphertext ) */
    XOR32BITS( mac[12], *auth );                 /*  tag (mac) = N ^ C'       */
#else
    oMac( 1, D, Q, aData, aDataLen, tag );       /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );
    oMac( 2, D, Q, crtxt, ptextLen, mac );       /*  C = OMAC(2; ciphertext)  */
    xorBlock( mac, tag );                        /*  tag = N ^ H ^ C          */
    memcpy( auth, tag, EAX_TAG_LEN );
#endif
    BURN( RoundKey );
}

/**
 * @brief   decrypt the input ciphertext using EAX-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     initialization vector with EAX_NONCE_LEN bytes unless EAX'
 * @param   nonceLen  size of the nonce byte array; should be non-zero in EAX'
 * @param   aData     additional authentication data; for EAX only, not EAX'
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of cipher-text; excluding tag / 4-bytes mac in EAX'
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message authentication/decryption was successful
 */
char AES_EAX_decrypt( const uint8_t* key, const uint8_t* nonce,
#if EAXP
                      const size_t nonceLen,
#else
                      const void* aData, const size_t aDataLen,
#endif
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t D = { 0 }, Q, mac, tag;
    uint8_t const* auth = (uint8_t*) crtxt + crtxtLen;

    getSubkeys( &GFDOUBLE, 1, key, D, Q );
    oMac( 2, D, Q, crtxt, crtxtLen, tag );       /*  C = OMAC(2; ciphertext)  */
#if EAXP
    oMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = CMAC'( nonce )       */
    XOR32BITS( auth[0], tag[12] );
    XOR32BITS( mac[12], tag[12] );
    mac[12] &= 0x7F;
    mac[14] &= 0x7F;                             /*  clear 2 bits to get N'   */

    if (*(int32_t*) &tag[12] != 0)               /*  result of mac validation */
#else
    oMac( 1, D, Q, aData, aDataLen, mac );       /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );
    oMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = OMAC(0; nonce)       */
    xorBlock( mac, tag );                        /*  tag = N ^ H ^ C          */

    if (memcmp_s( auth, tag, EAX_TAG_LEN ))
#endif
    {                                            /* authenticate then decrypt */
        BURN( RoundKey );
        return M_AUTHENTICATION_ERROR;
    }
    CTR_cipher( mac, CTR_DEFAULT, crtxt, crtxtLen, pntxt );
    BURN( RoundKey );
    return M_RESULT_SUCCESS;
}
#endif /* EAX */


/*----------------------------------------------------------------------------*\
          OCB-AES (offset codebook mode): auxiliary and main functions
    + how to parallelize it by independent calculation of the offset blocks
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(OCB)

static void nop( const block_t x, block_t y ) {}

/** Calculate the offset block (Δ_i) at a specified index, given the initial Δ_0
 * and L$ blocks. This method has minimum memory usage, but it might be slow. To
 * make it faster, pre-calculate all L_{i}s (avoid doubling inside the loop). */
static void getDelta( const count_t index,
                      const block_t Ld, const block_t delta0, block_t delta )
{
    count_t mask, bit = 1;
    block_t L;                                   /*  Δ_i = Δ_{i-1} ^ L_ntz(i) */

    memcpy( L, Ld, sizeof L );                   /*  initialize L_$ and Δ     */
    memcpy( delta, delta0, BLOCKSIZE );

    while ((mask = index - bit) < index)
    {                                            /*  L_0 = double( L_$ ),     */
        doubleBblock( L );                       /*  L_k = double( L_{k-1} )  */
        mask &= bit <<= 1;
        if (!mask)
        {
            xorBlock( L, delta );
        }
    }
}

/**
 * @brief   encrypt or decrypt the data using OCB method
 * @param   key       encryption or decryption key
 * @param   nonce     byte array with a fixed size of OCB_NONCE_LEN
 * @param   ptextLen  size of input 'plain'text; will be zero in decryption
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   dataSize  size of input data, to be encrypted/decrypted
 * @param   data      result of encryption/decryption process
 * @param   tag       calculated tag from plaintext checksum, and PMAC of aData
 */
static void OCB_cipher( const uint8_t* key, const uint8_t* nonce,
                        const size_t ptextLen,
                        const void* aData, const size_t aDataLen,
                        const size_t dataSize, void* data, block_t tag )
{
    fmix_t cipher = ptextLen ? &rijndaelEncrypt : &rijndaelDecrypt;

    block_t offset[4] = { { 0 } };               /*  [L_$] [L_*] [Ktop] [Δ_n] */
    uint8_t *y;
    uint8_t *Ld = offset[0], *Ls = offset[1], *kt = offset[2], *del = offset[3];
    count_t n = nonce[OCB_NONCE_LEN - 1] % 64, i;
    uint8_t const s = 8 - n % 8, *x = kt + n / 8;

    memcpy( kt + BLOCKSIZE - OCB_NONCE_LEN, nonce, OCB_NONCE_LEN );
    kt[0 ] |= OCB_TAG_LEN << 4;
    kt[LAST - OCB_NONCE_LEN] |= 1;               /*  set one and clear last   */
    kt[LAST] &= 0xC0;                            /*  ..six bits of nonce (kt) */

    getSubkeys( &doubleBblock, 0, key, Ls, Ld );
    rijndaelEncrypt( kt, kt );                   /*  construct K_top          */
    memcpy( del, kt + 1, HB );                   /*  stretch K_top            */
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        del[i] ^= kt[i];
        kt[i] = (x[i] << 8 | x[i + 1]) >> s;     /* shift the stretched K_top */
    }

    xMac( data, ptextLen, NULL, &nop, tag );     /*  get plaintext? checksum  */
    i = 0, n = dataSize / BLOCKSIZE;

    for (y = data; i < n; y += BLOCKSIZE)
    {                                            /*  calculate Δ_i using      */
        getDelta( ++i, Ld, kt, del );            /*  ..my 'magic' algorithm   */
        xorBlock( del, y );
        cipher( y, y );
        xorBlock( del, y );                      /* Y = Δ_i ^ Cipher(Δ_i ^ X) */
    }
    if (n == 0)
    {
        del = kt;                                /*  Δ_N = Δ_0 = K_top        */
        kt = offset[3];
    }
    if ((i = dataSize % BLOCKSIZE) != 0)
    {                                            /*  Y_* = Enc(L_* ^ Δ_N) ^ X */
        tag[i] ^= 0x80;                          /*  and pad X_* or checksum  */
        xorBlock( Ls, del );
        mixThenXor( &rijndaelEncrypt, del, kt, y, i, y );
    }

    xMac( data, dataSize - ptextLen, NULL, &nop, tag );
    cMac( Ld, NULL, del, BLOCKSIZE, tag );

    /*- tag = Enc( checksum ^ Δ_* ^ L_$ ) so far. next, add "PMAC" of aData: **/
    i = 0, n = aDataLen / BLOCKSIZE;

    for (x = aData; i < n; x += BLOCKSIZE)
    {
        getDelta( ++i, Ld, x, del );
        rijndaelEncrypt( del, del );             /*  Δ = Enc( A_i ^ Δ_i )     */
        xorBlock( del, tag );                    /*  add Δ to the tag         */
    }
    if ((i = aDataLen % BLOCKSIZE) != 0)
    {
        memset( kt, 0, BLOCKSIZE );
        getDelta( n, Ld, kt, del );
        cMac( NULL, Ls, x, i, del );             /*  Δ = Enc(L_* ^ A_* ^ Δ_N) */
        xorBlock( del, tag );                    /*  add Δ to the tag         */
    }
    BURN( RoundKey );
}

/**
 * @brief   encrypt the input stream using OCB-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: OCB_NONCE_LEN
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   crtxt     resulting cipher-text buffer + message authentication tag
 */
void AES_OCB_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    block_t tag = { 0 };
    uint8_t* auth = (uint8_t*) crtxt + ptextLen;

    memcpy( crtxt, pntxt, ptextLen );            /* doing in-place encryption */
    OCB_cipher( key, nonce, ptextLen, aData, aDataLen, ptextLen, crtxt, tag );
    memcpy( auth, tag, OCB_TAG_LEN );
}

/**
 * @brief   decrypt the input stream using OCB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: OCB_NONCE_LEN
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message decryption/authentication was successful
 */
char AES_OCB_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t tag = { 0 };
    uint8_t const* auth = (uint8_t*) crtxt + crtxtLen;

    memcpy( pntxt, crtxt, crtxtLen );            /* doing in-place decryption */
    OCB_cipher( key, nonce, 0, aData, aDataLen, crtxtLen, pntxt, tag );

    if (memcmp_s( auth, tag, OCB_TAG_LEN ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
#endif /* OCB */


/*----------------------------------------------------------------------------*\
             KW-AES: Main functions for AES key-wrapping (RFC-3394)
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(KWA)
/**
 * @brief   encrypt the input secret with key-wrapping method
 * @param   kek       key-encryption-key a.k.a master key
 * @param   secret    input plaintext secret
 * @param   secretLen size of secret in bytes
 * @param   wrapped   wrapped secret, prepended with an additional half-block
 * @return            error if size is not a multiple of HB, or size < BLOCKSIZE
 */
char AES_KEY_wrap( const uint8_t* kek,
                   const void* secret, const size_t secretLen, void* wrapped )
{
    uint8_t *w = wrapped;
    uint8_t *r = w + HB, *endpoint = w + secretLen;
    block_t A;
    count_t i, n = secretLen / HB;               /*  number of semi-blocks    */

    if (n < 2 || secretLen % HB)  return M_DATALENGTH_ERROR;

    memset( A, 0xA6, HB );                       /*  initialization vector    */
    memcpy( r, secret, secretLen );              /*  in-place encryption      */
    AES_setkey( kek );

    for (i = 0, n *= 6; i++ < n; )
    {
        memcpy( A + HB, r, HB );                 /*  R  = LSB(64, A)          */
        rijndaelEncrypt( A, A );                 /*  A* = Enc( L | R )        */
        memcpy( r, A + HB, HB );                 /*  L* = MSB(64, A*) ^ i     */
        xorBEint( A, i, MIDST );
        r = (r == endpoint ? w : r) + HB;
    }
    BURN( RoundKey );

    memcpy( w, A, HB );                          /*  authentication vector    */
    return M_RESULT_SUCCESS;
}

/**
 * @brief   unwrap/decrypt a wrapped secret according to RFC-3394
 * @param   kek       key-encryption-key a.k.a master key
 * @param   wrapped   cipher-text input, the wrapped secret
 * @param   wrapLen   size of ciphertext/wrapped input in bytes
 * @param   secret    unwrapped secret, which is a half block shorter than input
 * @return            whether decrypting/unwrapping secret was successful
 */
char AES_KEY_unwrap( const uint8_t* kek,
                     const void* wrapped, const size_t wrapLen, void* secret )
{
    uint8_t const* w = wrapped;
    uint8_t *r = secret, *end = (uint8_t*) secret + wrapLen - HB;
    block_t A;
    count_t i, n = wrapLen / HB;                 /*  number of semi-blocks    */

    if (n < 0x3 || wrapLen % HB)  return M_DATALENGTH_ERROR;

    memcpy( A, w, HB );
    memcpy( r, w + HB, wrapLen - HB );           /*  in-place decryption      */
    AES_setkey( kek );

    for (--n, i = n * 6; i; --i)
    {
        r = (r == secret ? end : r) - HB;
        xorBEint( A, i, MIDST );
        memcpy( A + HB, r, HB );                 /*  L  = MSB(64, A) ^ i      */
        rijndaelDecrypt( A, A );                 /*  A* = Dec( L | R )        */
        memcpy( r, A + HB, HB );                 /*  R* = LSB(64, A*)         */
    }
    BURN( RoundKey );

    for (n = 0, i = HB; i--; )                   /*  authenticate/error-check */
    {
        n |= A[i] - 0xA6;
    }
    return n ? M_AUTHENTICATION_ERROR : M_RESULT_SUCCESS;
}
#endif /* KWA */


/*----------------------------------------------------------------------------*\
     Poly1305-AES message authentication: auxiliary functions and main API
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(POLY1305)

/** add two little-endian blocks x and y up to length len, so that: y = y + x */
static void addLblocks( const uint8_t* x, const uint8_t len, uint8_t* y )
{
    int a, i;
    for (i = a = 0; i < len; a >>= 8)
    {
        a += x[i] + y[i];
        y[i++] = (uint8_t) a;
    }
}

/** derive modulo(2^130-5) for a large integer saved in a little-endian block */
static void modP1305( uint8_t* block, int32_t q )
{
    if (q < 4)  return;                          /* q is block's MSBs: B>>128 */

    block[PL - 1] &= 3;                          /* subtract (q >> 2) << 130  */

    for (q = (q >> 2) * 5; q; q >>= 8)           /* suppose Q = B / (2 ^ 130) */
    {                                            /* ..then "almost" always:   */
        q += *block;                             /*   mod = B - Q * (2^130-5) */
        *block++ = (uint8_t) q;                  /* so subtract Q * 2^130 and */
    }                                            /* ..then add (Q * 5) := q   */
}

/** modular multiplication of two little-endian poly1305 blocks: y *= x mod P */
static void mulLblocks( const uint8_t* x, uint8_t* y )
{
    uint8_t n = PL, result[PL] = { 0 };
    while (n--)
    {                                            /*  Y = [Y_0][Y_1]...[Y_16], */
        uint8_t s = 8 * (n != 0), i;             /*  multiply X by MSB of Y   */
        int32_t m = 0, y_n = y[n];               /* ..and add to the result   */

        for (i = 0; i < sizeof result; ++i)      /*  if Y has another byte in */
        {                                        /* ..queue, shift the result */
            m >>= 8;                             /* ..but don't shift for Y_0 */
            m += (y_n * x[i] + result[i]) << s;
            result[i] = (uint8_t) m;
        }
        modP1305( result, m );                   /*  modular multiplication   */
    }
    memcpy( y, result, sizeof result );
}

/**
 * @brief   derive the Poly1305-AES mac of message using a nonce and key pair.
 * @param   keys      pair of encryption/mixing keys (k, r); size = KEYSIZE + 16
 * @param   nonce     a 128 bit string which is encrypted by AES_k
 * @param   data      buffer of input data
 * @param   dataSize  size of data in bytes
 * @param   mac       calculated Poly1305-AES mac
 */
void AES_Poly1305( const uint8_t* keys, const block_t nonce,
                   const void* data, const size_t dataSize, block_t mac )
{
    uint8_t r[PL], rk[PL] = { 1 }, c[PL] = { 0 }, poly[PL] = { 0 }, s = PL - 1;
    count_t q = (dataSize - 1) / BLOCKSIZE;
    const char* pos = (const char*) data + dataSize;

    AES_setkey( keys );
    rijndaelEncrypt( nonce, mac );               /* derive AES_k(nonce)       */
    BURN( RoundKey );

    if (!dataSize)  return;

    memcpy( r, keys + KEYSIZE, s );              /* extract r from (K,r) pair */
    for (r[s] = 0; s > 3; s -= 3)
    {
        r[s--] &= 0xFC;                          /* clear bottom 2 bits       */
        r[s  ] &= 0x0F;                          /* clear top 4 bits          */
    }
    s = dataSize - BLOCKSIZE * q;                /* size of last chunk        */
    do
    {
        memcpy( c, pos -= s, s );                /* copy message to chunk     */
        c[s] = 1;                                /* append 1 to each chunk    */
        s = BLOCKSIZE;
        mulLblocks( r, rk );                     /* r^k = r^{k-1} * r         */
        mulLblocks( rk, c );                     /* calculate c_{q-k} * r^k   */
        addLblocks( c, PL, poly );               /* ..and add it to poly,     */
        modP1305( poly, poly[s] );               /* ..then take mod(2^130-5)  */

    } while (q--);

    q = poly[s] * 4;                             /* still, in some rare cases */
    if (poly[0] > 0xFA && q == 12)               /* ..poly may be >= 2^130-5  */
    {                                            /* ..if so, set q=16         */
        for (q = 1; poly[q] == 0xFF; ++q);
    }
    modP1305( poly, q / 4 );

    addLblocks( poly, BLOCKSIZE, mac );          /* add AES_k(nonce) to poly  */
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
#define RADIX    10                              /*  strlen (ALPHABET)        */
#define LOGRDX   3.32192809488736                /*  log2 (RADIX)             */
#define MINLEN   6                               /*  ceil (6 / log10 (RADIX)) */
#define MAXLEN   56                              /*  only if FF_X == 3        */
#endif

#if ALPHABET_IS_NON_ASCII
typedef wchar_t  alpha_t;
#else
typedef char     alpha_t;                        /*  type of plain/ciphertext */
#endif

#if RADIX <= 1 + UCHAR_MAX
typedef unsigned char  radix_t;                  /*  digit type in base-radix */
#else
typedef unsigned short radix_t;
#endif

#if FF_X == 3                                    /*  FF3 'tweakLen' is fixed  */
#define FPE_PERMUTE    FF3_cipher
#define TWEAK_PARAMS   uint8_t* tweak
#define TWEAK_AGRS     tweak
#else                                            /*  FF1 implementation:      */
#define FPE_PERMUTE    FF1_cipher
#define TWEAK_PARAMS   uint8_t* tweak, const size_t tweakLen
#define TWEAK_AGRS     tweak, tweakLen

static size_t b1;                                /*  the b constant in FF1    */

/** convert the string s in base-RADIX to a big-endian number, denoted by num */
static void numRadix( const radix_t* s, size_t len, uint8_t* num, size_t bytes )
{
    memset( num, 0, bytes );
    while (len--)
    {                                            /*  we can reasonably assume */
        size_t i, y = *s++;                      /*  .. RADIX^2 <= SIZE_MAX+1 */
        for (i = bytes; i--; y >>= 8)
        {
            y += num[i] * RADIX;
            num[i] = (uint8_t) y;                /*  num = num * RADIX + y    */
        }
    }
}

/** convert a big-endian number to string s, its representation in base-RADIX */
static void strRadix( const uint8_t* num, size_t bytes, radix_t* s, size_t len )
{
    memset( s, 0, sizeof (radix_t) * len );
    while (bytes--)
    {
        size_t i, x = *num++;
        for (i = len; i--; x /= RADIX)
        {
            x += s[i] << 8;                      /*  str = (str << 8) + x     */
            s[i] = x % RADIX;
        }
    }
}

/** add two numbers x, y in base-RADIX and save the result in y, i.e. y += x; */
static void addRadix( const radix_t* x, const size_t len, radix_t* y )
{
    size_t i, a = 0;
    for (i = len; i--; a /= RADIX)               /*  big-endian addition      */
    {
        a += y[i] + x[i];                        /*  a /= RADIX is equivalent */
        y[i] = a % RADIX;                        /*  ..to: a = (a >= RADIX)   */
    }
}

/** subtract two numbers in base-RADIX and save the result in y, i.e. y -= x; */
static void subRadix( const radix_t* x, const size_t len, radix_t* y )
{
    size_t i, s = 1;
    for (i = len; i--; s /= RADIX)               /*  big-endian subtraction   */
    {
        s += RADIX - 1 + y[i] - x[i];
        y[i] = s % RADIX;
    }
}

/** derive C at step i of FF1 rounds, given the values: u, v and PRF_init = P */
static void FF1round( const uint8_t i, const block_t P,
                      const size_t u, const size_t v, radix_t* C )
{
    block_t R = { 0 };
    uint8_t* num = (uint8_t*) &C[u];             /* use pre-allocated memory, */
    size_t k = b1 % sizeof R, ext = (i & 1) * u;

    numRadix( C - v - ext, v, num, b1 );         /* ..to get NUM_radix(B)     */
    num[-1] = i;
    memcpy( R + LAST - k, num - 1, k + 1 );      /* feed NUM_radix to the PRF */

    xMac( P, BLOCKSIZE, R, &rijndaelEncrypt, R );
    xMac( num + k, b1 - k, R, &rijndaelEncrypt, R );

    memcpy( num, R, sizeof R );                  /* R = PRF(P || Q)           */
    k = (b1 + 3L) / sizeof R;                    /* total additional blocks   */

    for (ext = 0; k; ext = k--)
    {                                            /* S = R | Enc(R ^[k]) | ... */
        xorBEint( R, ext ^ k, LAST );
        rijndaelEncrypt( R, num + k * sizeof R );
    }
    strRadix( num, (b1 + 7) & ~3L, C, u );       /* take first 'd' bytes of S */
}

/** encrypt/decrypt a base-RADIX string X with length len using FF1 algorithm */
static void FF1_cipher( const uint8_t* key, const char mode,
                        const TWEAK_PARAMS, const size_t len, radix_t* X )
{
    size_t u = (len + !mode) / 2, t = tweakLen;
    radix_t* xC = X + len;
    block_t P = { 1, 2, 1, RADIX >> 16, RADIX >> 8 & 0xFF, RADIX & 0xFF, 10 };
    uint8_t i = t % sizeof P + b1 % sizeof P < BLOCKSIZE ? t % sizeof P : 0;

    AES_setkey( key );

    P[7] ^= len / 2;                             /*  initializing P block     */
    xorBEint( P, len, 11 );
    xorBEint( P, t, LAST );
    rijndaelEncrypt( P, P );                     /*  P -> PRF(P || tweak)     */
    xMac( tweak, t - i, P, &rijndaelEncrypt, P );

    while (i)
    {
        P[--i] ^= tweak[--t];
    }
    for (; i < 10 * mode; ++i, u = t)            /*  Feistel procedure        */
    {                                            /*  encryption rounds        */
        FF1round( i, P, u, t = len - u, xC );
        addRadix( xC, u, X + (i & 1) * t );      /*  add C to A then swap A,B */
    }
    for (i ^= 10; i-- != 0x00; u = t)            /*  decryption rounds        */
    {
        FF1round( i, P, u, t = len - u, xC );
        subRadix( xC, u, X + (i & 1) * t );      /*  subtract C from A        */
    }
}
#endif /* FF1 */

#if FF_X == 3                                    /*  FF3/FF3-1 method:        */

/** converts a string in base-RADIX to a little-endian number, denoted by num */
static void numRadix( const radix_t* s, uint8_t len, uint8_t* num, char bytes )
{
    memset( num, 0, bytes );
    while (len--)
    {
        size_t i, y = s[len];
        for (i = 0; i < bytes; y >>= 8)          /*  bytes = 12  "always"     */
        {
            y += num[i] * RADIX;
            num[i++] = (uint8_t) y;              /*  num = num * RADIX + y    */
        }
    }
}

/** convert a little-endian number to its base-RADIX representation string: s */
static void strRadix( const uint8_t* num, char bytes, radix_t* s, uint8_t len )
{
    memset( s, 0, sizeof (radix_t) * len );
    while (bytes--)
    {
        size_t i, x = num[bytes];
        for (i = 0; i < len; x /= RADIX)
        {
            x += s[i] << 8;                      /*  str = (str << 8) + x     */
            s[i++] = x % RADIX;
        }
    }
}

/** add two numbers x, y in base-RADIX and save the result in y, i.e. y += x; */
static void addRadix( const radix_t* x, const uint8_t len, radix_t* y )
{
    size_t i, a = 0;
    for (i = 0; i < len; a /= RADIX)             /* little-endian addition    */
    {
        a += y[i] + x[i];
        y[i++] = a % RADIX;
    }
}

/** subtract two numbers in base-RADIX and save the result in y, i.e. y -= x; */
static void subRadix( const radix_t* x, const uint8_t len, radix_t* y )
{
    size_t i, s = 1;
    for (i = 0; i < len; s /= RADIX)             /* little-endian subtraction */
    {
        s += RADIX - 1 + y[i] - x[i];
        y[i++] = s % RADIX;
    }
}

/** calculate C at step i of FF3 rounds, given the values: u, v and tweak (T) */
static void FF3round( const uint8_t i, const uint8_t* T,
                      const uint8_t u, const uint8_t v, radix_t* C )
{
    uint8_t w = (i & 1) * 4, ext = (i & 1) * u;
    block_t P;
    COPYDWORD( T[w], P[12] );                    /*  W = (i is odd) ? TR : TL */
    P[12] ^= i;

    numRadix( C - v - ext, v, P, 12 );           /*  get REV. NUM_radix( B )  */
    rijndaelEncrypt( P, P );
    strRadix( P, sizeof P, C, u );               /*  C = REV. STR_m( c )      */
}

/** encrypt/decrypt a base-RADIX string X with size len using FF3-1 algorithm */
static void FF3_cipher( const uint8_t* key, const char mode,
                        const TWEAK_PARAMS, const size_t len, radix_t* X )
{
    radix_t* xC = X + len;
    uint8_t T[8], u = (len + mode) / 2, v, i, *k = (void*) xC;

    memcpy( k, tweak, FF3_TWEAK_LEN );
    if (FF3_TWEAK_LEN == 7)                      /*  FF3 vs. FF3-1            */
    {
        k[7] = (uint8_t) (k[3] << 4);
        k[3] &= 0xF0;
    }

    for (i = 8; i --> 0; )  T[7 - i] = k[i];
    for (i = KEYSIZE; i; )  k[--i] = *key++;     /*  key/tweak are reversed   */

    AES_setkey( k );
    SABOTAGE( k, KEYSIZE );

    for (; i < 8 * mode; ++i, u = v)             /*  Feistel procedure        */
    {                                            /*  encryption rounds        */
        FF3round( i, T, u, v = len - u, xC );
        addRadix( xC, u, X + (i & 1) * v );      /*  add C to A then swap A,B */
    }
    for (i ^= 8; i-- != 0x00; u = v)             /*  decryption rounds        */
    {
        FF3round( i, T, u, v = len - u, xC );
        subRadix( xC, u, X + (i & 1) * v );
    }
}
#endif /* FF3 */

/*----------------------------------------------------------------------------*\
                            FPE-AES: main functions
\*----------------------------------------------------------------------------*/
#include <stdlib.h>

/**
 * @brief   encrypt or decrypt the input string with FPE method
 * @param   key       encryption or decryption key
 * @param   mode      mode of operation: encrypting (1) or decrypting (0)
 * @param   tweak     tweak byte array
 * @param   tweakLen  size of tweak. must be exactly 7 in FF3-1
 * @param   input     input string, consisted of characters in ALPHABET
 * @param   dataSize  length of the string, or its number of characters
 * @param   output    result of format-preserved encryption/decryption
 * @return            error character if failed, or '\0' if ended in success
 */
static char FPE_cipher( const uint8_t* key, const char mode, const TWEAK_PARAMS,
                        const void* input, const size_t dataSize, void* output )
{
    size_t v = (dataSize + 1) / 2;
    size_t n = (dataSize + v) * sizeof (radix_t);
    alpha_t const* alpha = ALPHABET;
    alpha_t* y = output;
    radix_t* index;

    if (dataSize < MINLEN)  return 'l';
#if FF_X == 3
    if (dataSize > MAXLEN)  return 'L';

    v *= sizeof (radix_t);
    n += v < KEYSIZE ? KEYSIZE - v : 0;
#else                                            /*  extra memory is needed.. */
    b1 = (size_t) (LOGRDX * v + 8 - 1e-14) / 8;  /*  to store NUM_radix and.. */
    n += (b1 + 4 + LAST) & ~LAST;                /*  mix it in Feistel rounds */
#endif

    if ((index = malloc( n )) == NULL)
    {
        return 'm';                              /*  memory allocation failed */
    }
    for (n = 0; n < dataSize; ++n)               /*  find index of each char  */
    {
        const alpha_t *ch = (alpha_t*) input + n;
        for (v = 0x0; *ch != alpha[v]; )
        {
            if (++v == RADIX)
            {
                free( index );                   /*  invalid character found  */
                return 'C';
            }
        }
        *(index + n) = (radix_t) v;
    }                                            /*  now permute the indexes: */

    FPE_PERMUTE( key, mode, TWEAK_AGRS, n, index );
    BURN( RoundKey );

    for (y[n] = 0; n--; )                        /*  construct the output as  */
    {                                            /*  null-terminated? string  */
        y[n] = alpha[index[n]];
    }
    free( index );
    return 0;
}

/**
 * @brief   encrypt the input string using FPE-AES block-cipher method
 * @param   key       encryption key with a fixed size specified by KEYSIZE
 * @param   tweak     tweak byte array; similar to nonce in other schemes
 * @param   tweakLen  size of tweak. must be exactly 7 in FF3-1
 * @param   pntxt     input plaintext string, consisted of ALPHABET characters
 * @param   ptextLen  size of plaintext string, or number of characters
 * @param   crtxt     resulting ciphertext string
 * @return            whether encryption was successful
 */
char AES_FPE_encrypt( const uint8_t* key, const TWEAK_PARAMS,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    char result = FPE_cipher( key, 1, TWEAK_AGRS, pntxt, ptextLen, crtxt );
    return result == 0 ? M_RESULT_SUCCESS : M_ENCRYPTION_ERROR;
}

/**
 * @brief   decrypt a ciphertext string using FPE-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   tweak     tweak byte array; similar to nonce in other schemes
 * @param   tweakLen  size of tweak. must be exactly 7 in FF3-1
 * @param   crtxt     input ciphertext string, consisted of ALPHABET characters
 * @param   crtxtLen  size of ciphertext string, or number of characters
 * @param   pntxt     resulting plaintext string
 * @return            whether decryption was successful
 */
char AES_FPE_decrypt( const uint8_t* key, const TWEAK_PARAMS,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    char result = FPE_cipher( key, 0, TWEAK_AGRS, crtxt, crtxtLen, pntxt );
    return result == 0 ? M_RESULT_SUCCESS : M_DECRYPTION_ERROR;
}
#endif /* FPE */
