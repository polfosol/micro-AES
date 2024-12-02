/*
 ==============================================================================
 Name        : micro_aes.c
 Author      : polfosol
 Version     : 10
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
    BLOCKSIZE =   (128) / 8,      /* Block length in AES is 'always' 128-bits */
    KEYSIZE =  AES_KEY_SIZE,
    Nb      = BLOCKSIZE / 4,      /* number of columns comprising a AES state */
    Nk      =   KEYSIZE / 4,      /* number of 32 bit words in a key.         */
    ROUNDS  =        Nk + 6,      /* number of rounds in AES Cipher.          */
    LAST    = BLOCKSIZE - 1,      /* index of last element (LSB) in a block.  */
    HB      = BLOCKSIZE / 2,      /* length of a half-block unit.             */
    SP      = 17                  /* length of data blocks in poly-1305 mode. */
};

#define IMPLEMENT(x)  (x) > 0

#define INCREASE_SECURITY   0     /* see the comments at the bottom of header */
#define DISCARD_SUBROUTINES 0
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

#if DISCARD_SUBROUTINES

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

/** XOR two 128bit numbers (blocks) called src and dest, so that: dest ^= src */
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

            /* RCON reaches 0 only in AES-128, otherwise the line is ignored. */
            if (4 / Nk && rcon == 0)  rcon = 0x1b;

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

/** Add the round keys to the rijndael state matrix (adding in GF means XOR). */
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
        C[0] ^= C[3];            /* C[0] = xor of all elements in i-th column */
        C[0] ^= xtime( C[1] );
        C[1]  = xtime( C[3] );

        state[i][0] ^= C[0];
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
#define MISMATCH            constmemcmp          /*  a.k.a secure memcmp      */
#else
#define MISMATCH            memcmp
#define SABOTAGE(buf, len)  (void)  buf
#define BURN(key)           (void)  key          /*  the line will be ignored */
#endif

#if INCREASE_SECURITY && AEAD_MODES

/** for constant-time comparison of memory blocks, to avoid "timing attacks". */
static uint8_t constmemcmp( const uint8_t* src, const uint8_t* dst, uint8_t n )
{
    uint8_t cmp = 0;
    while (n--)
    {
        cmp |= src[n] ^ dst[n];
    }
    return cmp;
}
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
    array[LAST] ^= c * 0x87;                     /* .. B ^= 10000111b (B.E.)  */
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
    array[0] ^= c * 0x87;                        /*    B ^= 10000111b (L.E.)  */
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
    if (c & 1)  array[0] ^= 0xe1;                /* .. B ^= 11100001b << 120  */
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
    if (c & 1)  array[LAST] ^= 0xe1;             /* B ^= LE. 11100001b << 120 */
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
    if (n != 0)
    {
        mix( B, f );                             /*  Y = f(B) ^ X             */
        while (n--)
        {
            Y[n] = f[n] ^ X[n];
        }
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
    if ((n = dataSize % BLOCKSIZE) != 0)         /* if any partial block left */
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

    if (n == 0)  return M_ENCRYPTION_ERROR;      /*  data size >= BLOCKSIZE   */
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

    if (n == 0)  return M_DECRYPTION_ERROR;
#else
    if (r != 0)  return M_DECRYPTION_ERROR;
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
    case 2:
        incBlock( c, index );                    /*  pre-increment in CCM/GCM */
        break;
    case 4:
        c[+8] &= 0x7F;                           /*  SIV mode: clear two bits */
        c[12] &= 0x7F;
        break;
    case 8:                                      /*  GCM-SIV: set one bit     */
        c[index] |= 0x80;
        index = 0;
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
#if CTR_IV_LENGTH == 16
    uint8_t const* ctr = iv;                     /*  block is pre-initialized */
#else
    block_t ctr = { 0 };
    memcpy( ctr, iv, CTR_IV_LENGTH );

    xorBEint( ctr, CTR_STARTVALUE, LAST );       /*  initialize the counter   */
#endif
    AES_setkey( key );
    CTR_cipher( ctr, 0, pntxt, ptextLen, crtxt );
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
    if (ptextLen < BLOCKSIZE)  return M_ENCRYPTION_ERROR;

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
    if (crtxtLen < BLOCKSIZE)  return M_DECRYPTION_ERROR;

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
static void Ghash( const block_t H, const void* aData, const void* crtxt,
                   const size_t aDataLen, const size_t crtxtLen, block_t gh )
{
    block_t len = { 0 };
    xorBEint( len, aDataLen * 8, LAST / 2 );
    xorBEint( len, crtxtLen * 8, LAST );         /*  save bit-sizes into len  */

    xMac( aData, aDataLen, H, &mulGF128, gh );   /*  first digest AAD, then   */
    xMac( crtxt, crtxtLen, H, &mulGF128, gh );   /*  ..ciphertext, and then   */
    xMac( len, sizeof len, H, &mulGF128, gh );   /*  ..bit sizes into GHash   */
}

/** encrypt zeros to get authentication subkey H, and prepare the IV for GCM. */
static void GCMinit( const uint8_t* key,
                     const uint8_t* nonce, block_t auKey, block_t iv )
{
    AES_setkey( key );
    rijndaelEncrypt( auKey, auKey );             /* auKey = Enc( zero block ) */
#if GCM_NONCE_LEN != 12
    Ghash( auKey, NULL, nonce, 0, GCM_NONCE_LEN, iv );
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
    block_t gh = { 0 }, H = { 0 }, iv = { 0 };
    GCMinit( key, nonce, H, iv );                /*  get IV & auth. subkey H  */

    CTR_cipher( iv, 2, pntxt, ptextLen, crtxt );
    rijndaelEncrypt( iv, iv );
    BURN( RoundKey );

    Ghash( H, aData, crtxt, aDataLen, ptextLen, gh );
    xorBlock( iv, gh );
    memcpy( auTag, gh, BLOCKSIZE );              /*  GMAC = Enc(iv) ^ G-HASH  */
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
 * @return            whether message authentication/decryption was successful
 */
char AES_GCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    block_t gh = { 0 }, H = { 0 }, iv = { 0 };
    GCMinit( key, nonce, H, iv );

    Ghash( H, aData, crtxt, aDataLen, crtxtLen, gh );
    rijndaelEncrypt( iv, H );
    xorBlock( gh, H );                           /*  tag = Enc(iv) ^ G-HASH   */

    if (MISMATCH( H, crtxt + crtxtLen, tagLen ))
    {                                            /*  compare tags and         */
        BURN( RoundKey );                        /*  ..proceed if they match  */
        return M_AUTHENTICATION_ERROR;
    }
    CTR_cipher( iv, 2, crtxt, crtxtLen, pntxt );
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
    uint8_t s = aDataLen < LAST ? aDataLen : sizeof A - 2;

    memcpy( M, iv, BLOCKSIZE );                  /*  initialize CBC-MAC       */
    M[0] |= (CCM_TAG_LEN - 2) << 2;              /*  set some flags on M_*    */
    xorBEint( M, ptextLen, LAST );               /*  copy data size into M_*  */

    if (aDataLen)                                /*  construct the 'A' block  */
    {
        M[0] |= 0x40;
        rijndaelEncrypt( M, M );                 /*  flag M_* and encrypt it  */
        if (aDataLen > 0xFEFF)
        {                                        /*  assuming aDataLen < 2^32 */
            s -= 4;
            A[0] = 0xFF,  A[1] = 0xFE;           /*  prepend FFFE to aDataLen */
        }
        xorBEint( A, aDataLen, LAST - s );       /*  copy aDataLen into A,    */
        memcpy( A + sizeof A - s, aData, s );    /*  ..and append aData       */
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
 * @param   pntxt     input plain-text buffer
 * @param   ptextLen  size of plaintext in bytes
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   crtxt     resulting cipher-text buffer
 * @param   auTag     message authentication tag
 */
void AES_CCM_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, uint8_t* auTag )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, tag;
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );

    AES_setkey( key );
    CCMtag( iv, aData, pntxt, aDataLen, ptextLen, tag );
    CTR_cipher( iv, 2, pntxt, ptextLen, crtxt );
    BURN( RoundKey );
    memcpy( auTag, tag, CCM_TAG_LEN );
}

/**
 * @brief   decrypt the input ciphertext using CCM-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: CCM_NONCE_LEN
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message decryption/authentication was successful
 */
char AES_CCM_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    block_t iv = { 14 - CCM_NONCE_LEN, 0 }, tag;
    memcpy( iv + 1, nonce, CCM_NONCE_LEN );

    if (tagLen != CCM_TAG_LEN)  return M_DECRYPTION_ERROR;

    AES_setkey( key );
    CTR_cipher( iv, 2, crtxt, crtxtLen, pntxt );
    CCMtag( iv, aData, pntxt, aDataLen, crtxtLen, tag );
    BURN( RoundKey );

    if (MISMATCH( tag, crtxt + crtxtLen, tagLen ))
    {                                            /*  invalid tag: clear pntxt */
        SABOTAGE( pntxt, crtxtLen );
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
static void S2V( const uint8_t* key,
                 const void* aData, const void* pntxt,
                 const size_t aDataLen, const size_t ptextLen, block_t IV )
{
    block_t K[2] = { { 0 } }, Y;
    uint8_t r = ptextLen % BLOCKSIZE, *Q = K[1];

    memcpy( IV, *K, BLOCKSIZE );                 /*  initialize/clear IV      */
    getSubkeys( &doubleBblock, 1, key, *K, Q );
    rijndaelEncrypt( *K, Y );                    /*  Y_0 = CMAC(zero block)   */

    /* in case of multiple AAD units, each one must be handled in a similar way.
     * for example, let aData be a 2-D array and aDataLen a null-terminated one.
     * then, instead of `if (aDataLen) { cMac( *K, Q, aData,...` we could write:
     * for (int i = 0; *aDataLen; ){ cMac(*K, Q, aData[i++], *aDataLen++, IV) */
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
    if (r)
    {
        memset( *K, 0, BLOCKSIZE );
    }
    xorBlock( Y, *K + r );
    cMac( *K, *K, pntxt, ptextLen - r, IV );     /*  CMAC*( Y  xor_end  M )   */
    if (r)
    {
        cMac( NULL, Q, (char*) pntxt + ptextLen - r, r, IV );
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
                      const void* pntxt, const size_t ptextLen,
                      const void* aData, const size_t aDataLen,
                      block_t iv, void* crtxt )
{
    S2V( keys, aData, pntxt, aDataLen, ptextLen, iv );
    AES_setkey( keys + KEYSIZE );
    CTR_cipher( iv, 4, pntxt, ptextLen, crtxt );
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
 * @return            whether message decryption/authentication was successful
 */
char AES_SIV_decrypt( const uint8_t* keys, const block_t iv,
                      const void* crtxt, const size_t crtxtLen,
                      const void* aData, const size_t aDataLen,
                      void* pntxt )
{
    block_t IV;
    AES_setkey( keys + KEYSIZE );
    CTR_cipher( iv, 4, crtxt, crtxtLen, pntxt );
    S2V( keys, aData, pntxt, aDataLen, crtxtLen, IV );
    BURN( RoundKey );

    if (MISMATCH( IV, iv, sizeof IV ))           /* verify the synthesized IV */
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
static void Polyval( const block_t H, const void* aData, const void* pntxt,
                     const size_t aDataLen, const size_t ptextLen, block_t pv )
{
    block_t len = { 0 };                         /*  save bit-sizes into len  */
    copyLint( len, aDataLen * 8, 0 );
    copyLint( len, ptextLen * 8, 8 );

    xMac( aData, aDataLen, H, &dotGF128, pv );   /*  first digest AAD, then   */
    xMac( pntxt, ptextLen, H, &dotGF128, pv );   /*  ..plaintext, and then    */
    xMac( len, sizeof len, H, &dotGF128, pv );   /*  ..bit sizes into POLYVAL */
}

/** derive the pair of authentication-encryption-keys from main key and nonce */
static void GCMSIVinit( const uint8_t* key, const uint8_t* nonce, block_t AK )
{
    uint8_t iv[5 * HB + KEYSIZE], *h, *k;
    k = h = iv + BLOCKSIZE;
    memcpy( iv + 4, nonce, 12 );

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
static void GSIVtag( const uint8_t* nonce, block_t polyval, block_t tag )
{
    XOR32BITS( nonce[0], polyval[0] );
    XOR32BITS( nonce[4], polyval[4] );           /*  xor POLYVAL with nonce   */
    XOR32BITS( nonce[8], polyval[8] );
    polyval[LAST] &= 0x7F;                       /*  clear one bit & encrypt, */
    rijndaelEncrypt( polyval, tag );
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
    block_t H, P = { 0 };
    GCMSIVinit( key, nonce, H );                 /* get authentication subkey */

    Polyval( H, aData, pntxt, aDataLen, ptextLen, P );
    GSIVtag( nonce, P, auTag );
    CTR_cipher( auTag, 8, pntxt, ptextLen, crtxt );
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
 * @return            whether message decryption/authentication was successful
 */
char GCM_SIV_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    uint8_t const* tag = crtxt + crtxtLen;
    block_t H, P = { 0 };

    if (tagLen != sizeof P)  return M_DECRYPTION_ERROR;

    GCMSIVinit( key, nonce, H );                 /* get authentication subkey */
    CTR_cipher( tag, 8, crtxt, crtxtLen, pntxt );
    Polyval( H, aData, pntxt, aDataLen, crtxtLen, P );
    GSIVtag( nonce, P, P );
    BURN( RoundKey );

    if (MISMATCH( P, tag, sizeof P ))
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

/** this function calculates the OMAC of a data array using D (K1) and Q (K2) */
static void OMac( const uint8_t t, const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
#if EAXP
    const uint8_t zero_mac = t && !dataSize, *K = t ? Q : D;

    zero_mac ? memset( mac, 0, BLOCKSIZE ) : memcpy( mac, K, BLOCKSIZE );

    if (zero_mac)  return;                       /* ignoring null ciphertext  */
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
#define FDOUBLE_T     &doubleLblock
                      const size_t nonceLen, uint8_t* crtxt )
#else
#define FDOUBLE_T     &doubleBblock
#define nonceLen      EAX_NONCE_LEN
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, block_t auTag )
#endif
{
    block_t D = { 0 }, Q, mac;

    getSubkeys( FDOUBLE_T, 1, key, D, Q );
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = OMAC(0; nonce)       */
#if EAXP
    COPYDWORD( mac[12], crtxt[ptextLen] );
    mac[12] &= 0x7F;
    mac[14] &= 0x7F;                             /*  clear 2 bits to get N'   */

    CTR_cipher( mac, 0, pntxt, ptextLen, crtxt );
    OMac( 2, D, Q, crtxt, ptextLen, mac );       /*  C' = CMAC'( ciphertext ) */
    XOR32BITS( mac[12], crtxt[ptextLen] );       /*  tag (a.k.a mac) = N ^ C' */
#else
    OMac( 1, D, Q, aData, aDataLen, auTag );     /*  H = OMAC(1; adata)       */
    xorBlock( mac, auTag );

    CTR_cipher( mac, 0, pntxt, ptextLen, crtxt );
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
 * @return            whether message authentication/decryption was successful
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

    getSubkeys( FDOUBLE_T, 1, key, D, Q );
    OMac( 2, D, Q, crtxt, crtxtLen, tag );       /*  C = OMAC(2; ciphertext)  */
#if EAXP
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = CMAC'( nonce )       */
    XOR32BITS( crtxt[crtxtLen], tag[12] );
    XOR32BITS( mac[12], tag[12] );
    mac[12] &= 0x7F;
    mac[14] &= 0x7F;                             /*  clear 2 bits to get N'   */

    if (*(int32_t*) &tag[12] != 0)               /*  result of mac validation */
#else
    OMac( 1, D, Q, aData, aDataLen, mac );       /*  H = OMAC(1; adata)       */
    xorBlock( mac, tag );
    OMac( 0, D, Q, nonce, nonceLen, mac );       /*  N = OMAC(0; nonce)       */
    xorBlock( mac, tag );                        /*  tag = N ^ H ^ C          */
    #undef nonceLen

    if (MISMATCH( tag, crtxt + crtxtLen, tagLen ))
#endif
    {                                            /* authenticate then decrypt */
        BURN( RoundKey );
        return M_AUTHENTICATION_ERROR;
    }
    CTR_cipher( mac, 0, crtxt, crtxtLen, pntxt );
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
    count_t r, b = 1;
    block_t L;

    memcpy( L, Ld, sizeof L );                   /*  initialize L_$ and Δ     */
    memcpy( delta, delta0, BLOCKSIZE );

    while ((r = index - b) < index)              /*  Δ_i = Δ_{i-1} ^ L_ntz(i) */
    {                                            /*  where:                   */
        doubleBblock( L );                       /*  L_0 = double( L_$ )      */
        b *= 2;                                  /*  L_k = double( L_{k-1} )  */

        if (r & b)  continue;

        xorBlock( L, delta );
    }
}

/**
 * @brief   encrypt or decrypt the data using OCB method
 * @param   key       encryption or decryption key
 * @param   nonce     byte array with a fixed size of OCB_NONCE_LEN
 * @param   ptLen     size of plaintext. ptLen = dataSize, only in encryption
 * @param   aDataLen  size of additional authentication data
 * @param   aData     additional authentication data
 * @param   dataSize  size of input data, to be encrypted/decrypted
 * @param   data      result of encryption/decryption process
 * @param   tag       calculated tag from plaintext checksum, and PMAC of aData
 */
static void OCB_cipher( const uint8_t* key, const uint8_t* nonce,
                        const size_t ptLen,
                        const size_t aDataLen, const void* aData,
                        const size_t dataSize, void* data, block_t tag )
{
    fmix_t cipher = ptLen ? &rijndaelEncrypt : &rijndaelDecrypt;

    block_t offset[4] = { { 0 } };               /*  [L_$] [L_*] [Ktop] [Δ_n] */
    uint8_t *y = data;
    uint8_t *Ld = offset[0], *Ls = offset[1], *kt = offset[2], *del = offset[3];
    count_t i, n = nonce[OCB_NONCE_LEN  - 1] % 64;
    uint8_t const s = 8 - n % 8, *a = aData;

    memcpy( kt + BLOCKSIZE - OCB_NONCE_LEN, nonce, OCB_NONCE_LEN );
    kt[0] = OCB_TAG_LEN << 4 & 0xFF;
    kt[LAST - OCB_NONCE_LEN] |= 1;               /*  set one and clear last 6 */
    kt[LAST] &= 0xC0;                            /*  .. bits of nonce (kt)    */

    getSubkeys( &doubleBblock, 0, key, Ls, Ld );
    rijndaelEncrypt( kt, kt );                   /*  construct K_top          */
    memcpy( del, kt + 1, 8 );                    /*  stretch K_top            */
    xorBlock( kt, del );

    n /= 8;
    for (i = 0; i < BLOCKSIZE; ++i, ++n)         /* shift the stretched K_top */
    {
        kt[i] = (kt[n] << 8 | kt[n + 1]) >> s;
    }

    xMac( data, ptLen, NULL, &nop, tag );        /*  get plaintext? checksum  */

    if ((n = dataSize / BLOCKSIZE) == 0)
    {
        del = kt;                                /*  Δ_N = Δ_0 = K_top        */
        kt = offset[3];
    }
    for (i = 0; i++ < n; y += BLOCKSIZE)
    {                                            /*  calculate Δ_i using      */
        getDelta( i, Ld, kt, del );              /*  .. my 'magic' algorithm  */
        xorBlock( del, y );
        cipher( y, y );
        xorBlock( del, y );                      /* Y = Δ_i ^ Cipher(Δ_i ^ X) */
    }
    if ((i = dataSize % BLOCKSIZE) != 0)
    {                                            /*  Y_* = Enc(L_* ^ Δ_N) ^ X */
        tag[i] ^= 0x80;                          /*  and pad X_* or checksum  */
        xorBlock( Ls, del );
        mixThenXor( &rijndaelEncrypt, del, kt, y, i, y );
    }

    xMac( data, dataSize - ptLen, NULL, &nop, tag );
    cMac( Ld, NULL, del, BLOCKSIZE, tag );

    /*- tag = Enc( checksum ^ Δ_* ^ L_$ ) so far. next, add "PMAC" of aData: **/
    n = aDataLen / BLOCKSIZE;

    for (i = 0; i < n; a += BLOCKSIZE)
    {
        getDelta( ++i, Ld, a, del );
        rijndaelEncrypt( del, del );             /*  Δ = Enc( A_i ^ Δ_i )     */
        xorBlock( del, tag );                    /*  add Δ to the tag         */
    }
    if ((i = aDataLen % BLOCKSIZE) != 0)
    {
        memset( kt, 0, BLOCKSIZE );
        getDelta( n, Ld, kt, del );
        cMac( NULL, Ls, a, i, del );             /*  Δ = Enc(L_* ^ A_* ^ Δ_N) */
        xorBlock( del, tag );                    /*  add Δ to the tag         */
    }
    BURN( RoundKey );
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
 * @param   auTag     message authentication tag
 */
void AES_OCB_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* pntxt, const size_t ptextLen,
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, uint8_t* auTag )
{
    block_t tag = { 0 };
    memcpy( crtxt, pntxt, ptextLen );            /* doing in-place encryption */

    OCB_cipher( key, nonce, ptextLen, aDataLen, aData, ptextLen, crtxt, tag );
    memcpy( auTag, tag, OCB_TAG_LEN );
}

/**
 * @brief   decrypt the input stream using OCB-AES block-cipher method
 * @param   key       decryption key with a fixed size specified by KEYSIZE
 * @param   nonce     a.k.a initialization vector with fixed size: OCB_NONCE_LEN
 * @param   crtxt     input cipher-text buffer + appended authentication tag
 * @param   crtxtLen  size of ciphertext, excluding tag
 * @param   aData     additional authentication data
 * @param   aDataLen  size of additional authentication data
 * @param   tagLen    length of authentication tag
 * @param   pntxt     resulting plaintext buffer
 * @return            whether message decryption/authentication was successful
 */
char AES_OCB_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const uint8_t* crtxt, const size_t crtxtLen,
                      const uint8_t* aData, const size_t aDataLen,
                      const uint8_t tagLen, uint8_t* pntxt )
{
    block_t tag = { 0 };

    if (tagLen != OCB_TAG_LEN)  return M_DECRYPTION_ERROR;

    memcpy( pntxt, crtxt, crtxtLen );            /*    in-place  decryption   */
    OCB_cipher( key, nonce, 0, aDataLen, aData, crtxtLen, pntxt, tag );

    if (MISMATCH( tag, crtxt + crtxtLen, tagLen ))
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
 * @brief   wrap the input secret whose size is a multiple of 8 and >= 16
 * @param   kek       key-encryption-key a.k.a master key
 * @param   secret    input plain text secret
 * @param   secretLen size of input, must be a multiple of HB (half-block size)
 * @param   wrapped   wrapped secret, prepended with an additional half-block
 * @return            error if size is not a multiple of HB, or size < BLOCKSIZE
 */
char AES_KEY_wrap( const uint8_t* kek,
                   const void* secret, const size_t secretLen, uint8_t* wrapped )
{
    size_t i = 0, n = secretLen / HB;            /*  number of semi-blocks    */
    block_t A;
    uint8_t *r = wrapped + HB, *endpt = wrapped + secretLen;

    if (n < 2 || secretLen % HB)  return M_ENCRYPTION_ERROR;

    memset( A, 0xA6, HB );                       /*  initialization vector    */
    memcpy( r, secret, secretLen );              /*  copy input to the output */
    AES_setkey( kek );

    for (n *= 6; i++ < n; )
    {
        memcpy( A + HB, r, HB );
        rijndaelEncrypt( A, A );                 /*  A = Enc( V | R_{k-1} )   */
        memcpy( r, A + HB, HB );                 /*  R_{k} = LSB(64, A)       */
        xorBEint( A, i, HB - 1 );                /*  V = MSB(64, A) ^ i       */
        r = (r == endpt ? wrapped : r) + HB;
    }
    BURN( RoundKey );

    memcpy( wrapped, A, HB );                    /*  authentication vector    */
    return M_RESULT_SUCCESS;
}

/**
 * @brief   unwrap a wrapped key input, whose size is a multiple of 8 and >= 24
 * @param   kek       key-encryption-key a.k.a master key
 * @param   wrapped   cipher-text input, the wrapped secret
 * @param   wrapLen   size of ciphertext/wrapped input in bytes
 * @param   secret    unwrapped secret, which is a half block shorter than input
 * @return            a value indicating whether decryption was successful
 */
char AES_KEY_unwrap( const uint8_t* kek,
                     const void* wrapped, const size_t wrapLen, uint8_t* secret )
{
    size_t n = 0, i = wrapLen / HB;              /*  number of semi-blocks    */
    block_t A;
    uint8_t *r = secret, *endpt = secret + wrapLen - HB;

    if (i-- < 3 || wrapLen % HB)  return M_DECRYPTION_ERROR;

    memcpy( A, wrapped, HB );
    memcpy( r, (char*) wrapped + HB, wrapLen - HB );
    AES_setkey( kek );

    for (i *= 6; i; --i)
    {
        r = (r == secret ? endpt : r) - HB;
        xorBEint( A, i, HB - 1 );                /*  V = MSB(64, A) ^ i       */
        memcpy( A + HB, r, HB );                 /*  A = Dec( V | R_{k} )     */
        rijndaelDecrypt( A, A );                 /*  R_{k-1} = LSB(64, A)     */
        memcpy( r, A + HB, HB );
    }
    BURN( RoundKey );

    while (i < HB)                               /*  authenticate/error check */
    {
        n |= A[i++] ^ 0xA6;
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

    block[SP - 1] &= 3;                          /* get rid of excess bits.   */

    for (q = (q >> 2) * 5; q; q >>= 8)           /* suppose Q = B / (2 ^ 130) */
    {                                            /* ..then "almost" always:   */
        q += *block;                             /*   mod = B - Q * (2^130-5) */
        *block++ = (uint8_t) q;                  /* so subtract Q * 2^130 and */
    }                                            /* ..then add (Q * 5) := q   */
}

/** modular multiplication of two little-endian poly1305 blocks: y *= x mod P */
static void mulLblocks( const uint8_t* x, uint8_t* y )
{
    uint8_t n = SP, result[SP] = { 0 };
    while (n--)                                  /*  Y = [Y_0][Y_1]...[Y_n],  */
    {
        uint8_t s = 8 * (n != 0), i;             /*  multiply X by MSB of Y   */
        int32_t m = 0;                           /* ..and add to the result   */

        for (i = 0; i < sizeof result; ++i)      /*  if Y has another byte in */
        {                                        /* ..queue, shift the result */
            m >>= 8;                             /* ..but don't shift for Y_0 */
            m += (y[n] * x[i] + result[i]) << s;
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
    uint8_t r[SP], rk[SP] = { 1 }, c[SP] = { 0 }, poly[SP] = { 0 }, s = SP - 1;
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
        mulLblocks( r, rk );                     /* r^k = r^{k-1} * r         */
        mulLblocks( rk, c );                     /* calculate c_{q-k} * r^k   */
        addLblocks( c, SP, poly );               /* ..and add it to poly,     */
        s = SP - 1;                              /* ..then take mod(2^130-5)  */
        modP1305( poly, poly[s] );

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
#define string_t char*                           /*  string pointer type      */
#define RADIX    10                              /*  strlen (ALPHABET)        */
#define LOGRDX   3.32192809488736                /*  log2 (RADIX)             */
#define MINLEN   6                               /*  ceil (6 / log10 (RADIX)) */
#define MAXLEN   0x38                            /*  only if FF_X == 3        */
#endif

#if RADIX - 1 <= UCHAR_MAX
typedef unsigned char  rbase_t;                  /*  digit type in base-radix */
#else
typedef unsigned short rbase_t;
#endif

#if FF_X != 3                                    /*  FF1 method:              */

static size_t bb;                                /*  the b constant in FF1    */

/** convert a string `s` in base-RADIX to a big-endian number, denoted by num */
static void numRadix( const rbase_t* s, size_t len, uint8_t* num, size_t bytes )
{
    memset( num, 0, bytes );
    while (len--)
    {
        size_t i, y = *s++;
        for (i = bytes; i--; y >>= 8)
        {
            y += num[i] * RADIX;                 /*  num = num * RADIX + y    */
            num[i] = (uint8_t) y;
        }
    }
}

/** convert a big-endian number to its base-RADIX representation string: `s`. */
static void strRadix( const uint8_t* num, size_t bytes, rbase_t* s, size_t len )
{
    memset( s, 0, sizeof (rbase_t) * len );
    while (bytes--)
    {
        size_t i, x = *num++;
        for (i = len; i--; x /= RADIX)
        {
            x += s[i] << 8;                      /*  numstr = numstr << 8 + x */
            s[i] = x % RADIX;
        }
    }
}

/** add two numbers in base-RADIX represented by q and p, so that: p = p + q; */
static void addRadix( const rbase_t* q, const size_t len, rbase_t* p )
{
    size_t i, a = 0;
    for (i = len; i--; a /= RADIX)               /*  big-endian addition      */
    {
        a += p[i] + q[i];                        /*  a /= RADIX is equivalent */
        p[i] = a % RADIX;                        /*  ..to: a = (a >= RADIX)   */
    }
}

/** subtract two numbers in base-RADIX represented by q and p, so that p -= q */
static void subRadix( const rbase_t* q, const size_t len, rbase_t* p )
{
    size_t i, s = 1;
    for (i = len; i--; s /= RADIX)               /*  big-endian subtraction   */
    {
        s += RADIX - 1 + p[i] - q[i];
        p[i] = s % RADIX;
    }
}

/** derive C at step i of FF1 rounds, given the values: u, v and PRF_init = P */
static void FF1round( const uint8_t i, const block_t P,
                      const size_t u, const size_t v, rbase_t* C )
{
    uint8_t* num = (void*) (C + u);              /* use pre-allocated memory  */
    block_t R = { 0 };
    size_t k = bb % sizeof R, ext = (i & 1) * u;

    numRadix( C - v - ext, v, num, bb );         /* ..to get NUM_radix(B)     */
    R[LAST - k] = i;

    memcpy( R - k + sizeof R, num, k );          /* feed NUM_radix to the PRF */
    xMac( P, BLOCKSIZE, R, &rijndaelEncrypt, R );
    xMac( num + k, bb - k, R, &rijndaelEncrypt, R );

    memcpy( num, R, sizeof R );                  /* R = PRF(P || Q)           */
    k = (bb + 3L) / sizeof R;                    /* total additional blocks   */

    for (ext = 0; k; ext = k--)
    {                                            /* S = R | Enc(R ^[k]) | ... */
        ext ^= k;
        xorBEint( R, ext, LAST );
        rijndaelEncrypt( R, num + k * sizeof R );
    }
    strRadix( num, (bb + 7) & ~3L, C, u );       /* take first 'd' bytes of S */
}

/** encrypt/decrypt a base-RADIX string X with length len using FF1 algorithm */
static void FF1_cipher( const uint8_t* key, const char mode, const size_t len,
                        const uint8_t* tweak, const size_t tweakLen,
                        rbase_t* X )
{
    size_t u = (len + !mode) / 2, t = tweakLen;
    rbase_t* Xc = X + len;
    block_t P = { 1, 2, 1, RADIX >> 16, RADIX >> 8 & 0xFF, RADIX & 0xFF, 10 };
    uint8_t i = t % BLOCKSIZE;

    i *= i <= (uint8_t) ~bb % BLOCKSIZE;         /*  if i > (t+bb)%16 : i = 0 */
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
    for (; i < 10 * mode; u = len - u)           /*  Feistel procedure        */
    {                                            /*  encryption rounds        */
        FF1round( i++, P, u, len - u, Xc );
        addRadix( Xc, u, i & 1 ? X : Xc - u );   /*  add C to A then swap A,B */
    }
    for (i ^= 10; i != 0; u = len - u)           /*  decryption rounds        */
    {
        FF1round( --i, P, u, len - u, Xc );
        subRadix( Xc, u, i & 1 ? Xc - u : X );   /*  subtract C from A        */
    }
    BURN( RoundKey );
}
#else                                            /*  FF3/FF3-1 method:        */

/** converts a string in base-RADIX to a little-endian number, denoted by num */
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

/** add two numbers in base-RADIX represented by q and p, so that: p = p + q; */
static void addRadix( const rbase_t* q, const uint8_t len, rbase_t* p )
{
    size_t i, a = 0;
    for (i = 0; i < len; a /= RADIX)             /* little-endian addition    */
    {
        a += p[i] + q[i];
        p[i++] = a % RADIX;
    }
}

/** subtract two numbers in base-RADIX represented by q and p, so that p -= q */
static void subRadix( const rbase_t* q, const uint8_t len, rbase_t* p )
{
    size_t i, s = 1;
    for (i = 0; i < len; s /= RADIX)             /* little-endian subtraction */
    {
        s += RADIX - 1 + p[i] - q[i];
        p[i++] = s % RADIX;
    }
}

/** calculate C at step i of FF3 rounds, given the values: u, v and tweak (T) */
static void FF3round( const uint8_t i, const uint8_t* T,
                      const uint8_t u, const uint8_t v, rbase_t* C )
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
static void FF3_cipher( const uint8_t* key, const char mode, const uint8_t len,
                        const uint8_t* tweak, rbase_t* X )
{
    rbase_t* Xc = X + len;
    uint8_t T[8], u = (len + mode) / 2, *k = (void*) Xc, i;

    memcpy( k, tweak, FF3_TWEAK_LEN );
#if FF3_TWEAK_LEN ==  7
    k[7] = (uint8_t) (k[3] << 4);                /*  see the comments at the  */
    k[3] &= 0xF0;                                /*  ..bottom of header file  */
#endif

    for (i = 8; i --> 0; )  T[7 - i] = k[i];
    for (i = KEYSIZE; i; )  k[--i] = *key++;     /*  key/tweak are reversed   */

    AES_setkey( k );
    SABOTAGE( k, KEYSIZE );

    for (; i < 8 * mode; u = len - u)            /*  Feistel procedure        */
    {                                            /*  encryption rounds        */
        FF3round( i++, T, u, len - u, Xc );
        addRadix( Xc, u, i & 1 ? X : Xc - u );   /*  add C to A then swap A,B */
    }
    for (i ^= 8; i != 0; u = len - u)            /*  decryption rounds        */
    {
        FF3round( --i, T, u, len - u, Xc );
        subRadix( Xc, u, i & 1 ? Xc - u : X );
    }
    BURN( RoundKey );
}
#endif /* FF_X */

/*----------------------------------------------------------------------------*\
                            FPE-AES: main functions
\*----------------------------------------------------------------------------*/
#include <stdlib.h>

/** allocate the required memory and validate the input string in FPE mode... */
static char FPEinit( const string_t str, const size_t len, rbase_t** idx )
{
    const string_t alpha = ALPHABET;
    size_t u = (len + 1) / 2;
    size_t n = (len + u) * sizeof (rbase_t);

#if FF_X != 3                                    /*  extra memory is needed.. */
    bb = (size_t) (LOGRDX * u + 8 - 1e-14) / 8;  /*  to store NUM_radix and.. */
    n += (bb + 4 + LAST) & ~LAST;                /*  mix it in Feistel rounds */
#else
    u *= len > MAXLEN ? 0 : sizeof (rbase_t);
    n += u >= KEYSIZE ? 0 : KEYSIZE - u;
#endif

    if (!(len >= MINLEN && u))  return 'L';      /*  invalid string-length    */

    if (!(*idx = malloc( n )))  return 'M';      /*  memory allocation failed */

    for (n = len; n--; )
    {
        for (u = 0; alpha[u] != str[n]; )
        {
            if (++u == RADIX)
            {
                free( *idx );                    /*  invalid character found  */
                return 'C';
            }
        }
        (*idx)[n] = (rbase_t) u;
    }
    return 0;
}

/** make the output string after completing the process of FPE en/decryption. */
static void FPEfinalize( const rbase_t* index, size_t n, void* output )
{
    const string_t alpha = ALPHABET;
    string_t str = output;
    str[n] = 0;                                  /*  null-terminated strings? */

    while (n--)  str[n] = alpha[index[n]];
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
    rbase_t* index = NULL;

    if (FPEinit( pntxt, ptextLen, &index ) != 0)  return M_ENCRYPTION_ERROR;

#if FF_X == 3
    FF3_cipher( key, 1, ptextLen, tweak, index );
#else
    FF1_cipher( key, 1, ptextLen, tweak, tweakLen, index );
#endif
    FPEfinalize( index, ptextLen, crtxt );
    free( index );
    return M_RESULT_SUCCESS;
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
    rbase_t* index = NULL;

    if (FPEinit( crtxt, crtxtLen, &index ) != 0)  return M_DECRYPTION_ERROR;

#if FF_X == 3
    FF3_cipher( key, 0, crtxtLen, tweak, index );
#else
    FF1_cipher( key, 0, crtxtLen, tweak, tweakLen, index );
#endif
    FPEfinalize( index, crtxtLen, pntxt );
    free( index );
    return M_RESULT_SUCCESS;
}
#endif /* FPE */
