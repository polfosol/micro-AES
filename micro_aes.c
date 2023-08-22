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
          Global constants, data types, and important / useful MACROs
\*----------------------------------------------------------------------------*/

#define KEYSIZE AES_KEY_SIZE
#define BLOCKSIZE  (128 / 8)  /* Block length in AES is 'always' 128-bits.    */
#define Nb   (BLOCKSIZE / 4)  /* The number of columns comprising a AES state */
#define Nk     (KEYSIZE / 4)  /* The number of 32 bit words in a key.         */
#define ROUNDS      (Nk + 6)  /* The number of rounds in AES Cipher.          */

#define IMPLEMENT(x) (x) > 0

#define INCREASE_SECURITY  0
#define DONT_USE_FUNCTIONS 0
#define SMALL_CIPHER       0  /* for more info, see the bottom of header file */

/** block_t indicates fixed-size memory blocks, and state_t represents the state
 * matrix. note that state[i][j] means the i-th COLUMN and j-th ROW of matrix */
typedef uint8_t  block_t[BLOCKSIZE];
typedef uint8_t  state_t[Nb][4];

/*----------------------------------------------------------------------------*\
                               Private variables:
\*----------------------------------------------------------------------------*/

/** The array that stores all round keys during the AES key-expansion process */
static uint8_t RoundKey[BLOCKSIZE * ROUNDS + KEYSIZE];

/** Lookup-tables are static constant, so that they can be placed in read-only
 * storage instead of RAM. They can be computed dynamically trading ROM for RAM.
 * This may be useful in (embedded) bootloader applications, where ROM is often
 * limited. Note that sbox[y] = x, if and only if rsbox[x] = y. You may read the
 * wikipedia article for more info: https://en.wikipedia.org/wiki/Rijndael_S-box
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
    "\231a\27+\4~\272w\326&\341i\24cU!\f}";
#endif

/*----------------------------------------------------------------------------*\
                 Auxiliary functions for the Rijndael algorithm
\*----------------------------------------------------------------------------*/

#define SBoxValue(x)       ( sbox[x])
#define InvSBoxValue(x)    (rsbox[x])    /* omitted dynamic s-box calculation */

#define COPY32BIT(x, y)   *(int32_t*) &y  = *(int32_t*) &x
#define XOR32BITS(x, y)   *(int32_t*) &y ^= *(int32_t*) &x

#if DONT_USE_FUNCTIONS

/** note: 'long long' type is NOT supported in C89. so this may throw errors: */
#define xorBlock(x, y)                                    \
{                                                         \
    *(long long*) &(y)[0] ^= *(long long const*) &(x)[0]; \
    *(long long*) &(y)[8] ^= *(long long const*) &(x)[8]; \
}

#define xtime(x)   (x < 0x80 ? x * 2 : x * 2 ^ 0x11b)

#define InvGM(a, b, c, d)          d ^ c ^ b ^ xtime(b) ^ \
        xtime(a) ^ (xtime(xtime(a))) ^  (xtime(xtime(c))) \
        ^ xtime(xtime(xtime(a))) ^ xtime(xtime(xtime(b))) \
        ^ xtime(xtime(xtime(c))) ^ xtime(xtime(xtime(d)))
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
#define InvGM(a, b, c, d)  gmul(a, 14) ^ gmul(b, 11) ^ gmul(c, 13) ^ gmul(d, 9)

/** This function multiplies two numbers in the Galois bit field of GF(2^8).. */
static uint8_t gmul( uint8_t x, uint8_t y )
{
    uint8_t m;
    for (m = 0; y > 1; y >>= 1)          /* optimized algorithm for nonzero y */
    {
        if (y & 01)  m ^= x;
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

    for (i = KEYSIZE; i < BLOCKSIZE * (ROUNDS + 1); i += 4)
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
            XOR32BITS( RoundKey[(i - 4)], RoundKey[i] );
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
 * with a different offset (= Row number). So the first row won't be shifted. */
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

/** Mix the columns of the state matrix. See: crypto.stackexchange.com/q/2402 */
static void MixColumns( state_t *state )
{
    uint8_t a, b, c, d, i;
    for (i = 0; i < Nb; ++i)
    {
        a  = (*state)[i][0] ^ (*state)[i][1];
        b  = (*state)[i][1] ^ (*state)[i][2];
        c  = (*state)[i][2] ^ (*state)[i][3];

        d  = a ^ c;                 /*  d is XOR of all elements in a column  */
        (*state)[i][0] ^= d ^ xtime( a );
        (*state)[i][1] ^= d ^ xtime( b );

        b ^= d;                     /* -> b = (*state)[i][3] ^ (*state)[i][0] */
        (*state)[i][2] ^= d ^ xtime( c );
        (*state)[i][3] ^= d ^ xtime( b );
    }
}

/** Encrypt a plaintext input block and save the result/ciphertext as output. */
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
    uint8_t i, c[4];
    for (i = 0; i < Nb; ++i)        /*  see: crypto.stackexchange.com/q/2569  */
    {
        COPY32BIT( (*state)[i], c[0] );
        (*state)[i][0] = InvGM( c[0], c[1], c[2], c[3] );
        (*state)[i][1] = InvGM( c[1], c[2], c[3], c[0] );
        (*state)[i][2] = InvGM( c[2], c[3], c[0], c[1] );
        (*state)[i][3] = InvGM( c[3], c[0], c[1], c[2] );
    }
}

/** Decrypt a ciphertext input block and save the result/plaintext to output. */
static void rijndaelDecrypt( const block_t input, block_t output )
{
    uint8_t r;
    state_t *state = (void*) output;

    /* copy input to the state matrix, i.e initialize the state by ciphertext */
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
    KeyExpansion( key );
    mode & 1 ? rijndaelEncrypt( x, y ) : rijndaelDecrypt( x, y );
}
#endif

/*----------------------------------------------------------------------------*\
 *              Implementation of different block ciphers modes               *
 *                     Definitions & Auxiliary Functions                      *
\*----------------------------------------------------------------------------*/

#define AES_SetKey(key)     KeyExpansion( key )

/** function-pointer types, indicating functions that take fixed-size blocks: */
typedef void (*fdouble_t)( block_t );
typedef void (*fmix_t)( const block_t, block_t );

#define LAST (BLOCKSIZE - 1)                     /*  last index in a block    */

#if INCREASE_SECURITY
#define BURN(key)           memset( key, 0, sizeof key )
#define SABOTAGE(buf, len)  memset( buf, 0, len )
#define MISMATCH            constmemcmp          /*  a.k.a secure memcmp      */
#else
#define MISMATCH            memcmp
#define SABOTAGE(buf, len)  (void)  buf
#define BURN(key)           (void)  key          /*  the line is ignored.     */
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

#define incBlock(block, big)    ++block[big ? LAST : 0]
#define xorBENum(buf, num, pos)     buf[pos - 1] ^= (num) >> 8;  buf[pos] ^= num
#define copyLNum(buf, num, pos)     buf[pos + 1]  = (num) >> 8;  buf[pos]  = num

#else
typedef size_t  count_t;

#if CTR || KWA || FPE

/** xor a byte array with a big-endian integer, whose LSB is at specified pos */
static void xorBENum( uint8_t* buff, size_t num, uint8_t pos )
{
    do
        buff[pos--] ^= (uint8_t) num;
    while (num >>= 8);
}
#endif

#if XTS || GCM_SIV

/** copy a little endian integer to the block, with LSB at specified position */
static void copyLNum( block_t block, size_t num, uint8_t pos )
{
    do
        block[pos++] = (uint8_t) num;
    while (num >>= 8);
}
#endif

#if CTR

/** increment the value of a 128-bit counter block, regarding its endian-ness */
static void incBlock( block_t block, uint8_t b )
{
    if (b)                                       /*  big-endian: inc the LSB, */
    {                                            /*  ..until no overflow      */
        for (b = LAST; !++block[b]; )  --b;
        return;
    }
    while (!++block[b])                          /*  little-endian counter    */
    {
        if (++b == 4)  return;
    }
}
#endif
#endif /* SMALL CIPHER */

#if EAX && !EAXP || SIV || OCB || CMAC

/** Multiply a block by two in Galois bit field GF(2^128): big-endian version */
static void doubleBGF128( block_t block )
{
    int i, c = 0;
    for (i = BLOCKSIZE; i > 0; c >>= 8)          /* from last byte (LSB) to   */
    {                                            /* first: left-shift, then   */
        c |= block[--i] << 1;                    /* append the previous MSBit */
        block[i] = (uint8_t) c;
    }                                            /* if first MSBit is carried */
    block[LAST] ^= c * 0x87;                     /* .. B ^= 10000111b (B.E.)  */
}
#endif

#if XTS || EAXP

/** Multiply a block by two in the GF(2^128) field: the little-endian version */
static void doubleLGF128( block_t block )
{
    int c = 0, i;
    for (i = 0; i < BLOCKSIZE; c >>= 8)          /* the same as doubleBGF128  */
    {                                            /* ..but with reversed bytes */
        c |= block[i] << 1;
        block[i++] = (uint8_t) c;
    }
    block[0] ^= c * 0x87;                        /*    B ^= 10000111b (L.E.)  */
}
#endif

#if GCM

/** Divide a block by two in GF(2^128) field: used in big endian, 128bit mul. */
static void halveBGF128( block_t block )
{
    unsigned i, c = 0;
    for (i = 0; i < BLOCKSIZE; c <<= 8)          /* from first to last byte,  */
    {                                            /*  prepend the previous LSB */
        c |= block[i];                           /*  then shift it to right.  */
        block[i++] = (uint8_t) (c >> 1);
    }                                            /* if block is odd (LSB = 1) */
    if (c & 0x100)  block[0] ^= 0xe1;            /* .. B ^= 11100001b << 120  */
}

/** This function carries out multiplication in 128bit Galois field GF(2^128) */
static void mulGF128( const block_t x, block_t y )
{
    block_t result = { 0 };                      /*  working memory           */
    uint8_t b, i = 0;
    do
        for (b = 0x80; b; b >>= 1)               /*  check all the bits of X, */
        {
            if (x[i] & b)                        /*  ..and if any bit is set, */
            {
                xorBlock( y, result );           /*  ..add Y to the result    */
            }
            halveBGF128( y );                    /*  Y_next = (Y / 2) in GF   */
        }
    while (i++ != LAST);

    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* GCM */

#if GCM_SIV

/** Divide a block by two in GF(2^128) field: the little-endian version (duh) */
static void halveLGF128( block_t block )
{
    unsigned c = 0, i;
    for (i = BLOCKSIZE; i > 0; c <<= 8)          /* the same as halveBGF128 ↑ */
    {                                            /* ..but with reversed bytes */
        c |= block[--i];
        block[i] = (uint8_t) (c >> 1);
    }
    if (c & 0x100)  block[LAST] ^= 0xe1;         /* B ^= LE. 11100001b << 120 */
}

/** Dot multiplication in GF(2^128) field: used in POLYVAL hash for GCM-SIV.. */
static void dotGF128( const block_t x, block_t y )
{
    block_t result = { 0 };
    uint8_t b, i = LAST;
    do
        for (b = 0x80; b; b >>= 1)               /*  pretty much the same as  */
        {                                        /*  ..(reversed) mulGF128    */
            halveLGF128( y );
            if (x[i] & b)
            {
                xorBlock( y, result );
            }
        }
    while (i-- != 0);

    memcpy( y, result, sizeof result );          /*  result is saved into y   */
}
#endif /* GCM-SIV */

#if CBC || CFB || OFB || CTR || OCB

/** Result of applying a function to block `B` is xor-ed with `X` to get `Y`. */
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
    for (n = dataSize % BLOCKSIZE; n--; )
    {
        result[n] ^= x[n];
        if (!n)
        {
            mix( seed, result );
        }
    }
}
#endif

#if CMAC || SIV || EAX || OCB

/** calculate the CMAC of input data using pre-calculated keys: D (K1) and Q. */
static void cMac( const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    const uint8_t s = dataSize ? (dataSize - 1) % BLOCKSIZE + 1 : 0;
    const uint8_t *e = s ? (uint8_t const*) data + dataSize - s : &s;

    xMac( data, dataSize - s, mac, &rijndaelEncrypt, mac );
    if (s < BLOCKSIZE)
    {
        mac[s] ^= 0x80;
    }
    xorBlock( s < BLOCKSIZE ? Q : D, mac );      /*  pad( M; D, Q )           */
    xMac( e, s + !s, mac, &rijndaelEncrypt, mac );
}

/** calculate key-dependent constants D and Q using a given doubling function */
static void getSubkeys( fdouble_t fdouble, const char quad,
                        const uint8_t* key, block_t D, block_t Q )
{
    AES_SetKey( key );
    rijndaelEncrypt( D, D );                     /*  H or L_* = Enc(zeros)    */
    if (quad)
    {
        fdouble( D );                            /*  D or L_$ = double(L_*)   */
    }
    memcpy( Q, D, BLOCKSIZE );
    fdouble( Q );                                /*  Q or L_0 = double(L_$)   */
}
#endif

#ifdef AES_PADDING

/** in ECB mode & CBC without CTS, the last (partial) block has to be padded. */
static char padBlock( const uint8_t len, block_t block )
{
#if AES_PADDING
    uint8_t n = BLOCKSIZE - len, *p = &block[len];
    memset( p, n * (AES_PADDING != 2), n );
    *p ^= (0x80) * (AES_PADDING == 2);           /* either PKCS#7 / IEC7816-4 */
#else
    if (len)                                     /* default (zero) padding    */
    {
        memset( block + len, 0, BLOCKSIZE - len );
    }
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
    memcpy( pntxt, crtxt, crtxtLen );            /*  do in-place decryption   */

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
    if (n == 0)  return ENCRYPTION_FAILURE;      /* size of data >= BLOCKSIZE */

    if (r == 0 && --n)  r = BLOCKSIZE;
    n += !n;                                     /*  if single block, set n=1 */
#endif
    memcpy( crtxt, pntxt, ptextLen );            /*  do in-place encryption   */

    AES_SetKey( key );
    for (y = crtxt; n--; y += BLOCKSIZE)
    {
        xorBlock( iv, y );                       /*  C = Enc(IV ^ P)          */
        rijndaelEncrypt( y, y );                 /*  IV_next = C              */
        iv = y;
    }
#if CTS                                          /*  cipher-text stealing CS3 */
    if (r)
    {
        block_t yn = { 0 };
        memcpy( yn, y, r );                      /*  backup the last chunk    */
        memcpy( y, y - BLOCKSIZE, r );           /*  'steal' the cipher-text  */
        y -= BLOCKSIZE;                          /*  ..to fill the last chunk */
        iv = yn;
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
    if (n == 0)  return DECRYPTION_FAILURE;

    if (r == 0 && --n)  r = BLOCKSIZE;
    n -= (r > 0) - !n;                           /*  hold the last two blocks */
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
        mixThenXor( &rijndaelDecrypt, x, y, x + BLOCKSIZE, r, y + BLOCKSIZE );
        memcpy( y, x + BLOCKSIZE, r );
        rijndaelDecrypt( y, y );                 /*  P1 = Dec(T) ^ IV, where  */
        xorBlock( iv, y );                       /*  T = C2 padded by Dec(C1) */
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
    count_t n = ptextLen / BLOCKSIZE;
    uint8_t *y;
    block_t iv;

    memcpy( iv, iVec, sizeof iv );
    memcpy( crtxt, pntxt, ptextLen );            /*  i.e. in-place encryption */

    AES_SetKey( key );
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
 * @brief   the general scheme of operation in block-counter mode
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
                      const uint8_t* pntxt, const size_t ptextLen, uint8_t* crtxt )
{
#if CTR_IV_LENGTH == BLOCKSIZE
#define CTRBLOCK  iv
#else
    block_t CTRBLOCK = { 0 };
    memcpy( CTRBLOCK, iv, CTR_IV_LENGTH );
    xorBENum( CTRBLOCK, CTR_STARTVALUE, LAST );  /*  initialize the counter   */
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
 * @param   tweak     data unit identifier block, similar to nonce in CTR mode
 * @param   sectid    sector id: if the given value is -1, use tweak value
 * @param   dataSize  size of input data, to be encrypted/decrypted
 * @param   T         one-time pad which is xor-ed with both plain/cipher text
 * @param   storage   working memory; result of encryption/decryption process
 */
static void XEX_Cipher( fmix_t cipher, const uint8_t* keypair,
                        const block_t tweak, const size_t sectid,
                        const size_t dataSize, block_t T, void* storage )
{
    uint8_t *y;
    count_t n = dataSize / BLOCKSIZE;

    if (sectid == ~(size_t) 0)
    {                                            /* the `i` block is either   */
        memcpy( T, tweak, BLOCKSIZE );           /* ..a little-endian number  */
    }                                            /* ..or a byte array.        */
    else
    {
        memset( T, 0, BLOCKSIZE );
        copyLNum( T, sectid, 0 );
    }
    AES_SetKey( keypair + KEYSIZE );             /* T = encrypt `i` with key2 */
    rijndaelEncrypt( T, T );

    AES_SetKey( keypair );                       /* key1 is set as cipher key */
    for (y = storage; n--; y += BLOCKSIZE)
    {
        xorBlock( T, y );                        /*  xor T with input         */
        cipher( y, y );
        xorBlock( T, y );                        /*  Y = T ^ Cipher( T ^ X )  */
        doubleLGF128( T );                       /*  T_next = T * alpha       */
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
    uint8_t r = ptextLen % BLOCKSIZE, *c;
    size_t len = ptextLen - r;
    block_t T;

    if (len == 0)  return ENCRYPTION_FAILURE;

    memcpy( crtxt, pntxt, len );                 /*  do in-place encryption   */
    c = crtxt + len - BLOCKSIZE;
    XEX_Cipher( &rijndaelEncrypt, keys, tweak, ~0, len, T, crtxt );
    if (r)
    {                                            /*  XTS for partial block    */
        memcpy( crtxt + len, c, r );             /* 'steal' the cipher-text   */
        memcpy( c, pntxt + len, r );             /*  ..to fill the last chunk */
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
    uint8_t r = crtxtLen % BLOCKSIZE, *p;
    size_t len = crtxtLen - r;
    block_t TT, T;

    if (len == 0)  return DECRYPTION_FAILURE;

    memcpy( pntxt, crtxt, len );                 /*  in-place decryption      */
    p = pntxt + len - BLOCKSIZE;
    XEX_Cipher( &rijndaelDecrypt, keys, tweak, ~0, len - BLOCKSIZE, T, pntxt );
    if (r)
    {
        memcpy( TT, T, sizeof T );
        doubleLGF128( TT );                      /*  TT = T * alpha,          */
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
    getSubkeys( &doubleBGF128, 1, key, K1, K2 );
    cMac( K1, K2, data, dataSize, mac );
    BURN( RoundKey );
}
#endif /* CMAC */


/*----------------------------------------------------------------------------*\
    GCM-AES (Galois counter mode): authentication with GMAC & main functions
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(GCM)

/** calculate the GMAC of ciphertext and AAD using an authentication subkey H */
static void GHash( const block_t H, const void* aData, const void* crtxt,
                   const size_t adataLen, const size_t crtxtLen, block_t gsh )
{
    block_t len = { 0 };
    xorBENum( len, adataLen * 8, LAST / 2 );
    xorBENum( len, crtxtLen * 8, LAST );         /*  save bit-sizes into len  */

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
    uint8_t s = aDataLen < LAST ? aDataLen : sizeof A - 2;

    memcpy( M, iv, BLOCKSIZE );                  /*  initialize CBC-MAC       */
    M[0] |= (CCM_TAG_LEN - 2) << 2;              /*  set some flags on M_*    */
    xorBENum( M, ptextLen, LAST );               /*  copy data size into M_*  */

    if (aDataLen)                                /*  feed aData into CBC-MAC  */
    {
        M[0] |= 0x40;
        rijndaelEncrypt( M, M );                 /*  flag M_* and encrypt it  */
        if (aDataLen > 0xFEFF)
        {                                        /*  assuming aDataLen < 2^32 */
            s -= 4;
            A[0] = 0xFF;  A[1] = 0xFE;           /*  prepend FFFE to aDataLen */
        }
        xorBENum( A, aDataLen, LAST - s );       /*  copy aDataLen into A,    */
        memcpy( A + sizeof A - s, aData, s );    /*  ..and append aData       */
    }

    xMac( A, sizeof A, M, &rijndaelEncrypt, M ); /*  CBC-MAC start of aData,  */
    if (aDataLen > s)                            /*  and then the rest of it  */
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
    uint8_t r = ptextLen % BLOCKSIZE, *D = K[0], *Q = K[1];

    memset( *K, 0, BLOCKSIZE );
    memset( IV, 0, BLOCKSIZE );                  /*  initialize/clear IV      */
    getSubkeys( &doubleBGF128, 1, key, D, Q );
    rijndaelEncrypt( D, Y );                     /*  Y_0 = CMAC(zero block)   */

    /* in case of multiple AAD units, each must be handled the same way as this.
     * e.g. let aData be a 2D array and aDataLen a null-terminated one. then the
     * following three lines starting with `if (aDataLen)` can be replaced by:
     * for (i = 0; *aDataLen; ++i) { cMac( D, Q, aData[i], *aDataLen++, IV ); */
    if (aDataLen)
    {
        cMac( D, Q, aData, aDataLen, IV );
        doubleBGF128( Y );                       /*  Y_$ = double( Y_{i-1} )  */
        xorBlock( IV, Y );                       /*  Y_i = Y_$ ^ CMAC(AAD_i)  */
        memset( IV, 0, BLOCKSIZE );
    }
    if (ptextLen < sizeof Y)
    {                                            /*  for short messages:      */
        doubleBGF128( Y );                       /*  Y = double( Y_n )        */
        r = 0;
    }
    if (r)
    {
        memset( D, 0, BLOCKSIZE );
    }
    xorBlock( Y, D + r );
    cMac( D, D, pntxt, ptextLen - r, IV );       /*  CMAC*( Y  xor_end  M )   */
    if (r)
    {
        cMac( NULL, Q, (const char*) pntxt + ptextLen - r, r, IV );
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
    copyLNum( len, aDataLen * 8, 0 );
    copyLNum( len, ptextLen * 8, 8 );

    xMac( aData, aDataLen, H, &dotGF128, pv );   /*  first digest AAD, then   */
    xMac( pntxt, ptextLen, H, &dotGF128, pv );   /*  ..plaintext, and then    */
    xMac( len, sizeof len, H, &dotGF128, pv );   /*  ..bit sizes into POLYVAL */
}

/** derive the pair of authentication-encryption-keys from main key and nonce */
static void GCMSIV_Init( const uint8_t* key, const uint8_t* nonce, block_t AK )
{
    uint8_t iv[10 * Nb + KEYSIZE], *h, *k;
    k = h = iv + BLOCKSIZE;
    memcpy( iv + 4, nonce, 12 );

    AES_SetKey( key );
    for (*(int32_t*) iv = 0; *iv < 2 + Nk / 2; ++*iv)
    {
        rijndaelEncrypt( iv, k );                /* encrypt & take half, then */
        k += 8;                                  /* ..increment iv's LSB      */
    }
    AES_SetKey( k - KEYSIZE );                   /*  set the main cipher-key  */
    memcpy( AK, h, BLOCKSIZE );                  /*  take authentication key  */
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
    GCMSIV_Init( key, nonce, H );                /* get authentication subkey */

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

    GCMSIV_Init( key, nonce, H );                /* get authentication subkey */
    memcpy( S, crtxt + crtxtLen, tagLen );
    S[LAST] |= 0x80;                             /* tag is IV for CTR cipher  */
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

/** this function calculates the OMAC of a data array using D (K1) and Q (K2) */
static void OMac( const uint8_t t, const block_t D, const block_t Q,
                  const void* data, const size_t dataSize, block_t mac )
{
    int nodata = (!EAXP || t) && !dataSize;
#if EAXP
    const uint8_t* K = t ? Q : D;                /* ↓ ignore null ciphertext  */

    nodata ? memset( mac, 0, BLOCKSIZE ) : memcpy( mac, K, BLOCKSIZE );
#else
    nodata ? memcpy( mac, D, BLOCKSIZE ) : memset( mac, 0, BLOCKSIZE );
    mac[LAST] ^= t;
    rijndaelEncrypt( mac, mac );
#endif
    if (nodata)  return;                         /*  OMAC = CMAC( [t]_n )     */

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
#define F_DOUBLE      doubleLGF128
#else
                      const uint8_t* aData, const size_t aDataLen,
                      uint8_t* crtxt, block_t auTag )
#define F_DOUBLE      doubleBGF128
#define nonceLen      EAX_NONCE_LEN
#endif
{
    block_t D = { 0 }, Q, mac;
    getSubkeys( &F_DOUBLE, 1, key, D, Q );
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
    getSubkeys( &F_DOUBLE, 1, key, D, Q );
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

static block_t OCBsubkeys[4];                    /*  [L_$] [L_*] [Ktop] [Δ_n] */

/** Calculate the offset block (Δ_i) at a specified index, given the initial Δ_0
 * and L$ blocks. This method has minimum memory usage, but it's clearly slow */
static void getDelta( const count_t index, block_t delta )
{
    size_t m, b = 1;
    block_t L;
    memcpy( L, *OCBsubkeys, sizeof L );          /*  initialize L_$           */

    while (b <= index && b)                      /*  we can pre-calculate all */
    {                                            /*  .. L_{i}s to boost speed */
        m = (4 * b - 1) & (index - b);
        b <<= 1;                                 /*  L_0 = double( L_$ )      */
        doubleBGF128( L );                       /*  L_i = double( L_{i-1} )  */
        if (b > m)  xorBlock( L, delta );        /*  Δ_i = Δ_{i-1} ^ L_ntz(i) */
    }
}

/** encrypt or decrypt the input data with OCB method. cipher function is either
 * rijndaelEncrypt or rijndaelDecrypt, and nonce size must be = OCB_NONCE_LEN */
static void OCB_Cipher( fmix_t cipher, const uint8_t* nonce,
                        const size_t dataSize, void* data )
{
    uint8_t *Ls = OCBsubkeys[1], *kt = OCBsubkeys[2], *del = OCBsubkeys[3];
    count_t i = 0, n = nonce[OCB_NONCE_LEN - 1] % 64;
    uint8_t *y = data, r = n % 8;                /*  n = last 6 bits of nonce */

    memcpy( kt + BLOCKSIZE - OCB_NONCE_LEN, nonce, OCB_NONCE_LEN );
    kt[0] = OCB_TAG_LEN << 4 & 0xFF;
    kt[LAST - OCB_NONCE_LEN] |= 1;
    kt[LAST] &= 0xC0;                            /*  clear last 6 bits        */

    rijndaelEncrypt( kt, kt );                   /*  construct K_top          */
    memcpy( del, kt + 1, 8 );                    /*  stretch K_top            */
    xorBlock( kt, del );

    for (n /= 8; i < BLOCKSIZE; ++n)             /* shift the stretched K_top */
    {
        kt[i++] = kt[n] << r | kt[n + 1] >> (8 - r);
    }
    if ((n = dataSize / BLOCKSIZE) == 0)
    {
        memcpy( del, kt, BLOCKSIZE );            /*  initialize Δ_0           */
    }

    for (i = 0; i++ < n; y += BLOCKSIZE)
    {
        memcpy( del, kt, BLOCKSIZE );
        getDelta( i, del );                      /*  calculate Δ_i using my   */
        xorBlock( del, y );                      /*  .. 'magic' algorithm     */
        cipher( y, y );
        xorBlock( del, y );                      /* Y = Δ_i ^ Cipher(Δ_i ^ X) */
    }
    if ((r = dataSize % BLOCKSIZE) != 0)
    {                                            /*  Y_* = Enc(L_* ^ Δ_n) ^ X */
        xorBlock( Ls, del );
        mixThenXor( &rijndaelEncrypt, del, kt, y, r, y );
        del[r] ^= 0x80;                          /*        pad Δ_* (i.e. tag) */
    }
}

static void nop( const block_t x, block_t y ) {}

/** calculate tag and save to Δ_*, using plaintext checksum and PMAC of aData */
static void OCB_GetTag( const void* pntxt, const void* aData,
                        const size_t ptextLen, const size_t aDataLen )
{
    block_t T = { 0 };
    count_t n = aDataLen / BLOCKSIZE;
    uint8_t r = aDataLen % BLOCKSIZE, *tag = OCBsubkeys[3];
    uint8_t const *Ld = OCBsubkeys[0], *Ls = OCBsubkeys[1];
    uint8_t const *xa = (uint8_t const *) aData + aDataLen - r;

    xMac( pntxt, ptextLen, NULL, &nop, tag );    /*  get plaintext checksum   */
    xorBlock( Ld, tag );                         /*  S = Δ_* ^ checksum ^ L_$ */
    rijndaelEncrypt( tag, tag );                 /*  tag_0 = Enc( S )         */

    if (r)                                       /*  PMAC authentication:     */
    {
        getDelta( n, T );
        cMac( NULL, Ls, xa, r, T );              /*  T = Enc(A_* ^ L_* ^ Δ_n) */
        xorBlock( T, tag );                      /*  add it to tag            */
    }
    while (n)
    {
        memcpy( T, xa -= sizeof T, sizeof T );   /*  initialize Δ             */
        getDelta( n--, T );
        rijndaelEncrypt( T, T );                 /*  T_i = Enc(A_i ^ Δ_i)     */
        xorBlock( T, tag );                      /*  add T_i to tag           */
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
    uint8_t *Ld = OCBsubkeys[0], *Ls = OCBsubkeys[1], *tag = OCBsubkeys[3];

    memcpy( crtxt, pntxt, ptextLen);             /* doing in-place encryption */
    memset( Ls, 0, 2 * BLOCKSIZE );
    getSubkeys( &doubleBGF128, 0, key, Ls, Ld );
    OCB_Cipher( &rijndaelEncrypt, nonce, ptextLen, crtxt );
    OCB_GetTag( pntxt, aData, ptextLen, aDataLen );

    memcpy( auTag, tag, OCB_TAG_LEN );
    BURN( RoundKey );
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
    getSubkeys( &doubleBGF128, 0, key, Ls, Ld );
    OCB_Cipher( &rijndaelDecrypt, nonce, crtxtLen, pntxt );
    OCB_GetTag( pntxt, aData, crtxtLen, aDataLen );

    BURN( RoundKey );
    if (MISMATCH( tag, crtxt + crtxtLen, tagLen ))
    {
        SABOTAGE( pntxt, crtxtLen );
        BURN( OCBsubkeys );
        return AUTHENTICATION_FAILURE;
    }
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
 * @param   wrapped   wrapped secret, prepended with an additional half-block
 * @return            error if size is not a multiple of HB, or size < BLOCKSIZE
 */
char AES_KEY_wrap( const uint8_t* kek,
                   const uint8_t* secret, const size_t secretLen, uint8_t* wrapped )
{
    size_t q, i = 0, n = secretLen / HB;         /*  number of semi-blocks    */
    block_t A;

    if (n < 2 || secretLen % HB)  return ENCRYPTION_FAILURE;

    memset( A, 0xA6, HB );                       /*  initialization vector    */
    memcpy( wrapped + HB, secret, secretLen );   /*  copy input to the output */
    AES_SetKey( kek );

    for (q = 6 * n; i < q; )
    {
        uint8_t *r = wrapped + (i++ % n + 1) * HB;
        memcpy( A + HB, r, HB );
        rijndaelEncrypt( A, A );                 /*  A = Enc( V | R_{k-1} )   */
        memcpy( r, A + HB, HB );                 /*  R_{k} = LSB(64, A)       */
        xorBENum( A, i, HB - 1 );                /*  V = MSB(64, A) ^ i       */
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
    size_t i, n = wrapLen / HB;                  /*  number of semi-blocks    */
    block_t A;

    if (n-- < 3 || wrapLen % HB)  return DECRYPTION_FAILURE;

    memcpy( A, wrapped, HB );                    /*  authentication vector    */
    memcpy( secret, wrapped + HB, wrapLen - HB );
    AES_SetKey( kek );

    for (i = 6 * n; i; --i)
    {
        uint8_t *r = secret + ((i - 1) % n) * HB;
        xorBENum( A, i, HB - 1 );
        memcpy( A + HB, r, HB );                 /*  V = MSB(64, A) ^ i       */
        rijndaelDecrypt( A, A );                 /*  A = Dec( V | R_{k} )     */
        memcpy( r, A + HB, HB );                 /*  R_{k-1} = LSB(64, A)     */
    }
    BURN( RoundKey );

    for (n = 0; i < HB; )  n |= A[i++] ^ 0xA6;   /*  authenticate/error check */

    return n ? AUTHENTICATION_FAILURE : ENDED_IN_SUCCESS;
}
#endif /* KWA */


/*----------------------------------------------------------------------------*\
     Poly1305-AES message authentication: auxiliary functions and main API
\*----------------------------------------------------------------------------*/
#if IMPLEMENT(POLY1305)
#define SP  17                                   /* size of poly1305 blocks   */

/** derive modulo(2^130-5) for a little endian block, by repeated subtraction */
static void modP1305( uint8_t* block, const int ovrfl )
{
    uint8_t* msb = block + SP - 1;
    int32_t q = ovrfl << 6 | *msb >> 2;          /*   q = B / (2 ^ 130)       */

    if (!q)  return;

    *msb -= 4 * (uint8_t) q;                     /* first, subtract q * 2^130 */
    for (q *= 5; q; q >>= 8)                     /* since most of the times:  */
    {                                            /*   mod = B - q * (2^130-5) */
        q += *block;                             /* then add (q * 5)          */
        *block++ = (uint8_t) q;
    }
}

/** add two little-endian poly1305 blocks. use modular addition if necessary. */
static void addLBlocks( const uint8_t* x, const uint8_t len, uint8_t* y )
{
    int a, i;
    for (i = a = 0; i < len; a >>= 8)
    {
        a += x[i] + y[i];
        y[i++] = (uint8_t) a;                    /*  a >> 8 is overflow/carry */
    }
    if (i == SP)  modP1305( y, a );
}

/** modular multiplication of two little-endian poly1305 blocks: y *= x mod P */
static void mulLBlocks( const uint8_t* x, uint8_t* y )
{
    uint8_t i, sh, n = SP, prod[SP] = { 0 };     /*  Y = [Y_0][Y_1]...[Y_n]   */
    int32_t m;
    while (n--)                                  /* multiply X by MSB of Y    */
    {                                            /* ..and add to the result   */
        sh = n ? 8 : 0;                          /* ..shift the result if Y   */
        for (m = i = 0; i < SP; m >>= 8)         /* ..has other byte in queue */
        {                                        /* ..but don't shift for Y_0 */
            m += (prod[i] + x[i] * y[n]) << sh;
            prod[i++] = (uint8_t) m;
        }
        modP1305( prod, m );                     /*  modular multiplication   */
    }
    memcpy( y, prod, SP );
}

/** handle some special/rare cases that might be missed by modP1305 function. */
static void cmpToP1305( uint8_t* block )
{
    int c = block[SP - 1] == 3 && *block >= 0xFB ? SP - 1 : block[SP - 1] / 4;
    while (c > 1)
    {
        if (block[--c] < 0xFF)  return;          /* compare block to 2^130-5, */
    }
    for (c *= 5; c; c >>= 8)
    {                                            /* and if (block >= 2^130-5) */
        c += *block;                             /* .. add it with 5          */
        *block++ = (uint8_t) c;
    }
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

    AES_SetKey( keys );
    rijndaelEncrypt( nonce, mac );               /* derive AES_k(nonce)       */
    BURN( RoundKey );

    if (!dataSize)  return;

    memcpy( r, keys + KEYSIZE, s );              /* extract r from (k,r) pair */
    for (r[s] = 0; s > 0; s -= 3)
    {
        r[s--] &= 0xFC;                          /* clear bottom 2 bits       */
        r[s  ] &= 0x0F;                          /* clear top 4 bits          */
    }
    s = dataSize - BLOCKSIZE * q++;              /* size of last chunk        */

    for (pos -= s; q--; pos -= (s = BLOCKSIZE))
    {
        memcpy( c, pos, s );                     /* copy message to chunk     */
        c[s] = 1;                                /* append 1 to each chunk    */
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
#define MAXLEN   0x38                            /*  only if FF_X == 3        */
#endif

#if (RADIX - 1 > 0xFF)
typedef unsigned short  rbase_t;                 /*  digit type in base-radix */
#else
typedef uint8_t  rbase_t;
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
        for (i = bytes; i; y >>= 8)
        {
            y += num[--i] * RADIX;               /*  num = num * RADIX + y    */
            num[i] = (uint8_t) y;
        }
    }
}

/** convert a big-endian number to its base-RADIX representation string: `s`  */
static void strRadix( const uint8_t* num, size_t bytes, rbase_t* s, size_t len )
{
    memset( s, 0, sizeof (rbase_t) * len );
    while (bytes--)
    {
        size_t i, x = *num++;
        for (i = len; i; x /= RADIX)
        {
            x += s[--i] << 8;                    /*  numstr = numstr << 8 + x */
            s[i] = x % RADIX;
        }
    }
}

/** add two numbers in base-RADIX represented by q and p, so that: p = p + q  */
static void rbase_add( const rbase_t* q, const size_t len, rbase_t* p )
{
    size_t i, a = 0;
    for (i = len; i--; a /= RADIX)               /*  big-endian addition      */
    {
        a += p[i] + q[i];                        /*  a /= RADIX is equivalent */
        p[i] = a % RADIX;                        /*  ..to  a = (a >= RADIX)   */
    }
}

/** subtract two numbers in base-RADIX represented by q and p, so that p -= q */
static void rbase_sub( const rbase_t* q, const size_t len, rbase_t* p )
{
    size_t i, s = 1;
    for (i = len; i--; s /= RADIX)               /*  big-endian subtraction   */
    {
        s += RADIX - 1 + p[i] - q[i];
        p[i] = s % RADIX;
    }
}

/** derive C at step i of FF1 rounds, given string size len, u and PRF_init P */
static void FF1round( const uint8_t i, const block_t P, const size_t u,
                      const size_t len, rbase_t* C )
{
    size_t k = bb % BLOCKSIZE, d = (bb + 7) & ~3UL, a = i & 1 ? len : len - u;
    block_t R = { 0 };
    uint8_t* num = (void*) (C + u);              /* use pre-allocated memory  */

    R[LAST - k] = i;
    numRadix( C - a, len - u, num, bb );         /* get NUM_radix(B) and      */
    memcpy( R + sizeof R - k, num, k );          /* ..then feed it into PRF:  */

    xMac( P, BLOCKSIZE, R, &rijndaelEncrypt, R );
    xMac( num + k, bb - k, R, &rijndaelEncrypt, R );

    memcpy( num, R, sizeof R );                  /* R = PRF(P || Q)           */
    k = (d - 0x1) / sizeof R;                    /* total additional blocks   */
    for (num += k * sizeof R; k; --k)
    {
        memcpy( num, R, sizeof R );
        xorBENum( num, k, LAST );                /* num = R || R ^ [k] ||...  */
        rijndaelEncrypt( num, num );             /* S = R || Enc(R ^ [k])...  */
        num -= sizeof R;
    }
    strRadix( num, d, C, u );                    /* take first d bytes of S   */
}

/** encrypt/decrypt a base-RADIX string X with length len using FF1 algorithm */
static void FF1_Cipher( const uint8_t* key, const char mode, const size_t len,
                        const uint8_t* tweak, const size_t tweakLen,
                        rbase_t* X )
{
    size_t u = (len + !mode) / 2, t = tweakLen;
    rbase_t* Xc = X + len;
    block_t P = { 1, 2, 1, RADIX >> 16, RADIX >> 8 & 0xFF, RADIX & 0xFF, 10 };
    uint8_t i = tweakLen % BLOCKSIZE;

    if (i > (uint8_t) ~bb % BLOCKSIZE)  i = 0;

    P[7] = len / 2 & 0xFF;                       /* P = [1,2,1][radix][10]... */
    xorBENum( P, len, 11 );
    xorBENum( P, t, LAST );

    AES_SetKey( key );
    rijndaelEncrypt( P, P );                     /* P -> PRF(P || tweak)      */
    xMac( tweak, t - i, P, &rijndaelEncrypt, P );
    while (i)
    {
        P[--i] ^= tweak[--t];
    }
    for ( ; i < 10 * mode; u = len - u)          /* Feistel procedure         */
    {
        FF1round( i++, P, u, len, Xc );          /* encryption rounds         */
        rbase_add( Xc, u, i & 1 ? X : Xc - u );
    }
    for (i ^= 10; i > (0); u = len - u)          /* A → X, C → Xc, B → Xc - u */
    {
        FF1round( --i, P, u, len, Xc );          /* decryption rounds         */
        rbase_sub( Xc, u, i & 1 ? Xc - u : X );
    }
}
#else                                            /*         FF3/FF3-1         */

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

/** add two numbers in base-RADIX represented by q and p, so that: p = p + q  */
static void rbase_add( const rbase_t* q, const uint8_t len, rbase_t* p )
{
    size_t i, a = 0;
    for (i = 0; i < len; a /= RADIX)             /* little-endian addition    */
    {
        a += p[i] + q[i];
        p[i++] = a % RADIX;
    }
}

/** subtract two numbers in base-RADIX represented by q and p, so that p -= q */
static void rbase_sub( const rbase_t* q, const uint8_t len, rbase_t* p )
{
    size_t i, s = 1;
    for (i = 0; i < len; s /= RADIX)             /* little-endian subtraction */
    {
        s += RADIX - 1 + p[i] - q[i];
        p[i++] = s % RADIX;
    }
}

/** calculate C at step i of FF3 rounds, given the string size len, u, and T. */
static void FF3round( const uint8_t i, const uint8_t* T, const uint8_t u,
                      const uint8_t len, rbase_t* C )
{
    uint8_t w = (i & 1) * 4, a = i & 1 ? len : len - u;
    block_t P;
    COPY32BIT( T[w], P[12] );                    /*  W = (i is odd) ? TR : TL */
    P[12] ^= i;

    numRadix( C - a, len - u, P, 12 );           /*  get REV. NUM_radix( B )  */
    rijndaelEncrypt( P, P );
    strRadix( P, sizeof P, C, u );               /*  C = REV. STR_m( c )      */
}

/** encrypt/decrypt a base-RADIX string X with size len using FF3-1 algorithm */
static void FF3_Cipher( const uint8_t* key, const char mode,
                        const uint8_t len, const uint8_t* tweak, rbase_t* X )
{
    rbase_t* Xc = X + len;
    uint8_t T[8], u = (len + mode) / 2, *k = (void*) Xc, i;

    memcpy( k, tweak, FF3_TWEAK_LEN );
#if FF3_TWEAK_LEN ==  7                          /*  old version of FF3 had a */
    k[7] = (uint8_t) (k[3] << 4);                /* ..64-bit tweak. but FF3-1 */
    k[3] &= 0xF0;                                /* ..tweaks must be 56-bit   */
#endif

    for (i = 8; i --> 0; )  T[i] = k[7 - i];
    for (i = KEYSIZE; i; )  k[--i] = *key++;     /*  key/tweak are reversed   */

    AES_SetKey( k );
    SABOTAGE( k, KEYSIZE );

    for ( ; i < 8 * mode; u = len - u)           /*  Feistel procedure        */
    {
        FF3round( i++, T, u, len, Xc );          /*  encryption rounds        */
        rbase_add( Xc, u, i & 1 ? X : Xc - u );
    }
    for (i ^= (8); i > 0; u = len - u)           /* A → X, C → Xc, B → Xc - u */
    {
        FF3round( --i, T, u, len, Xc );          /*  decryption rounds        */
        rbase_sub( Xc, u, i & 1 ? Xc - u : X );
    }
}
#endif /* FF_X */

/*----------------------------------------------------------------------------*\
                            FPE-AES: main functions
\*----------------------------------------------------------------------------*/
#include <stdlib.h>

/** allocate the required memory and validate the input string in FPE mode... */
static char FPEinit( const string_t str, const size_t len, rbase_t** indices )
{
    const string_t alpha = ALPHABET;
    size_t i = (len + 1) / 2;
    size_t n = (len + i) * sizeof (rbase_t);

#if FF_X != 3                                    /*  extra memory is needed.. */
    bb = (size_t) (LOGRDX * i + 8 - 1e-10) / 8;  /*  to store NUM_radix and.. */
    n += (bb + 3 + BLOCKSIZE) & ~15UL;           /*  mix it in Feistel rounds */
#else
    i *= len > MAXLEN ? 0 : sizeof (rbase_t);
    n += i >= KEYSIZE ? 0 : KEYSIZE - i;
#endif

    if (len < MINLEN || i == 0)  return 'L';     /*  invalid string-length    */

    *indices = malloc( n );
    if (*indices == NULL)  return 'M';           /*  memory allocation failed */

    for (n = 0; n < len; ++n)
    {
        for (i = 0; alpha[i] != str[n]; )
        {
            if (++i == RADIX)
            {
                free( *indices );                /*  invalid character found  */
                return 'C';
            }
        }
        (*indices)[n] = (rbase_t) i;
    }
    return 0;
}

/** make the output string after completing FPE encrypt/decryption procedures */
static void FPEfinalize( const rbase_t* index, const size_t len, void* output )
{
    const string_t abc = ALPHABET;
    string_t str = output;
    size_t i;
    BURN( RoundKey );

    str[len] = 0;                                /*  null-terminated strings? */
    for (i = len; i--; )  str[i] = abc[index[i]];
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
    if (FPEinit( pntxt, ptextLen, &index ) != 0)  return ENCRYPTION_FAILURE;

#if FF_X == 3
    FF3_Cipher( key, 1, ptextLen, tweak, index );
#else
    FF1_Cipher( key, 1, ptextLen, tweak, tweakLen, index );
#endif
    FPEfinalize( index, ptextLen, crtxt );
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
    rbase_t* index = NULL;
    if (FPEinit( crtxt, crtxtLen, &index ) != 0)  return DECRYPTION_FAILURE;

#if FF_X == 3
    FF3_Cipher( key, 0, crtxtLen, tweak, index );
#else
    FF1_Cipher( key, 0, crtxtLen, tweak, tweakLen, index );
#endif
    FPEfinalize( index, crtxtLen, pntxt );
    free( index );
    return ENDED_IN_SUCCESS;
}
#endif /* FPE */
