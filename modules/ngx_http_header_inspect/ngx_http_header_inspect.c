/*
 * ngx_http_header_inspect - Inspect HTTP headers
 *
 * Copyright (c) 2011, Andreas Jaggi <andreas.jaggi@waterwave.ch>
 */


/*
 * IronFox header inspector
 * Copyright (c) 2019, Khalegh Salehi <khaleghsalehi@gmail.com)
 *
 *
 * IronFox valid request hashmap's (key,value) template
 * +------------------------+----------------------+--------------------------------- ---------------------------------+
 * | Key magic code Len(4)  |  Key body Len(48)    | Value Len(60)                                                     |
 * +------------------------+----------------------+-------------------------------------------------------------------+
 * 1268abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR   D533CB822B97D2D8B0159825AD300E07 AlfdJrkVZ0u4QmSu8bbNcw2ynKXX
 * 1268abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR   A857F30D57D818D9E59D8264B1C3D077 YgE1S0RiaaGfDEi6DPiJ6D5D6l8A
 * 0.............................................47   48............................79 80.......................107
 *              48                                          32                                28
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_array.h>

#define HASH_CODE_LEN_MAX 256
#define SDK_VERSION "0.09.0"
#define MAGIC_LEN 4
#define HEADER_KEY_LEN 48
#define HEADER_VAL_LEN 64
#define IRON_FOX_HEADER_NAME "ironfoxhash"

#include <hiredis/hiredis.h>
#include <ngx_log.h>
//#include "ironaes.h"







// all of AES  here

/*

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97
    f5d3d58503b9699de785895a96fdbaaf
    43b1cd7f598ece23881b00e3ed030688
    7b0c785e27e8ad3f8223207104725dd4


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include <string.h> // CBC mode, for memset
//#include "ironaes.h"






//~~~~~~~~~~~~~~~~~


#include <stdint.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
#define CBC 1
#endif

#ifndef ECB
#define ECB 1
#endif

#ifndef CTR
#define CTR 1
#endif


#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
#define AES_KEYLEN 32
#define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
#define AES_KEYLEN 24
#define AES_keyExpSize 208
#else
#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176
#endif

struct AES_ctx {
    uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
    uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);

#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);

void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);

#endif

#if defined(ECB) && (ECB == 1)

// buffer size is exactly AES_BLOCKLEN bytes;
// you need only AES_init_ctx as IV is not used in ECB
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);

void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)

// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length);

void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting.
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length);

#endif // #if defined(CTR) && (CTR == 1)





//~~~~~~~~~~~~~~~~~













/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
#define Nk 8
#define Nr 14
#elif defined(AES192) && (AES192 == 1)
#define Nk 6
#define Nr 12
#else
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.
#endif

// jcallan@github points out that declaring Multiply as a function
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];


// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
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
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rsbox[256] = {
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
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 *
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed),
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key) {
    unsigned i, j, k;
    uint8_t tempa[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for (i = 0; i < Nk; ++i) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        {
            k = (i - 1) * 4;
            tempa[0] = RoundKey[k + 0];
            tempa[1] = RoundKey[k + 1];
            tempa[2] = RoundKey[k + 2];
            tempa[3] = RoundKey[k + 3];

        }

        if (i % Nk == 0) {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            {
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }

            tempa[0] = tempa[0] ^ Rcon[i / Nk];
        }
#if defined(AES256) && (AES256 == 1)
        if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
        j = i * 4;
        k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key) {
    KeyExpansion(ctx->RoundKey, key);
}

#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv) {
    KeyExpansion(ctx->RoundKey, key);
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv) {
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t *state) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t *state) {
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t *state) {
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i) {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1];
        Tm = xtime(Tm);
        (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2];
        Tm = xtime(Tm);
        (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3];
        Tm = xtime(Tm);
        (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t;
        Tm = xtime(Tm);
        (*state)[i][3] ^= Tm ^ Tmp;
    }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t *state) {
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i) {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t *state) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = getSBoxInvert((*state)[j][i]);
        }
    }
}

static void InvShiftRows(state_t *state) {
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}

#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t *state, const uint8_t *RoundKey) {
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

static void InvCipher(state_t *state, const uint8_t *RoundKey) {
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(Nr, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = (Nr - 1); round > 0; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        InvMixColumns(state);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, RoundKey);
}

#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)


void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf) {
    // The next function call encrypts the PlainText with the Key using AES algorithm.
    Cipher((state_t *) buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf) {
    // The next function call decrypts the PlainText with the Key using AES algorithm.
    InvCipher((state_t *) buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)


#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t *buf, const uint8_t *Iv) {
    uint8_t i;
    for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
    {
        buf[i] ^= Iv[i];
    }
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length) {
    uintptr_t i;
    uint8_t *Iv = ctx->Iv;
    for (i = 0; i < length; i += AES_BLOCKLEN) {
        XorWithIv(buf, Iv);
        Cipher((state_t *) buf, ctx->RoundKey);
        Iv = buf;
        buf += AES_BLOCKLEN;
        //printf("Step %d - %d", i/16, i);
    }
    /* store Iv in ctx for next call */
    memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length) {
    uintptr_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];
    for (i = 0; i < length; i += AES_BLOCKLEN) {
        memcpy(storeNextIv, buf, AES_BLOCKLEN);
        InvCipher((state_t *) buf, ctx->RoundKey);
        XorWithIv(buf, ctx->Iv);
        memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }

}

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length) {
    uint8_t buffer[AES_BLOCKLEN];

    unsigned i;
    int bi;
    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi) {
        if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
        {

            memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t *) buffer, ctx->RoundKey);

            /* Increment Iv and handle overflow */
            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi) {
                /* inc will overflow */
                if (ctx->Iv[bi] == 255) {
                    ctx->Iv[bi] = 0;
                    continue;
                }
                ctx->Iv[bi] += 1;
                break;
            }
            bi = 0;
        }

        buf[i] = (buf[i] ^ buffer[bi]);
    }
}

#endif // #if defined(CTR) && (CTR == 1)







// end of  AES
//todo refactor AES,











static ngx_int_t
get_and_check(redisContext *con, char *key, char *value, ngx_log_t *log);


typedef struct {
    ngx_flag_t inspect;
    ngx_flag_t log;
    ngx_flag_t log_uninspected;
    ngx_flag_t block;

    ngx_uint_t range_max_byteranges;
} ngx_header_inspect_loc_conf_t;


static ngx_int_t ngx_header_inspect_init(ngx_conf_t *cf);

static ngx_int_t ngx_header_inspect_http_date(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len);

static ngx_int_t
ngx_header_inspect_parse_base64(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, u_char *data,
                                ngx_uint_t maxlen);

static ngx_int_t ngx_header_inspect_parse_entity_tag(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len);

static ngx_int_t ngx_header_inspect_parse_languagerange(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len);

static ngx_int_t ngx_header_inspect_range_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_acceptencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_contentencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_acceptlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_contentlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_acceptcharset_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_digit_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_ifmatch_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t ngx_header_inspect_allow_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t ngx_header_inspect_host_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t ngx_header_inspect_accept_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_conection_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_contentrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_useragent_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_upgrade_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t ngx_header_inspect_via_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t ngx_header_inspect_from_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_ifrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t ngx_header_inspect_pragma_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_contenttype_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_date_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, char *header, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_contentmd5_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_authorization_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log,
                                        ngx_str_t value);

static ngx_int_t ngx_header_inspect_expect_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_warning_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_trailer_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_transferencoding_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log,
                                           ngx_str_t value);

static ngx_int_t
ngx_header_inspect_referer_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t
ngx_header_inspect_cachecontrol_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);

static ngx_int_t ngx_header_inspect_process_request(ngx_http_request_t *r);

static void *ngx_header_inspect_create_conf(ngx_conf_t *cf);

static char *ngx_header_inspect_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t ngx_header_inspect_commands[] = {
        {
                ngx_string("inspect_headers"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, inspect),
                NULL
        },
        {
                ngx_string("inspect_headers_log_violations"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, log),
                NULL
        },
        {
                ngx_string("inspect_headers_block_violations"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, block),
                NULL
        },
        {
                ngx_string("inspect_headers_log_uninspected"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, log_uninspected),
                NULL
        },
        {
                ngx_string("inspect_headers_range_max_byteranges"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_num_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, range_max_byteranges),
                NULL
        },
        ngx_null_command
};

static ngx_http_module_t ngx_header_inspect_module_ctx = {
        NULL,                             /* preconfiguration */
        ngx_header_inspect_init,          /* postconfiguration */

        NULL,                             /* create main configuration */
        NULL,                             /* init main configuration */

        NULL,                             /* create server configuration */
        NULL,                             /* merge server configuration */

        ngx_header_inspect_create_conf,   /* create location configuration */
        ngx_header_inspect_merge_conf,    /* merge location configuration */
};

ngx_module_t ngx_http_header_inspect_module = {
        NGX_MODULE_V1,
        &ngx_header_inspect_module_ctx, /* module context */
        ngx_header_inspect_commands,    /* module directives */
        NGX_HTTP_MODULE,                /* module type */
        NULL,                           /* init master */
        NULL,                           /* init module */
        NULL,                           /* init process */
        NULL,                           /* init thread */
        NULL,                           /* exit thread */
        NULL,                           /* exit process */
        NULL,                           /* exit master */
        NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_header_inspect_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_header_inspect_process_request;

    return NGX_OK;
}

static ngx_int_t ngx_header_inspect_range_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i, a, b, setcount;
    ngx_int_t rc = NGX_OK;
    enum range_header_states {
        RHS_NEWSET, RHS_NUM1, DELIM, RHS_NUM2, RHS_SUFDELIM, RHS_SUFNUM
    } state;

    if ((value.len < 6) || (ngx_strncmp("bytes=", value.data, 6) != 0)) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Range header does not start with \"bytes=\"");
        }
        rc = NGX_ERROR;
    }

    setcount = 1;
    a = 0;
    b = 0;
    state = RHS_NEWSET;

    i = 6; /* start after bytes= */
    for (; i < value.len; i++) {

        switch (value.data[i]) {
            case ',':
                if ((state != DELIM) && (state != RHS_NUM2) && (state != RHS_SUFNUM)) {
                    if (conf->log) {
                        ngx_log_error(NGX_LOG_ALERT, log, 0,
                                      "header_inspect: unexpected ',' at position %d in Range header \"%s\"", i,
                                      value.data);
                    }
                    rc = NGX_ERROR;
                }
                if (state == RHS_NUM2) {
                    /* verify a <= b in 'a-b' sets */
                    if (a > b) {
                        if (conf->log) {
                            ngx_log_error(NGX_LOG_ALERT, log, 0,
                                          "header_inspect: invalid range definition at position %d in Range header \"%s\"",
                                          i, value.data);
                        }
                        rc = NGX_ERROR;
                    }
                }
                setcount++;
                a = 0;
                b = 0;
                state = RHS_NEWSET;
                break;

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                if ((state == RHS_NEWSET) || (state == RHS_NUM1)) {
                    a = a * 10 + (value.data[i] - '0');
                    state = RHS_NUM1;
                } else if ((state == DELIM) || (state == RHS_NUM2)) {
                    b = b * 10 + (value.data[i] - '0');
                    state = RHS_NUM2;
                } else if ((state == RHS_SUFDELIM) || (state == RHS_SUFNUM)) {
                    state = RHS_SUFNUM;
                } else {
                    if (conf->log) {
                        ngx_log_error(NGX_LOG_ALERT, log, 0,
                                      "header_inspect: unexpected digit at position %d in Range header \"%s\"", i,
                                      value.data);
                    }
                    rc = NGX_ERROR;
                }
                break;

            case '-':
                if (state == RHS_NEWSET) {
                    state = RHS_SUFDELIM;
                } else if (state == RHS_NUM1) {
                    state = DELIM;
                } else {
                    if (conf->log) {
                        ngx_log_error(NGX_LOG_ALERT, log, 0,
                                      "header_inspect: unexpected '-' at position %d in Range header \"%s\"", i,
                                      value.data);
                    }
                    rc = NGX_ERROR;
                }
                break;

            default:
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: illegal char at position %d in Range header \"%s\"", i, value.data);
                }
                rc = NGX_ERROR;
        }

        if (setcount > conf->range_max_byteranges) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Range header contains more than %d byteranges",
                              conf->range_max_byteranges);
            }
            return NGX_ERROR;
            break;
        }
    }

    if ((state != DELIM) && (state != RHS_NUM2) && (state != RHS_SUFNUM)) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "header_inspect: Range header \"%s\" contains incomplete byteset definition", value.data);
        }
        rc = NGX_ERROR;
    }
    if (state == RHS_NUM2) {
        /* verify a <= b in 'a-b' sets */
        if (a > b) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid range definition at position %d in Range header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
        }
    }

    return rc;
}

static ngx_int_t ngx_header_inspect_http_date(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
    ngx_uint_t i = 0;
    enum http_date_type {
        RFC1123, RFC850, ASCTIME
    } type;

    if (maxlen < 24) {
        *len = i;
        return NGX_ERROR;
    }

    if ((data[0] == 'M') && (data[1] == 'o') && (data[2] == 'n')) {
        /* Mon(day) */
        switch (data[3]) {
            case ',':
                type = RFC1123;
                i = 4;
                break;
            case ' ':
                type = ASCTIME;
                i = 3;
                break;
            case 'd':
                type = RFC850;
                if (
                        (data[4] != 'a') ||
                        (data[5] != 'y') ||
                        (data[6] != ',')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i = 7;
                break;
            default:
                *len = i;
                return NGX_ERROR;
        }
    } else if ((data[0] == 'T') && (data[1] == 'u') && (data[2] == 'e')) {
        /* Tue(sday) */
        switch (data[3]) {
            case ',':
                type = RFC1123;
                i = 4;
                break;
            case ' ':
                type = ASCTIME;
                i = 3;
                break;
            case 's':
                type = RFC850;
                if (
                        (data[4] != 'd') ||
                        (data[5] != 'a') ||
                        (data[6] != 'y') ||
                        (data[7] != ',')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i = 8;
                break;
            default:
                *len = i;
                return NGX_ERROR;
        }
    } else if ((data[0] == 'W') && (data[1] == 'e') && (data[2] == 'd')) {
        /* Wed(nesday) */
        switch (data[3]) {
            case ',':
                type = RFC1123;
                i = 4;
                break;
            case ' ':
                type = ASCTIME;
                i = 3;
                break;
            case 'n':
                type = RFC850;
                if (
                        (data[4] != 'e') ||
                        (data[5] != 's') ||
                        (data[6] != 'd') ||
                        (data[7] != 'a') ||
                        (data[8] != 'y') ||
                        (data[9] != ',')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i = 10;
                break;
            default:
                *len = i;
                return NGX_ERROR;
        }
    } else if ((data[0] == 'T') && (data[1] == 'h') && (data[2] == 'u')) {
        /* Thu(rsday) */
        switch (data[3]) {
            case ',':
                type = RFC1123;
                i = 4;
                break;
            case ' ':
                type = ASCTIME;
                i = 3;
                break;
            case 'r':
                type = RFC850;
                if (
                        (data[4] != 's') ||
                        (data[5] != 'd') ||
                        (data[6] != 'a') ||
                        (data[7] != 'y') ||
                        (data[8] != ',')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i = 9;
                break;
            default:
                *len = i;
                return NGX_ERROR;
        }
    } else if ((data[0] == 'F') && (data[1] == 'r') && (data[2] == 'i')) {
        /* Fri(day) */
        switch (data[3]) {
            case ',':
                type = RFC1123;
                i = 4;
                break;
            case ' ':
                type = ASCTIME;
                i = 3;
                break;
            case 'd':
                type = RFC850;
                if (
                        (data[4] != 'a') ||
                        (data[5] != 'y') ||
                        (data[6] != ',')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i = 7;
                break;
            default:
                *len = i;
                return NGX_ERROR;
        }
    } else if ((data[0] == 'S') && (data[1] == 'a') && (data[2] == 't')) {
        /* Sat(urday) */
        switch (data[3]) {
            case ',':
                type = RFC1123;
                i = 4;
                break;
            case ' ':
                type = ASCTIME;
                i = 3;
                break;
            case 'u':
                type = RFC850;
                if (
                        (data[4] != 'r') ||
                        (data[5] != 'd') ||
                        (data[6] != 'a') ||
                        (data[7] != 'y') ||
                        (data[8] != ',')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i = 9;
                break;
            default:
                *len = i;
                return NGX_ERROR;
        }
    } else if ((data[0] == 'S') && (data[1] == 'u') && (data[2] == 'n')) {
        /* Sun(day) */
        switch (data[3]) {
            case ',':
                type = RFC1123;
                i = 4;
                break;
            case ' ':
                type = ASCTIME;
                i = 3;
                break;
            case 'd':
                type = RFC850;
                if (
                        (data[4] != 'a') ||
                        (data[5] != 'y') ||
                        (data[6] != ',')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i = 7;
                break;
            default:
                *len = i;
                return NGX_ERROR;
        }
    } else {
        *len = i;
        return NGX_ERROR;
    }

    switch (type) {
        case RFC1123:
            if (maxlen < 29) {
                *len = i;
                return NGX_ERROR;
            }
            break;
        case RFC850:
            if (maxlen < 30) {
                *len = i;
                return NGX_ERROR;
            }
            break;
        case ASCTIME:
            if (maxlen < 24) {
                *len = i;
                return NGX_ERROR;
            }
            break;
        default:
            *len = i;
            return NGX_ERROR;
    }

    if (data[i] != ' ') {
        *len = i;
        return NGX_ERROR;
    }
    i++;

    if (type == RFC1123) {
        /* rfc1123: day */
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if (data[i] != ' ') {
            *len = i;
            return NGX_ERROR;
        }
        i++;
    } else if (type == RFC850) {
        /* rfc850: day */
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if (data[i] != '-') {
            *len = i;
            return NGX_ERROR;
        }
        i++;
    }

    /* month: Nov */
    if (
            ((data[i] == 'J') && (data[i + 1] == 'a') && (data[i + 2] == 'n')) ||
            ((data[i] == 'F') && (data[i + 1] == 'e') && (data[i + 2] == 'b')) ||
            ((data[i] == 'M') && (data[i + 1] == 'a') && (data[i + 2] == 'r')) ||
            ((data[i] == 'A') && (data[i + 1] == 'p') && (data[i + 2] == 'r')) ||
            ((data[i] == 'M') && (data[i + 1] == 'a') && (data[i + 2] == 'y')) ||
            ((data[i] == 'J') && (data[i + 1] == 'u') && (data[i + 2] == 'n')) ||
            ((data[i] == 'J') && (data[i + 1] == 'u') && (data[i + 2] == 'l')) ||
            ((data[i] == 'A') && (data[i + 1] == 'u') && (data[i + 2] == 'g')) ||
            ((data[i] == 'S') && (data[i + 1] == 'e') && (data[i + 2] == 'p')) ||
            ((data[i] == 'O') && (data[i + 1] == 'c') && (data[i + 2] == 't')) ||
            ((data[i] == 'N') && (data[i + 1] == 'o') && (data[i + 2] == 'v')) ||
            ((data[i] == 'D') && (data[i + 1] == 'e') && (data[i + 2] == 'c'))
            ) {
        i += 3;
    } else {
        *len = i;
        return NGX_ERROR;
    }

    if (type == RFC1123) {
        /* rfc1123: year */
        if (data[i] != ' ') {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
    } else if (type == RFC850) {
        /* rfc850: year */
        if (data[i] != '-') {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if ((data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
    } else if (type == ASCTIME) {
        /* asctime: day */
        if (data[i] != ' ') {
            *len = i;
            return NGX_ERROR;
        }
        i++;
        if ((data[i] != ' ') || (data[i] < '0') || (data[i] > '9')) {
            *len = i;
            return NGX_ERROR;
        }
        i++;
    }
    if ((data[i] < '0') || (data[i] > '9')) {
        *len = i;
        return NGX_ERROR;
    }
    i++;
    if (data[i] != ' ') {
        *len = i;
        return NGX_ERROR;
    }
    i++;

    /* time 08:49:37 */
    if (
            (data[i] < '0') || (data[i] > '9') ||
            (data[i + 1] < '0') || (data[i + 1] > '9') ||
            (data[i + 2] != ':')
            ) {
        *len = i;
        return NGX_ERROR;
    }
    i += 3;
    if (
            (data[i] < '0') || (data[i] > '9') ||
            (data[i + 1] < '0') || (data[i + 1] > '9') ||
            (data[i + 2] != ':')
            ) {
        *len = i;
        return NGX_ERROR;
    }
    i += 3;
    if (
            (data[i] < '0') || (data[i] > '9') ||
            (data[i + 1] < '0') || (data[i + 1] > '9') ||
            (data[i + 2] != ' ')
            ) {
        *len = i;
        return NGX_ERROR;
    }
    i += 3;

    if (type == ASCTIME) {
        /* asctime: year: 1994 */
        if (
                (data[i] < '0') || (data[i] > '9') ||
                (data[i + 1] < '0') || (data[i + 1] > '9') ||
                (data[i + 2] < '0') || (data[i + 2] > '9') ||
                (data[i + 3] < '0') || (data[i + 3] > '9')
                ) {
            *len = i;
            return NGX_ERROR;
        }
        i += 4;
    } else {
        /* GMT */
        if ((data[i] != 'G') || (data[i + 1] != 'M') || (data[i + 2] != 'T')) {
            *len = i;
            return NGX_ERROR;
        }
        i += 3;
    }

    *len = i;
    return NGX_OK;
}

static ngx_int_t ngx_header_inspect_parse_entity_tag(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
    ngx_uint_t i = 0;

    if (maxlen < 2) {
        *len = 0;
        return NGX_ERROR;
    }

    if (data[0] == 'W') {
        if (data[1] != '/') {
            *len = 2;
            return NGX_ERROR;
        }
        i = 2;
    }

    if (i + 1 >= maxlen) {
        *len = i;
        return NGX_ERROR;
    }

    if (data[i] != '"') {
        *len = i + 1;
        return NGX_ERROR;
    }
    i++;

    for (; i < maxlen - 1; i++) {
        if (data[i] == '"') {
            *len = i + 1;
            return NGX_OK;
        }
    }

    *len = maxlen;
    return NGX_ERROR;
}

static ngx_int_t ngx_header_inspect_parse_qvalue(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {

    *len = 0;

    if ((maxlen < 3) || (data[0] != 'q') || (data[1] != '=')) {
        return NGX_ERROR;
    }

    if (data[2] == '0') {
        if ((maxlen == 3) || (data[3] != '.')) {
            *len = 3;
            return NGX_OK;
        }
        if ((data[4] < '0') || (data[4] > '9')) {
            *len = 4;
            return NGX_OK;
        }
        if ((data[5] < '0') || (data[5] > '9')) {
            *len = 5;
            return NGX_OK;
        }
        if ((data[6] < '0') || (data[6] > '9')) {
            *len = 6;
        } else {
            *len = 7;
        }
        return NGX_OK;
    } else if (data[2] == '1') {
        if ((maxlen == 3) || (data[3] != '.')) {
            *len = 3;
            return NGX_OK;
        }
        if (data[4] != '0') {
            *len = 4;
            return NGX_OK;
        }
        if (data[5] != '0') {
            *len = 5;
            return NGX_OK;
        }
        if (data[6] != '0') {
            *len = 6;
        } else {
            *len = 7;
        }
        return NGX_OK;
    } else {
        *len = 2;
        return NGX_ERROR;
    }
}

static ngx_int_t ngx_header_inspect_parse_contentcoding(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {

    if (maxlen < 1) {
        *len = 0;
        return NGX_ERROR;
    }
    *len = 1;

    switch (data[0]) {
        case '*':
            return NGX_OK;
            break;
        case 'c':
            if ((maxlen < 8) || (ngx_strncmp("compress", data, 8) != 0)) {
                return NGX_ERROR;
            }
            *len = 8;
            break;
        case 'd':
            if ((maxlen < 7) || (ngx_strncmp("deflate", data, 7) != 0)) {
                return NGX_ERROR;
            }
            *len = 7;
            break;
        case 'e':
            if ((maxlen < 3) || (ngx_strncmp("exi", data, 3) != 0)) {
                return NGX_ERROR;
            }
            *len = 3;
            break;
        case 'g':
            if ((maxlen < 4) || (ngx_strncmp("gzip", data, 4) != 0)) {
                return NGX_ERROR;
            }
            *len = 4;
            break;
        case 'i':
            if ((maxlen < 8) || (ngx_strncmp("identity", data, 8) != 0)) {
                return NGX_ERROR;
            }
            *len = 8;
            break;
        case 'p':
            if ((maxlen < 12) || (ngx_strncmp("pack200-gzip", data, 12) != 0)) {
                return NGX_ERROR;
            }
            *len = 12;
            break;
        default:
            return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_header_inspect_parse_mediatype(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
    ngx_uint_t i = 0;
    u_char d;
    ngx_uint_t secondpart = 0;
    ngx_uint_t parameter = 0;

    if (maxlen < 1) {
        *len = 0;
        return NGX_ERROR;
    }

    *len = 1;
    while (i < maxlen) {
        d = data[i];
        if (d == '/') {
            if (i < 1) {
                *len = 1;
                return NGX_ERROR;
            } else {
                if (secondpart == 0) {
                    secondpart = 1;
                    i++;
                    continue;
                } else {
                    *len = i;
                    return NGX_ERROR;
                }
            }
        }

        if (
                ((d < '0') || (d > '9')) &&
                ((d < 'a') || (d > 'z')) &&
                ((d < 'A') || (d > 'Z')) &&
                (d != '-') && (d != '_') &&
                (d != '+') && (d != '.') &&
                (d != ':') && (d != '*')
            /* TODO: check with RFC which chars are valid */
                ) {
            *len = i;
            if (secondpart == 0) {
                return NGX_ERROR;
            } else {
                if (d == ';') {
                    parameter = 1;
                    break;
                } else {
                    return NGX_OK;
                }
            }
        }
        i++;
    }

    if (parameter) {
        if (i + 4 > maxlen) {
            return NGX_ERROR;
        }
        while (i < maxlen) {
            if (data[i] != ';') {
                *len = i;
                return NGX_OK;
            }
            i++;

            while ((i < maxlen) && (data[i] == ' ')) { i++; }
            if (i == maxlen) {
                *len = i;
                return NGX_ERROR;
            }

            /* attribute */
            while (i < maxlen) {
                d = data[i];

                if (d == '=') {
                    break;
                }

                if (
                        ((d < '0') || (d > '9')) &&
                        ((d < 'a') || (d > 'z')) &&
                        ((d < 'A') || (d > 'Z')) &&
                        (d != '-') && (d != '_') &&
                        (d != '+') && (d != '.') &&
                        (d != ':') && (d != '*')
                        ) {
                    *len = i;
                    return NGX_ERROR;
                }
                i++;
            }
            if (i == maxlen) {
                *len = i;
                return NGX_ERROR;
            }
            i++;

            /* value */
            /* TODO: what if value is double-quoted? */
            while (i < maxlen) {
                d = data[i];

                if (d == ';') {
                    break;
                }

                if (
                        ((d < '0') || (d > '9')) &&
                        ((d < 'a') || (d > 'z')) &&
                        ((d < 'A') || (d > 'Z')) &&
                        (d != '-') && (d != '_') &&
                        (d != '+') && (d != '.') &&
                        (d != ':') && (d != '*')
                        ) {
                    *len = i;
                    return NGX_OK;
                }
                i++;
            }
            while ((i < maxlen) && (data[i] == ' ')) { i++; }
        }
    }

    *len = i;
    if (secondpart == 0) {
        return NGX_ERROR;
    } else {
        return NGX_OK;
    }
}

static ngx_int_t ngx_header_inspect_parse_charset(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
    ngx_uint_t i;
    u_char d;
    ngx_uint_t alphacount = 0;

    if (maxlen < 1) {
        *len = 0;
        return NGX_ERROR;
    }

    if (data[0] == '*') {
        *len = 1;
        return NGX_OK;
    }

    *len = 1;
    for (i = 0; i < maxlen; i++) {
        d = data[i];
        if (
                (d == '-') ||
                (d == '_') ||
                (d == '+') ||
                (d == '.') ||
                (d == ':')
                ) {
            if (alphacount == 0) {
                *len = i;
                return NGX_ERROR;
            }
            alphacount = 0;
            continue;
        }
        if (
                ((d < '0') || (d > '9')) &&
                ((d < 'a') || (d > 'z')) &&
                ((d < 'A') || (d > 'Z'))
                ) {
            *len = i;
            if (alphacount == 0) {
                return NGX_ERROR;
            } else {
                return NGX_OK;
            }
        }
        alphacount++;
    }

    *len = i;
    if (alphacount == 0) {
        return NGX_ERROR;
    } else {
        return NGX_OK;
    }
}

static ngx_int_t ngx_header_inspect_parse_languagerange(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
    ngx_uint_t i;
    u_char d;
    ngx_uint_t alphacount = 0;

    if (maxlen < 1) {
        *len = 0;
        return NGX_ERROR;
    }

    if (data[0] == '*') {
        *len = 1;
        return NGX_OK;
    }

    *len = 1;
    for (i = 0; i < maxlen; i++) {
        d = data[i];
        if (d == '-') {
            if (alphacount == 0) {
                *len = i;
                return NGX_ERROR;
            }
            alphacount = 0;
            continue;
        }
        if (
                ((d < 'a') || (d > 'z')) &&
                ((d < 'A') || (d > 'Z'))
                ) {
            *len = i;
            if (alphacount == 0) {
                return NGX_ERROR;
            } else {
                return NGX_OK;
            }
        }
        if (alphacount == 8) {
            *len = i;
            return NGX_ERROR;
        }
        alphacount++;
    }

    *len = i;
    if (alphacount == 0) {
        return NGX_ERROR;
    } else {
        return NGX_OK;
    }
}

static ngx_int_t
ngx_header_inspect_ifmatch_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if ((value.len == 1) && (value.data[0] == '*')) {
        return NGX_OK;
    }

    if (value.len < 2) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: %s header \"%s\" too short", header, value.data);
        }
        return NGX_ERROR;
    }

    while (i < value.len) {
        if (ngx_header_inspect_parse_entity_tag(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid entity-tag at position %d in %s header \"%s\"", i, header,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in %s header \"%s\"",
                              i, header, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }

    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"", header,
                          value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;
}

static ngx_int_t
ngx_header_inspect_digit_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i = 0;

    if (value.len <= 0) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: %s header \"%s\" is empty", header, value.data);
        }
        return NGX_ERROR;
    }

    for (i = 0; i < value.len; i++) {
        if ((value.data[i] < '0') || (value.data[i] > '9')) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid digit at position %d in %s header \"%s\"",
                              i, header, value.data);
            }
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_acceptcharset_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
        return NGX_OK;
    }

    while (i < value.len) {
        if (ngx_header_inspect_parse_charset(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid charset at position %d in Accept-Charset header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] == ';') {
            i++;
            if (i >= value.len) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: unexpected end of Accept-Charset header \"%s\"", value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len - i, &v) != NGX_OK) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: invalid qvalue at position %d in Accept-Charset header \"%s\"", i,
                                  value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            i += v;
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (i == value.len) {
                rc = NGX_OK;
                break;
            }
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Accept-Charset header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }

    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Charset header \"%s\"",
                          value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;
}

static ngx_int_t
ngx_header_inspect_contentlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Language header \"%s\" too short",
                          value.data);
        }
        return NGX_ERROR;
    }

    while (i < value.len) {
        if (value.data[i] == '*') {
            /* hack, to prevent parse_languagerange from matching '*' */
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Content-Language header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        if (ngx_header_inspect_parse_languagerange(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid language-range at position %d in Content-Language header \"%s\"",
                              i, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Content-Language header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }

    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Content-Language header \"%s\"",
                          value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;

}

static ngx_int_t
ngx_header_inspect_acceptlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
        return NGX_OK;
    }

    while (i < value.len) {
        if (ngx_header_inspect_parse_languagerange(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid language-range at position %d in Accept-Language header \"%s\"",
                              i, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] == ';') {
            i++;
            if (i >= value.len) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: unexpected end of Accept-Language header \"%s\"", value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len - i, &v) != NGX_OK) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: invalid qvalue at position %d in Accept-Language header \"%s\"", i,
                                  value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            i += v;
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (i == value.len) {
                rc = NGX_OK;
                break;
            }
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Accept-Language header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }

    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Language header \"%s\"",
                          value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;
}

static ngx_int_t
ngx_header_inspect_contentencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Encoding header \"%s\" too short",
                          value.data);
        }
        return NGX_ERROR;
    }

    while (i < value.len) {
        if (value.data[i] == '*') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Content-Encoding header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        if (ngx_header_inspect_parse_contentcoding(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid content-coding at position %d in Content-Encoding header \"%s\"",
                              i, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Content-Encoding header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }

    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Content-Encoding header \"%s\"",
                          value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;

}

static ngx_int_t
ngx_header_inspect_acceptencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
        return NGX_OK;
    }

    while (i < value.len) {
        if (ngx_header_inspect_parse_contentcoding(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid content-coding at position %d in Accept-Encoding header \"%s\"",
                              i, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] == ';') {
            i++;
            if (i >= value.len) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: unexpected end of Accept-Encoding header \"%s\"", value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len - i, &v) != NGX_OK) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: invalid qvalue at position %d in Accept-Encoding header \"%s\"", i,
                                  value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            i += v;
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (i == value.len) {
                rc = NGX_OK;
                break;
            }
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Accept-Encoding header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }

    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Encoding header \"%s\"",
                          value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;
}

static ngx_int_t ngx_header_inspect_parse_cache_directive(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
    ngx_uint_t i = 0;
    if ((maxlen >= 8) && (ngx_strncmp("no-cache", data, 8) == 0)) {
        *len = 8;
        return NGX_OK;
    }
    if ((maxlen >= 8) && (ngx_strncmp("no-store", data, 8) == 0)) {
        *len = 8;
        return NGX_OK;
    }
    if ((maxlen >= 12) && (ngx_strncmp("no-transform", data, 12) == 0)) {
        *len = 12;
        return NGX_OK;
    }
    if ((maxlen >= 14) && (ngx_strncmp("only-if-cached", data, 14) == 0)) {
        *len = 14;
        return NGX_OK;
    }
    if ((maxlen >= 9) && (ngx_strncmp("max-stale", data, 9) == 0)) {
        *len = 9;
        if (maxlen >= 11) {
            if ((data[9] == '=') && (data[10] >= '0') && (data[10] <= '9')) {
                i = 11;
                while ((i <= maxlen) && (data[i] >= '0') && (data[i] <= '9')) {
                    i++;
                }
                *len = i;
            }
        }
        return NGX_OK;
    }
    if ((maxlen >= 9) && (ngx_strncmp("max-age=", data, 8) == 0) && (data[8] >= '0') && (data[8] <= '9')) {
        i = 9;
        while ((i < maxlen) && (data[i] >= '0') && (data[i] <= '9')) {
            i++;
        }
        *len = i;
        return NGX_OK;
    }
    if ((maxlen >= 11) && (ngx_strncmp("min-fresh=", data, 10) == 0) && (data[10] >= '0') && (data[10] <= '9')) {
        i = 11;
        while ((i < maxlen) && (data[i] >= '0') && (data[i] <= '9')) {
            i++;
        }
        *len = i;
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_header_inspect_cachecontrol_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if (value.len < 1) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Cache-Control header \"%s\" too short", value.data);
        }
        return NGX_ERROR;
    }

    while (i < value.len) {
        if (ngx_header_inspect_parse_cache_directive(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid cache-directive at position %d in Cache-Control header \"%s\"",
                              i, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Cache-Control header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }
    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Cache-Control header \"%s\"",
                          value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;
}

static ngx_int_t
ngx_header_inspect_referer_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    enum referer_header_states {
        RS_START,
        RS_SCHEME,
        RS_COLON,
        RS_SLASH1,
        RS_SLASH2,
        RS_HOST,
        RS_BR1,
        RS_IP6,
        RS_BR2,
        RS_COLON2,
        RS_PORT,
        RS_PATH
    } state;
    ngx_uint_t i;
    ngx_int_t rc = NGX_OK;
    u_char d;

    if (value.len < 1) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: %s header \"%s\" too short", header, value.data);
        }
        return NGX_ERROR;
    }

    switch (value.data[0]) {
        case '/':
            /* relativePath */
            return NGX_OK;
            break;
        case 'h':
        case 'f':
            /* absoluteURI */
            state = RS_START;
            for (i = 0; i < value.len; i++) {
                d = value.data[i];

                if (
                        ((d >= 'g') && (d <= 'z')) ||
                        ((d >= 'G') && (d <= 'Z')) ||
                        (d == '.')
                        ) {
                    switch (state) {
                        case RS_START:
                            if (
                                    !(
                                            ((value.len > 4) && (ngx_strncmp("http:", value.data, 5) == 0)) ||
                                            ((value.len > 5) && (ngx_strncmp("https:", value.data, 6) == 0)) ||
                                            ((value.len > 3) && (ngx_strncmp("ftp:", value.data, 4) == 0)) ||
                                            ((value.len > 4) && (ngx_strncmp("ftps:", value.data, 5) == 0))
                                    )
                                    ) {
                                if (conf->log) {
                                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                                  "header_inspect: unknown scheme at begin of %s header \"%s\"", header,
                                                  value.data);
                                }
                                return NGX_ERROR;
                            }
                            state = RS_SCHEME;
                            break;
                        case RS_SLASH2:
                            state = RS_HOST;
                            break;
                        case RS_HOST:
                        case RS_PATH:
                        case RS_SCHEME:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                } else if (
                        ((d >= 'a') && (d <= 'f')) ||
                        ((d >= 'A') && (d <= 'F'))
                        ) {
                    switch (state) {
                        case RS_START:
                            if (
                                    !(
                                            ((value.len > 4) && (ngx_strncmp("http:", value.data, 5) == 0)) ||
                                            ((value.len > 5) && (ngx_strncmp("https:", value.data, 6) == 0)) ||
                                            ((value.len > 3) && (ngx_strncmp("ftp:", value.data, 4) == 0)) ||
                                            ((value.len > 4) && (ngx_strncmp("ftps:", value.data, 5) == 0))
                                    )
                                    ) {
                                if (conf->log) {
                                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                                  "header_inspect: unknown scheme at begin of %s header \"%s\"", header,
                                                  value.data);
                                }
                                return NGX_ERROR;
                            }
                            state = RS_SCHEME;
                            break;
                        case RS_SLASH2:
                            state = RS_HOST;
                            break;
                        case RS_BR1:
                            state = RS_IP6;
                            break;
                        case RS_HOST:
                        case RS_PATH:
                        case RS_SCHEME:
                        case RS_IP6:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                } else if ((d >= '0') && (d <= '9')) {
                    switch (state) {
                        case RS_SLASH2:
                            state = RS_HOST;
                            break;
                        case RS_COLON2:
                            state = RS_PORT;
                            break;
                        case RS_BR1:
                            state = RS_IP6;
                            break;
                        case RS_PORT:
                        case RS_HOST:
                        case RS_PATH:
                        case RS_IP6:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                } else if (d == '/') {
                    switch (state) {
                        case RS_COLON:
                            state = RS_SLASH1;
                            break;
                        case RS_SLASH1:
                            state = RS_SLASH2;
                            break;
                        case RS_PORT:
                        case RS_HOST:
                        case RS_BR2:
                            state = RS_PATH;
                            break;
                        case RS_PATH:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                } else if (d == ':') {
                    switch (state) {
                        case RS_SCHEME:
                            state = RS_COLON;
                            break;
                        case RS_HOST:
                        case RS_BR2:
                            state = RS_COLON2;
                            break;
                        case RS_BR1:
                            state = RS_IP6;
                            break;
                        case RS_PATH:
                        case RS_IP6:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                } else if (d == '[') {
                    switch (state) {
                        case RS_SLASH2:
                            state = RS_BR1;
                            break;
                        case RS_PATH:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                } else if (d == ']') {
                    switch (state) {
                        case RS_IP6:
                            state = RS_BR2;
                            break;
                        case RS_PATH:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                } else {
                    switch (state) {
                        case RS_PATH:
                            break;
                        default:
                            rc = NGX_ERROR;
                    }
                }
                if (rc == NGX_ERROR) {
                    if (conf->log) {
                        ngx_log_error(NGX_LOG_ALERT, log, 0,
                                      "header_inspect: illegal character at position %d of %s header \"%s\"", i, header,
                                      value.data);
                    }
                    return NGX_ERROR;
                }
            }
            switch (state) {
                case RS_PATH:
                case RS_PORT:
                case RS_HOST:
                case RS_BR2:
                    return NGX_OK;
                default:
                    if (conf->log) {
                        ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"",
                                      header, value.data);
                    }
                    return NGX_ERROR;
            }
            break;
        default:
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at begin of %s header \"%s\"",
                              header, value.data);
            }
            return NGX_ERROR;
    }
}

static ngx_int_t
ngx_header_inspect_transferencoding_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log,
                                           ngx_str_t value) {
    ngx_uint_t i;
    ngx_int_t rc = NGX_OK;
    enum transferencoding_header_states {
        TS_START, TS_FIELD, TS_PARDELIM, TS_PARKEY, TS_PAREQ, TS_PARVAL, TS_PARVALQ, TS_PARVALQE, TS_DELIM, TS_SPACE
    } state;
    u_char d;
    ngx_uint_t te_header = 0;

    if (ngx_strncmp("TE", header, 2) == 0) {
        te_header = 1;
    }

    state = TS_START;
    for (i = 0; i < value.len; i++) {
        d = value.data[i];

        if (
                ((d >= 'a') && (d <= 'z')) ||
                ((d >= 'A') && (d <= 'Z')) ||
                ((d >= '0') && (d <= '9'))
                ) {
            switch (state) {
                case TS_START:
                case TS_SPACE:
                    /* ensure transfer-codings is one of chunked, compress, deflate, gzip or identity */
                    state = TS_FIELD;
                    if (
                            !(
                                    ((value.len - i >= 7) && (ngx_strncmp("chunked", &(value.data[i]), 7) == 0) &&
                                     ((value.data[i + 7] == ',') || (value.data[i + 7] == ';') ||
                                      (value.data[i + 7] == '\0'))) ||
                                    ((value.len - i >= 8) && (ngx_strncmp("compress", &(value.data[i]), 8) == 0) &&
                                     ((value.data[i + 8] == ',') || (value.data[i + 8] == ';') ||
                                      (value.data[i + 8] == '\0'))) ||
                                    ((value.len - i >= 7) && (ngx_strncmp("deflate", &(value.data[i]), 7) == 0) &&
                                     ((value.data[i + 7] == ',') || (value.data[i + 7] == ';') ||
                                      (value.data[i + 7] == '\0'))) ||
                                    ((value.len - i >= 4) && (ngx_strncmp("gzip", &(value.data[i]), 4) == 0) &&
                                     ((value.data[i + 4] == ',') || (value.data[i + 4] == ';') ||
                                      (value.data[i + 4] == '\0'))) ||
                                    ((value.len - i >= 8) && (ngx_strncmp("identity", &(value.data[i]), 8) == 0) &&
                                     ((value.data[i + 8] == ',') || (value.data[i + 8] == ';') ||
                                      (value.data[i + 8] == '\0'))) ||
                                    ((te_header == 1) && (value.len - i >= 8) &&
                                     (ngx_strncmp("trailers", &(value.data[i]), 8) == 0) &&
                                     ((value.data[i + 8] == ',') || (value.data[i + 8] == ';') ||
                                      (value.data[i + 8] == '\0')))
                            )
                            ) {
                        if (conf->log) {
                            ngx_log_error(NGX_LOG_ALERT, log, 0,
                                          "header_inspect: illegal field at position %d in %s header \"%s\"", i, header,
                                          value.data);
                        }
                        return NGX_ERROR;
                    }
                    break;
                case TS_PARDELIM:
                    /* TODO: if parkey is 'q', validate q-value */
                    state = TS_PARKEY;
                    break;
                case TS_PAREQ:
                    state = TS_PARVAL;
                    break;
                case TS_FIELD:
                case TS_PARKEY:
                case TS_PARVAL:
                case TS_PARVALQ:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '.') {
            switch (state) {
                case TS_PARVAL:
                case TS_PARVALQ:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ',') {
            switch (state) {
                case TS_FIELD:
                case TS_PARVAL:
                case TS_PARVALQE:
                    state = TS_DELIM;
                    break;
                case TS_PARVALQ:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ' ') {
            switch (state) {
                case TS_DELIM:
                    state = TS_SPACE;
                    break;
                case TS_PARVAL:
                case TS_PARVALQ:
                case TS_PARDELIM:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ';') {
            switch (state) {
                case TS_FIELD:
                case TS_PARVAL:
                case TS_PARVALQE:
                    state = TS_PARDELIM;
                    break;
                case TS_PARVALQ:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '=') {
            switch (state) {
                case TS_PARKEY:
                    state = TS_PAREQ;
                    break;
                case TS_PARVALQ:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '"') {
            switch (state) {
                case TS_PAREQ:
                    state = TS_PARVALQ;
                    break;
                case TS_PARVALQ:
                    state = TS_PARVALQE;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else {
            switch (state) {
                case TS_PARVALQ:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in %s header \"%s\"",
                              i, header, value.data);
            }
            return NGX_ERROR;
        }
    }
    switch (state) {
        case TS_FIELD:
        case TS_PARVAL:
        case TS_PARVALQE:
            break;
        case TS_START:
            if (te_header == 1) {
                break;
            }
        default:
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"", header,
                              value.data);
            }
            return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_trailer_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i;
    ngx_int_t rc = NGX_OK;
    enum trail_header_states {
        TS_START, TS_FIELD, TS_DELIM, TS_SPACE
    } state;
    u_char d;

    state = TS_START;
    for (i = 0; i < value.len; i++) {
        d = value.data[i];

        if (
                ((d >= 'a') && (d <= 'z')) ||
                ((d >= 'A') && (d <= 'Z')) ||
                ((d >= '0') && (d <= '9')) ||
                (d == '-')
                ) {
            switch (state) {
                case TS_START:
                case TS_SPACE:
                    /* ensure field is not Transfer-Encondig, Content-Length or Trailer */
                    if (
                            (((value.len - i) >= 17) && (ngx_strncmp("Transfer-Encoding", &(value.data[i]), 17) == 0) &&
                             ((value.data[i + 17] == ',') || (value.data[i + 17] == '\0'))) ||
                            (((value.len - i) >= 14) && (ngx_strncmp("Content-Length", &(value.data[i]), 14) == 0) &&
                             ((value.data[i + 14] == ',') || (value.data[i + 14] == '\0'))) ||
                            (((value.len - i) >= 7) && (ngx_strncmp("Trailer", &(value.data[i]), 7) == 0) &&
                             ((value.data[i + 7] == ',') || (value.data[i + 7] == '\0')))
                            ) {
                        if (conf->log) {
                            ngx_log_error(NGX_LOG_ALERT, log, 0,
                                          "header_inspect: illegal field at position %d in Trailer header \"%s\"", i,
                                          value.data);
                        }
                        return NGX_ERROR;
                    }
                    state = TS_FIELD;
                    break;
                case TS_FIELD:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ',') {
            switch (state) {
                case TS_FIELD:
                    state = TS_DELIM;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ' ') {
            switch (state) {
                case TS_DELIM:
                    state = TS_SPACE;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else {
            rc = NGX_ERROR;
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in Trailer header \"%s\"", i,
                              value.data);
            }
            return NGX_ERROR;
        }
    }
    if (state != TS_FIELD) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Trailer header \"%s\"", value.data);
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_warning_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i;
    ngx_uint_t v;
    ngx_int_t rc = NGX_OK;
    enum warn_header_states {
        WS_START,
        WS_CODE1,
        WS_CODE2,
        WS_CODE3,
        WS_SP1,
        WS_HOST,
        WS_COLON,
        WS_PORT,
        WS_SP2,
        WS_TXT,
        WS_TXTE,
        WS_SP3,
        WS_DATE,
        WS_DELIM,
        WS_SPACE
    } state;
    u_char d;

    state = WS_START;
    for (i = 0; i < value.len; i++) {
        d = value.data[i];

        if ((d >= '0') && (d <= '9')) {
            switch (state) {
                case WS_START:
                case WS_SPACE:
                    state = WS_CODE1;
                    break;
                case WS_CODE1:
                    state = WS_CODE2;
                    break;
                case WS_CODE2:
                    state = WS_CODE3;
                    break;
                case WS_SP1:
                    state = WS_HOST;
                    break;
                case WS_COLON:
                    state = WS_PORT;
                    break;
                case WS_HOST:
                case WS_PORT:
                case WS_TXT:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (((d >= 'a') && (d <= 'z')) || ((d >= 'A') && (d <= 'Z'))) {
            switch (state) {
                case WS_SP1:
                    state = WS_HOST;
                    break;
                case WS_HOST:
                case WS_TXT:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if ((d == '-') || (d == '.')) {
            switch (state) {
                case WS_HOST:
                case WS_TXT:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ':') {
            switch (state) {
                case WS_HOST:
                    state = WS_COLON;
                    break;
                case WS_TXT:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ',') {
            switch (state) {
                case WS_DATE:
                case WS_TXTE:
                    state = WS_DELIM;
                    break;
                case WS_TXT:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ' ') {
            switch (state) {
                case WS_CODE3:
                    state = WS_SP1;
                    break;
                case WS_HOST:
                case WS_PORT:
                    state = WS_SP2;
                    break;
                case WS_TXTE:
                    state = WS_SP3;
                    break;
                case WS_DELIM:
                    state = WS_SPACE;
                    break;
                case WS_TXT:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '"') {
            switch (state) {
                case WS_SP2:
                    state = WS_TXT;
                    break;
                case WS_TXT:
                    state = WS_TXTE;
                    break;
                case WS_SP3:
                    state = WS_DATE;
                    i++; /* skip qoute */
                    if (ngx_header_inspect_http_date(&(value.data[i]), value.len - i, &v) != NGX_OK) {
                        if (conf->log) {
                            ngx_log_error(NGX_LOG_ALERT, log, 0,
                                          "header_inspect: illegal date at position %d in Warning header \"%s\"", i,
                                          value.data);
                        }
                        return NGX_ERROR;
                    }
                    i += v;
                    if (i >= value.len) {
                        if (conf->log) {
                            ngx_log_error(NGX_LOG_ALERT, log, 0,
                                          "header_inspect: unexpected end of Warning header \"%s\"", value.data);
                        }
                        return NGX_ERROR;
                    }
                    if (value.data[i] != '"') {
                        rc = NGX_ERROR;
                    }
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else {
            switch (state) {
                case WS_TXT:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in Warning header \"%s\"", i,
                              value.data);
            }
            return NGX_ERROR;
        }
    }
    switch (state) {
        case WS_TXTE:
        case WS_DATE:
            break;
        default:
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Warning header \"%s\"",
                              value.data);
            }
            return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_expect_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {

    /* currently only the 'known' "100-continue" value is allowed */
    if ((value.len == 12) && (ngx_strncasecmp((u_char *) "100-continue", value.data, 12) == 0)) {
        return NGX_OK;
    } else {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown value in Expect header \"%s\"", value.data);
        }
        return NGX_ERROR;
    }
}

static ngx_int_t
ngx_header_inspect_authorization_header(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log,
                                        ngx_str_t value) {
    ngx_uint_t i;
    ngx_int_t rc = NGX_OK;
    enum digest_header_states {
        DS_START, DS_KEY, DS_EQ, DS_VAL, DS_VALQ, DS_VALQE, DS_DELIM, DS_SPACE
    } state;
    u_char d;

    if (value.len == 0) {
        return NGX_OK;
    }

    if ((value.len >= 6) && (ngx_strncmp("Basic ", value.data, 6) == 0)) {
        return ngx_header_inspect_parse_base64(header, conf, log, &(value.data[6]), value.len - 6);
    }

    if ((value.len >= 7) && (ngx_strncmp("Digest ", value.data, 7) == 0)) {
        i = 7; /* start after "Digest " */
        state = DS_START;
        for (; i < value.len; i++) {
            d = value.data[i];

            if ((d >= 'a') && (d <= 'z')) {
                switch (state) {
                    case DS_START:
                    case DS_SPACE:
                        state = DS_KEY;
                        if (
                                !(
                                        (((value.len - i) >= 9) &&
                                         (ngx_strncmp("username=", &(value.data[i]), 9) == 0)) ||
                                        (((value.len - i) >= 6) && (ngx_strncmp("realm=", &(value.data[i]), 6) == 0)) ||
                                        (((value.len - i) >= 6) && (ngx_strncmp("nonce=", &(value.data[i]), 6) == 0)) ||
                                        (((value.len - i) >= 4) && (ngx_strncmp("uri=", &(value.data[i]), 4) == 0)) ||
                                        (((value.len - i) >= 9) &&
                                         (ngx_strncmp("response=", &(value.data[i]), 9) == 0)) ||
                                        (((value.len - i) >= 10) &&
                                         (ngx_strncmp("algorithm=", &(value.data[i]), 10) == 0)) ||
                                        (((value.len - i) >= 7) &&
                                         (ngx_strncmp("cnonce=", &(value.data[i]), 7) == 0)) ||
                                        (((value.len - i) >= 7) &&
                                         (ngx_strncmp("opaque=", &(value.data[i]), 7) == 0)) ||
                                        (((value.len - i) >= 4) && (ngx_strncmp("qop=", &(value.data[i]), 4) == 0)) ||
                                        (((value.len - i) >= 3) && (ngx_strncmp("nc=", &(value.data[i]), 3) == 0))
                                )
                                ) {
                            if (conf->log) {
                                ngx_log_error(NGX_LOG_ALERT, log, 0,
                                              "header_inspect: unknown auth-param at position %d in %s header \"%s\"",
                                              i, header, value.data);
                            }
                            return NGX_ERROR;
                        }
                        break;
                    case DS_EQ:
                        state = DS_VAL;
                        break;
                    case DS_VAL:
                    case DS_VALQ:
                    case DS_KEY:
                        break;
                    default:
                        rc = NGX_ERROR;
                }
            } else if (d == ',') {
                switch (state) {
                    case DS_VAL:
                    case DS_VALQE:
                    case DS_EQ:
                        state = DS_DELIM;
                        break;
                    case DS_VALQ:
                        break;
                    default:
                        rc = NGX_ERROR;
                }
            } else if (d == '=') {
                switch (state) {
                    case DS_KEY:
                        state = DS_EQ;
                        break;
                    case DS_VALQ:
                        break;
                    default:
                        rc = NGX_ERROR;
                }

            } else if (d == ' ') {
                switch (state) {
                    case DS_DELIM:
                        state = DS_SPACE;
                        break;
                    case DS_VALQ:
                        break;
                    default:
                        rc = NGX_ERROR;
                }
            } else if (d == '"') {
                switch (state) {
                    case DS_EQ:
                        state = DS_VALQ;
                        break;
                    case DS_VALQ:
                        state = DS_VALQE;
                        break;
                    default:
                        rc = NGX_ERROR;
                }
            } else if ((d != '"')) {
                switch (state) {
                    case DS_VAL:
                    case DS_VALQ:
                        break;
                    default:
                        rc = NGX_ERROR;
                }
            } else {
                rc = NGX_ERROR;
            }
            if (rc == NGX_ERROR) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: illegal character at position %d in %s header \"%s\"", i, header,
                                  value.data);
                }
                return NGX_ERROR;
            }
        }
        switch (state) {
            case DS_VALQE:
            case DS_VAL:
                break;
            default:
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"", header,
                                  value.data);
                }
                return NGX_ERROR;
        }
        return NGX_OK;
    }

    if (conf->log) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown auth-scheme in %s header \"%s\"", header,
                      value.data);
    }
    return NGX_ERROR;
}

static ngx_int_t
ngx_header_inspect_contentmd5_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    return ngx_header_inspect_parse_base64("Content-MD5", conf, log, value.data, value.len);
}

static ngx_int_t
ngx_header_inspect_parse_base64(char *header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, u_char *data,
                                ngx_uint_t maxlen) {
    ngx_uint_t i;
    u_char d;

    if (maxlen == 0) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: empty base64 value in %s header", header);
        }
        return NGX_ERROR;
    }

    for (i = 0; i < maxlen; i++) {
        d = data[i];

        if ((d >= '0') && (d <= '9')) {
            continue;
        }
        if ((d >= 'a') && (d <= 'z')) {
            continue;
        }
        if ((d >= 'A') && (d <= 'Z')) {
            continue;
        }
        if ((d == '+') || (d == '/')) {
            continue;
        }
        if (d == '=') {
            continue;
            i++;
            while (i < maxlen) {
                if (data[i] != '=') {
                    if (conf->log) {
                        ngx_log_error(NGX_LOG_ALERT, log, 0,
                                      "header_inspect: trailing characters at position %d in base64 value \"%s\" of %s header",
                                      i, data, header);
                    }
                    return NGX_ERROR;
                }
                i++;
            }
            break;
        }
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "header_inspect: illegal character at position %d in base64 value \"%s\" of %s header", i,
                          data, header);
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_contenttype_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t v;

    if (value.len < 3) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Type header \"%s\" too short", value.data);
        }
        return NGX_ERROR;
    }

    if (ngx_header_inspect_parse_mediatype(value.data, value.len, &v) != NGX_OK) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid media-type in Content-Type header \"%s\"",
                          value.data);
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_pragma_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    /* currently only the 'known' "no-cache" value is allowed */
    if ((value.len == 8) && (ngx_strncasecmp((u_char *) "no-cache", value.data, 8) == 0)) {
        return NGX_OK;
    } else {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown value in Pragama header \"%s\"", value.data);
        }
        return NGX_ERROR;
    }
}

static ngx_int_t ngx_header_inspect_from_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i = 0;
    u_char d;
    ngx_int_t rc = NGX_OK;
    enum from_header_states {
        FS_START, FS_LOCALPART, FS_AT, FS_DOMAIN, FS_DOT
    } state;

    if (value.len < 3) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: From header \"%s\" too short", value.data);
        }
        return NGX_ERROR;
    }

    state = FS_START;
    for (i = 0; i < value.len; i++) {
        d = value.data[i];
        if (
                ((d >= '0') && (d <= '9')) ||
                ((d >= 'a') && (d <= 'z')) ||
                ((d >= 'A') && (d <= 'Z')) ||
                (d == '-')
                ) {
            switch (state) {
                case FS_START:
                    state = FS_LOCALPART;
                    break;
                case FS_AT:
                case FS_DOT:
                    state = FS_DOMAIN;
                    break;
                case FS_LOCALPART:
                case FS_DOMAIN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '+') {
            switch (state) {
                case FS_START:
                    state = FS_LOCALPART;
                    break;
                case FS_LOCALPART:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '.') {
            switch (state) {
                case FS_START:
                    state = FS_LOCALPART;
                    break;
                case FS_LOCALPART:
                    break;
                case FS_DOMAIN:
                    state = FS_DOT;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '@') {
            switch (state) {
                case FS_LOCALPART:
                    state = FS_AT;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else {
            rc = NGX_ERROR;
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in From header \"%s\"", i, value.data);
            }
            return NGX_ERROR;
        }
    }
    if (state != FS_DOMAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of From header \"%s\"", value.data);
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_header_inspect_via_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i = 0;
    u_char d;
    ngx_int_t rc = NGX_OK;
    enum via_header_states {
        VS_START,
        VS_PROT,
        VS_SLASH,
        VS_VER,
        VS_SPACE1,
        VS_HOST,
        VS_COLON,
        VS_PORT,
        VS_DELIM,
        VS_SPACE2,
        VS_PAREN,
        VS_PARENEND,
        VS_SPACE3
    } state;

    if (value.len < 3) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Via header \"%s\" too short", value.data);
        }
        return NGX_ERROR;
    }

    state = VS_START;
    for (i = 0; i < value.len; i++) {
        d = value.data[i];
        if (((d >= '0') && (d <= '9'))) {
            switch (state) {
                case VS_START:
                case VS_SPACE3:
                    state = VS_PROT;
                    break;
                case VS_SLASH:
                    state = VS_VER;
                    break;
                case VS_SPACE1:
                    state = VS_HOST;
                    break;
                case VS_COLON:
                    state = VS_PORT;
                    break;
                case VS_PROT:
                case VS_VER:
                case VS_PORT:
                case VS_HOST:
                case VS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (
                ((d >= 'a') && (d <= 'z')) ||
                ((d >= 'A') && (d <= 'Z')) ||
                (d == '-') || (d == '.')
                ) {
            switch (state) {
                case VS_START:
                case VS_SPACE3:
                    state = VS_PROT;
                    break;
                case VS_SLASH:
                    state = VS_VER;
                    break;
                case VS_SPACE1:
                    state = VS_HOST;
                    break;
                case VS_PROT:
                case VS_VER:
                case VS_HOST:
                case VS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ' ') {
            switch (state) {
                case VS_PROT:
                case VS_VER:
                    state = VS_SPACE1;
                    break;
                case VS_HOST:
                case VS_PORT:
                    state = VS_SPACE2;
                    break;
                case VS_DELIM:
                    state = VS_SPACE3;
                    break;
                case VS_SPACE1:
                case VS_SPACE2:
                case VS_SPACE3:
                case VS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '/') {
            switch (state) {
                case VS_PROT:
                    state = VS_SLASH;
                    break;
                case VS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ':') {
            switch (state) {
                case VS_HOST:
                    state = VS_COLON;
                    break;
                case VS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '(') {
            switch (state) {
                case VS_SPACE2:
                    state = VS_PAREN;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ')') {
            switch (state) {
                case VS_PAREN:
                    state = VS_PARENEND;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ',') {
            switch (state) {
                case VS_HOST:
                case VS_PORT:
                case VS_PARENEND:
                    state = VS_DELIM;
                    break;
                case VS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else {
            rc = NGX_ERROR;
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in Via header \"%s\"", i, value.data);
            }
            return NGX_ERROR;
        }
    }
    switch (state) {
        case VS_HOST:
        case VS_PORT:
        case VS_PARENEND:
            break;
        default:
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Via header \"%s\"", value.data);
            }
            return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_upgrade_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i = 0;
    u_char d;
    ngx_int_t rc = NGX_OK;
    enum upgrade_header_states {
        UPS_START, UPS_PROD, UPS_SLASH, UPS_VER, UPS_DELIM, UPS_SPACE
    } state;

    if (value.len < 1) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Upgrade header \"%s\" too short", value.data);
        }
        return NGX_ERROR;
    }

    state = UPS_START;
    for (i = 0; i < value.len; i++) {
        d = value.data[i];

        if (
                ((d >= '0') && (d <= '9')) ||
                ((d >= 'a') && (d <= 'z')) ||
                ((d >= 'A') && (d <= 'Z')) ||
                (d == '-') || (d == '.')
                ) {
            switch (state) {
                case UPS_START:
                case UPS_SPACE:
                    state = UPS_PROD;
                    break;
                case UPS_SLASH:
                    state = UPS_VER;
                    break;
                case UPS_PROD:
                case UPS_VER:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '/') {
            switch (state) {
                case UPS_PROD:
                    state = UPS_SLASH;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ' ') {
            switch (state) {
                case UPS_DELIM:
                    state = UPS_SPACE;
                    break;
                case UPS_SPACE:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ',') {
            switch (state) {
                case UPS_PROD:
                case UPS_VER:
                    state = UPS_DELIM;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else {
            rc = NGX_ERROR;
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in Upgrade header \"%s\"", i,
                              value.data);
            }
            return NGX_ERROR;
        }
    }
    switch (state) {
        case UPS_PROD:
        case UPS_VER:
            break;
        default:
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Upgrade header \"%s\"",
                              value.data);
            }
            return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_useragent_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i = 0;
    u_char d;
    ngx_int_t rc = NGX_OK;
    enum useragent_header_states {
        UAS_START, UAS_PROD, UAS_SLASH, UAS_VER, UAS_SPACE, UAS_PAREN
    } state;


    if (value.len < 1) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: User-Agent header \"%s\" too short", value.data);
        }
        return NGX_ERROR;
    }

    state = UAS_START;
    for (i = 0; i < value.len; i++) {
        d = value.data[i];
        if (
                ((d >= '0') && (d <= '9')) ||
                ((d >= 'a') && (d <= 'z')) ||
                ((d >= 'A') && (d <= 'Z')) ||
                (d == '-') || (d == '.')
                ) {
            switch (state) {
                case UAS_START:
                case UAS_SPACE:
                    state = UAS_PROD;
                    break;
                case UAS_PROD:
                case UAS_VER:
                case UAS_PAREN:
                    break;
                case UAS_SLASH:
                    state = UAS_VER;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '/') {
            switch (state) {
                case UAS_PROD:
                    state = UAS_SLASH;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ' ') {
            switch (state) {
                case UAS_VER:
                    state = UAS_SPACE;
                    break;
                case UAS_SPACE:
                case UAS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == '(') {
            switch (state) {
                case UAS_SPACE:
                    state = UAS_PAREN;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (d == ')') {
            switch (state) {
                case UAS_PAREN:
                    state = UAS_SPACE;
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else if (
                (d == ',') || (d == ':') || (d == ';') ||
                (d == '+') || (d == '_')
                ) {
            switch (state) {
                case UAS_PAREN:
                    break;
                default:
                    rc = NGX_ERROR;
            }
        } else {
            rc = NGX_ERROR;
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in User-Agent header \"%s\"", i,
                              value.data);
            }
            return NGX_ERROR;
        }
    }
    switch (state) {
        case UAS_SPACE:
        case UAS_PROD:
        case UAS_VER:
            break;
        default:
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of User-Agent header \"%s\"",
                              value.data);
            }
            return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_contentrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i = 0;
    ngx_int_t rc = NGX_OK;
    ngx_int_t a, b, c;
    enum contentrange_header_states {
        RHS_START, RHS_STAR1, RHS_NUM1, DELIM, RHS_NUM2, RHS_SLASH, RHS_STAR2, RHS_NUM3
    } state;

    if ((value.len < 6) || (ngx_strncmp("bytes ", value.data, 6) != 0)) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "header_inspect: Content-Range header \"%s\"  does not start with \"bytes \"", value.data);
        }
        return NGX_ERROR;
    }
    if (value.len < 9) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Range header \"%s\" is too short",
                          value.data);
        }
        return NGX_ERROR;
    }

    state = RHS_START;
    a = -1;
    b = -1;
    c = -1;

    i = 6; /* start after "bytes " */
    for (; i < value.len; i++) {
        switch (value.data[i]) {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                switch (state) {
                    case RHS_START:
                        state = RHS_NUM1;
                        a = (value.data[i] - '0');
                        break;
                    case RHS_NUM1:
                        a = a * 10 + (value.data[i] - '0');
                        break;
                    case RHS_NUM2:
                        b = b * 10 + (value.data[i] - '0');
                        break;
                    case RHS_NUM3:
                        c = c * 10 + (value.data[i] - '0');
                        break;
                    case DELIM:
                        state = RHS_NUM2;
                        b = (value.data[i] - '0');
                        break;
                    case RHS_SLASH:
                        state = RHS_NUM3;
                        c = (value.data[i] - '0');
                        break;
                    default:
                        rc = NGX_ERROR;
                }
                break;
            case '*':
                switch (state) {
                    case RHS_START:
                        state = RHS_STAR1;
                        break;
                    case RHS_SLASH:
                        state = RHS_STAR2;
                        break;
                    default:
                        rc = NGX_ERROR;
                }
                break;
            case '/':
                switch (state) {
                    case RHS_STAR1:
                    case RHS_NUM2:
                        state = RHS_SLASH;
                        break;
                    default:
                        rc = NGX_ERROR;
                }
                break;
            case '-':
                switch (state) {
                    case RHS_NUM1:
                        state = DELIM;
                        break;
                    default:
                        rc = NGX_ERROR;
                }
                break;
            default:
                rc = NGX_ERROR;
        }
        if (rc == NGX_ERROR) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in Content-Range header \"%s\"", i,
                              value.data);
            }
            return NGX_ERROR;
        }
    }
    switch (state) {
        case RHS_NUM3:
        case RHS_STAR2:
            break;
        default:
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Content-Range header \"%s\"",
                              value.data);
            }
            return NGX_ERROR;
    }

    /* in "a-b/c" ensure a < b and b < c if any of them are defined */
    if ((a != -1) && (b != -1)) {
        if ((a >= b) || ((c != -1) && (b >= c))) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal range specification in Content-Range header \"%s\"", value.data);
            }
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_conection_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t i = 0;

    while (i < value.len) {
        /* as per 13.5.1 of RFC2616 only allow Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailer, Transfer-Encoding and Upgrade headers in conection header */
        if (((i + 5) <= value.len) && (ngx_strncmp("close", &(value.data[i]), 5) == 0)) {
            i += 5;
        } else if (((i + 10) <= value.len) && (ngx_strncmp("keep-alive", &(value.data[i]), 10) == 0)) {
            i += 10;
        } else if (((i + 10) <= value.len) && (ngx_strncmp("Keep-Alive", &(value.data[i]), 10) == 0)) {
            i += 10;
        } else if (((i + 18) <= value.len) && (ngx_strncmp("Proxy-Authenticate", &(value.data[i]), 18) == 0)) {
            i += 18;
        } else if (((i + 19) <= value.len) && (ngx_strncmp("Proxy-Authorization", &(value.data[i]), 19) == 0)) {
            i += 19;
        } else if (((i + 2) <= value.len) && (ngx_strncmp("TE", &(value.data[i]), 2) == 0)) {
            i += 2;
        } else if (((i + 7) <= value.len) && (ngx_strncmp("Trailer", &(value.data[i]), 7) == 0)) {
            i += 7;
        } else if (((i + 17) <= value.len) && (ngx_strncmp("Transfer-Encoding", &(value.data[i]), 17) == 0)) {
            i += 17;
        } else if (((i + 7) <= value.len) && (ngx_strncmp("Upgrade", &(value.data[i]), 7) == 0)) {
            i += 7;
        } else {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal value at position %d in conection header \"%s\"", i,
                              value.data);
            }
            return NGX_ERROR;
        }

        if ((i < value.len) && (value.data[i] == ' ')) {
            i++;
        }

        if (i == value.len) {
            return NGX_OK;
        }

        if ((i < value.len) && (value.data[i] != ',')) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal character at position %d in conection header \"%s\"", i,
                              value.data);
            }
            return NGX_ERROR;
        }
        i++;

        if ((i < value.len) && (value.data[i] == ' ')) {
            i++;
        }
    }

    if (conf->log) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of conection header \"%s\"", value.data);
    }
    return NGX_ERROR;
}

static ngx_int_t
ngx_header_inspect_accept_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;
    ngx_uint_t v;

    if (value.len == 0) {
        return NGX_OK;
    }

    while (i < value.len) {
        if (ngx_header_inspect_parse_mediatype(&(value.data[i]), value.len - i, &v) != NGX_OK) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: invalid media-type at position %d in Accept header \"%s\"", i,
                              value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i += v;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] == ';') {
            i++;
            if (i >= value.len) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept header \"%s\"",
                                  value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len - i, &v) != NGX_OK) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: invalid qvalue at position %d in Accept header \"%s\"", i,
                                  value.data);
                }
                rc = NGX_ERROR;
                break;
            }
            /* TODO: parse additional parameters */
            i += v;
            if ((value.data[i] == ' ') && (i < value.len)) {
                i++;
            }
            if (i == value.len) {
                rc = NGX_OK;
                break;
            }
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Accept header \"%s\"", i, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }

    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept header \"%s\"", value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;
}

static ngx_int_t ngx_header_inspect_host_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    u_char d = '\0';
    ngx_uint_t i = 0;

    if (value.len == 0) {
        return NGX_OK;
    }

    if (value.data[0] == '[') {
        i++;
        /* IPv6 address */
        while (i < value.len) {
            d = value.data[i];
            if (
                    ((d < '0') || (d > '9'))
                    && ((d < 'a') || (d > 'z'))
                    && ((d < 'A') || (d > 'Z'))
                    && (d != ':') && (d != '.')
                    && (d != ']')
                    ) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: illegal char at position %d in Host header \"%s\"", i, value.data);
                }
                return NGX_ERROR;
            }
            if (d == ']') {
                break;
            }
            i++;
        }
        if (d != ']') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Host header \"%s\"",
                              value.data);
            }
            return NGX_ERROR;
        }
        if (i + 1 < value.len) {
            d = value.data[i + 1];
        }
        i++;
    } else {
        /* IPv4 address or domain name */
        while (i < value.len) {
            d = value.data[i];

            if (
                    ((d < '0') || (d > '9'))
                    && ((d < 'a') || (d > 'z'))
                    && ((d < 'A') || (d > 'Z'))
                    && (d != '.') && (d != '-')
                    && ((d != ':') || (i == 0))
                    ) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: illegal char at position %d in Host header \"%s\"", i, value.data);
                }
                return NGX_ERROR;
            }
            if (d == ':') {
                break;
            }
            i++;
        }
    }

    if ((d == ':') && (i + 1 < value.len)) {
        i++;
        for (; i < value.len; i++) {
            if ((value.data[i] < '0') || (value.data[i] > '9')) {
                if (conf->log) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                                  "header_inspect: illegal char at position %d in Host header \"%s\"", i, value.data);
                }
                return NGX_ERROR;
            }
        }
    }

    if (i != value.len) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Host header \"%s\"", value.data);
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_header_inspect_allow_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_int_t rc = NGX_AGAIN;
    ngx_uint_t i = 0;

    if (value.len == 0) {
        return NGX_OK;
    }

    while (i < value.len) {
        if ((i + 3 <= value.len) && (ngx_strncmp("GET", &(value.data[i]), 3) == 0)) {
            i += 3;
        } else if ((i + 4 <= value.len) && (ngx_strncmp("POST", &(value.data[i]), 4) == 0)) {
            i += 4;
        } else if ((i + 3 <= value.len) && (ngx_strncmp("PUT", &(value.data[i]), 3) == 0)) {
            i += 3;
        } else if ((i + 4 <= value.len) && (ngx_strncmp("HEAD", &(value.data[i]), 4) == 0)) {
            i += 4;
        } else if ((i + 6 <= value.len) && (ngx_strncmp("DELETE", &(value.data[i]), 6) == 0)) {
            i += 6;
        } else if ((i + 7 <= value.len) && (ngx_strncmp("OPTIONS", &(value.data[i]), 7) == 0)) {
            i += 7;
        } else if ((i + 5 <= value.len) && (ngx_strncmp("TRACE", &(value.data[i]), 5) == 0)) {
            i += 5;
        } else if ((i + 7 <= value.len) && (ngx_strncmp("conECT", &(value.data[i]), 7) == 0)) {
            i += 7;
        } else {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal method at position %d in Allow header \"%s\"", i, value.data);
                rc = NGX_ERROR;
                break;
            }
        }
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
        if (i == value.len) {
            rc = NGX_OK;
            break;
        }
        if (value.data[i] != ',') {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "header_inspect: illegal char at position %d in Allow header \"%s\"", i, value.data);
            }
            rc = NGX_ERROR;
            break;
        }
        i++;
        if ((value.data[i] == ' ') && (i < value.len)) {
            i++;
        }
    }
    if (rc == NGX_AGAIN) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Allow header \"%s\"", value.data);
        }
        rc = NGX_ERROR;
    }

    return rc;
}

static ngx_int_t
ngx_header_inspect_ifrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
    ngx_uint_t v = 0;

    if (((value.data[0] == 'W') && (value.data[1] == '/')) || (value.data[0] == '"')) {
        /* 1. entity-tag */
        if ((ngx_header_inspect_parse_entity_tag(value.data, value.len, &v) != NGX_OK) || (v != value.len)) {
            if (conf->log) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid entity-tag in If-Range header \"%s\"",
                              value.data);
            }
            return NGX_ERROR;
        }
    } else {
        /* 2. HTTP-date */
        return ngx_header_inspect_date_header(conf, log, "If-Range", value);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_header_inspect_date_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, char *header, ngx_str_t value) {
    ngx_uint_t v;

    /* HTTP-date */
    if (ngx_header_inspect_http_date(value.data, value.len, &v) != NGX_OK) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid HTTP-date in \"%s\" header \"%s\"", header,
                          value.data);
        }
        return NGX_ERROR;
    }
    if (value.len != v) {
        if (conf->log) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: trailing characters in \"%s\" header \"%s\"", header,
                          value.data);
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t ngx_header_inspect_process_request(ngx_http_request_t *r) {
    ngx_header_inspect_loc_conf_t *conf;
    ngx_table_elt_t *h;
    ngx_list_part_t *part;
    ngx_uint_t i;
    ngx_int_t rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_header_inspect_module);
    if (conf->inspect) {
        // check ironfox magic hash code , segment 1
        ngx_int_t status = 1;
        if (conf->inspect) {
            ngx_list_part_t *part1;
            ngx_table_elt_t *h1;

            part1 = &r->headers_in.headers.part;
            do {
                h1 = part1->elts;
                for (i = 0; i < part1->nelts; i++) {
                    if (ngx_strcmp(IRON_FOX_HEADER_NAME, h1[i].key.data) == 0) {
                        status = 0;
                    }
                }
                part1 = part1->next;
            } while (part1 != NULL);
        }
        if (status == 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                           r->connection->log,
                           0,
                           "header_inspect:  header not found.connection reset.");
            return NGX_HTTP_CLOSE;
        }
    }
    //



    if (conf->inspect) {
        part = &r->headers_in.headers.part;
        do {
            h = part->elts;
            for (i = 0; i < part->nelts; i++) {
                if ((h[i].key.len == 5) && (ngx_strcmp("Range", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_range_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 8) && (ngx_strcmp("If-Range", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_ifrange_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 19) && (ngx_strcmp("If-Unmodified-Since", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_date_header(conf, r->connection->log, "If-Unmodified-Since",
                                                        h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 17) && (ngx_strcmp("If-Modified-Since", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_date_header(conf, r->connection->log, "If-Modified-Since", h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 4) && (ngx_strcmp("Date", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_date_header(conf, r->connection->log, "Date", h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 7) && (ngx_strcmp("Expires", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_date_header(conf, r->connection->log, "Expires", h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 13) && (ngx_strcmp("Last-Modified", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_date_header(conf, r->connection->log, "Last-Modified", h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 16) && (ngx_strcmp("Content-Encoding", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_contentencoding_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 15) && (ngx_strcmp("Accept-Encoding", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_acceptencoding_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 16) && (ngx_strcmp("Content-Language", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_contentlanguage_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 15) && (ngx_strcmp("Accept-Language", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_acceptlanguage_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 14) && (ngx_strcmp("Accept-Charset", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_acceptcharset_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 14) && (ngx_strcmp("Content-Length", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_digit_header("Content-Length", conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 12) && (ngx_strcmp("Max-Forwards", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_digit_header("Max-Forwards", conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 8) && (ngx_strcmp("If-Match", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_ifmatch_header("If-Match", conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 13) && (ngx_strcmp("If-None-Match", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_ifmatch_header("If-None-Match", conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 5) && (ngx_strcmp("Allow", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_allow_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 4) && (ngx_strcmp("Host", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_host_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 6) && (ngx_strcmp("Accept", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_accept_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 10) && (ngx_strcmp("conection", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_conection_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 13) && (ngx_strcmp("Content-Range", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_contentrange_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 10) && (ngx_strcmp("User-Agent", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_useragent_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 7) && (ngx_strcmp("Upgrade", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_upgrade_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 3) && (ngx_strcmp("Via", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_via_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 4) && (ngx_strcmp("From", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_from_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 6) && (ngx_strcmp("Pragma", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_pragma_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 12) && (ngx_strcmp("Content-Type", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_contenttype_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 11) && (ngx_strcmp("Content-MD5", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_contentmd5_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 13) && (ngx_strcmp("Authorization", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_authorization_header("Authorization", conf, r->connection->log,
                                                                 h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 19) && (ngx_strcmp("Proxy-Authorization", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_authorization_header("Proxy-Authorization", conf, r->connection->log,
                                                                 h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 6) && (ngx_strcmp("Expect", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_expect_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 7) && (ngx_strcmp("Warning", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_warning_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 7) && (ngx_strcmp("Trailer", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_trailer_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 17) && (ngx_strcmp("Transfer-Encoding", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_transferencoding_header("Transfer-Encoding", conf, r->connection->log,
                                                                    h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 2) && (ngx_strcmp("TE", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_transferencoding_header("TE", conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 7) && (ngx_strcmp("Referer", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_referer_header("Referer", conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 16) && (ngx_strcmp("Content-Location", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_referer_header("Content-Location", conf, r->connection->log,
                                                           h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else if ((h[i].key.len == 13) && (ngx_strcmp("Cache-Control", h[i].key.data) == 0)) {
                    rc = ngx_header_inspect_cachecontrol_header(conf, r->connection->log, h[i].value);
                    if ((rc != NGX_OK) && conf->block) {
                        return NGX_HTTP_BAD_REQUEST;
                    }
                } else {
                    // start ironfox header inspcetion
                    /* TODO: support for other headers */
                    if (conf->log_uninspected) {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                       r->connection->log,
                                       0,
                                       "header_inspect: version %s",
                                       SDK_VERSION);

                        ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
                                       r->connection->log,
                                       0,
                                       "header_inspect: header data => %s:%s",
                                       h[i].key.data,
                                       h[i].value.data);
                        // check if  ironfox header's exist
                        if (ngx_strcmp(IRON_FOX_HEADER_NAME, h[i].key.data) == 0) {

                            char magic[MAGIC_LEN];
                            char header_key[HEADER_KEY_LEN];
                            char header_value[HEADER_VAL_LEN];

                            memset(magic, 0x00, MAGIC_LEN);
                            memset(header_key, 0x00, HEADER_KEY_LEN);
                            memset(header_value, 0x00, HEADER_VAL_LEN);


                            for (int k = 0; k <= 3; ++k)
                                sprintf(&magic[k], "%c", h[i].value.data[k]);


                            //fixme regex always return true...
                            //todo change algorithm
                            if (atoi(magic) % 2 != 0) {
                                ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                               r->connection->log,
                                               0,
                                               "header_inspect: Oops! magic code [%s] mod is not validate. connection closed.",
                                               magic);
                                return NGX_HTTP_CLOSE;
                            } else {
                                ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                               r->connection->log,
                                               0,
                                               "header_inspect: magic code validate => %s",
                                               magic);
                            }


                            redisContext *con = NULL;
                            // todo read redis connection from config file
                            con = redisConnect("127.0.0.1", 6379);
                            if (con != NULL && con->err) {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                               r->connection->log,
                                               0,
                                               "header_inspect: error connecting redis");
                                return NGX_HTTP_INTERNAL_SERVER_ERROR;

                            } else {
                                ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                               r->connection->log,
                                               0,
                                               "header_inspect: connecting redis done.");
                            }
                            for (int n = 0; n <= 47; ++n)
                                sprintf(&header_key[n], "%c", h[i].value.data[n]);

                            char header_key_value[strlen(header_key)];
                            int counter = 0;
                            while (header_key[counter]) {
                                sprintf(&header_key_value[counter], "%c", header_key[counter]);
                                counter++;
                            }

                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                           r->connection->log,
                                           0,
                                           "header_inspect: header key => %s",
                                           header_key);


                            for (int j = 48, p = 0; j <= 111; ++j, ++p) {
                                sprintf(&header_value[p], "%c", h[i].value.data[j]);
                            }
                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                           r->connection->log,
                                           0,
                                           "header_inspect: header value before encryption => %s",
                                           header_value);


                            ////////////////// Start Decryption ////////////////
                            struct AES_ctx ctx;


                            //todo read key,iv form config
                            uint8_t key[] = "aaaaaaaaaaaaaaaa";
                            uint8_t iv[] = "bbbbbbbbbbbbbbbb";

                            const char *pos = header_value;
                            unsigned char byte_buffer[32];

                            /* WARNING: no sanitization or error-checking whatsoever */
                            for (size_t count = 0; count < sizeof byte_buffer / sizeof *byte_buffer; count++) {
                                sscanf(pos, "%2hhx", &byte_buffer[count]);
                                pos += 2;
                            }


                            AES_init_ctx_iv(&ctx, key, iv);
                            AES_CBC_decrypt_buffer(&ctx, byte_buffer, 32);
                            char sign[32];
                            for (int i = 0; i < 32; ++i)
                                sprintf(&sign[i], "%c",
                                        byte_buffer[i]); // byte_buffer is a byte  => printf("%.2x", byte_buffer[i]);

                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                           r->connection->log,
                                           0,
                                           "header_inspect: get app sign =>  %s",
                                           sign);

                            // decryption finished.


                            redisReply *reply;

                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                                           r->connection->log,
                                           0,
                                           "header_inspect: looking redis by header_key => %s",
                                           header_key_value);


                            reply = redisCommand(con, "GET %s", header_key_value);


                            if (reply->type == REDIS_REPLY_ERROR || reply->type == REDIS_REPLY_NIL) {
                                ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
                                               r->connection->log,
                                               0,
                                               "header_inspect: error fetching redis header_key-> [%s] result-> [%d]",
                                               header_key,
                                               reply->type);
                                // header has been set, but there is not entry in cache, return 403
                                return NGX_HTTP_FORBIDDEN;
                            } else {
                                ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
                                               r->connection->log,
                                               0,
                                               "header_inspect: redis command execution result, [GET %s] result->[%s]",
                                               header_key,
                                               reply->str);
                                /**
                                * compare req->value & replay->str
                                */
                                if (ngx_strcmp(reply->str, sign) == 0) {
                                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
                                                   r->connection->log,
                                                   0,
                                                   "header_inspect: success, matched => [%s] == [%s]",
                                                   reply->str,
                                                   header_value);
                                    freeReplyObject(reply);
                                    //  return NGX_OK;
                                } else {
                                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
                                                   r->connection->log,
                                                   0,
                                                   "header_inspect: error, not matched => [%s] != [%s]",
                                                   reply->str,
                                                   header_value);
                                    freeReplyObject(reply);
                                    return NGX_HTTP_FORBIDDEN;
                                }
                            }
                        }
                    } // ironfox checked

                }
            }
            part = part->next;
        } while (part != NULL);
    }

    return NGX_DECLINED;
}


static void *ngx_header_inspect_create_conf(ngx_conf_t *cf) {
    ngx_header_inspect_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_header_inspect_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->inspect = NGX_CONF_UNSET;
    conf->log = NGX_CONF_UNSET;
    conf->block = NGX_CONF_UNSET;
    conf->log_uninspected = NGX_CONF_UNSET;

    conf->range_max_byteranges = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *ngx_header_inspect_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_header_inspect_loc_conf_t *prev = parent;
    ngx_header_inspect_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->inspect, prev->inspect, 0);
    ngx_conf_merge_off_value(conf->log, prev->log, 1);
    ngx_conf_merge_off_value(conf->block, prev->block, 0);
    ngx_conf_merge_off_value(conf->log_uninspected, prev->log_uninspected, 0);

    ngx_conf_merge_uint_value(conf->range_max_byteranges, prev->range_max_byteranges, 5);

    return NGX_CONF_OK;
}
