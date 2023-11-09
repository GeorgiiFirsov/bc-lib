/**
 * @file kuznyechik.c
 * @author Georgy Firsov (gfirsov007@gmail.com)
 * @brief Kuznyechik block cipher
 * @version 0.1
 * @date 2023-07-07
 * 
 * @copyright Copyright (c) 2023
 */


#include "ciphers/kuznyechik/kuznyechik.h"
#include "common/utils.h"
#include "galoislib.h"

#include <mmintrin.h>
#include <emmintrin.h>


/**
 * @brief Number of rounds in cipher.
 */
#define KUZNYECHIK_ROUNDS 10


/**
 * @brief 64 bit type (defined here intentionally to
 *        be able not to include any of stdlib headers.
 */
typedef unsigned long long uint64_t;


//
// Just to be sure if we a going well :)
//

BCLIB_STATIC_ASSERT(sizeof(uint64_t) == 8, wrong_64_bit_type);


/**
 * @brief Internal Kuznyechik key structure.
 */
typedef struct tagINTERNAL_KEY
{
    __m128i key[KUZNYECHIK_ROUNDS];
} INTERNAL_KEY;


//
// Check if generic key can hold a key for Kuznyechik
//

BCLIB_STATIC_ASSERT(sizeof(INTERNAL_KEY) <= MAX_KEY_SIZE,
                    maximum_key_size_is_less_than_necessary);


/**
 * @brief SBox. Chapter 4.1.1 of GOST 34.12-2018
 */
static const unsigned char kuznyechikp_sbox[256] = {
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6
};


/**
 * @brief Inverse of SBox. Chapter 4.1.1 of GOST 34.12-2018
 */
static const unsigned char kuznyechikp_sbox_inverse[256] = {
    0xa5, 0x2d, 0x32, 0x8f, 0x0e, 0x30, 0x38, 0xc0, 0x54, 0xe6, 0x9e, 0x39, 0x55, 0x7e, 0x52, 0x91,
    0x64, 0x03, 0x57, 0x5a, 0x1c, 0x60, 0x07, 0x18, 0x21, 0x72, 0xa8, 0xd1, 0x29, 0xc6, 0xa4, 0x3f,
    0xe0, 0x27, 0x8d, 0x0c, 0x82, 0xea, 0xae, 0xb4, 0x9a, 0x63, 0x49, 0xe5, 0x42, 0xe4, 0x15, 0xb7,
    0xc8, 0x06, 0x70, 0x9d, 0x41, 0x75, 0x19, 0xc9, 0xaa, 0xfc, 0x4d, 0xbf, 0x2a, 0x73, 0x84, 0xd5,
    0xc3, 0xaf, 0x2b, 0x86, 0xa7, 0xb1, 0xb2, 0x5b, 0x46, 0xd3, 0x9f, 0xfd, 0xd4, 0x0f, 0x9c, 0x2f,
    0x9b, 0x43, 0xef, 0xd9, 0x79, 0xb6, 0x53, 0x7f, 0xc1, 0xf0, 0x23, 0xe7, 0x25, 0x5e, 0xb5, 0x1e,
    0xa2, 0xdf, 0xa6, 0xfe, 0xac, 0x22, 0xf9, 0xe2, 0x4a, 0xbc, 0x35, 0xca, 0xee, 0x78, 0x05, 0x6b,
    0x51, 0xe1, 0x59, 0xa3, 0xf2, 0x71, 0x56, 0x11, 0x6a, 0x89, 0x94, 0x65, 0x8c, 0xbb, 0x77, 0x3c,
    0x7b, 0x28, 0xab, 0xd2, 0x31, 0xde, 0xc4, 0x5f, 0xcc, 0xcf, 0x76, 0x2c, 0xb8, 0xd8, 0x2e, 0x36,
    0xdb, 0x69, 0xb3, 0x14, 0x95, 0xbe, 0x62, 0xa1, 0x3b, 0x16, 0x66, 0xe9, 0x5c, 0x6c, 0x6d, 0xad,
    0x37, 0x61, 0x4b, 0xb9, 0xe3, 0xba, 0xf1, 0xa0, 0x85, 0x83, 0xda, 0x47, 0xc5, 0xb0, 0x33, 0xfa,
    0x96, 0x6f, 0x6e, 0xc2, 0xf6, 0x50, 0xff, 0x5d, 0xa9, 0x8e, 0x17, 0x1b, 0x97, 0x7d, 0xec, 0x58,
    0xf7, 0x1f, 0xfb, 0x7c, 0x09, 0x0d, 0x7a, 0x67, 0x45, 0x87, 0xdc, 0xe8, 0x4f, 0x1d, 0x4e, 0x04,
    0xeb, 0xf8, 0xf3, 0x3e, 0x3d, 0xbd, 0x8a, 0x88, 0xdd, 0xcd, 0x0b, 0x13, 0x98, 0x02, 0x93, 0x80,
    0x90, 0xd0, 0x24, 0x34, 0xcb, 0xed, 0xf4, 0xce, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3a, 0x01, 0x26,
    0x12, 0x1a, 0x48, 0x68, 0xf5, 0x81, 0x8b, 0xc7, 0xd6, 0x20, 0x0a, 0x08, 0x00, 0x4c, 0xd7, 0x74
};


/**
 * @brief Linear transformation vector. Chapter 4.1.1 of GOST 34.12-2018
 */
static const unsigned char kuznyechikp_linear_vector[16] = {
    0x94, 0x20, 0x85, 0x10, 0xc2, 0xc0, 0x01, 0xfb, 0x01, 0xc0, 0xc2, 0x10, 0x85, 0x20, 0x94, 0x01
};


/**
 * @brief Lookup table for computing LS trnsformation. Chapter 4.2 of GOST 34.12-2018
 */
BCLIB_ALIGN16 static unsigned char kuznyechikp_ls_lookup_table[16 * 256 * 16];


/**
 * @brief Lookup table for computing inverse L transformation. Chapter 4.2 of GOST 34.12-2018
 */
BCLIB_ALIGN16 static unsigned char kuznyechikp_linear_inverse_lookup_table[16 * 256 * 16];


/**
 * @brief Lookup table for computing inverse of LS transformation. Chapter 4.2 of GOST 34.12-2018
 */
BCLIB_ALIGN16 static unsigned char kuznyechikp_ls_inverse_lookup_table[16 * 256 * 16];


/**
 * @brief Implementation of linear transformation.Chapter 4.1.2 of GOST 34.12-2018
 */
static void kuznyechikp_linear_transform(unsigned char* inout)
{
    unsigned char temporary;
    int idx1;
    int idx2;

    for (idx1 = 16; idx1; --idx1)
    {
        temporary = inout[15];

        for (idx2 = 14; idx2 >= 0; --idx2)
        {
            inout[idx2 + 1] = inout[idx2];
            temporary ^= gf8_multiply(inout[idx2], kuznyechikp_linear_vector[idx2]);
        }

        inout[0] = temporary;
    }
}


/**
 * @brief Implementation of linear transformation inverse.Chapter 4.1.2 of GOST 34.12-2018
 */
BCLIB_FORCEINLINE static void kuznyechikp_linear_transform_inverse(unsigned char* inout)
{
    unsigned char temporary;
    int idx1;
    int idx2;

    for (idx1 = 16; idx1 > 0; --idx1)
    {
        temporary = inout[0];

        for (idx2 = 0; idx2 < 15; ++idx2)
        {
            inout[idx2] = inout[idx2 + 1];
            temporary ^= gf8_multiply(inout[idx2], kuznyechikp_linear_vector[idx2]);
        }

        inout[15] = temporary;
    }
}


/**
 * @brief Initializes lookup tables for internal transformations.
 */
BCLIB_FORCEINLINE static void kuznyechikp_initialize_tables()
{
    static char initialized = 0;

    if (initialized)
    {
        return;
    }

    initialized = 1;

    unsigned int idx1;
    unsigned int idx2;
    unsigned int table_offset = 0;

    unsigned char* table_pointer;

    for (idx1 = 0; idx1 < 16; ++idx1)
    {
        for (idx2 = 0; idx2 < 256; ++idx2)
        {
            //
            // LS transformation (substitution and linear transformation)
            //

            table_pointer       = kuznyechikp_ls_lookup_table + table_offset;
            table_pointer[idx1] = kuznyechikp_sbox[idx2];
            kuznyechikp_linear_transform(table_pointer);

            //
            // Inverse of LS transformation
            //

            table_pointer       = kuznyechikp_ls_inverse_lookup_table + table_offset;
            table_pointer[idx1] = kuznyechikp_sbox_inverse[idx2];
            kuznyechikp_linear_transform_inverse(table_pointer);

            //
            // Inverse of linear transformation
            //

            table_pointer       = kuznyechikp_linear_inverse_lookup_table + table_offset;
            table_pointer[idx1] = (unsigned char)idx2;
            kuznyechikp_linear_transform_inverse(table_pointer);

            table_offset += 16;
        }
    }
}


/**
 * @brief Preparation for lookup tables usage
 */
#define KUZNYECHIKP_XOR_LOOKUP_INIT()                                                               \
    __m128i kuznyechikp_temporary1;                                                                 \
    __m128i kuznyechikp_temporary2;                                                                 \
    __m128i kuznyechikp_lookup_mask = _mm_setr_epi8(0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, \
                                                    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff)


/**
 * @brief Internal lookup table accessor
 */
#define KUZNYECHIKP_XOR_LOOKUP(table, a)                                                                    \
    kuznyechikp_temporary1 = _mm_and_si128(kuznyechikp_lookup_mask, a);                                     \
    kuznyechikp_temporary2 = _mm_andnot_si128(kuznyechikp_lookup_mask, a);                                  \
                                                                                                            \
    kuznyechikp_temporary1 = _mm_srli_epi16(kuznyechikp_temporary1, 4);                                     \
    kuznyechikp_temporary2 = _mm_slli_epi16(kuznyechikp_temporary2, 4);                                     \
                                                                                                            \
    a = _mm_load_si128((const void*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 0)));                \
                                                                                                            \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 0) + 0x1000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 1) + 0x2000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 1) + 0x3000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 2) + 0x4000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 2) + 0x5000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 3) + 0x6000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 3) + 0x7000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 4) + 0x8000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 4) + 0x9000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 5) + 0xa000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 5) + 0xb000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 6) + 0xc000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 6) + 0xd000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary2, 7) + 0xe000)); \
    a = _mm_xor_si128(a, *(const __m128i*)(table + _mm_extract_epi16(kuznyechikp_temporary1, 7) + 0xf000));


/**
 * @brief X transformation.Chapter 4.2 of GOST 34.12-2018
 */
#define KUZNYECHIKP_X(a, k) a = _mm_xor_si128(a, k)


/**
 * @brief LS transformation.Chapter 4.2 of GOST 34.12-2018
 */
#define KUZNYECHIKP_LS(a) KUZNYECHIKP_XOR_LOOKUP(kuznyechikp_ls_lookup_table, a)


/**
 * @brief Inverse of LS transformation.Chapter 4.2 of GOST 34.12-2018
 */
#define KUZNYECHIKP_ILS(a) KUZNYECHIKP_XOR_LOOKUP(kuznyechikp_ls_inverse_lookup_table, a)


/**
 * @brief Inverse of L transformation.Chapter 4.2 of GOST 34.12-2018
 */
#define KUZNYECHIKP_IL(a) KUZNYECHIKP_XOR_LOOKUP(kuznyechikp_linear_inverse_lookup_table, a)


/**
 * @brief Inverse of S transformation.Chapter 4.2 of GOST 34.12-2018
 */
#define KUZNYECHIKP_IS(a)                                   \
    {                                                       \
        unsigned char* c = ((unsigned char*)&a);            \
        c[0]             = kuznyechikp_sbox_inverse[c[0]];  \
        c[1]             = kuznyechikp_sbox_inverse[c[1]];  \
        c[2]             = kuznyechikp_sbox_inverse[c[2]];  \
        c[3]             = kuznyechikp_sbox_inverse[c[3]];  \
        c[4]             = kuznyechikp_sbox_inverse[c[4]];  \
        c[5]             = kuznyechikp_sbox_inverse[c[5]];  \
        c[6]             = kuznyechikp_sbox_inverse[c[6]];  \
        c[7]             = kuznyechikp_sbox_inverse[c[7]];  \
        c[8]             = kuznyechikp_sbox_inverse[c[8]];  \
        c[9]             = kuznyechikp_sbox_inverse[c[9]];  \
        c[10]            = kuznyechikp_sbox_inverse[c[10]]; \
        c[11]            = kuznyechikp_sbox_inverse[c[11]]; \
        c[12]            = kuznyechikp_sbox_inverse[c[12]]; \
        c[13]            = kuznyechikp_sbox_inverse[c[13]]; \
        c[14]            = kuznyechikp_sbox_inverse[c[14]]; \
        c[15]            = kuznyechikp_sbox_inverse[c[15]]; \
    }


/**
 * @brief Kuznyechik block encryption.
 *
 * @param in Plaintext block
 * @param round_keys Initialized key schedule for Kuznyechik encryption
 * @param out Ciphertext block
 */
static void kuznyechik_encrypt_block(const __m128i in, const KEY* round_keys, __m128i* out)
{
    KUZNYECHIKP_XOR_LOOKUP_INIT();

    //
    // Chapter 4.4.1 of GOST 34.12-2018
    // E(a) = X[K10] LS X[K9] ... LS X[K2] LS X[K1](a)
    //

    __m128i temporary                 = in;
    const INTERNAL_KEY* internal_keys = (const INTERNAL_KEY*)round_keys;

    KUZNYECHIKP_X(temporary, internal_keys->key[0]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[1]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[2]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[3]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[4]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[5]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[6]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[7]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[8]);
    KUZNYECHIKP_LS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[9]);

    *out = temporary;
}


/**
 * @brief Kuznyechik block decryption.
 *
 * @param in Ciphertext block
 * @param round_keys Initialized key schedule for Kuznyechik decryption
 * @param out Plaintext block
 */
static void kuznyechik_decrypt_block(const __m128i in, const KEY* round_keys, __m128i* out)
{
    KUZNYECHIKP_XOR_LOOKUP_INIT();

    //
    // Chapter 4.4.2 of GOST 34.12-2018
    // D(a) = X[K1] ILS X[K2] ... ILS X[K9] ILS X[K10](a)
    //

    __m128i temporary                 = in;
    const INTERNAL_KEY* internal_keys = (const INTERNAL_KEY*)round_keys;

    KUZNYECHIKP_IL(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[9]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[8]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[7]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[6]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[5]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[4]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[3]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[2]);
    KUZNYECHIKP_ILS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[1]);
    KUZNYECHIKP_IS(temporary);
    KUZNYECHIKP_X(temporary, internal_keys->key[0]);

    *out = temporary;
}


/**
 * @brief Kuznyechik encryption key initialization.
 *
 * @param key Binary key representation
 * @param round_keys Initialized key schedule for Kuznyechik encryption
 */
void kuznyechik_initialize_encrypt_key(const unsigned char* key, KEY* round_keys)
{
    //
    // Chapter 4.3 of GOST 34.12-2018
    //

    INTERNAL_KEY* internal_keys = (INTERNAL_KEY*)round_keys;

    unsigned int idx1;
    unsigned int idx2;
    uint64_t x[4];
    uint64_t z[2];
    unsigned char temporary[16];

    x[0] = ((uint64_t*)key)[0];
    x[1] = ((uint64_t*)key)[1];
    x[2] = ((uint64_t*)key)[2];
    x[3] = ((uint64_t*)key)[3];

    ((uint64_t*)&internal_keys->key[0])[0] = x[0];
    ((uint64_t*)&internal_keys->key[0])[1] = x[1];
    ((uint64_t*)&internal_keys->key[1])[0] = x[2];
    ((uint64_t*)&internal_keys->key[1])[1] = x[3];

    for (idx1 = 1; idx1 <= 32; ++idx1)
    {
        ((uint64_t*)temporary)[0] = 0;
        ((uint64_t*)temporary)[1] = 0;

        temporary[15] = (unsigned char)idx1;
        kuznyechikp_linear_transform(temporary);

        z[0] = x[0] ^ ((uint64_t*)temporary)[0];
        z[1] = x[1] ^ ((uint64_t*)temporary)[1];

        for (idx2 = 0; idx2 < 16; ++idx2)
        {
            ((unsigned char*)z)[idx2] = kuznyechikp_sbox[((unsigned char*)z)[idx2]];
        }

        kuznyechikp_linear_transform((unsigned char*)z);

        z[0] ^= x[2];
        z[1] ^= x[3];

        x[2] = x[0];
        x[3] = x[1];

        x[0] = z[0];
        x[1] = z[1];

        if ((idx1 & 7) == 0)
        {
            ((uint64_t*)&internal_keys->key[(idx1 >> 2)])[0]     = x[0];
            ((uint64_t*)&internal_keys->key[(idx1 >> 2)])[1]     = x[1];
            ((uint64_t*)&internal_keys->key[(idx1 >> 2) + 1])[0] = x[2];
            ((uint64_t*)&internal_keys->key[(idx1 >> 2) + 1])[1] = x[3];
        }
    }
}


/**
 * @brief Kuznyechik decryption key initialization.
 * 
 * @param key Binary key representation
 * @param round_keys Initialized key schedule for Kuznyechik decryption
 */
void kuznyechik_initialize_decrypt_key(const unsigned char* key, KEY* round_keys)
{
    //
    // Chapter 4.3 of GOST 34.12-2018
    //

    unsigned int idx;
    INTERNAL_KEY* internal_keys = (INTERNAL_KEY*)round_keys;

    kuznyechik_initialize_encrypt_key(key, round_keys);

    for (idx = 1; idx < KUZNYECHIK_ROUNDS; ++idx)
    {
        kuznyechikp_linear_transform_inverse((unsigned char*)&internal_keys->key[idx]);
    }
}


void kuznyechik_initialize_interface(BLOCK_CIPHER* cipher)
{
    //
    // Perform initialization first
    //

    kuznyechikp_initialize_tables();

    cipher->block_size = KUZNYECHIK_BLOCK_SIZE;
    cipher->key_size   = KUZNYECHIK_KEY_SIZE;

    cipher->encrypt_block          = kuznyechik_encrypt_block;
    cipher->decrypt_block          = kuznyechik_decrypt_block;
    cipher->initialize_encrypt_key = kuznyechik_initialize_encrypt_key;
    cipher->initialize_decrypt_key = kuznyechik_initialize_decrypt_key;
}
