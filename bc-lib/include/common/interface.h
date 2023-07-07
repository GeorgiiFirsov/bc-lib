/**
 * @file interface.h
 * @author Georgy Firsov (gfirsov007@gmail.com)
 * @brief Generic block cipher interface declaration
 * @date 2023-07-07
 * 
 * @copyright Copyright (c) 2023
 */

#ifndef BCLIB_INTERFACE_INCLUDED
#define BCLIB_INTERFACE_INCLUDED


#include "common/utils.h"
#include <emmintrin.h>


#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus


/**
 * @brief Maximal number of bytes in key. Note, that key 
 *        here is in expanded form, hence it is larger,
 *        than in standards and documentation.
 */
#define MAX_KEY_SIZE 160  // Kuznyechik


/**
 * @brief Generic key representation.
 */
typedef struct tagKEY
{
    BCLIB_ALIGN16 unsigned char key[MAX_KEY_SIZE]; /**< Key bytes */
} KEY;


/**
 * @brief Maximal number of bytes in block supported.
 */
#define MAX_BLOCK_SIZE 16


/**
 * @brief Block cipher dispatch table.
 */
typedef struct tagBLOCK_CIPHER
{
    unsigned char block_size; /**< Block size in bytes */
    unsigned char key_size;   /**< Key size in bytes */

    /**
	 * @brief Block encryption procedure.
	 */
    void (*encrypt_block)(const __m128i in, const KEY* round_keys, __m128i* out);

    /**
	 * @brief Block decryption procedure.
	 */
    void (*decrypt_block)(const __m128i in, const KEY* round_keys, __m128i* out);

    /**
	 * @brief Encryption key initialization procedure.
	 */
    void (*initialize_encrypt_key)(const unsigned char* key, KEY* round_keys);

    /**
	 * @brief Decryption key initialization procedure.
	 */
    void (*initialize_decrypt_key)(const unsigned char* key, KEY* round_keys);
} BLOCK_CIPHER;


#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !BCLIB_INTERFACE_INCLUDED