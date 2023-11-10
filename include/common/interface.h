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
 * @brief Block encryption procedure.
 *
 * @param in Plaintext block
 * @param round_keys Initialized key schedule for encryption
 * @param out Ciphertext block
 */
#define BCLIB_ENCRYPT_BLOCK(block_type)          \
    void (*encrypt_block)(const block_type in,   \
                          const KEY* round_keys, \
                          block_type* out)


/**
 * @brief Block decryption procedure.
 *
 * @param in Ciphertext block
 * @param round_keys Initialized key schedule for decryption
 * @param out Plaintext block
 */
#define BCLIB_DECRYPT_BLOCK(block_type)          \
    void (*decrypt_block)(const block_type in,   \
                          const KEY* round_keys, \
                          block_type* out)


/**
 * @brief Encryption key schedule initialization procedure.
 *
 * @param key Binary key representation
 * @param round_keys Key schedule for encryption to initialize
 */
#define BCLIB_INIT_ENCRYPT_KEY()                             \
    void (*initialize_encrypt_key)(const unsigned char* key, \
                                   KEY* round_keys)


/**
 * @brief Decryption key schedule initialization procedure.
 * 
 * @param key Binary key representation
 * @param round_keys Key schedule for decryption to initialize
 */
#define BCLIB_INIT_DECRYPT_KEY()                             \
    void (*initialize_decrypt_key)(const unsigned char* key, \
                                   KEY* round_keys)


/**
 * @brief Defines a block cipher dispatch table.
 * 
 * Block ciphers with different block sizes are described using different
 * dispatch tables intentionally to allow implementing algorithms with 
 * high performance for research purposes.
 */
#define BCLIB_DEFINE_CIPHER_TABLE(name, block_type)                                               \
    typedef struct tag##name                                                                      \
    {                                                                                             \
        unsigned char block_size; /**< Block size in bytes */                                     \
        unsigned char key_size;   /**< Key size in bytes */                                       \
                                                                                                  \
        BCLIB_ENCRYPT_BLOCK(block_type); /**< Block encryption procedure */                       \
        BCLIB_DECRYPT_BLOCK(block_type); /**< Block decryption procedure */                       \
        BCLIB_INIT_ENCRYPT_KEY();        /**< Encryption key schedule initialization procedure */ \
        BCLIB_INIT_DECRYPT_KEY();        /**< Decryption key schedule initialization procedure */ \
    } name


/**
 * @brief 128-bit block cipher dispatch table.
 */
BCLIB_DEFINE_CIPHER_TABLE(BLOCK_CIPHER, __m128i);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !BCLIB_INTERFACE_INCLUDED