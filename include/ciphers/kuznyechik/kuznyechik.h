/**
 * @file kuznyechik.h
 * @author Georgy Firsov (gfirsov007@gmail.com)
 * @brief Kuznyechik block cipher
 * @date 2023-07-07
 * 
 * @copyright Copyright (c) 2023
 */

#ifndef BCLIB_KUZNYECHIK_INCLUDED
#define BCLIB_KUZNYECHIK_INCLUDED


#include "common/interface.h"


#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus


/**
 * @brief Kuznyechik block size in bytes.
 */
#define KUZNYECHIK_BLOCK_SIZE 16


/**
 * @brief Kuznyechik key size in bytes.
 */
#define KUZNYECHIK_KEY_SIZE 32


/**
 * @brief Initializes block cipher interface for Kuznyechik.
 * 
 * @param cipher Block cipher interface to be initialized.
 */
void kuznyechik_initialize_interface(BLOCK_CIPHER* cipher);


#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !BCLIB_KUZNYECHIK_INCLUDED
