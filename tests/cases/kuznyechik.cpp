/**
 * @file kuznyechik.cpp
 * @author Georgy Firsov (gfirsov007@gmail.com)
 * @brief Test cases for Kuznyechik cipher
 * @date 2023-07-07
 * 
 * @copyright Copyright (c) 2023
 */

#include "tests_common.hpp"


TEST(Kuznyechik, Initialize)
{
    //
    // MUST NOT throw any exception
    // MUST initialize all required fields of BLOCK_CIPHER structure.
    //

    BLOCK_CIPHER cipher = {};
    kuznyechik_initialize_interface(&cipher);

    EXPECT_EQ(cipher.block_size, KUZNYECHIK_BLOCK_SIZE);
    EXPECT_EQ(cipher.key_size, KUZNYECHIK_KEY_SIZE);
    EXPECT_NE(cipher.encrypt_block, nullptr);
    EXPECT_NE(cipher.decrypt_block, nullptr);
    EXPECT_NE(cipher.initialize_encrypt_key, nullptr);
    EXPECT_NE(cipher.initialize_decrypt_key, nullptr);
}


TEST(Kuznyechik, Encrypt)
{
    //
    // MUST NOT throw any exception
    // Encrypted text MUST match an expected test vector
    //

    BCLIB_TESTS_ALIGN16 constexpr unsigned char plaintext[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    };

    constexpr unsigned char raw_key[] = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    constexpr unsigned char expected_ciphertext[] = {
        0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
        0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd
    };

    BLOCK_CIPHER cipher = {};
    kuznyechik_initialize_interface(&cipher);

    KEY key = {};
    cipher.initialize_encrypt_key(raw_key, &key);

    BCLIB_TESTS_ALIGN16 unsigned char ciphertext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    cipher.encrypt_block(*reinterpret_cast<const __m128i*>(plaintext),
                         &key, reinterpret_cast<__m128i*>(ciphertext));

    EXPECT_PRED3(test::details::EqualBlocks, expected_ciphertext, ciphertext, KUZNYECHIK_BLOCK_SIZE);
}


TEST(Kuznyechik, Decrypt)
{
    //
    // MUST NOT throw any exception
    // Decrypted text MUST match an expected test vector
    //

    BCLIB_TESTS_ALIGN16 constexpr unsigned char ciphertext[] = {
        0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
        0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd
    };

    constexpr unsigned char raw_key[] = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    constexpr unsigned char expected_plaintext[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    };

    BLOCK_CIPHER cipher = {};
    kuznyechik_initialize_interface(&cipher);

    KEY key = {};
    cipher.initialize_decrypt_key(raw_key, &key);

    BCLIB_TESTS_ALIGN16 unsigned char plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    cipher.decrypt_block(*reinterpret_cast<const __m128i*>(ciphertext),
                         &key, reinterpret_cast<__m128i*>(plaintext));

    EXPECT_PRED3(test::details::EqualBlocks, expected_plaintext, plaintext, KUZNYECHIK_BLOCK_SIZE);
}