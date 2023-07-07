/**
 * @file tests_utils.hpp
 * @author Georgy Firsov (gfirsov007@gmail.com)
 * @brief Some helpers for tests
 * @date 2023-07-07
 * 
 * @copyright Copyright (c) 2023
 */

#pragma once

#include <cstddef>


namespace test::details {

//
// Necessary helper macro
//

#if defined(_MSC_VER)
#   define BCLIB_TESTS_ALIGN16 __declspec(align(16))
#elif defined(__GNUC__) 
#   define BCLIB_TESTS_ALIGN16 __attribute__ ((aligned(16)))
#else
#   error Unsupported target for now
#endif 


/**
 * @brief Test blocks for equality.
 */
inline bool EqualBlocks(const unsigned char* lhs, const unsigned char* rhs, std::size_t block_size)
{
    for (std::size_t idx = 0; idx < block_size; ++idx)
    {
        if (lhs[idx] != rhs[idx])
        {
            return false;
        }
    }

    return true;
}

}  // namespace test::details
