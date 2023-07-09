/**
 * @file utils.h
 * @author Georgy Firsov (gfirsov007@gmail.com)
 * @brief Some helpers
 * @date 2023-07-07
 * 
 * @copyright Copyright (c) 2023
 */

#ifndef BCLIB_UTILS_INCLUDED
#define BCLIB_UTILS_INCLUDED


/**
 * @brief Alignment specifier (alignas is supported since C11).
 */
#if defined(_MSC_VER)
#   define BCLIB_ALIGN16 __declspec(align(16))
#elif defined(__GNUC__) 
#   define BCLIB_ALIGN16 __attribute__ ((aligned(16)))
#else
#   error Unsupported target for now
#endif 


/**
 * @brief Force inlining specifier.
 */
#if defined(_MSC_VER)
#   define BCLIB_FORCEINLINE __forceinline
#elif defined(__GNUC__)
#   define BCLIB_FORCEINLINE __attribute__((always_inline))
#else
#   error Unsupported target for now
#endif 


/**
 * @brief Static assertion for C language (prior to C11).
 */
#define BCLIB_STATIC_ASSERT(cond, msg) \
   typedef char static_assertion_failed_##msg[(cond) ? 1 : -1]

#endif  // !BCLIB_UTILS_INCLUDED