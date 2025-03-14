#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int32_t i32;
typedef int64_t i64;

#define MAX_NUM_SIZE sizeof(u64)
#define MAX_NUM_BITS (MAX_NUM_SIZE * CHAR_BIT)
#define MAX_KEY_SIZE MAX_NUM_SIZE
#define URANDOM_PATH "/dev/urandom"

u64 powmod(u64 x, u64 y, u64 mod);

/**
 * @brief Generate a random number with a specified number of bits.
 *
 * @param bits The number of bits the random number should have.
 * @return u64 The random number.
 */
u64 rand_num(u32 bits);
int cmd_rand(u32 num_bytes);

u64 gen_prime(u32 bits, bool verbose);
int cmd_prime(u64 num, bool generate, u32 bits);
