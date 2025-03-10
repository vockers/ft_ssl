#pragma once

#include <stdint.h>

typedef __uint8_t u8;
typedef uint32_t  u32;
typedef uint64_t  u64;

typedef int32_t i32;
typedef int64_t i64;

#define MAX_NUM_SIZE sizeof(u64)
#define MAX_KEY_SIZE MAX_NUM_SIZE
#define URANDOM_PATH "/dev/urandom"

u64 rand_num(u32 bits);
int cmd_rand(u32 num_bytes);
