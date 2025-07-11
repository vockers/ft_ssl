#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int32_t i32;
typedef int64_t i64;

typedef size_t  usize;
typedef ssize_t isize;

#define BUFFER_SIZE 16384 // Size of the buffer for reading files

#define LEFT_ROTATE(n, d)  ((n << d) | (n >> (32 - d)))
#define RIGHT_ROTATE(n, d) ((n >> d) | (n << (32 - d)))
