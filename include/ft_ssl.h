#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int32_t i32;
typedef int64_t i64;

typedef size_t usize;

#define MAX_NUM_SIZE    sizeof(u64)
#define MAX_NUM_BITS    (MAX_NUM_SIZE * CHAR_BIT)
#define MAX_KEY_SIZE    MAX_NUM_SIZE
#define PUBLIC_EXPONENT 65537

#define URANDOM_PATH "/dev/urandom"

// DER identifiers
#define DER_INT 0x02
#define DER_SEQ 0x30

typedef struct s_rsa_privkey
{
    u64 n;    // modulus
    u64 e;    // public exponent
    u64 d;    // private exponent
    u64 p;    // prime 1
    u64 q;    // prime 2
    u64 dmp1; // d mod (p - 1)
    u64 dmq1; // d mod (q - 1)
    u64 iqmp; // q^-1 mod p
} t_rsa_privkey;

u64 powmod(u64 x, u64 y, u64 mod);
u64 mod_inverse(u64 a, u64 b);

/**
 * @brief DER encode the rsa private key.
 *
 * @param output The buffer to write the DER encoded key to.
 * @param key The rsa private key.
 * @return usize The length of the DER encoded key.
 */
usize der_encode_rsa_privkey(u8* output, t_rsa_privkey* key);

/**
 * @brief Encode a byte array to base64.
 *
 * @param data The data to encode.
 * @param input_length The length of the data.
 * @return char* The base64 encoded data.
 */
char* base64_encode(const u8* data, usize input_length);

/**
 * @brief Generate a random number with a specified number of bits.
 *
 * @param bits The number of bits the random number should have.
 * @return u64 The random number.
 */
u64 rand_num(u32 bits);
i32 cmd_rand(u32 num_bytes);

u64 gen_prime(u32 bits, bool verbose);
i32 cmd_prime(u64 num, bool generate, u32 bits);

int cmd_rsa();
