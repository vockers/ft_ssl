#pragma once

#include "cli.h"
#include "utils.h"

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

#define MD5_BLOCK_SIZE    64 // 512 bits
#define MD5_LENGTH_SIZE   8  // 64 bits (for padding)
#define MD5_DIGEST_SIZE   16 // 128 bits
#define SHA256_BLOCK_SIZE 64 // 512 bits

#define LEFT_ROTATE(n, d)  ((n << d) | (n >> (32 - d)))
#define RIGHT_ROTATE(n, d) ((n >> d) | (n << (32 - d)))

typedef struct s_dgst_opt
{
    bool  p; // echo STDIN to STDOUT and append the checksum to STDOUT
    bool  q; // quiet mode, only print the checksum
    bool  r; // reverse the format of the output
    char* s; // print the checksum of the given string
} t_dgst_opt;

typedef struct s_md5_ctx
{
    u32   a, b, c, d;             // MD5 state variables
    u8    buffer[MD5_BLOCK_SIZE]; // Buffer for the current block
    usize buffer_len;             // Length of the current block
    usize msg_len;                // Length of the original message
} t_md5_ctx;

typedef struct s_sha256_ctx
{
    u32 a, b, c, d, e, f, g, h; // SHA-256 state variables
} t_sha256_ctx;

/**
 * @brief Modular exponentiation.
 * @param x The base.
 * @param y The exponent.
 * @param mod The modulus.
 * @return u64 The result of (x^y) % mod.
 */
u64 powmod(u64 x, u64 y, u64 mod);
// Greatest Common Divisor (for lcm)
u64 gcd(u64 a, u64 b);
// Least Common Multiple
u64 lcm(u64 a, u64 b);
// Modular Inverse (using extended Euclidean)
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

// MD5
void md5_init(t_md5_ctx* ctx);
void md5_update(t_md5_ctx* ctx, const u8* data, usize len);
void md5_final(t_md5_ctx* ctx, u8* digest);
void md5_str(const char* str, usize len, u8* digest);

// SHA-256
int cmd_sha256(const char* file_path);
