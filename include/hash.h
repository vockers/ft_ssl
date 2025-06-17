#pragma once

#include "utils.h"

#define MD5_BLOCK_SIZE     64 // 512 bits
#define MD5_LENGTH_SIZE    8  // 64 bits (for padding)
#define MD5_DIGEST_SIZE    16 // 128 bits
#define SHA256_BLOCK_SIZE  64 // 512 bits
#define SHA256_LENGTH_SIZE 8  // 64 bits (for padding)
#define SHA256_DIGEST_SIZE 32 // 256 bits

typedef struct s_hash_opt
{
    bool  p; // echo STDIN to STDOUT and append the checksum to STDOUT
    bool  q; // quiet mode, only print the checksum
    bool  r; // reverse the format of the output
    char* s; // print the checksum of the given string
} t_hash_opt;

typedef struct s_md5_ctx
{
    u32   a, b, c, d;             // MD5 state variables
    u8    buffer[MD5_BLOCK_SIZE]; // Buffer for the current block
    usize buffer_len;             // Length of the current block
    usize msg_len;                // Length of the original message
} t_md5_ctx;

typedef struct s_sha256_ctx
{
    u32   a, b, c, d, e, f, g, h;    // SHA-256 state variables
    u8    buffer[SHA256_BLOCK_SIZE]; // Buffer for the current block
    usize buffer_len;                // Length of the current block
    usize msg_len;                   // Length of the original message
} t_sha256_ctx;

// clang-format off
typedef struct s_hash_algo
{
    const char* name;        // Name of the hash algorithm
    usize       digest_size; // Size of the hash digest in bytes

    void (*init)  (void* ctx); // Function to initialize the context
    void (*update)(void*     ctx,
                   const u8* data,
                   usize     len);                          // Function to update the context with data
    void (*final) (void* ctx, u8* digest);                  // Function to finalize the hash and produce the digest
    void (*str)   (const char* str, usize len, u8* digest); // Function to hash a string

    usize ctx_size; // Size of the context structure
} t_hash_algo;
// clang-format on

// MD5
void md5_init(t_md5_ctx* ctx);
void md5_update(t_md5_ctx* ctx, const u8* data, usize len);
void md5_final(t_md5_ctx* ctx, u8* digest);
void md5_str(const char* str, usize len, u8* digest);

// SHA-256
void sha256_init(t_sha256_ctx* ctx);
void sha256_update(t_sha256_ctx* ctx, const u8* data, usize len);
void sha256_final(t_sha256_ctx* ctx, u8* digest);
void sha256_str(const char* str, usize len, u8* digest);
