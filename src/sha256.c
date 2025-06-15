#include "ft_ssl.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "libft.h"

// clang-format off
static const u32 sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
// clang-format on

static void sha256_init(t_sha256_ctx* ctx)
{
    ctx->a = 0x6a09e667;
    ctx->b = 0xbb67ae85;
    ctx->c = 0x3c6ef372;
    ctx->d = 0xa54ff53a;
    ctx->e = 0x510e527f;
    ctx->f = 0x9b05688c;
    ctx->g = 0x1f83d9ab;
    ctx->h = 0x5be0cd19;
}

static void sha256_block(t_sha256_ctx* ctx0, const u8* block)
{
    u32 w[64];
    for (i32 i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) |
               (block[i * 4 + 3]);
    }
    for (i32 i = 16; i < 64; i++) {
        u32 s0 = RIGHT_ROTATE(w[i - 15], 7) ^ RIGHT_ROTATE(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = RIGHT_ROTATE(w[i - 2], 17) ^ RIGHT_ROTATE(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i]   = w[i - 16] + s0 + w[i - 7] + s1;
    }

    t_sha256_ctx ctx = *ctx0; // Save the initial state

    for (int i = 0; i < 64; i++) {
        u32 S1    = RIGHT_ROTATE(ctx.e, 6) ^ RIGHT_ROTATE(ctx.e, 11) ^ RIGHT_ROTATE(ctx.e, 25);
        u32 ch    = (ctx.e & ctx.f) ^ (~ctx.e & ctx.g);
        u32 temp1 = ctx.h + S1 + ch + sha256_k[i] + w[i];
        u32 S0    = RIGHT_ROTATE(ctx.a, 2) ^ RIGHT_ROTATE(ctx.a, 13) ^ RIGHT_ROTATE(ctx.a, 22);
        u32 maj   = (ctx.a & ctx.b) ^ (ctx.a & ctx.c) ^ (ctx.b & ctx.c);
        u32 temp2 = S0 + maj;

        ctx.h = ctx.g;
        ctx.g = ctx.f;
        ctx.f = ctx.e;
        ctx.e = ctx.d + temp1;
        ctx.d = ctx.c;
        ctx.c = ctx.b;
        ctx.b = ctx.a;
        ctx.a = temp1 + temp2;
    }

    // Update the context with the new values
    ctx0->a += ctx.a;
    ctx0->b += ctx.b;
    ctx0->c += ctx.c;
    ctx0->d += ctx.d;
    ctx0->e += ctx.e;
    ctx0->f += ctx.f;
    ctx0->g += ctx.g;
    ctx0->h += ctx.h;
}

static ssize_t sha256_handle_padding(u8* buffer, ssize_t bytes_read, ssize_t total_bytes_read)
{
    int padding_zeroes;
    if (bytes_read % SHA256_BLOCK_SIZE > 55) {
        padding_zeroes = 128 - (bytes_read % 64) - 9;
    } else {
        padding_zeroes = SHA256_BLOCK_SIZE - (bytes_read % 64) - 9;
    }

    buffer[bytes_read] = 0x80; // Add the 1 bit
    ft_memset(buffer + bytes_read + 1, 0, padding_zeroes);

    // Append the length of the original message in bits
    *(size_t*)(&buffer[bytes_read + padding_zeroes + 1]) = ft_bswap64(total_bytes_read * 8);

    return bytes_read + padding_zeroes + 9; // Return the total size of the padded block
}

int cmd_sha256(const char* file_path)
{
    int          fd = STDIN_FILENO;
    t_sha256_ctx ctx;
    u8           buffer[SHA256_BLOCK_SIZE * 2]; // Twice the block size to handle padding

    if (file_path && (fd = open(file_path, O_RDONLY)) < 0) {
        perror(file_path);
        return -1;
    }

    // Initialize SHA-256 context
    sha256_init(&ctx);

    ssize_t bytes_read;
    ssize_t total_bytes_read = 0;

    while ((bytes_read = read(fd, buffer, SHA256_BLOCK_SIZE)) == SHA256_BLOCK_SIZE) {
        total_bytes_read += bytes_read;
        sha256_block(&ctx, buffer);
    }

    ssize_t padded_block_size =
        sha256_handle_padding(buffer, bytes_read, total_bytes_read + bytes_read);
    sha256_block(&ctx, buffer); // Process the last block
    // If the last block couldn't fit the padding, process the next block
    if (padded_block_size == SHA256_BLOCK_SIZE * 2) {
        sha256_block(&ctx, buffer + SHA256_BLOCK_SIZE);
    }

    // Output the final hash
    printf("%.8x%.8x%.8x%.8x%.8x%.8x%.8x%.8x\n",
           ctx.a,
           ctx.b,
           ctx.c,
           ctx.d,
           ctx.e,
           ctx.f,
           ctx.g,
           ctx.h);

    if (fd != STDIN_FILENO)
        close(fd);

    return 0;
}
