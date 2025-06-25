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

static void sha256_block(t_sha256_ctx* ctx0)
{
    u8* block = ctx0->buffer;

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

    for (i32 i = 0; i < 64; i++) {
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

void sha256_init(t_sha256_ctx* ctx)
{
    ft_bzero(ctx, sizeof(t_sha256_ctx));

    ctx->a = 0x6a09e667;
    ctx->b = 0xbb67ae85;
    ctx->c = 0x3c6ef372;
    ctx->d = 0xa54ff53a;
    ctx->e = 0x510e527f;
    ctx->f = 0x9b05688c;
    ctx->g = 0x1f83d9ab;
    ctx->h = 0x5be0cd19;
}

void sha256_update(t_sha256_ctx* ctx, const u8* data, usize len)
{
    ctx->msg_len += len;

    while (len > 0) {
        usize to_copy =
            SHA256_BLOCK_SIZE - ctx->buffer_len > len ? len : SHA256_BLOCK_SIZE - ctx->buffer_len;
        ft_memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        data += to_copy;
        ctx->buffer_len += to_copy;
        len -= to_copy;
        if (ctx->buffer_len == SHA256_BLOCK_SIZE) {
            sha256_block(ctx);
            ctx->buffer_len = 0;
        }
    }
}

void sha256_final(t_sha256_ctx* ctx, u8* digest)
{
    // Handle padding
    ctx->buffer[ctx->buffer_len++] = 0x80; // Append a single '1' bit
    ft_bzero(ctx->buffer + ctx->buffer_len, SHA256_BLOCK_SIZE - ctx->buffer_len);
    if (ctx->buffer_len > SHA256_BLOCK_SIZE - SHA256_LENGTH_SIZE) {
        // If the msg length doesn't fit in the current block, process it
        sha256_block(ctx);
        ft_bzero(ctx->buffer, SHA256_BLOCK_SIZE);
    }

    *(u64*)(ctx->buffer + SHA256_BLOCK_SIZE - SHA256_LENGTH_SIZE) = ft_bswap64(ctx->msg_len * 8);

    sha256_block(ctx); // Process the final block

    ctx->a = ft_bswap32(ctx->a);
    ctx->b = ft_bswap32(ctx->b);
    ctx->c = ft_bswap32(ctx->c);
    ctx->d = ft_bswap32(ctx->d);
    ctx->e = ft_bswap32(ctx->e);
    ctx->f = ft_bswap32(ctx->f);
    ctx->g = ft_bswap32(ctx->g);
    ctx->h = ft_bswap32(ctx->h);

    // Copy the final digest to the output buffer
    ft_memcpy(digest, &ctx->a, SHA256_DIGEST_SIZE);
}

void sha256_str(const char* str, usize len, u8* digest)
{
    t_sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const u8*)str, len);
    sha256_final(&ctx, digest);
}
