#include "ft_ssl.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "libft.h"

// clang-format off
static const u32 md5_k[64] = 
{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const u32 md5_s[64] =
{
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};
// clang-format on

static void md5_block(t_md5_ctx* ctx0)
{
    u32*      m   = (u32*)ctx0->buffer; // Pointer to the message block
    t_md5_ctx ctx = *ctx0;              // Save the initial state

    for (int i = 0; i < 64; i++) {
        u32 f, g;
        if (i < 16) {
            f = (ctx.b & ctx.c) | (~ctx.b & ctx.d);
            g = i;
        } else if (i < 32) {
            f = (ctx.d & ctx.b) | (~ctx.d & ctx.c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = ctx.b ^ ctx.c ^ ctx.d;
            g = (3 * i + 5) % 16;
        } else {
            f = ctx.c ^ (ctx.b | ~ctx.d);
            g = (7 * i) % 16;
        }

        f += ctx.a + md5_k[i] + m[g];
        ctx.a = ctx.d;
        ctx.d = ctx.c;
        ctx.c = ctx.b;
        ctx.b += LEFT_ROTATE(f, md5_s[i]);
    }

    // Update the context with the new values
    ctx0->a += ctx.a;
    ctx0->b += ctx.b;
    ctx0->c += ctx.c;
    ctx0->d += ctx.d;
}

void md5_init(t_md5_ctx* ctx)
{
    ft_bzero(ctx, sizeof(t_md5_ctx));

    ctx->a = 0x67452301;
    ctx->b = 0xEFCDAB89;
    ctx->c = 0x98BADCFE;
    ctx->d = 0x10325476;
}

void md5_update(t_md5_ctx* ctx, const u8* data, usize len)
{
    ctx->msg_len += len;

    while (len > 0) {
        usize to_copy =
            MD5_BLOCK_SIZE - ctx->buffer_len > len ? len : MD5_BLOCK_SIZE - ctx->buffer_len;
        ft_memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        data += to_copy;
        ctx->buffer_len += to_copy;
        len -= to_copy;
        if (ctx->buffer_len == MD5_BLOCK_SIZE) {
            md5_block(ctx);
            ctx->buffer_len = 0;
        }
    }
}

void md5_final(t_md5_ctx* ctx, u8* digest)
{
    // Handle padding
    ctx->buffer[ctx->buffer_len++] = 0x80; // Append a single '1' bit
    ft_bzero(ctx->buffer + ctx->buffer_len, MD5_BLOCK_SIZE - ctx->buffer_len);
    if (ctx->buffer_len > MD5_BLOCK_SIZE - MD5_LENGTH_SIZE) {
        // If the msg length doesn't fit in the current block, process it
        md5_block(ctx);
        ft_bzero(ctx->buffer, MD5_BLOCK_SIZE);
    }

    *(u64*)(ctx->buffer + MD5_BLOCK_SIZE - MD5_LENGTH_SIZE) = ctx->msg_len * 8;

    md5_block(ctx); // Process the final block

    // Copy the final digest to the output buffer
    ft_memcpy(digest, &ctx->a, MD5_DIGEST_SIZE);
}

void md5_str(const char* str, usize len, u8* digest)
{
    t_md5_ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, (const u8*)str, len);
    md5_final(&ctx, digest);
}
