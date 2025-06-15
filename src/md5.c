#include "ft_ssl.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "libft.h"

#define LEFT_ROTATE(n, d) ((n << d) | (n >> (32 - d)))

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

static inline u32 swap_endian(u32 val)
{

    return ((0xFF000000 & val) >> 24) |

           ((0x00FF0000 & val) >> 8) |

           ((0x0000FF00 & val) << 8) |

           ((0x000000FF & val) << 24);
}

static ssize_t
md5_handle_padding(t_md5_ctx* ctx, u8* buffer, ssize_t bytes_read, ssize_t total_bytes_read)
{
    int padding_zeroes;
    if (bytes_read % MD5_BLOCK_SIZE > 55) {
        padding_zeroes = 128 - (bytes_read % MD5_BLOCK_SIZE) - 9;
    } else {
        padding_zeroes = 64 - (bytes_read % MD5_BLOCK_SIZE) - 9;
    }

    buffer[bytes_read] = 0x80; // Add the 1 bit
    ft_memset(buffer + bytes_read + 1, 0, padding_zeroes);

    // Append the length of the original message in bits
    *(size_t*)(&buffer[bytes_read + padding_zeroes + 1]) = total_bytes_read * 8;

    return bytes_read + padding_zeroes + 9; // Return the total size of the padded block
}

static void md5_block(t_md5_ctx* ctx0, const u8* block)
{
    u32*      m   = (u32*)block;
    t_md5_ctx ctx = *ctx0; // Save the initial state

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

static void md5_init(t_md5_ctx* ctx)
{
    ctx->a = 0x67452301;
    ctx->b = 0xEFCDAB89;
    ctx->c = 0x98BADCFE;
    ctx->d = 0x10325476;
}

int cmd_md5(const char* file_path)
{
    int       fd = STDIN_FILENO;
    t_md5_ctx ctx;
    u8        buffer[MD5_BLOCK_SIZE * 2]; // Twice the block size to handle padding

    if (file_path && (fd = open(file_path, O_RDONLY)) < 0) {
        perror(file_path);
        return -1;
    }

    // Initialize MD5 context
    md5_init(&ctx);

    ssize_t bytes_read;
    ssize_t total_bytes_read = 0;

    while ((bytes_read = read(fd, buffer, MD5_BLOCK_SIZE)) == MD5_BLOCK_SIZE) {
        total_bytes_read += bytes_read;
        md5_block(&ctx, buffer);
    }

    ssize_t padded_block_size =
        md5_handle_padding(&ctx, buffer, bytes_read, total_bytes_read + bytes_read);
    md5_block(&ctx, buffer); // Process the last block
    // If the last block couldn't fit the padding, process the next block
    if (padded_block_size == MD5_BLOCK_SIZE * 2) {
        md5_block(&ctx, buffer + MD5_BLOCK_SIZE);
    }

    // Print the final MD5 hash digest
    ctx.a = swap_endian(ctx.a);
    ctx.b = swap_endian(ctx.b);
    ctx.c = swap_endian(ctx.c);
    ctx.d = swap_endian(ctx.d);
    printf("%.8x%.8x%.8x%.8x\n", ctx.a, ctx.b, ctx.c, ctx.d);

    if (fd != STDIN_FILENO)
        close(fd);

    return 0;
}
