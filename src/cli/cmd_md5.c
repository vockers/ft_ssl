#include "ft_ssl.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "libft.h"

i32 cmd_md5(i32 argc, char* argv[])
{
    int   p, q, r, index;
    char* s;

    // clang-format off
    const t_argp_option md5_opts[] = {
        {FT_ARGP_OPT_BOOL,   NULL, 'p', &p, "echo STDIN to STDOUT and append the checksum to STDOUT"},
        {FT_ARGP_OPT_BOOL,   NULL, 'q', &q, "quiet mode, only print the checksum"},
        {FT_ARGP_OPT_BOOL,   NULL, 'r', &r, "reverse the format of the output"},
        {FT_ARGP_OPT_STRING, NULL, 's', &s, "print the checksum of the given string"},
        {FT_ARGP_OPT_END}
    };
    // clang-format on

    ft_argp_parse(argc, argv, &index, md5_opts);

    const char* file_path = index != -1 ? argv[index] : NULL;

    printf("p: %d, q: %d, r: %d, s: %s, file_path: %s\n",
           p,
           q,
           r,
           s ? s : "NULL",
           file_path ? file_path : "NULL");
    return 0;

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
    ctx.a = ft_bswap32(ctx.a);
    ctx.b = ft_bswap32(ctx.b);
    ctx.c = ft_bswap32(ctx.c);
    ctx.d = ft_bswap32(ctx.d);
    printf("%.8x%.8x%.8x%.8x\n", ctx.a, ctx.b, ctx.c, ctx.d);

    if (fd != STDIN_FILENO)
        close(fd);

    return 0;
}
