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

    int       fd = STDIN_FILENO;
    t_md5_ctx ctx;
    u8        buffer[BUFFER_SIZE];

    if (file_path && (fd = open(file_path, O_RDONLY)) < 0) {
        perror(file_path);
        return -1;
    }

    // Initialize MD5 context
    md5_init(&ctx);

    ssize_t bytes_read;

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        md5_update(&ctx, buffer, bytes_read);
    }

    u8 output[MD5_DIGEST_SIZE];
    md5_final(&ctx, output);

    for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    if (fd != STDIN_FILENO)
        close(fd);

    return 0;
}
