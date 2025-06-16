#include "ft_ssl.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "libft.h"

void print_digest(
    const u8* digest, usize size, bool is_str, const char* input, const char* name, t_dgst_opt* opt)
{
    if (!opt->q && !opt->r) {
        ft_printf("%s (", name);
        if (is_str)
            ft_printf("\"");
        ft_printf("%s", input);
        if (is_str)
            ft_printf("\"");
        ft_printf(") = ");
    }

    for (usize i = 0; i < MD5_DIGEST_SIZE; i++) {
        ft_printf("%02x", digest[i]);
    }

    if (!opt->q && opt->r) {
        printf(" ");
        if (is_str)
            printf("\"");
        printf("%s", input);
        if (is_str)
            printf("\"");
    }

    printf("\n");
}

i32 cmd_md5(i32 argc, char* argv[])
{
    t_dgst_opt opt;
    int        arg_index;

    // clang-format off
    const t_argp_option md5_opts[] = {
        {FT_ARGP_OPT_BOOL,   NULL, 'p', &opt.p, "echo STDIN to STDOUT and append the checksum to STDOUT"},
        {FT_ARGP_OPT_BOOL,   NULL, 'q', &opt.q, "quiet mode, only print the checksum"},
        {FT_ARGP_OPT_BOOL,   NULL, 'r', &opt.r, "reverse the format of the output"},
        {FT_ARGP_OPT_STRING, NULL, 's', &opt.s, "print the checksum of the given string"},
        {FT_ARGP_OPT_END}
    };
    // clang-format on

    ft_argp_parse(argc, argv, &arg_index, md5_opts);

    t_md5_ctx ctx;
    u8        buffer[BUFFER_SIZE];
    u8        digest[MD5_DIGEST_SIZE];

    if (opt.p || (arg_index == -1 && !opt.s)) {
        md5_init(&ctx);
        ssize_t bytes_read;

        if (!opt.q && opt.p)
            ft_printf("(\"");
        while ((bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {
            if (opt.p) {
                write(STDOUT_FILENO, buffer, bytes_read);
            }
            md5_update(&ctx, buffer, bytes_read);
        }
        if (!opt.q && opt.p)
            ft_printf("\") = ");

        md5_final(&ctx, digest);

        if (opt.p) {
            for (usize i = 0; i < MD5_DIGEST_SIZE; i++) {
                ft_printf("%02x", digest[i]);
            }
            printf("\n");
        } else
            print_digest(digest, MD5_DIGEST_SIZE, false, "stdin", "", &opt);
    }

    if (opt.s) {
        md5_str(opt.s, ft_strlen(opt.s), digest);
        print_digest(digest, MD5_DIGEST_SIZE, true, opt.s, "MD5", &opt);
    }

    if (arg_index == -1)
        return 0;

    for (; arg_index < argc; arg_index++) {
        const char* file_path = argv[arg_index];

        int fd;
        if ((fd = open(file_path, O_RDONLY)) < 0) {
            error(0, errno, "%s", file_path);
            return -1;
        }

        // Initialize MD5 context
        md5_init(&ctx);

        ssize_t bytes_read;
        while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
            md5_update(&ctx, buffer, bytes_read);
        }

        md5_final(&ctx, digest);

        print_digest(digest, MD5_DIGEST_SIZE, false, file_path, "MD5", &opt);

        close(fd);
    }

    return 0;
}
