#include "ft_ssl.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>

#include "libft.h"

#define FILE_BUFFER_SIZE 14400 // Multiple of 3 and 4 for base64 encoding

static i32 base64_file(i32 fd_in, i32 fd_out, bool decode)
{
    u8      buffer[FILE_BUFFER_SIZE + 1];
    ssize_t bytes_read;

    while ((bytes_read = read(fd_in, buffer, FILE_BUFFER_SIZE)) > 0) {
        if (bytes_read < 0) {
            error(0, errno, "failed to read from input file");
            return -1;
        }

        if (decode) {
            buffer[bytes_read] = '\0';
            for (isize i = 0; i < bytes_read; i += 64) {
                usize decoded_length;
                u8*   decoded = base64_decode((char*)buffer + i, 64, &decoded_length);
                if (!decoded)
                    return -1;

                write(fd_out, decoded, decoded_length);
                free(decoded);
            }
        } else {
            for (isize i = 0; i < bytes_read; i += 48) {
                char* encoded = base64_encode(buffer + i, MIN(bytes_read - i, 48));
                if (!encoded)
                    return -1;

                ft_dprintf(fd_out, "%s\n", encoded);
                free(encoded);
            }
        }
    }

    return 0;
}

i32 cmd_base64(i32 argc, char* argv[])
{
    t_base64_opt opt;
    i32          arg_index;
    // clang-format off
    const t_argp_option opts[] = {
        {FT_ARGP_OPT_BOOL,   NULL, 'd', &opt.decode, "decode mode"},
        {FT_ARGP_OPT_STRING, NULL, 'i', &opt.input_file, "input file"},
        {FT_ARGP_OPT_STRING, NULL, 'o', &opt.output_file, "output file"},
        {FT_ARGP_OPT_END,    NULL,  0,  NULL,   NULL},
    };
    // clang-format on

    if ((ft_argp_parse(argc, argv, &arg_index, opts) != ARGP_SUCCESS)) {
        return -1;
    }

    // Read from stdin if no input file is specified
    i32 input_fd = STDIN_FILENO;
    if (opt.input_file) {
        input_fd = open(opt.input_file, O_RDONLY);
        if (input_fd < 0) {
            error(0, errno, "failed to open input file '%s'", opt.input_file);
            return -1;
        }
    }
    // Write to stdout if no output file is specified
    i32 output_fd = STDOUT_FILENO;
    if (opt.output_file) {
        output_fd = open(opt.output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd < 0) {
            error(0, errno, "failed to open output file '%s'", opt.output_file);
            if (input_fd != STDIN_FILENO)
                close(input_fd);

            return -1;
        }
    }

    i32 status = base64_file(input_fd, output_fd, opt.decode);

    if (input_fd != STDIN_FILENO)
        close(input_fd);
    if (output_fd != STDOUT_FILENO)
        close(output_fd);

    return status;
}
