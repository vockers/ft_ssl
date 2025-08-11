#include "ft_ssl.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>

#include "libft.h"

#define FILE_BUFFER_SIZE 14400 // Multiple of 3 and 4 for base64 encoding

static i32 base64_file(i32 fd_in, i32 fd_out, bool decode)
{
    u8      buffer[FILE_BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(fd_in, buffer, FILE_BUFFER_SIZE)) > 0) {
        if (bytes_read < 0) {
            error(0, errno, "failed to read from input file");
            return -1;
        }

        if (decode) {
            for (isize i = 0; i < bytes_read; i += 64) {
                usize decoded_length;
                u8*   decoded = base64_decode((char*)buffer + i, 64, &decoded_length);
                if (!decoded)
                    return -1;

                write(STDOUT_FILENO, decoded, decoded_length);
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
    if (!opt.input_file) {
        base64_file(STDIN_FILENO, STDOUT_FILENO, opt.decode);
    }

    return 0;
}
