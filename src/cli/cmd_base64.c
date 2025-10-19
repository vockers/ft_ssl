#include "ft_ssl.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>

#include "libft.h"

#define FILE_BUFFER_SIZE  14400 // Multiple of 3 and 4
#define ENCODE_CHUNK_SIZE 48
#define DECODE_CHUNK_SIZE 64

static inline isize strip_whitespace_inplace(char* str, isize len)
{
    isize new_len = 0;
    for (isize i = 0; i < len; i++) {
        char c = str[i];
        if (!ft_isspace(c)) {
            str[new_len++] = c;
        }
    }
    return new_len;
}

static i32 base64_encode_file(i32 fd_in, i32 fd_out)
{
    u8    buffer[FILE_BUFFER_SIZE];
    isize bytes_read;

    while ((bytes_read = read(fd_in, buffer, FILE_BUFFER_SIZE)) > 0) {
        for (isize i = 0; i < bytes_read; i += ENCODE_CHUNK_SIZE) {
            char* encoded = base64_encode(buffer + i, MIN(bytes_read - i, ENCODE_CHUNK_SIZE));
            if (!encoded)
                return -1;

            ft_dprintf(fd_out, "%s\n", encoded);
            free(encoded);
        }
    }

    return 0;
}

static i32 base64_decode_file(i32 fd_in, i32 fd_out)
{
    u8    buffer[FILE_BUFFER_SIZE + 4]; // Extra space for carry-over
    isize bytes_read;
    usize carry_len = 0;

    while ((bytes_read = read(fd_in, buffer + carry_len, FILE_BUFFER_SIZE)) > 0) {
        bytes_read += carry_len;
        isize stripped_len = strip_whitespace_inplace((char*)buffer, bytes_read);

        buffer[stripped_len] = '\0';
        isize used = (stripped_len / 4) * 4; // Number of bytes that can be decoded (multiple of 4)
        for (isize i = 0; i < used; i += DECODE_CHUNK_SIZE) {
            usize block_size = MIN(used - i, DECODE_CHUNK_SIZE);
            usize decoded_length;
            u8*   decoded = base64_decode((char*)buffer + i, block_size, &decoded_length);
            if (!decoded) {
                return -1;
            }

            write(fd_out, decoded, decoded_length);
            free(decoded);
        }

        // Move undecoded bytes to the beginning of the buffer
        carry_len = stripped_len - used;
        ft_memmove(buffer, buffer + used, carry_len);
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

    i32 status = opt.decode ? base64_decode_file(input_fd, output_fd)
                            : base64_encode_file(input_fd, output_fd);

    if (input_fd != STDIN_FILENO)
        close(input_fd);
    if (output_fd != STDOUT_FILENO)
        close(output_fd);

    return status;
}
