#include "ft_ssl.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>

#include "libft.h"

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
        u8 buffer[BUFFER_SIZE];

        char* input = ft_strdup("");

        ssize_t bytes_read;
        while ((bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {
            char* tmp = input;
            input     = ft_strnjoin(input, (const char*)buffer, ft_strlen(input), bytes_read);
            free(tmp);
        }

        char* encoded = base64_encode((const u8*)input, ft_strlen(input));
        free(input);
        if (!encoded) {
            error(0, errno, "base64 encoding failed");
            return -1;
        }

        ft_printf("%s\n", encoded);
        free(encoded);
    }

    return 0;
}