#include "ft_ssl.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>

#include "libft.h"

// clang-format off
static const t_hash_algo g_hash_algos[] = {
{
        .name        = "MD5",
        .digest_size = MD5_DIGEST_SIZE,
        .init        = (void*)md5_init,
        .update      = (void*)md5_update,
        .final       = (void*)md5_final,
        .str         = md5_str,
        .ctx_size    = sizeof(t_md5_ctx)
    },
{
        .name        = "SHA256",
        .digest_size = SHA256_DIGEST_SIZE,
        .init        = (void*)sha256_init,
        .update      = (void*)sha256_update,
        .final       = (void*)sha256_final,
        .str         = sha256_str,
        .ctx_size    = sizeof(t_sha256_ctx)
    },
    {NULL, 0, NULL, NULL, NULL, NULL, 0},
};
// clang-format on

const t_hash_algo* get_hash_algo(const char* name)
{
    for (const t_hash_algo* algo = g_hash_algos; algo->name; ++algo) {
        if (ft_strcasecmp(name, algo->name) == 0) {
            return algo;
        }
    }
    return NULL;
}

static void print_bytes(const u8* bytes, usize size)
{
    for (usize i = 0; i < size; i++) {
        ft_printf("%02x", bytes[i]);
    }
}

static void print_digest(
    const u8* digest, usize size, bool is_str, const char* input, const char* name, t_hash_opt* opt)
{
    if (!opt->q && !opt->r) {
        if (is_str)
            ft_printf("%s (\"%s\") = ", name, input);
        else
            ft_printf("%s (%s) = ", name, input);
    }

    print_bytes(digest, size);

    if (!opt->q && opt->r) {
        if (is_str)
            ft_printf(" \"%s\"", input);
        else
            ft_printf(" %s", input);
    }

    ft_printf("\n");
}

i32 cmd_hash(i32 argc, char* argv[])
{
    const t_hash_algo* algo = get_hash_algo(argv[0]);
    if (!algo) {
        error(0, 0, "unkown hash algorithm: %s", argv[0]);
        return -1;
    }

    t_hash_opt opt;
    int        arg_index;
    // clang-format off
    const t_argp_option opts[] = {
        {FT_ARGP_OPT_BOOL,   NULL, 'p', &opt.p, "echo STDIN to STDOUT and append the checksum to STDOUT"},
        {FT_ARGP_OPT_BOOL,   NULL, 'q', &opt.q, "quiet mode, only print the checksum"},
        {FT_ARGP_OPT_BOOL,   NULL, 'r', &opt.r, "reverse the format of the output"},
        {FT_ARGP_OPT_STRING, NULL, 's', &opt.s, "print the checksum of the given string"},
        {FT_ARGP_OPT_END,    NULL, 0,   NULL,   NULL},
    };
    // clang-format on

    if ((ft_argp_parse(argc, argv, &arg_index, opts) != ARGP_SUCCESS)) {
        return -1;
    }

    void* ctx = malloc(algo->ctx_size);
    if (!ctx) {
        error(0, errno, "hash context allocation failed");
        return -1;
    }

    u8* digest = malloc(algo->digest_size);
    if (!digest) {
        error(0, errno, "digest allocation failed");
        free(ctx);
        return -1;
    }

    u8 buffer[BUFFER_SIZE]; // Buffer for reading input data
    if (opt.p || (arg_index == -1 && !opt.s)) {
        algo->init(ctx);

        char* input = ft_strdup("");

        ssize_t bytes_read;
        while ((bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {
            if (!opt.q && opt.p) {
                // write(STDOUT_FILENO, buffer, bytes_read);
                char* tmp = input;
                input     = ft_strnjoin(input, (const char*)buffer, ft_strlen(input), bytes_read);
                free(tmp);
            }
            algo->update(ctx, buffer, bytes_read);
        }

        algo->final(ctx, digest);

        if (!opt.q) {
            if (opt.p)
                ft_printf(" (\"%s\")= ", input);
            else
                ft_printf(" (stdin)= ");
        }

        free(input);

        print_bytes(digest, algo->digest_size);
        ft_printf("\n");
    }

    if (opt.s) {
        algo->str(opt.s, ft_strlen(opt.s), digest);
        print_digest(digest, algo->digest_size, true, opt.s, algo->name, &opt);
    }

    if (arg_index != -1) {
        for (; arg_index < argc; arg_index++) {
            const char* file_path = argv[arg_index];

            int fd;
            if ((fd = open(file_path, O_RDONLY)) < 0) {
                error(0, errno, "%s", file_path);
                free(digest);
                free(ctx);
                return -1;
            }

            algo->init(ctx);

            ssize_t bytes_read;
            while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
                algo->update(ctx, buffer, bytes_read);
            }

            algo->final(ctx, digest);

            print_digest(digest, algo->digest_size, false, file_path, algo->name, &opt);

            close(fd);
        }
    }

    free(digest);
    free(ctx);

    return 0;
}
