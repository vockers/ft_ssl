#include "ft_ssl.h"

#include "libft.h"

// clang-format off
struct s_cli_cmd g_cli_cmds[] = {
    {"md5", cmd_hash, "compute MD5 hash"},
    {"sha256", cmd_hash, "compute SHA-256 hash"},
    {"whirlpool", cmd_hash, "compute Whirlpool hash"},
    {NULL, NULL, NULL},
};
// clang-format on

static void print_help()
{
    ft_printf("\nCommands:\n");
    for (t_cli_cmd* cmd = g_cli_cmds; cmd->name; ++cmd) {
        ft_printf("%s\n", cmd->name);
    }

    ft_printf("\nFlags:\n");
    ft_printf("-p -q -r -s\n");
}

i32 cli_run(i32 argc, char* argv[])
{
    if (argc < 1) {
        ft_putstr_fd("usage: ft_ssl command [flags] [file/string]", STDERR_FILENO);
        return EXIT_FAILURE;
    }

    const char* cmd_name = argv[0];
    t_cli_cmd*  cli_cmd;
    for (cli_cmd = g_cli_cmds; cli_cmd->name; ++cli_cmd) {
        if (ft_strcmp(cli_cmd->name, cmd_name) == 0) {
            break;
        }
    }

    if (!cli_cmd->name) {
        ft_dprintf(STDERR_FILENO, "ft_ssl: Error: '%s' is an invalid command.\n", cmd_name);
        print_help();
        return EXIT_FAILURE;
    }

    cli_cmd->func(argc, argv);

    return EXIT_SUCCESS;
}
