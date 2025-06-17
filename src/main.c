#include <readline/history.h>
#include <readline/readline.h>
#include <stdio.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "libft.h"

int main(int argc, char* argv[])
{
    if (argc > 1)
        return cli_run(--argc, ++argv);

    while (1) {
        char* input = readline("ft_ssl> ");

        if (input == NULL || *input == '\0') {
            free(input);
            continue; // Skip empty input
        }
        add_history(input);

        argv = ft_split(input, ' ');
        if (argv == NULL) {
            perror("splitting arguments failed");
            free(input);
            return EXIT_FAILURE;
        }
        for (argc = 0; argv[argc] != NULL;)
            argc++;

        cli_run(argc, argv);

        free(input);
        ft_free_strs(argv);
    }

    return EXIT_SUCCESS;
}
