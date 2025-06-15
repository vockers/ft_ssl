#pragma once

#include "utils.h"

typedef struct s_cli_cmd
{
    const char* name;                    // Command name
    i32 (*func)(i32 argc, char* argv[]); // Function to execute the command
    const char* doc;                     // Documentation for the command
} t_cli_cmd;

i32 cli_run(i32 argc, char* argv[]);

i32 cmd_md5(i32 argc, char* argv[]);
