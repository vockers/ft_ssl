#include <stdio.h>

#include "ft_ssl.h"

int main()
{
    // cmd_rand(10);
    cmd_prime(0, true, 5);

    cmd_prime(0, true, 64);

    cmd_prime(2, false, 0);

    cmd_prime(3, false, 0);

    cmd_prime(4, false, 0);

    cmd_prime(5, false, 0);

    printf("%lu\n", powmod(2, 3, 5));

    return 0;
}
