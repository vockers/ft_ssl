#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "libft.h"

#define MILLER_RABIN_ITERATIONS 5

static bool miller_rabin_test(u64 potential_prime, u64 odd_num)
{
    u64 random_u64 = (rand_num(MAX_NUM_BITS) % (potential_prime - 4)) + 2;
    u64 x          = powmod(random_u64, odd_num, potential_prime);

    if (x == 1 || x == potential_prime - 1) {
        return true;
    }

    while (odd_num != potential_prime - 1) {
        x = (x * x) % potential_prime;
        odd_num *= 2;
        if (x == 1) {
            return false;
        }
        if (x == potential_prime - 1) {
            return true;
        }
    }
    return false;
}

static bool is_prime(u64 potential_prime, bool verbose)
{
    if (potential_prime == 2 || potential_prime == 3) {
        return true;
    } else if (potential_prime < 5) {
        return false;
    }

    u64 odd_num = potential_prime - 1;
    while (odd_num % 2 == 0) {
        odd_num /= 2;
    }

    for (int i = 0; i < MILLER_RABIN_ITERATIONS; ++i) {
        if (!miller_rabin_test(potential_prime, odd_num)) {
            return false;
        }
        if (verbose)
            ft_putchar_fd('+', STDERR_FILENO);
    }
    return true;
}

u64 gen_prime(u32 bits, bool verbose)
{
    u64 num = 0;

    while (1) {
        num = rand_num(bits);
        // Make sure we check odd numbers
        num |= 1;
        // prioritize larger numbers by setting the most significant bit
        num |= 1ULL << (bits - 1ULL);
        if (verbose)
            ft_putchar_fd('.', STDERR_FILENO);
        if (is_prime(num, verbose))
            break;
    }

    if (verbose)
        ft_putchar_fd('*', STDERR_FILENO);

    return num;
}

int cmd_prime(u64 num, bool generate, u32 bits)
{
    if (generate) {
        u64 prime = gen_prime(bits, true);
        ft_putchar_fd('\n', STDERR_FILENO);
        printf("%lu\n", prime);
    } else {
        // TODO: print hex representation of num
        printf("%lu is %sprime\n", num, is_prime(num, false) ? "" : "not ");
    }

    return 0;
}
