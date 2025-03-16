#include "ft_ssl.h"

int cmd_rsa()
{
    u64 p, q, n, phi, e, d;

    while (1) {
        p = gen_prime(32, true);
        q = gen_prime(32, true);
        n = p * q;
        if (n / p == q) {
            break;
        }
    }
    e   = PUBLIC_EXPONENT;
    phi = (p - 1) * (q - 1);
    d   = mod_inverse(e, phi);

    return 0;
}
