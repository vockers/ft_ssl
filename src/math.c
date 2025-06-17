#include "ft_ssl.h"

u64 addmod(u64 x, u64 y, u64 mod)
{
    x = x % mod;
    y = y % mod;
    if (x >= mod - y) {
        return x - (mod - y);
    }
    return x + y;
}

u64 multmod(u64 x, u64 y, u64 mod)
{
    u64 ret = 0;
    for (; y > 0; y >>= 1) {
        if (y % 2 == 1) {
            ret = addmod(ret, x, mod);
        }
        x = addmod(x, x, mod);
    }
    return ret;
}

u64 powmod(u64 x, u64 y, u64 mod)
{
    u64 ret = 1;
    x       = x % mod;
    for (; y > 0; y >>= 1) {
        if (y % 2 == 1) {
            ret = multmod(ret, x, mod);
        }
        x = multmod(x, x, mod);
    }
    return ret;
}

u64 gcd(u64 a, u64 b)
{
    while (b) {
        u64 t = b;
        b     = a % b;
        a     = t;
    }
    return a;
}

u64 lcm(u64 a, u64 b)
{
    return (a / gcd(a, b)) * b;
}

u64 mod_inverse(u64 e, u64 lambda)
{
    u64 x1 = 0, x2 = 1, temp;
    u64 phi = lambda;

    while (e > 0) {
        u64 quotient = phi / e;
        temp         = e;
        e            = phi % e;
        phi          = temp;
        temp         = x2;
        x2           = x1 - quotient * x2;
        x1           = temp;
    }
    if (phi == 1) {
        return (x1 + lambda) % lambda;
    }
    return 0;
}
