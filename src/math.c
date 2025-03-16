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

u64 mod_inverse(u64 a, u64 m)
{
    u64 tmp, q;

    u64 m0 = m;
    u64 x0 = 0;
    u64 x1 = 1;
    if (a == m)
        return (0);
    while (a > 1) {
        q   = a / m;
        tmp = m;
        m   = a % m;
        a   = tmp;
        tmp = x0;
        x0  = x1 - q * x0;
        x1  = tmp;
    }
    return (x1 < 0 ? x1 += m0 : x1);
}
