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
    uint64_t ret = 0;
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
