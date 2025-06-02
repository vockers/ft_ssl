#include "ft_ssl.h"

#include <string.h>

usize num_len(u64 num)
{
    u8 n = 0;
    while (num) {
        num >>= 8;
        n++;
    }
    return n;
}

usize der_encode_int(u8* buffer, u64 num)
{
    buffer[0] = DER_INT;
    u8 len    = num_len(num);
    buffer[1] = len;

    // Write big-endian bytes (skip leading zeros)
    for (usize i = 0; i < len; i++) {
        buffer[2 + i] = (num >> (8 * (len - 1 - i))) & 0xFF;
    }

    return len + 2;
}

usize der_encode_rsa_privkey(u8* output, t_rsa_privkey* key)
{
    u8* out = output;
    *out++  = DER_SEQ;
    *out++  = 0; // Placeholder for length

    // Encode version
    *out++ = DER_INT;
    *out++ = 1;
    *out++ = 0;

    out += der_encode_int(out, key->n);
    out += der_encode_int(out, key->e);
    out += der_encode_int(out, key->d);
    out += der_encode_int(out, key->p);
    out += der_encode_int(out, key->q);
    out += der_encode_int(out, key->dmp1);
    out += der_encode_int(out, key->dmq1);
    out += der_encode_int(out, key->iqmp);

    // Encode the sequence length
    usize len = out - output;
    output[1] = len - 2;

    return len;
}
