#include "ft_ssl.h"

#include <stdio.h>
#include <stdlib.h>

#include "libft.h"

void print_pem(t_rsa_privkey* key)
{
    char buffer[1024];

    printf("-----BEGIN RSA PRIVATE KEY-----\n");
    ft_bzero(buffer, sizeof(buffer));
    usize len     = der_encode_rsa_privkey((u8*)buffer, key);
    char* encoded = base64_encode((u8*)buffer, len);
    printf("%s", encoded);
    free(encoded);
    printf("\n-----END RSA PRIVATE KEY-----\n");
}

int cmd_rsa()
{
    t_rsa_privkey key;

    while (1) {
        key.p = gen_prime(32, true);
        key.q = gen_prime(32, true);
        key.n = key.p * key.q;
        if (key.n / key.p == key.q) {
            break;
        }
    }
    key.e    = PUBLIC_EXPONENT;
    u64 phi  = (key.p - 1) * (key.q - 1);
    key.d    = mod_inverse(key.e, phi);
    key.dmp1 = key.d % (key.p - 1);
    key.dmq1 = key.d % (key.q - 1);
    key.iqmp = mod_inverse(key.q, key.p);

    fprintf(stderr, "\ne is %lu (%#lx)\n", key.e, key.e);
    print_pem(&key);

    return 0;
}
