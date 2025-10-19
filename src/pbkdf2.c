#include "ft_ssl.h"

#include <stdlib.h>

#include "libft.h"

u8* pbkdf2(const u8* password,
           usize     password_len,
           const u8* salt,
           usize     salt_len,
           u32       iterations,
           usize     dk_len)
{
    if (dk_len == 0 || iterations == 0 || password == NULL || salt == NULL)
        return NULL;

    u32 blocks = (dk_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;

    u8* digest = malloc(SHA256_DIGEST_SIZE * 2 + salt_len + 4);
    if (digest == NULL)
        return NULL;

    u8* derived_key = malloc(dk_len);
    if (derived_key == NULL)
        goto cleanup;

    u8* u          = digest + SHA256_DIGEST_SIZE;
    u8* salt_block = digest + SHA256_DIGEST_SIZE * 2;

    ft_memcpy(salt_block, salt, salt_len);

    for (u32 i = 1; i <= blocks; ++i) {
        // Prepare salt || INT(i)
        salt_block[salt_len++] = (i >> 24) & 0xFF;
        salt_block[salt_len++] = (i >> 16) & 0xFF;
        salt_block[salt_len++] = (i >> 8) & 0xFF;
        salt_block[salt_len++] = i & 0xFF;

        // U1 = HMAC(password, salt || INT(i))
        hmac_sha256(password, password_len, salt_block, salt_len, u);

        // T_i = U1
        ft_memcpy(digest, u, SHA256_DIGEST_SIZE);

        for (u32 j = 1; j < iterations; ++j) {
            // Uj = HMAC(password, Uj-1)
            hmac_sha256(password, password_len, u, SHA256_DIGEST_SIZE, u);

            // T_i = T_i XOR Uj
            for (usize k = 0; k < SHA256_DIGEST_SIZE; k++)
                digest[k] ^= u[k];
        }

        // Copy T_i to output
        usize offset  = (i - 1) * SHA256_DIGEST_SIZE;
        usize to_copy = (i == blocks) ? (dk_len - offset) : SHA256_DIGEST_SIZE;
        ft_memcpy(derived_key + offset, digest, to_copy);
    }

cleanup:
    free(digest);

    return derived_key;
}
