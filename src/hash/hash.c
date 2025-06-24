#include "ft_ssl.h"

#include "libft.h"

// clang-format off
static const t_hash_algo g_hash_algos[] = {
    {
        .name        = "MD5",
        .init        = (void*)md5_init,
        .update      = (void*)md5_update,
        .final       = (void*)md5_final,
        .str         = md5_str,
        .digest_size = MD5_DIGEST_SIZE,
        .block_size  = MD5_BLOCK_SIZE,
        .ctx_size    = sizeof(t_md5_ctx)
    },
    {
        .name        = "SHA256",
        .init        = (void*)sha256_init,
        .update      = (void*)sha256_update,
        .final       = (void*)sha256_final,
        .str         = sha256_str,
        .digest_size = SHA256_DIGEST_SIZE,
        .block_size  = SHA256_BLOCK_SIZE,
        .ctx_size    = sizeof(t_sha256_ctx)
    },
    {
        .name        = "WHIRLPOOL",
        .init        = (void*)whirlpool_init,
        .update      = (void*)whirlpool_update,
        .final       = (void*)whirlpool_final,
        .str         = whirlpool_str,
        .digest_size = WHIRLPOOL_DIGEST_SIZE,
        .block_size  = WHIRLPOOL_BLOCK_SIZE,
        .ctx_size    = sizeof(t_whirlpool_ctx)
    },
    {NULL, NULL, NULL, NULL, NULL, 0, 0, 0},
};
// clang-format on

const t_hash_algo* get_hash_algo(t_hash_algo_type type)
{
    return &g_hash_algos[type];
}

const t_hash_algo* find_hash_algo(const char* name)
{
    for (const t_hash_algo* algo = g_hash_algos; algo->name != NULL; ++algo) {
        if (ft_strcasecmp(algo->name, name) == 0) {
            return algo;
        }
    }

    return NULL;
}
