#include "ft_ssl.h"

#include <errno.h>
#include <error.h>

#include "libft.h"

static void hmac(const t_hash_algo* algo,
                 u8*                buffers,
                 const u8*          key,
                 usize              key_len,
                 const u8*          data,
                 usize              data_len,
                 u8*                digest)
{
    usize ctx_size    = algo->ctx_size;
    usize block_size  = algo->block_size;
    usize digest_size = algo->digest_size;

    void* ctx          = buffers;
    u8*   k_ipad       = buffers + ctx_size;
    u8*   k_opad       = k_ipad + block_size;
    u8*   inner_digest = k_opad + block_size;

    // If key is longer than block size, hash it first
    if (key_len > block_size) {
        algo->str((const char*)key, key_len, k_ipad);
        key_len = digest_size;
    } else {
        ft_memcpy(k_ipad, key, key_len);
    }

    // Pad key with zeros
    ft_bzero(k_ipad + key_len, block_size - key_len);
    ft_memcpy(k_opad, k_ipad, block_size);

    // XOR key with inner and outer padding
    for (usize i = 0; i < block_size; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // Inner hash
    algo->init(ctx);
    algo->update(ctx, k_ipad, block_size);
    algo->update(ctx, data, data_len);
    algo->final(ctx, inner_digest);

    // Outer hash
    algo->init(ctx);
    algo->update(ctx, k_opad, block_size);
    algo->update(ctx, inner_digest, digest_size);
    algo->final(ctx, digest);
}

#define IMPLEMENT_HMAC(algo_name, algo_type)                                      \
    void hmac_##algo_name(                                                        \
        const u8* key, usize key_len, const u8* data, usize data_len, u8* digest) \
    {                                                                             \
        const t_hash_algo* algo = get_hash_algo(algo_type);                       \
                                                                                  \
        u8 buffers[algo->ctx_size + (algo->block_size * 2) + algo->digest_size];  \
        hmac(algo, buffers, key, key_len, data, data_len, digest);                \
    }

IMPLEMENT_HMAC(md5, HASH_ALGO_MD5)
IMPLEMENT_HMAC(sha256, HASH_ALGO_SHA256)
IMPLEMENT_HMAC(whirlpool, HASH_ALGO_WHIRLPOOL)
