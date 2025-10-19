#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "../include/ft_ssl.h"

#include "libft.h"

#define IMPLEMENT_TEST_HMAC(algo_name, digest_size)                                          \
    void test_hmac_##algo_name(const char* key, const char* message, const char* expected)   \
    {                                                                                        \
        u8 digest[digest_size];                                                              \
        hmac_##algo_name(                                                                    \
            (const u8*)key, ft_strlen(key), (const u8*)message, ft_strlen(message), digest); \
        char digest_str[digest_size * 2 + 1];                                                \
        for (size_t i = 0; i < digest_size; i++) {                                           \
            sprintf(digest_str + i * 2, "%02x", digest[i]);                                  \
        }                                                                                    \
        digest_str[digest_size * 2] = '\0';                                                  \
        cr_assert_str_eq(digest_str,                                                         \
                         expected,                                                           \
                         "HMAC '%s' does not match expected '%s'\n",                         \
                         digest_str,                                                         \
                         expected);                                                          \
    }

IMPLEMENT_TEST_HMAC(md5, MD5_DIGEST_SIZE)
IMPLEMENT_TEST_HMAC(sha256, SHA256_DIGEST_SIZE)
IMPLEMENT_TEST_HMAC(whirlpool, WHIRLPOOL_DIGEST_SIZE)

Test(hmac_md5, test_hmac_md5)
{
    test_hmac_md5(
        "key", "The quick brown fox jumps over the lazy dog", "80070713463e7749b90c2dc24911e275");
    test_hmac_md5(
        "test", "The quick brown fox jumps over the lazy dog", "8499fbd52ef011d0e8259446c77c6392");
    test_hmac_md5("key", "Hello, World!", "cfad9d610c1e548a03562f8eac399033");
}

Test(hmac_sha256, test_hmac_sha256)
{
    test_hmac_sha256("key",
                     "The quick brown fox jumps over the lazy dog",
                     "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    test_hmac_sha256("test",
                     "The quick brown fox jumps over the lazy dog",
                     "e5290fc426cb3ca84e7df629bc66fd3a5e1d3dde82a4afcbcf4217d0071f83e2");
    test_hmac_sha256(
        "key", "Hello, World!", "7f424e2d0ff6bd5dec626e0102755bafec91c3510f19739a4eaec8f3bc3a01a4");
}
