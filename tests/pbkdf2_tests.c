#include <criterion/criterion.h>
#include <criterion/redirect.h>

#include "../include/ft_ssl.h"

#include "libft.h"

void test_pbkdf2(const char* password,
                 const char* salt,
                 u32         iterations,
                 usize       dk_len,
                 const char* expected_dk_hex)
{
    u8*  derived_key = pbkdf2((const u8*)password,
                             ft_strlen(password),
                             (const u8*)salt,
                             ft_strlen(salt),
                             iterations,
                             dk_len);
    char derived_key_hex[dk_len * 2 + 1];
    for (usize i = 0; i < dk_len; i++) {
        sprintf(derived_key_hex + i * 2, "%02x", derived_key[i]);
    }
    derived_key_hex[dk_len * 2] = '\0';

    cr_assert_str_eq(derived_key_hex,
                     expected_dk_hex,
                     "PBKDF2 derived key '%s' does not match expected '%s'\n",
                     derived_key_hex,
                     expected_dk_hex);

    free(derived_key);
}

// clang-format off
Test(pbkdf2, test_pbkdf2)
{
    test_pbkdf2("password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    test_pbkdf2("password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    test_pbkdf2("password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    test_pbkdf2("password", "salt", 1000, 16, "632c2812e46d4604102ba7618e9d6d7d");
}
