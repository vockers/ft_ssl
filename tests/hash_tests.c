#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <signal.h>

#include "ft_ssl.h"

void test_hash_str(const char* str,
                   const char* expected,
                   usize       digest_size,
                   void (*hash_func)(const char*, usize, u8*))
{
    u8   digest[SHA256_DIGEST_SIZE];
    char digest_str[SHA256_DIGEST_SIZE * 2 + 1];

    hash_func(str, ft_strlen(str), digest);
    for (size_t i = 0; i < digest_size; i++) {
        sprintf(digest_str + i * 2, "%02x", digest[i]);
    }
    digest_str[digest_size * 2] = '\0';

    cr_assert_str_eq(
        digest_str, expected, "Hash '%s' does not match expected '%s'\n", digest_str, expected);
}

#define TEST_MD5(str, expected)    test_hash_str(str, expected, MD5_DIGEST_SIZE, md5_str)
#define TEST_SHA256(str, expected) test_hash_str(str, expected, SHA256_DIGEST_SIZE, sha256_str)

Test(md5, test_md5)
{
    TEST_MD5("", "d41d8cd98f00b204e9800998ecf8427e");
    TEST_MD5("Hello, World!", "65a8e27d8879283831b664bd8b7f0ad4");
    TEST_MD5("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6");
    TEST_MD5("The quick brown fox jumps over the lazy dog.", "e4d909c290d0fb1ca068ffaddf22cbd0");
    TEST_MD5("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
             "35899082e51edf667f14477ac000cbba");
}

Test(sha256, test_sha256)
{
    TEST_SHA256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    TEST_SHA256("Hello, World!",
                "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    TEST_SHA256("The quick brown fox jumps over the lazy dog",
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    TEST_SHA256("The quick brown fox jumps over the lazy dog.",
                "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c");
    TEST_SHA256("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
                "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433");
}
