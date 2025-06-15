#include <criterion/criterion.h>

#include "ft_ssl.h"

Test(base64_encode, testSingleChar)
{
    cr_assert_str_eq(base64_encode((u8*)"A", 1), "QQ==");
    cr_assert_str_eq(base64_encode((u8*)"a", 1), "YQ==");
    cr_assert_str_eq(base64_encode((u8*)"B", 1), "Qg==");
    cr_assert_str_eq(base64_encode((u8*)"b", 1), "Yg==");
    cr_assert_str_eq(base64_encode((u8*)"C", 1), "Qw==");
    cr_assert_str_eq(base64_encode((u8*)"c", 1), "Yw==");
}

Test(base64_encode, testDoubleChar)
{
    cr_assert_str_eq(base64_encode((u8*)"AB", 2), "QUI=");
    cr_assert_str_eq(base64_encode((u8*)"BC", 2), "QkM=");
    cr_assert_str_eq(base64_encode((u8*)"CD", 2), "Q0Q=");
}

Test(base64_encode, testTripleChar)
{
    cr_assert_str_eq(base64_encode((u8*)"ABC", 3), "QUJD");
    cr_assert_str_eq(base64_encode((u8*)"BCD", 3), "QkNE");
    cr_assert_str_eq(base64_encode((u8*)"CDE", 3), "Q0RF");
}

Test(base64_encode, testQuadrupleChar)
{
    cr_assert_str_eq(base64_encode((u8*)"ABCD", 4), "QUJDRA==");
    cr_assert_str_eq(base64_encode((u8*)"BCDE", 4), "QkNERQ==");
    cr_assert_str_eq(base64_encode((u8*)"CDEF", 4), "Q0RFRg==");
}

Test(base64_encode, misc)
{
    cr_assert_str_eq(base64_encode((u8*)"Hello, World!", 13), "SGVsbG8sIFdvcmxkIQ==");
    cr_assert_str_eq(base64_encode((u8*)"Hello, World!!", 14), "SGVsbG8sIFdvcmxkISE=");
    cr_assert_str_eq(base64_encode((u8*)"Hello, World!!!", 15), "SGVsbG8sIFdvcmxkISEh");
}

// Test(md5, testEmptyString)
// {
//     cr_redirect_stdin();
//     cr_redirect_stdout();
//
//     FILE* f_stdin = cr_get_redirected_stdin();
//
//     fprintf(f_stdin, "");
//     fclose(f_stdin);
//
//     cmd_md5(NULL);
//
//     cr_assert_stdout_eq_str("d41d8cd98f00b204e9800998ecf8427e\n");
// }
