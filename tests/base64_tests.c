#include <criterion/criterion.h>

#include "ft_ssl.h"

#include <string.h>

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

#define TEST_BASE64_DECODE(input, expected_output)                                   \
    {                                                                                \
        usize output_length;                                                         \
        u8*   decoded         = base64_decode(input, strlen(input), &output_length); \
        usize expected_length = strlen(expected_output);                             \
        cr_assert_arr_eq(decoded, (u8*)expected_output, expected_length);            \
        cr_assert_eq(output_length, expected_length);                                \
        free(decoded);                                                               \
    }

#define TEST_BASE64_DECODE_ERROR(input)                                      \
    {                                                                        \
        usize output_length;                                                 \
        u8*   decoded = base64_decode(input, strlen(input), &output_length); \
        cr_assert_null(decoded);                                             \
    }

Test(base64_decode, testSingleChar)
{
    TEST_BASE64_DECODE("QQ==", "A");
    TEST_BASE64_DECODE("YQ==", "a");
    TEST_BASE64_DECODE("Qg==", "B");
    TEST_BASE64_DECODE("Yg==", "b");
}

Test(base64_decode, testDoubleChar)
{
    TEST_BASE64_DECODE("QUI=", "AB");
    TEST_BASE64_DECODE("QkM=", "BC");
    TEST_BASE64_DECODE("Q0Q=", "CD");
}

Test(base64_decode, testTripleChar)
{
    TEST_BASE64_DECODE("QUJD", "ABC");
    TEST_BASE64_DECODE("QkNE", "BCD");
    TEST_BASE64_DECODE("Q0RF", "CDE");
}

Test(base64_decode, testQuadrupleChar)
{
    TEST_BASE64_DECODE("QUJDRA==", "ABCD");
    TEST_BASE64_DECODE("QkNERQ==", "BCDE");
    TEST_BASE64_DECODE("Q0RFRg==", "CDEF");
}

Test(base64_decode, testErrors)
{
    TEST_BASE64_DECODE_ERROR("A");
    TEST_BASE64_DECODE_ERROR("!@#$%");
    TEST_BASE64_DECODE_ERROR("QUJDRA");
}
