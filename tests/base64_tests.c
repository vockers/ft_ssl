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

Test(base64_decode, testSingleChar)
{
    usize output_length;
    u8*   decoded = base64_decode("QQ==", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"A", 1);
    cr_assert_eq(output_length, 1);
    free(decoded);

    decoded = base64_decode("YQ==", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"a", 1);
    cr_assert_eq(output_length, 1);
    free(decoded);

    decoded = base64_decode("Qg==", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"B", 1);
    cr_assert_eq(output_length, 1);
}

Test(base64_decode, testDoubleChar)
{
    usize output_length;
    u8*   decoded = base64_decode("QUI=", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"AB", 2);
    cr_assert_eq(output_length, 2);
    free(decoded);

    decoded = base64_decode("QkM=", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"BC", 2);
    cr_assert_eq(output_length, 2);
    free(decoded);

    decoded = base64_decode("Q0Q=", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"CD", 2);
    cr_assert_eq(output_length, 2);
    free(decoded);
}

Test(base64_decode, testTripleChar)
{
    usize output_length;
    u8*   decoded = base64_decode("QUJD", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"ABC", 3);
    cr_assert_eq(output_length, 3);
    free(decoded);

    decoded = base64_decode("QkNE", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"BCD", 3);
    cr_assert_eq(output_length, 3);
    free(decoded);

    decoded = base64_decode("Q0RF", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"CDE", 3);
    cr_assert_eq(output_length, 3);
    free(decoded);
}

Test(base64_decode, testQuadrupleChar)
{
    usize output_length;
    u8*   decoded = base64_decode("QUJDRA==", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"ABCD", 4);
    cr_assert_eq(output_length, 4);
    free(decoded);

    decoded = base64_decode("QkNERQ==", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"BCDE", 4);
    cr_assert_eq(output_length, 4);
    free(decoded);

    decoded = base64_decode("Q0RFRg==", &output_length);
    cr_assert_arr_eq(decoded, (u8*)"CDEF", 4);
    cr_assert_eq(output_length, 4);
    free(decoded);
}

Test(base64_decode, testErrors)
{
    usize output_length;
    u8*   decoded;

    // Invalid base64 string length
    decoded = base64_decode("A", &output_length);
    cr_assert_null(decoded);

    // Invalid characters
    decoded = base64_decode("!@#$%", &output_length);
    cr_assert_null(decoded);

    // Invalid padding
    decoded = base64_decode("QUJDRA", &output_length);
    cr_assert_null(decoded);
}