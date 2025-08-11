#include "ft_ssl.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "libft.h"

static const char* base64_table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int base64_decode_table[] = {
    62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1,
    -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

static bool base64_is_valid_group(const char* input)
{
    for (usize i = 0; i < 4; i++) {
        char c = input[i];
        if ((c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != '+' &&
            c != '/' && c != '=') {
            return false;
        }
    }
    return true;
}

char* base64_encode(const u8* data, usize input_length)
{
    if (input_length == 0) {
        return ft_calloc(1, sizeof(char)); // Return empty string if input length is 0
    }

    usize output_length = ((input_length - 1) / 3) * 4 + 4;
    char* output        = malloc(sizeof(char) * (output_length + 1));
    if (output == NULL) {
        return NULL;
    }

    for (usize i = 0, j = 0; i < input_length;) {
        u32 octet_a = (u8)data[i++];
        u32 octet_b = i < input_length ? (u8)data[i++] : 0;
        u32 octet_c = i < input_length ? (u8)data[i++] : 0;

        u32 triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        output[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    // Add padding if input_length is not a multiple of 3
    for (usize i = 0; i < (3 - (input_length % 3)) % 3; i++)
        output[output_length - 1 - i] = '=';

    output[output_length] = '\0';

    return output;
}

u8* base64_decode(const char* input, usize n, usize* output_length)
{
    if (input == NULL || *input == '\0') {
        return NULL;
    }

    usize input_length = MIN(ft_strlen(input), n);
    if (input_length % 4 != 0) {
        return NULL; // Invalid base64 string length
    }

    usize decoded_length = (input_length / 4) * 3;
    if (input[input_length - 1] == '=')
        decoded_length--;
    if (input[input_length - 2] == '=')
        decoded_length--;

    u8* output = malloc(decoded_length);
    if (output == NULL) {
        return NULL;
    }

    for (usize i = 0, j = 0; i < input_length; i += 4, j += 3) {
        if (!base64_is_valid_group(&input[i])) {
            free(output);
            return NULL;
        }

        i32 v = base64_decode_table[input[i] - 43];

        v = (v << 6) | base64_decode_table[input[i + 1] - 43];
        v = input[i + 2] == '=' ? v << 6 : (v << 6) | base64_decode_table[input[i + 2] - 43];
        v = input[i + 3] == '=' ? v << 6 : (v << 6) | base64_decode_table[input[i + 3] - 43];

        output[j] = (v >> 16) & 0xFF;
        if (input[i + 2] != '=')
            output[j + 1] = (v >> 8) & 0xFF;
        if (input[i + 3] != '=')
            output[j + 2] = v & 0xFF;
    }

    *output_length = decoded_length;
    return output;
}
